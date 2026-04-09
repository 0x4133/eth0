// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_vlan_discover.h"

#include <string.h>

#include <Arduino.h>
#include <Ethernet2.h>
#include <utility/socket.h>
#include <utility/w5500.h>

#include "config.h"
#include "eth_frame.h"
#include "ids.h"
#include "inject.h"
#include "pcap_writer.h"
#include "state.h"

// ── Build an 802.1Q VLAN-tagged frame ──
// Inserts a 4-byte VLAN tag after source MAC.
// Returns total frame length.
uint16_t buildVlanFrame(uint8_t* buf, const uint8_t* dstMAC, uint16_t vlanID,
                        uint16_t innerEthertype) {
  uint16_t pos = 0;

  // Dst MAC
  memcpy(buf + pos, dstMAC, 6);
  pos += 6;
  // Src MAC
  memcpy(buf + pos, mac, 6);
  pos += 6;
  // 802.1Q TPID
  pktWrite16(buf + pos, 0x8100);
  pos += 2;
  // TCI: priority(3) + DEI(1) + VLAN ID(12)
  pktWrite16(buf + pos, vlanID & 0x0FFF);
  pos += 2;
  // Inner EtherType
  pktWrite16(buf + pos, innerEthertype);
  pos += 2;

  return pos;
}

void reconVlanDiscover() {
  Serial.println("[RECON] 802.1Q VLAN discovery (VLANs 1-100)...");
  Serial.println("  Sending tagged ARP probes on each VLAN.");

  idsSetLed(COLOR_YELLOW);

  uint16_t foundVlans[32];
  uint8_t foundCount = 0;

  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  for (uint16_t vlan = 1; vlan <= 100; vlan++) {
    // Build a VLAN-tagged ARP who-has for the gateway
    uint16_t pos = buildVlanFrame(txBuf, broadcast, vlan, ETHERTYPE_ARP);

    // ARP payload: who-has ourGW tell ourIP
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // HW type: Ethernet
    pktWrite16(txBuf + pos, 0x0800);
    pos += 2;          // Proto: IPv4
    txBuf[pos++] = 6;  // HW addr len
    txBuf[pos++] = 4;  // Proto addr len
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // Op: Request
    memcpy(txBuf + pos, mac, 6);
    pos += 6;  // Sender MAC
    memcpy(txBuf + pos, ourIP, 4);
    pos += 4;  // Sender IP
    memset(txBuf + pos, 0x00, 6);
    pos += 6;  // Target MAC (unknown)
    memcpy(txBuf + pos, ourGW, 4);
    pos += 4;  // Target IP

    while (pos < 64)
      txBuf[pos++] = 0;  // Pad (min frame + VLAN tag)

    sendRawFrame(txBuf, pos);
    delay(10);

    // Quick check for replies
    uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    while (rxSize > 0) {
      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len > 18) {  // 14 eth + 4 vlan tag minimum
        uint16_t tpid = pktRead16(packetBuf + 12);
        if (tpid == 0x8100) {
          uint16_t tci = pktRead16(packetBuf + 14);
          uint16_t respVlan = tci & 0x0FFF;
          // Check if we already found this one
          bool dup = false;
          for (int i = 0; i < foundCount; i++) {
            if (foundVlans[i] == respVlan) {
              dup = true;
              break;
            }
          }
          if (!dup && foundCount < 32) {
            foundVlans[foundCount++] = respVlan;
            Serial.printf("  [VLAN] ID %u - active (tagged response received)\n", respVlan);
          }
        }
      }
      if (capturing && len > 0) {
        writePcapPacket(packetBuf, len);
        packetCount++;
        uncommittedPkts++;
      }
      rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    }
  }

  // Final wait for late replies
  uint32_t waitUntil = millis() + 2000;
  while (millis() < waitUntil) {
    uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    while (rxSize > 0) {
      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len > 18) {
        uint16_t tpid = pktRead16(packetBuf + 12);
        if (tpid == 0x8100) {
          uint16_t tci = pktRead16(packetBuf + 14);
          uint16_t respVlan = tci & 0x0FFF;
          bool dup = false;
          for (int i = 0; i < foundCount; i++) {
            if (foundVlans[i] == respVlan) {
              dup = true;
              break;
            }
          }
          if (!dup && foundCount < 32) {
            foundVlans[foundCount++] = respVlan;
            Serial.printf("  [VLAN] ID %u - active\n", respVlan);
          }
        }
      }
      rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    }
    delay(10);
  }

  if (capturing && uncommittedPkts > 0)
    commitCaptureFile();

  Serial.printf("[RECON] VLAN discovery done. %u active VLANs found.\n", foundCount);
  if (foundCount == 0) {
    Serial.println("  (No tagged responses — port may be access mode, not trunk)");
  }

  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}
