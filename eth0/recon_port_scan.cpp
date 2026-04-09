// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_port_scan.h"

#include <string.h>

#include <Arduino.h>
#include <Ethernet2.h>
#include <utility/socket.h>
#include <utility/w5500.h>

#include "arp_table.h"
#include "config.h"
#include "eth_frame.h"
#include "ids.h"
#include "inject.h"
#include "pcap_writer.h"
#include "state.h"

void reconSynProbe(const uint8_t* targetIP, const uint16_t* ports, uint8_t numPorts) {
  Serial.printf("[RECON] TCP SYN probe: %u.%u.%u.%u (%u ports)\n", targetIP[0], targetIP[1],
                targetIP[2], targetIP[3], numPorts);

  idsSetLed(COLOR_YELLOW);

  // Try to find target MAC in ARP table, fall back to broadcast
  uint8_t dstMAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  for (int i = 0; i < ARP_TABLE_SIZE; i++) {
    if (arpTable[i].active && memcmp(arpTable[i].ip, targetIP, 4) == 0) {
      memcpy(dstMAC, arpTable[i].mac, 6);
      break;
    }
  }

  // If target is not on our subnet, use gateway MAC
  bool sameSubnet = true;
  for (int i = 0; i < 4; i++) {
    if ((targetIP[i] & ourSubnet[i]) != (ourIP[i] & ourSubnet[i])) {
      sameSubnet = false;
      break;
    }
  }
  if (!sameSubnet) {
    // Look up gateway MAC in ARP table
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
      if (arpTable[i].active && memcmp(arpTable[i].ip, ourGW, 4) == 0) {
        memcpy(dstMAC, arpTable[i].mac, 6);
        break;
      }
    }
    // If gateway MAC unknown, send an ARP request for it first
    if (dstMAC[0] == 0xFF && dstMAC[1] == 0xFF) {
      Serial.println("  [RECON] Resolving gateway MAC...");
      sendArpRequest(ourGW);
      delay(500);
      // Check for reply
      uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      while (rxSize > 0) {
        uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
        if (len > ETH_HEADER_LEN + 28) {
          uint16_t etype = pktRead16(packetBuf + ETH_TYPE);
          if (etype == ETHERTYPE_ARP) {
            const uint8_t* arp = packetBuf + ETH_HEADER_LEN;
            if (pktRead16(arp + 6) == 2) {  // ARP Reply
              const uint8_t* senderIP = arp + 14;
              const uint8_t* senderMAC = arp + 8;
              if (memcmp(senderIP, ourGW, 4) == 0) {
                memcpy(dstMAC, senderMAC, 6);
              }
              if (idsEnabled)
                idsCheckArp(packetBuf, len);
            }
          }
        }
        rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      }
    }
  }

  uint16_t openPorts[64];
  uint8_t openCount = 0;
  uint16_t closedCount = 0;
  uint16_t filteredCount = 0;

  static uint16_t ephemeralPort = 40000;

  for (uint8_t p = 0; p < numPorts; p++) {
    uint16_t dstPort = ports[p];
    uint16_t srcPort = ephemeralPort++;
    if (ephemeralPort > 60000)
      ephemeralPort = 40000;

    // Build and send SYN
    uint16_t frameLen = buildTcpSyn(txBuf, dstMAC, ourIP, targetIP, srcPort, dstPort);
    sendRawFrame(txBuf, frameLen);

    // Brief pause between probes
    delay(20);

    // Check for responses
    bool gotResponse = false;
    uint32_t probeTimeout = millis() + 200;

    while (millis() < probeTimeout) {
      uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      if (rxSize == 0) {
        delay(1);
        continue;
      }

      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len < ETH_HEADER_LEN + 40)
        continue;  // need IP + TCP headers

      uint16_t etype = pktRead16(packetBuf + ETH_TYPE);
      if (etype != ETHERTYPE_IPV4)
        continue;

      const uint8_t* ipHdr = packetBuf + ETH_HEADER_LEN;
      uint8_t proto = ipHdr[9];
      if (proto != IP_PROTO_TCP)
        continue;

      const uint8_t* srcIPpkt = ipHdr + 12;
      if (memcmp(srcIPpkt, targetIP, 4) != 0)
        continue;

      uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
      const uint8_t* tcpHdr = ipHdr + ipHdrLen;
      uint16_t respSrcPort = pktRead16(tcpHdr);
      uint16_t respDstPort = pktRead16(tcpHdr + 2);

      if (respSrcPort != dstPort || respDstPort != srcPort)
        continue;

      uint8_t flags = tcpHdr[13];
      bool syn = (flags & 0x02) != 0;
      bool ack = (flags & 0x10) != 0;
      bool rst = (flags & 0x04) != 0;

      if (syn && ack) {
        // PORT OPEN — got SYN-ACK
        if (openCount < 64)
          openPorts[openCount++] = dstPort;
        Serial.printf("  [OPEN]   %u/tcp\n", dstPort);

        // Send RST to be polite (close the half-open connection)
        // We'll just let it timeout — good enough for a probe
        gotResponse = true;
        break;
      } else if (rst) {
        // PORT CLOSED
        closedCount++;
        gotResponse = true;
        break;
      }

      // Write to capture
      if (capturing) {
        writePcapPacket(packetBuf, len);
        packetCount++;
        uncommittedPkts++;
      }
    }

    if (!gotResponse) {
      filteredCount++;  // No response = filtered
    }
  }

  if (capturing && uncommittedPkts > 0)
    commitCaptureFile();

  // Summary
  Serial.println();
  Serial.printf("[RECON] SYN probe done on %u.%u.%u.%u\n", targetIP[0], targetIP[1], targetIP[2],
                targetIP[3]);
  Serial.printf("  Open:     %u", openCount);
  if (openCount > 0) {
    Serial.print(" (");
    for (int i = 0; i < openCount; i++) {
      if (i > 0)
        Serial.print(", ");
      Serial.print(openPorts[i]);
    }
    Serial.print(")");
  }
  Serial.println();
  Serial.printf("  Closed:   %u\n", closedCount);
  Serial.printf("  Filtered: %u\n", filteredCount);

  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}
