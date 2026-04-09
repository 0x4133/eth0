// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_arp_sweep.h"

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

void reconArpSweep(uint32_t startIP, uint32_t endIP) {
  if (startIP > endIP)
    return;
  // Need at least one scannable host between network and broadcast.
  if (endIP - startIP < 2) {
    Serial.println("[RECON] ARP sweep: range too small (need at least /30).");
    return;
  }

  uint8_t startArr[4] = {(uint8_t)(startIP >> 24), (uint8_t)(startIP >> 16),
                         (uint8_t)(startIP >> 8), (uint8_t)(startIP)};
  uint8_t endArr[4] = {(uint8_t)(endIP >> 24), (uint8_t)(endIP >> 16), (uint8_t)(endIP >> 8),
                       (uint8_t)(endIP)};
  Serial.printf("[RECON] ARP sweep: %u.%u.%u.%u - %u.%u.%u.%u\n", startArr[0], startArr[1],
                startArr[2], startArr[3], endArr[0], endArr[1], endArr[2], endArr[3]);

  // Total scannable hosts = range size minus network + broadcast.
  uint32_t totalHosts = (endIP - startIP + 1) - 2;

  idsSetLed(COLOR_YELLOW);

  uint32_t sent = 0;
  uint32_t found = 0;

  // Iterate (startIP + 1) .. (endIP - 1) inclusive. Using an explicit break
  // before the increment keeps us safe when endIP == 0xFFFFFFFF, where a
  // naive `for (ip = start; ip <= end; ip++)` would wrap and loop forever.
  const uint32_t firstScanIP = startIP + 1;
  const uint32_t lastScanIP = endIP - 1;
  uint32_t ip = firstScanIP;
  for (;;) {
    uint8_t targetIP[4] = {(uint8_t)(ip >> 24), (uint8_t)(ip >> 16), (uint8_t)(ip >> 8),
                           (uint8_t)(ip)};

    // Skip our own IP
    if (memcmp(targetIP, ourIP, 4) != 0) {
      sendArpRequest(targetIP);
      sent++;

      // Small delay to avoid flooding the wire too fast
      delay(5);

      // Check for any incoming ARP replies while we send
      uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      while (rxSize > 0) {
        uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
        if (len > ETH_HEADER_LEN + 28) {
          uint16_t etype = pktRead16(packetBuf + ETH_TYPE);
          if (etype == ETHERTYPE_ARP) {
            const uint8_t* arp = packetBuf + ETH_HEADER_LEN;
            uint16_t op = pktRead16(arp + 6);
            if (op == 2) {  // ARP Reply
              const uint8_t* senderMAC = arp + 8;
              const uint8_t* senderIP = arp + 14;
              Serial.printf("  [FOUND] %u.%u.%u.%u -> %02X:%02X:%02X:%02X:%02X:%02X\n", senderIP[0],
                            senderIP[1], senderIP[2], senderIP[3], senderMAC[0], senderMAC[1],
                            senderMAC[2], senderMAC[3], senderMAC[4], senderMAC[5]);
              found++;

              // Feed to IDS ARP table
              if (idsEnabled)
                idsCheckArp(packetBuf, len);
            }
            // Also write to capture file if capturing
            if (capturing) {
              writePcapPacket(packetBuf, len);
              packetCount++;
              uncommittedPkts++;
            }
          }
        }
        rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      }

      // Print progress every 64 hosts
      if (sent % 64 == 0) {
        Serial.printf("  [SWEEP] %u/%u sent, %u found so far...\n", (unsigned)sent,
                      (unsigned)totalHosts, (unsigned)found);
      }
    }

    if (ip == lastScanIP)
      break;
    ip++;
  }

  // Wait a bit for remaining replies
  Serial.println("  [SWEEP] Waiting for remaining replies...");
  uint32_t waitUntil = millis() + 2000;
  while (millis() < waitUntil) {
    uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    while (rxSize > 0) {
      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len > ETH_HEADER_LEN + 28) {
        uint16_t etype = pktRead16(packetBuf + ETH_TYPE);
        if (etype == ETHERTYPE_ARP) {
          const uint8_t* arp = packetBuf + ETH_HEADER_LEN;
          uint16_t op = pktRead16(arp + 6);
          if (op == 2) {
            const uint8_t* senderMAC = arp + 8;
            const uint8_t* senderIP = arp + 14;
            Serial.printf("  [FOUND] %u.%u.%u.%u -> %02X:%02X:%02X:%02X:%02X:%02X\n", senderIP[0],
                          senderIP[1], senderIP[2], senderIP[3], senderMAC[0], senderMAC[1],
                          senderMAC[2], senderMAC[3], senderMAC[4], senderMAC[5]);
            found++;
            if (idsEnabled)
              idsCheckArp(packetBuf, len);
          }
          if (capturing) {
            writePcapPacket(packetBuf, len);
            packetCount++;
            uncommittedPkts++;
          }
        }
      }
      rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
    }
    delay(10);
  }

  if (capturing && uncommittedPkts > 0)
    commitCaptureFile();

  Serial.printf("[RECON] ARP sweep done. %u sent, %u hosts found.\n", (unsigned)sent,
                (unsigned)found);
  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}
