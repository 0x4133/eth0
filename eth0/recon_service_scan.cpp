// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_service_scan.h"

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

// ── HTTP probe sent to ports that wait for the client to speak first ──
static const char httpProbe[] =
    "GET / HTTP/1.0\r\nHost: target\r\nUser-Agent: eth0-scanner\r\n\r\n";

// ── Determine if a port needs a client probe to elicit a banner ──
static bool portNeedsProbe(uint16_t port) {
  // These protocols wait for the client to speak first
  return (port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 ||
          port == 3000 || port == 9090);
}

// ── Extract readable banner from raw TCP payload ──
// Copies printable chars, stops at first NUL or after maxLen
static void extractBanner(const uint8_t* data, uint16_t dataLen, char* out, uint16_t maxLen) {
  uint16_t j = 0;
  for (uint16_t i = 0; i < dataLen && j < maxLen - 1; i++) {
    uint8_t c = data[i];
    if (c == '\r')
      continue;
    if (c == '\n') {
      // Stop at second newline (end of first line for most banners)
      if (j > 0 && out[j - 1] == '|')
        break;
      out[j++] = '|';  // visual separator for multi-line
      continue;
    }
    if (c >= 0x20 && c < 0x7F) {
      out[j++] = (char)c;
    } else if (c == '\t') {
      out[j++] = ' ';
    }
    // skip non-printable
  }
  // Trim trailing separators
  while (j > 0 && (out[j - 1] == '|' || out[j - 1] == ' '))
    j--;
  out[j] = '\0';
}

void reconServiceScan(const uint8_t* targetIP, const uint16_t* ports, uint8_t numPorts) {
  Serial.printf("\n[SCAN] Service scan: %u.%u.%u.%u (%u ports)\n", targetIP[0], targetIP[1],
                targetIP[2], targetIP[3], numPorts);

  idsSetLed(COLOR_YELLOW);

  // Resolve target MAC
  uint8_t dstMAC[6];
  if (!resolveMacForIP(targetIP, dstMAC)) {
    Serial.println("[SCAN] Failed to resolve target MAC. Try: recon sweep first.");
    idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
    return;
  }

  Serial.printf("[SCAN] Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", dstMAC[0], dstMAC[1],
                dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5]);
  Serial.println("[SCAN] PORT       STATE    SERVICE");
  Serial.println("[SCAN] ─────────────────────────────────────────────");

  static uint16_t ephPort = 41000;
  uint8_t openCount = 0;

  for (uint8_t p = 0; p < numPorts; p++) {
    uint16_t dstPort = ports[p];
    uint16_t srcPort = ephPort++;
    if (ephPort > 59000)
      ephPort = 41000;

    // ── Phase 1: SYN ──
    uint32_t mySeq = micros() ^ (dstPort << 16) ^ srcPort;
    uint16_t frameLen = buildTcpSyn(txBuf, dstMAC, ourIP, targetIP, srcPort, dstPort);
    sendRawFrame(txBuf, frameLen);

    // ── Phase 2: Wait for SYN-ACK or RST ──
    uint32_t synAckDeadline = millis() + 1500;
    bool gotSynAck = false;
    bool gotRst = false;
    uint32_t serverSeq = 0;

    while (millis() < synAckDeadline) {
      uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      if (rxSize == 0) {
        delay(1);
        continue;
      }

      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len < ETH_HEADER_LEN + 40)
        continue;
      if (pktRead16(packetBuf + ETH_TYPE) != ETHERTYPE_IPV4)
        continue;

      const uint8_t* ipH = packetBuf + ETH_HEADER_LEN;
      if (ipH[9] != IP_PROTO_TCP)
        continue;
      if (memcmp(ipH + 12, targetIP, 4) != 0)
        continue;

      uint8_t ihl = (ipH[0] & 0x0F) * 4;
      const uint8_t* tcpH = ipH + ihl;
      if (pktRead16(tcpH) != dstPort || pktRead16(tcpH + 2) != srcPort)
        continue;

      uint8_t flags = tcpH[13];
      if ((flags & 0x12) == 0x12) {  // SYN+ACK
        serverSeq = pktRead32(tcpH + 4);
        gotSynAck = true;
        break;
      }
      if (flags & 0x04) {  // RST
        gotRst = true;
        break;
      }
    }

    if (!gotSynAck) {
      if (gotRst) {
        // closed — don't print, too noisy
      } else {
        Serial.printf("[SCAN] %-5u/tcp  filtered\n", dstPort);
      }
      continue;
    }

    // ── Phase 3: Complete handshake — send ACK ──
    uint32_t myAck = serverSeq + 1;
    mySeq++;  // SYN consumed one sequence number

    frameLen = buildTcpAck(txBuf, dstMAC, ourIP, targetIP, srcPort, dstPort, mySeq, myAck);
    sendRawFrame(txBuf, frameLen);

    openCount++;

    // ── Phase 4: Send probe if needed, then wait for banner ──
    if (portNeedsProbe(dstPort)) {
      delay(10);
      frameLen = buildTcpDataPush(txBuf, dstMAC, ourIP, targetIP, srcPort, dstPort, mySeq, myAck,
                                  (const uint8_t*)httpProbe, strlen(httpProbe));
      sendRawFrame(txBuf, frameLen);
      mySeq += strlen(httpProbe);
    }

    // ── Phase 5: Read banner ──
    char banner[128] = {0};
    bool gotBanner = false;
    uint32_t bannerDeadline = millis() + 2000;

    while (millis() < bannerDeadline) {
      uint16_t rxSize = w5500.getRXReceivedSize(RAW_SOCKET);
      if (rxSize == 0) {
        delay(5);
        continue;
      }

      uint16_t len = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (len < ETH_HEADER_LEN + 40)
        continue;
      if (pktRead16(packetBuf + ETH_TYPE) != ETHERTYPE_IPV4)
        continue;

      const uint8_t* ipH = packetBuf + ETH_HEADER_LEN;
      if (ipH[9] != IP_PROTO_TCP)
        continue;
      if (memcmp(ipH + 12, targetIP, 4) != 0)
        continue;

      uint8_t ihl = (ipH[0] & 0x0F) * 4;
      const uint8_t* tcpH = ipH + ihl;
      if (pktRead16(tcpH) != dstPort || pktRead16(tcpH + 2) != srcPort)
        continue;

      uint8_t flags = tcpH[13];
      uint8_t tcpHdrLen = ((tcpH[12] >> 4) & 0x0F) * 4;

      // Check for data (PSH+ACK or just ACK with payload)
      uint16_t ipTotalLen = pktRead16(ipH + 2);
      int payloadLen = ipTotalLen - ihl - tcpHdrLen;

      if (payloadLen > 0) {
        const uint8_t* payload = tcpH + tcpHdrLen;
        extractBanner(payload, (uint16_t)payloadLen, banner, sizeof(banner));
        gotBanner = true;

        // ACK the data
        uint32_t theirSeq = pktRead32(tcpH + 4);
        myAck = theirSeq + payloadLen;
        uint16_t ackFrame = buildTcpAck(txBuf, dstMAC, ourIP, targetIP, srcPort, dstPort, mySeq,
                                        myAck);
        sendRawFrame(txBuf, ackFrame);
        break;
      }

      // FIN from server (no data to send)
      if (flags & 0x01)
        break;
    }

    // ── Phase 6: RST to tear down ──
    frameLen = buildTcpRst(txBuf, dstMAC, ourIP, targetIP, srcPort, dstPort, mySeq);
    sendRawFrame(txBuf, frameLen);

    // ── Print result ──
    if (gotBanner && banner[0] != '\0') {
      Serial.printf("[SCAN] %-5u/tcp  open     %s\n", dstPort, banner);
    } else {
      Serial.printf("[SCAN] %-5u/tcp  open\n", dstPort);
    }

    delay(50);  // brief pause between ports
  }

  if (capturing && uncommittedPkts > 0)
    commitCaptureFile();

  Serial.printf("\n[SCAN] Done. %u open ports on %u.%u.%u.%u\n", openCount, targetIP[0],
                targetIP[1], targetIP[2], targetIP[3]);

  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}
