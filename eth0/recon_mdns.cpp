// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_mdns.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "dns_util.h"
#include "eth_frame.h"
#include "state.h"

MdnsHost mdnsTable[MDNS_TABLE_SIZE];

void mdnsCheckPacket(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 28)
    return;
  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  if (etype != ETHERTYPE_IPV4)
    return;

  const uint8_t* ipHdr = pkt + ETH_HEADER_LEN;
  if (ipHdr[9] != IP_PROTO_UDP)
    return;

  uint8_t ipHdrLen = (ipHdr[0] & 0x0F) * 4;
  const uint8_t* udpHdr = ipHdr + ipHdrLen;
  uint16_t srcPort = pktRead16(udpHdr);
  uint16_t dstPort = pktRead16(udpHdr + 2);
  uint16_t udpLen = pktRead16(udpHdr + 4);
  const uint8_t* srcIP = ipHdr + 12;

  // Skip our own
  if (memcmp(srcIP, ourIP, 4) == 0)
    return;

  bool isMdns = (dstPort == MDNS_PORT || srcPort == MDNS_PORT);
  bool isNbns = (dstPort == NBNS_PORT || srcPort == NBNS_PORT);

  if (!isMdns && !isNbns)
    return;
  if (udpLen < 8 + 12)
    return;

  const uint8_t* dns = udpHdr + 8;
  uint16_t dnsLen = udpLen - 8;

  // For mDNS, parse responses to extract hostnames and services
  if (isMdns) {
    uint16_t flags = pktRead16(dns + 2);
    uint16_t ancount = pktRead16(dns + 6);
    if (ancount == 0 && !(flags & 0x8000)) {
      // Query — still useful, decode question name
      char name[64];
      dnsDecodeName(dns, dnsLen, 12, name, sizeof(name));
      if (name[0] == '\0')
        return;

      // Find or create host entry
      int slot = -1, freeSlot = -1;
      for (int i = 0; i < MDNS_TABLE_SIZE; i++) {
        if (!mdnsTable[i].active) {
          if (freeSlot < 0)
            freeSlot = i;
          continue;
        }
        if (memcmp(mdnsTable[i].ip, srcIP, 4) == 0) {
          slot = i;
          break;
        }
      }
      if (slot < 0 && freeSlot >= 0)
        slot = freeSlot;
      if (slot < 0)
        return;

      MdnsHost& h = mdnsTable[slot];
      h.active = true;
      memcpy(h.ip, srcIP, 4);
      if (h.hostname[0] == '\0')
        strncpy(h.hostname, name, sizeof(h.hostname) - 1);
      h.lastSeen = millis();
      return;
    }

    // Response — parse answer section for A records
    if (flags & 0x8000) {
      // Skip question section
      uint16_t qdcount = pktRead16(dns + 4);
      uint16_t offset = 12;
      for (uint16_t q = 0; q < qdcount && offset < dnsLen; q++) {
        while (offset < dnsLen && dns[offset] != 0) {
          if ((dns[offset] & 0xC0) == 0xC0) {
            offset += 2;
            goto skipQ;
          }
          offset += 1 + dns[offset];
        }
        offset += 1 + 4;  // null + qtype + qclass
      skipQ:;
      }

      // Parse answers
      for (uint16_t a = 0; a < ancount && offset + 12 <= dnsLen; a++) {
        char aName[64];
        uint16_t consumed = dnsDecodeName(dns, dnsLen, offset, aName, sizeof(aName));

        // Skip name
        while (offset < dnsLen) {
          if ((dns[offset] & 0xC0) == 0xC0) {
            offset += 2;
            break;
          }
          if (dns[offset] == 0) {
            offset++;
            break;
          }
          offset += 1 + dns[offset];
        }

        if (offset + 10 > dnsLen)
          break;
        uint16_t atype = pktRead16(dns + offset);
        offset += 2;
        offset += 2;  // class
        offset += 4;  // TTL
        uint16_t rdlen = pktRead16(dns + offset);
        offset += 2;

        if (atype == 1 && rdlen == 4 && offset + 4 <= dnsLen) {
          // A record
          uint8_t aIP[4];
          memcpy(aIP, dns + offset, 4);

          int slot = -1, freeSlot = -1;
          for (int i = 0; i < MDNS_TABLE_SIZE; i++) {
            if (!mdnsTable[i].active) {
              if (freeSlot < 0)
                freeSlot = i;
              continue;
            }
            if (memcmp(mdnsTable[i].ip, aIP, 4) == 0) {
              slot = i;
              break;
            }
          }
          if (slot < 0 && freeSlot >= 0)
            slot = freeSlot;
          if (slot >= 0) {
            MdnsHost& h = mdnsTable[slot];
            h.active = true;
            memcpy(h.ip, aIP, 4);
            strncpy(h.hostname, aName, sizeof(h.hostname) - 1);
            h.lastSeen = millis();
          }
        }
        offset += rdlen;
      }
    }
  }

  // NBNS response sniffing
  if (isNbns && (srcPort == NBNS_PORT)) {
    uint16_t flags = pktRead16(dns + 2);
    if (!(flags & 0x8000))
      return;  // not a response
    uint16_t ancount = pktRead16(dns + 6);
    if (ancount == 0)
      return;

    // Decode NetBIOS name from answer
    char nbName[17] = {0};
    if (dnsLen >= 12 + 34) {
      const uint8_t* enc = dns + 13;
      for (int i = 0; i < 15; i++) {
        char c = ((enc[i * 2] - 'A') << 4) | (enc[i * 2 + 1] - 'A');
        nbName[i] = (c >= 0x20 && c < 0x7F) ? c : ' ';
      }
      nbName[15] = '\0';
      for (int i = 14; i >= 0 && nbName[i] == ' '; i--)
        nbName[i] = '\0';
    }

    int slot = -1, freeSlot = -1;
    for (int i = 0; i < MDNS_TABLE_SIZE; i++) {
      if (!mdnsTable[i].active) {
        if (freeSlot < 0)
          freeSlot = i;
        continue;
      }
      if (memcmp(mdnsTable[i].ip, srcIP, 4) == 0) {
        slot = i;
        break;
      }
    }
    if (slot < 0 && freeSlot >= 0)
      slot = freeSlot;
    if (slot >= 0) {
      MdnsHost& h = mdnsTable[slot];
      h.active = true;
      memcpy(h.ip, srcIP, 4);
      if (nbName[0])
        strncpy(h.hostname, nbName, sizeof(h.hostname) - 1);
      strncpy(h.service, "NBNS", sizeof(h.service) - 1);
      h.lastSeen = millis();
    }
  }
}

void mdnsPrintTable() {
  Serial.println("[MDNS] ═══ Discovered Hosts ═══");
  Serial.printf("  %-16s %-30s %-12s %s\n", "IP", "Hostname", "Service", "Seen");
  Serial.println("  ──────────────────────────────────────────────────────────");

  int count = 0;
  for (int i = 0; i < MDNS_TABLE_SIZE; i++) {
    if (!mdnsTable[i].active)
      continue;
    MdnsHost& h = mdnsTable[i];
    count++;
    Serial.printf("  %-16s %-30s %-12s %us\n",
                  (String(h.ip[0]) + "." + String(h.ip[1]) + "." + String(h.ip[2]) + "." +
                   String(h.ip[3]))
                      .c_str(),
                  h.hostname[0] ? h.hostname : "-", h.service[0] ? h.service : "-",
                  (millis() - h.lastSeen) / 1000);
  }

  if (count == 0)
    Serial.println("  (no hosts discovered yet — listening for mDNS/NBNS)");
  else
    Serial.printf("  %d host(s)\n", count);
}
