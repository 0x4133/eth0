// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_netbios.h"

#include <string.h>

#include <Arduino.h>
#include <Ethernet2.h>
#include <esp_random.h>
#include <utility/socket.h>
#include <utility/w5500.h>

#include "config.h"
#include "eth_frame.h"
#include "filter.h"
#include "ids.h"
#include "inject.h"
#include "pcap_writer.h"
#include "state.h"

NetbiosHost netbiosTable[NETBIOS_TABLE_SIZE];
uint8_t     netbiosCount = 0;

// ══════════════════════════════════════════════════════════════
//  5b. NetBIOS Reconnaissance
// ══════════════════════════════════════════════════════════════
// Active NetBIOS discovery:
//   - Broadcast NBNS name query to find all Windows hosts
//   - Unicast NBSTAT (Node Status) to dump a host's name table
//     (equivalent to nbtstat -A on Windows)

// ── Decode a NetBIOS first-level encoded name ──
// NetBIOS names are encoded as pairs of characters: each byte B becomes
// nbnsDecodeName was defined here in the original code but never
// called — netbiosParseResponse uses an inlined decoder. Removed.

// ── Encode a name in NetBIOS first-level encoding ──
// Input: 16-byte padded name (15 chars + suffix byte)
// Output: 32-byte encoded name
static void nbnsEncodeName(const char* name, uint8_t suffix, uint8_t* out) {
  uint8_t padded[16];
  memset(padded, 0x20, 15);  // pad with spaces
  int len = strlen(name);
  if (len > 15)
    len = 15;
  memcpy(padded, name, len);
  padded[15] = suffix;

  for (int i = 0; i < 16; i++) {
    out[i * 2] = 'A' + ((padded[i] >> 4) & 0x0F);
    out[i * 2 + 1] = 'A' + (padded[i] & 0x0F);
  }
}

// ── Map NetBIOS suffix to human-readable service type ──
static const char* nbnsTypeName(uint8_t suffix, bool isGroup) {
  if (isGroup) {
    switch (suffix) {
      case 0x00:
        return "Domain/Workgroup";
      case 0x1C:
        return "Domain Controller";
      case 0x1E:
        return "Browser Election";
      default:
        return "Group";
    }
  }
  switch (suffix) {
    case 0x00:
      return "Workstation";
    case 0x03:
      return "Messenger";
    case 0x06:
      return "RAS Server";
    case 0x1B:
      return "Domain Master Browser";
    case 0x1D:
      return "Master Browser";
    case 0x1F:
      return "NetDDE";
    case 0x20:
      return "File Server";
    case 0x21:
      return "RAS Client";
    case 0xBE:
      return "Network Monitor Agent";
    case 0xBF:
      return "Network Monitor App";
    default:
      return "Service";
  }
}

// ── Parse incoming NBNS/NBSTAT responses ──
void netbiosParseResponse(const uint8_t* pkt, uint16_t len) {
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
  if (srcPort != NBNS_PORT)
    return;

  uint16_t udpLen = pktRead16(udpHdr + 4);
  if (udpLen < 8 + 12)
    return;

  const uint8_t* nbns = udpHdr + 8;
  uint16_t nbnsLen = udpLen - 8;
  uint16_t flags = pktRead16(nbns + 2);
  const uint8_t* srcIP = ipHdr + 12;

  // Skip our own packets
  if (memcmp(srcIP, ourIP, 4) == 0)
    return;

  // Must be a response (bit 15 set)
  if (!(flags & 0x8000))
    return;

  uint16_t ancount = pktRead16(nbns + 6);

  // ── NBSTAT response (opcode 0, NBSTAT RR type 0x0021) ──
  // Check if this is an NBSTAT response by looking for NBSTAT RR type
  // The answer section starts after the question section
  uint16_t offset = 12;

  // Skip question section
  uint16_t qdcount = pktRead16(nbns + 4);
  for (uint16_t q = 0; q < qdcount && offset < nbnsLen; q++) {
    // Skip encoded name
    if (offset < nbnsLen && nbns[offset] == 0x20) {
      offset += 1 + 32 + 1;  // length(1) + encoded(32) + null(1)
    } else {
      // Compression or unexpected — skip
      while (offset < nbnsLen && nbns[offset] != 0) {
        if ((nbns[offset] & 0xC0) == 0xC0) {
          offset += 2;
          goto skipNbQ;
        }
        offset += 1 + nbns[offset];
      }
      offset++;  // null terminator
    }
    offset += 4;  // type + class
  skipNbQ:;
  }

  // Check each answer
  for (uint16_t a = 0; a < ancount && offset + 2 < nbnsLen; a++) {
    // Skip name (may be compressed or encoded)
    if ((nbns[offset] & 0xC0) == 0xC0) {
      offset += 2;
    } else if (nbns[offset] == 0x20) {
      offset += 1 + 32 + 1;
    } else {
      while (offset < nbnsLen && nbns[offset] != 0)
        offset += 1 + nbns[offset];
      offset++;
    }

    if (offset + 10 > nbnsLen)
      break;
    uint16_t rtype = pktRead16(nbns + offset);
    offset += 2;
    offset += 2;  // class
    offset += 4;  // TTL
    uint16_t rdlen = pktRead16(nbns + offset);
    offset += 2;

    if (offset + rdlen > nbnsLen)
      break;

    // ── Standard name query response (type 0x0020 = NB) ──
    if (rtype == 0x0020 && rdlen >= 6) {
      // NB record: 2 bytes flags + 4 bytes IP (per entry)
      // Just record the host
      int slot = -1, freeSlot = -1;
      for (int i = 0; i < NETBIOS_TABLE_SIZE; i++) {
        if (!netbiosTable[i].active) {
          if (freeSlot < 0)
            freeSlot = i;
          continue;
        }
        if (memcmp(netbiosTable[i].ip, srcIP, 4) == 0) {
          slot = i;
          break;
        }
      }
      if (slot < 0 && freeSlot >= 0) {
        slot = freeSlot;
        netbiosCount++;
      }
      if (slot >= 0) {
        NetbiosHost& h = netbiosTable[slot];
        h.active = true;
        memcpy(h.ip, srcIP, 4);
        memcpy(h.mac, pkt + ETH_SRC_MAC, 6);
        h.lastSeen = millis();
      }
      offset += rdlen;
      continue;
    }

    // ── NBSTAT response (type 0x0021) ──
    if (rtype == 0x0021 && rdlen >= 1) {
      uint8_t numNames = nbns[offset];
      uint16_t nOffset = offset + 1;

      Serial.printf("\n[NETBIOS] ═══ NBSTAT: %u.%u.%u.%u ═══\n", srcIP[0], srcIP[1], srcIP[2],
                    srcIP[3]);
      Serial.printf("  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", pkt[ETH_SRC_MAC],
                    pkt[ETH_SRC_MAC + 1], pkt[ETH_SRC_MAC + 2], pkt[ETH_SRC_MAC + 3],
                    pkt[ETH_SRC_MAC + 4], pkt[ETH_SRC_MAC + 5]);
      Serial.printf("  %-16s %-4s %-6s %s\n", "Name", "Type", "Flags", "Description");
      Serial.println("  ──────────────────────────────────────────────────");

      char firstName[16] = {0};
      char firstGroup[16] = {0};

      for (uint8_t n = 0; n < numNames && nOffset + 18 <= offset + rdlen; n++) {
        // Each entry: 15-byte name + 1-byte suffix + 2-byte flags
        char name[16];
        memset(name, 0, sizeof(name));
        for (int i = 0; i < 15; i++) {
          char c = nbns[nOffset + i];
          name[i] = (c >= 0x20 && c < 0x7F) ? c : ' ';
        }
        name[15] = '\0';
        // Trim trailing spaces
        for (int i = 14; i >= 0 && name[i] == ' '; i--)
          name[i] = '\0';

        uint8_t suffix = nbns[nOffset + 15];
        uint16_t nameFlags = pktRead16(nbns + nOffset + 16);
        bool isGroup = (nameFlags & 0x8000) != 0;

        Serial.printf("  %-16s <%02X>  %s  %s\n", name, suffix, isGroup ? "GROUP " : "UNIQUE",
                      nbnsTypeName(suffix, isGroup));

        // Track first unique name and first group name
        if (!isGroup && firstName[0] == '\0' && suffix == 0x00)
          strncpy(firstName, name, 15);
        if (isGroup && firstGroup[0] == '\0' && suffix == 0x00)
          strncpy(firstGroup, name, 15);

        nOffset += 18;
      }

      // Store in table
      int slot = -1, freeSlot = -1;
      for (int i = 0; i < NETBIOS_TABLE_SIZE; i++) {
        if (!netbiosTable[i].active) {
          if (freeSlot < 0)
            freeSlot = i;
          continue;
        }
        if (memcmp(netbiosTable[i].ip, srcIP, 4) == 0) {
          slot = i;
          break;
        }
      }
      if (slot < 0 && freeSlot >= 0) {
        slot = freeSlot;
        netbiosCount++;
      }
      if (slot >= 0) {
        NetbiosHost& h = netbiosTable[slot];
        h.active = true;
        memcpy(h.ip, srcIP, 4);
        memcpy(h.mac, pkt + ETH_SRC_MAC, 6);
        if (firstName[0])
          strncpy(h.name, firstName, 15);
        if (firstGroup[0])
          strncpy(h.group, firstGroup, 15);
        h.lastSeen = millis();
      }

      Serial.println();
      offset += rdlen;
      continue;
    }

    offset += rdlen;
  }
}

// ── Send a broadcast NBNS name query (wildcard *) ──
void reconNetbiosSweep() {
  Serial.println("[NETBIOS] Broadcasting wildcard name query...");

  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  uint8_t bcastIP[4] = {(uint8_t)(ourIP[0] | ~ourSubnet[0]), (uint8_t)(ourIP[1] | ~ourSubnet[1]),
                        (uint8_t)(ourIP[2] | ~ourSubnet[2]), (uint8_t)(ourIP[3] | ~ourSubnet[3])};

  // Build NBNS name query for "*" (wildcard)
  uint8_t nbnsPayload[62];
  uint16_t npos = 0;

  // Header
  uint16_t txid = (uint16_t)(esp_random() & 0xFFFF);
  pktWrite16(nbnsPayload + npos, txid);
  npos += 2;  // TXID
  pktWrite16(nbnsPayload + npos, 0x0110);
  npos += 2;  // Flags: query, broadcast
  pktWrite16(nbnsPayload + npos, 1);
  npos += 2;  // QDCOUNT
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;  // ANCOUNT
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;  // NSCOUNT
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;  // ARCOUNT

  // Question: encoded wildcard name "*"
  nbnsPayload[npos++] = 0x20;  // length: 32 bytes
  // Encode "*\0\0..." (padded with nulls)
  uint8_t wildcardName[16];
  memset(wildcardName, 0, 16);
  wildcardName[0] = '*';  // wildcard
  // First-level encode
  for (int i = 0; i < 16; i++) {
    nbnsPayload[npos++] = 'A' + ((wildcardName[i] >> 4) & 0x0F);
    nbnsPayload[npos++] = 'A' + (wildcardName[i] & 0x0F);
  }
  nbnsPayload[npos++] = 0x00;  // null terminator

  pktWrite16(nbnsPayload + npos, 0x0021);
  npos += 2;  // NBSTAT type
  pktWrite16(nbnsPayload + npos, 0x0001);
  npos += 2;  // IN class

  // Wrap in UDP -> IP
  uint16_t udpLen = 8 + npos;
  uint16_t pos = 0;
  pos = buildEthHeader(txBuf, broadcast, ETHERTYPE_IPV4);
  pos += buildIPv4Header(txBuf + pos, ourIP, bcastIP, IP_PROTO_UDP, udpLen);

  pktWrite16(txBuf + pos, NBNS_PORT);
  pos += 2;  // src port
  pktWrite16(txBuf + pos, NBNS_PORT);
  pos += 2;  // dst port
  pktWrite16(txBuf + pos, udpLen);
  pos += 2;
  pktWrite16(txBuf + pos, 0);
  pos += 2;  // no checksum

  memcpy(txBuf + pos, nbnsPayload, npos);
  pos += npos;

  sendRawFrame(txBuf, pos);

  // Also send a standard wildcard name query
  npos = 0;
  txid = (uint16_t)(esp_random() & 0xFFFF);
  pktWrite16(nbnsPayload + npos, txid);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0x0110);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 1);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;

  nbnsPayload[npos++] = 0x20;
  nbnsEncodeName("*", 0x00, nbnsPayload + npos);
  npos += 32;
  nbnsPayload[npos++] = 0x00;

  pktWrite16(nbnsPayload + npos, 0x0020);
  npos += 2;  // NB type
  pktWrite16(nbnsPayload + npos, 0x0001);
  npos += 2;

  udpLen = 8 + npos;
  pos = 0;
  pos = buildEthHeader(txBuf, broadcast, ETHERTYPE_IPV4);
  pos += buildIPv4Header(txBuf + pos, ourIP, bcastIP, IP_PROTO_UDP, udpLen);
  pktWrite16(txBuf + pos, NBNS_PORT);
  pos += 2;
  pktWrite16(txBuf + pos, NBNS_PORT);
  pos += 2;
  pktWrite16(txBuf + pos, udpLen);
  pos += 2;
  pktWrite16(txBuf + pos, 0);
  pos += 2;
  memcpy(txBuf + pos, nbnsPayload, npos);
  pos += npos;
  sendRawFrame(txBuf, pos);

  Serial.println("[NETBIOS] Queries sent. Waiting for responses (3s)...");
  Serial.println("  Responses will print as they arrive.");
  Serial.println("  Use 'recon netbios' again to view the full table.");

  // Wait for responses
  uint32_t start = millis();
  while (millis() - start < 3000) {
    uint16_t plen = w5500.getRXReceivedSize(RAW_SOCKET);
    if (plen > 0 && plen <= MAX_FRAME_SIZE) {
      uint16_t rlen = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (rlen > 0) {
        netbiosParseResponse(packetBuf, rlen);
        // Also run through other analyzers
        if (idsEnabled)
          idsAnalyzePacket(packetBuf, rlen);
        // And write to pcap if capturing
        if (capturing && packetMatchesFilter(packetBuf, rlen)) {
          writePcapPacket(packetBuf, rlen);
          packetCount++;
        }
      }
    }
    delay(1);
  }

  Serial.printf("[NETBIOS] Sweep done. %u host(s) in table.\n", netbiosCount);
}

// ── Send NBSTAT (Node Status) query to a specific IP ──
void reconNbstat(const uint8_t* targetIP) {
  Serial.printf("[NETBIOS] NBSTAT query -> %u.%u.%u.%u\n", targetIP[0], targetIP[1], targetIP[2],
                targetIP[3]);

  // Resolve target MAC
  uint8_t targetMAC[6];
  if (!resolveMacForIP(targetIP, targetMAC)) {
    Serial.println("[NETBIOS] Failed to resolve MAC. Try: recon sweep first");
    return;
  }

  // Build NBSTAT query for wildcard name
  uint8_t nbnsPayload[62];
  uint16_t npos = 0;

  uint16_t txid = (uint16_t)(esp_random() & 0xFFFF);
  pktWrite16(nbnsPayload + npos, txid);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0x0000);
  npos += 2;  // Flags: query, unicast
  pktWrite16(nbnsPayload + npos, 1);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;
  pktWrite16(nbnsPayload + npos, 0);
  npos += 2;

  // Question: NBSTAT for "*"
  nbnsPayload[npos++] = 0x20;
  uint8_t wildcardName[16];
  memset(wildcardName, 0, 16);
  wildcardName[0] = '*';
  for (int i = 0; i < 16; i++) {
    nbnsPayload[npos++] = 'A' + ((wildcardName[i] >> 4) & 0x0F);
    nbnsPayload[npos++] = 'A' + (wildcardName[i] & 0x0F);
  }
  nbnsPayload[npos++] = 0x00;

  pktWrite16(nbnsPayload + npos, 0x0021);
  npos += 2;  // NBSTAT type
  pktWrite16(nbnsPayload + npos, 0x0001);
  npos += 2;  // IN class

  // Wrap in UDP -> IP
  uint16_t udpLen = 8 + npos;
  uint16_t pos = 0;
  pos = buildEthHeader(txBuf, targetMAC, ETHERTYPE_IPV4);
  pos += buildIPv4Header(txBuf + pos, ourIP, targetIP, IP_PROTO_UDP, udpLen);

  pktWrite16(txBuf + pos, NBNS_PORT);
  pos += 2;
  pktWrite16(txBuf + pos, NBNS_PORT);
  pos += 2;
  pktWrite16(txBuf + pos, udpLen);
  pos += 2;
  pktWrite16(txBuf + pos, 0);
  pos += 2;

  memcpy(txBuf + pos, nbnsPayload, npos);
  pos += npos;

  sendRawFrame(txBuf, pos);

  // Wait for response
  Serial.println("[NETBIOS] Waiting for NBSTAT response (3s)...");
  uint32_t start = millis();
  bool gotResponse = false;

  while (millis() - start < 3000) {
    uint16_t plen = w5500.getRXReceivedSize(RAW_SOCKET);
    if (plen > 0 && plen <= MAX_FRAME_SIZE) {
      uint16_t rlen = recvfrom(RAW_SOCKET, packetBuf, MAX_FRAME_SIZE, NULL, NULL);
      if (rlen > 0) {
        netbiosParseResponse(packetBuf, rlen);
        // Check if this was our response
        if (rlen >= ETH_HEADER_LEN + 28) {
          const uint8_t* rIP = packetBuf + ETH_HEADER_LEN + 12;
          if (memcmp(rIP, targetIP, 4) == 0)
            gotResponse = true;
        }
        if (idsEnabled)
          idsAnalyzePacket(packetBuf, rlen);
        if (capturing && packetMatchesFilter(packetBuf, rlen)) {
          writePcapPacket(packetBuf, rlen);
          packetCount++;
        }
      }
    }
    delay(1);
  }

  if (!gotResponse)
    Serial.println("[NETBIOS] No response. Host may not support NetBIOS or is firewalled.");
}

// ── Print NetBIOS host table ──
void netbiosPrintTable() {
  Serial.println("[NETBIOS] ═══ Discovered Hosts ═══");
  Serial.printf("  %-16s %-18s %-16s %s\n", "IP", "MAC", "Name", "Workgroup");
  Serial.println("  ──────────────────────────────────────────────────────────");

  int count = 0;
  for (int i = 0; i < NETBIOS_TABLE_SIZE; i++) {
    if (!netbiosTable[i].active)
      continue;
    NetbiosHost& h = netbiosTable[i];
    count++;
    Serial.printf("  %-16s %02X:%02X:%02X:%02X:%02X:%02X %-16s %s\n",
                  (String(h.ip[0]) + "." + String(h.ip[1]) + "." + String(h.ip[2]) + "." +
                   String(h.ip[3]))
                      .c_str(),
                  h.mac[0], h.mac[1], h.mac[2], h.mac[3], h.mac[4], h.mac[5],
                  h.name[0] ? h.name : "-", h.group[0] ? h.group : "-");
  }

  if (count == 0)
    Serial.println("  (no hosts discovered)");
  else
    Serial.printf("  %d host(s)\n", count);
}
