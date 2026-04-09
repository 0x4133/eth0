// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_lldp.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"

LldpNeighbor lldpTable[LLDP_TABLE_SIZE];

static void lldpCopyStr(char* dst, uint16_t maxLen, const uint8_t* src, uint16_t srcLen) {
  uint16_t cpLen = (srcLen < maxLen - 1) ? srcLen : maxLen - 1;
  for (uint16_t i = 0; i < cpLen; i++) {
    dst[i] = (src[i] >= 0x20 && src[i] < 0x7F) ? (char)src[i] : '.';
  }
  dst[cpLen] = '\0';
}

void lldpCheckFrame(const uint8_t* pkt, uint16_t len) {
  if (len < ETH_HEADER_LEN + 4)
    return;

  uint16_t etype = pktRead16(pkt + ETH_TYPE);
  bool isLLDP = (etype == LLDP_ETHERTYPE);

  // CDP: LLC/SNAP to 01:00:0C:CC:CC:CC
  bool isCDP = false;
  if (!isLLDP && len > ETH_HEADER_LEN + 8) {
    if (pkt[0] == 0x01 && pkt[1] == 0x00 && pkt[2] == 0x0C && pkt[3] == 0xCC && pkt[4] == 0xCC &&
        pkt[5] == 0xCC) {
      // Check for LLC SNAP header: AA:AA:03 + OUI 00:00:0C + PID 0x2000
      const uint8_t* llc = pkt + ETH_HEADER_LEN;
      if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 && llc[3] == 0x00 && llc[4] == 0x00 &&
          llc[5] == 0x0C && pktRead16(llc + 6) == 0x2000) {
        isCDP = true;
      }
    }
  }

  if (!isLLDP && !isCDP)
    return;

  // Find or create neighbor entry
  int slot = -1;
  int freeSlot = -1;
  for (int i = 0; i < LLDP_TABLE_SIZE; i++) {
    if (!lldpTable[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    if (memcmp(lldpTable[i].srcMAC, pkt + ETH_SRC_MAC, 6) == 0) {
      slot = i;
      break;
    }
  }
  if (slot < 0) {
    if (freeSlot < 0)
      freeSlot = 0;  // overwrite oldest
    slot = freeSlot;
  }

  LldpNeighbor& n = lldpTable[slot];
  n.active = true;
  n.isCDP = isCDP;
  memcpy(n.srcMAC, pkt + ETH_SRC_MAC, 6);
  n.lastSeen = millis();
  n.chassisId[0] = '\0';
  n.portId[0] = '\0';
  n.sysName[0] = '\0';
  n.sysDesc[0] = '\0';
  n.vlanId = 0;

  if (isLLDP) {
    // Parse LLDP TLV chain
    const uint8_t* tlv = pkt + ETH_HEADER_LEN;
    uint16_t remaining = len - ETH_HEADER_LEN;

    while (remaining >= 2) {
      uint16_t hdr = pktRead16(tlv);
      uint8_t type = (hdr >> 9) & 0x7F;
      uint16_t tlen = hdr & 0x01FF;
      tlv += 2;
      remaining -= 2;
      if (tlen > remaining)
        break;

      if (type == 0)
        break;  // End
      if (type == 1 && tlen > 1)
        lldpCopyStr(n.chassisId, sizeof(n.chassisId), tlv + 1, tlen - 1);
      if (type == 2 && tlen > 1)
        lldpCopyStr(n.portId, sizeof(n.portId), tlv + 1, tlen - 1);
      if (type == 5)
        lldpCopyStr(n.sysName, sizeof(n.sysName), tlv, tlen);
      if (type == 6)
        lldpCopyStr(n.sysDesc, sizeof(n.sysDesc), tlv, tlen);
      // Port VLAN ID (TLV 127, OUI 00:80:C2, subtype 1)
      if (type == 127 && tlen >= 5 && tlv[0] == 0x00 && tlv[1] == 0x80 && tlv[2] == 0xC2 &&
          tlv[3] == 1) {
        n.vlanId = pktRead16(tlv + 4);
      }

      tlv += tlen;
      remaining -= tlen;
    }
  } else if (isCDP) {
    // CDP TLV: starts after LLC/SNAP (8 bytes) + CDP header (4 bytes: version, TTL, checksum)
    const uint8_t* cdp = pkt + ETH_HEADER_LEN + 8;
    uint16_t cdpLen = len - ETH_HEADER_LEN - 8;
    if (cdpLen < 4)
      return;

    const uint8_t* tlv = cdp + 4;
    uint16_t remaining = cdpLen - 4;

    while (remaining >= 4) {
      uint16_t type = pktRead16(tlv);
      uint16_t tlen = pktRead16(tlv + 2);
      if (tlen < 4 || tlen > remaining)
        break;

      uint16_t vlen = tlen - 4;
      const uint8_t* val = tlv + 4;

      if (type == 0x0001)
        lldpCopyStr(n.chassisId, sizeof(n.chassisId), val, vlen);  // Device ID
      if (type == 0x0003)
        lldpCopyStr(n.portId, sizeof(n.portId), val, vlen);  // Port ID
      if (type == 0x0005)
        lldpCopyStr(n.sysName, sizeof(n.sysName), val, vlen);  // Software Version -> sysName
      if (type == 0x0006)
        lldpCopyStr(n.sysDesc, sizeof(n.sysDesc), val, vlen);  // Platform

      tlv += tlen;
      remaining -= tlen;
    }
  }
}

void lldpPrintTable() {
  Serial.println("[LLDP/CDP] ═══ Network Neighbors ═══");
  int count = 0;
  for (int i = 0; i < LLDP_TABLE_SIZE; i++) {
    if (!lldpTable[i].active)
      continue;
    LldpNeighbor& n = lldpTable[i];
    count++;

    Serial.printf("\n  [%s] %02X:%02X:%02X:%02X:%02X:%02X (seen %us ago)\n",
                  n.isCDP ? "CDP" : "LLDP", n.srcMAC[0], n.srcMAC[1], n.srcMAC[2], n.srcMAC[3],
                  n.srcMAC[4], n.srcMAC[5], (millis() - n.lastSeen) / 1000);
    if (n.chassisId[0])
      Serial.printf("    Chassis: %s\n", n.chassisId);
    if (n.portId[0])
      Serial.printf("    Port:    %s\n", n.portId);
    if (n.sysName[0])
      Serial.printf("    Name:    %s\n", n.sysName);
    if (n.sysDesc[0])
      Serial.printf("    Desc:    %s\n", n.sysDesc);
    if (n.vlanId > 0)
      Serial.printf("    VLAN:    %u\n", n.vlanId);
  }

  if (count == 0) {
    Serial.println("  (no neighbors discovered yet)");
    Serial.println("  LLDP/CDP frames are passively captured.");
    Serial.println("  Switches typically send LLDP every 30s, CDP every 60s.");
  } else
    Serial.printf("\n  %d neighbor(s)\n", count);
}
