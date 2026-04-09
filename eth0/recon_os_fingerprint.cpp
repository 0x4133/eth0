// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "recon_os_fingerprint.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "eth_frame.h"
#include "state.h"

OsFingerprint fpTable[FP_TABLE_SIZE];

static void fpGuessOS(OsFingerprint& fp) {
  // Infer initial TTL
  uint8_t initTTL;
  if (fp.ttl <= 64)
    initTTL = 64;
  else if (fp.ttl <= 128)
    initTTL = 128;
  else
    initTTL = 255;

  if (initTTL == 128) {
    if (fp.windowSize == 65535 || fp.windowSize == 8192)
      strcpy(fp.osGuess, "Windows");
    else if (fp.windowSize == 64240)
      strcpy(fp.osGuess, "Windows 10/11");
    else
      strcpy(fp.osGuess, "Windows (?)");
  } else if (initTTL == 64) {
    if (fp.mss == 1460 && fp.wscaleVal >= 6 && fp.wscaleVal <= 7)
      strcpy(fp.osGuess, "macOS/iOS");
    else if (fp.mss == 1460 && fp.sackOk)
      strcpy(fp.osGuess, "Linux");
    else if (fp.mss == 1460)
      strcpy(fp.osGuess, "Linux/Unix");
    else if (fp.mss == 536)
      strcpy(fp.osGuess, "Linux (old)");
    else
      strcpy(fp.osGuess, "Unix-like");
  } else if (initTTL == 255) {
    strcpy(fp.osGuess, "Network device");
  } else {
    strcpy(fp.osGuess, "Unknown");
  }
}

void fpAnalyzePacket(const uint8_t* pkt, uint16_t len) {
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
  uint8_t flags = tcpHdr[13];

  // Only analyze SYN or SYN-ACK
  bool isSyn = (flags & 0x02) != 0;
  if (!isSyn)
    return;

  const uint8_t* srcIP = ipHdr + 12;

  // Skip our own packets
  if (memcmp(srcIP, ourIP, 4) == 0)
    return;

  uint8_t ttl = ipHdr[8];
  uint16_t windowSize = pktRead16(tcpHdr + 14);
  uint8_t tcpHdrLen = ((tcpHdr[12] >> 4) & 0x0F) * 4;

  // Parse TCP options
  uint16_t mss = 0;
  bool sackOk = false;
  uint8_t wscaleVal = 0;

  if (tcpHdrLen > 20) {
    const uint8_t* opts = tcpHdr + 20;
    uint16_t optLen = tcpHdrLen - 20;
    uint16_t i = 0;
    while (i < optLen) {
      uint8_t kind = opts[i];
      if (kind == 0)
        break;  // End
      if (kind == 1) {
        i++;
        continue;
      }  // NOP
      if (i + 1 >= optLen)
        break;
      uint8_t olen = opts[i + 1];
      if (olen < 2 || i + olen > optLen)
        break;

      if (kind == 2 && olen == 4)
        mss = pktRead16(opts + i + 2);
      if (kind == 3 && olen == 3)
        wscaleVal = opts[i + 2];
      if (kind == 4)
        sackOk = true;

      i += olen;
    }
  }

  // Find or create entry
  int slot = -1;
  int freeSlot = -1;

  for (int i = 0; i < FP_TABLE_SIZE; i++) {
    if (!fpTable[i].active) {
      if (freeSlot < 0)
        freeSlot = i;
      continue;
    }
    if (memcmp(fpTable[i].ip, srcIP, 4) == 0) {
      slot = i;
      break;
    }
  }

  if (slot < 0) {
    if (freeSlot < 0)
      return;  // table full
    slot = freeSlot;
  }

  OsFingerprint& fp = fpTable[slot];
  fp.active = true;
  memcpy(fp.ip, srcIP, 4);
  fp.ttl = ttl;
  fp.windowSize = windowSize;
  fp.mss = mss;
  fp.sackOk = sackOk;
  fp.wscaleVal = wscaleVal;
  fp.lastSeen = millis();
  fpGuessOS(fp);
}

void fpPrintTable() {
  Serial.println("[FINGERPRINT] ═══ OS Fingerprints ═══");
  Serial.printf("  %-16s %-18s TTL  Win    MSS   Opts\n", "IP", "OS Guess");
  Serial.println("  ──────────────────────────────────────────────────────────");

  int count = 0;
  for (int i = 0; i < FP_TABLE_SIZE; i++) {
    if (!fpTable[i].active)
      continue;
    OsFingerprint& fp = fpTable[i];
    count++;
    char ipStr[16];
    snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", fp.ip[0], fp.ip[1], fp.ip[2], fp.ip[3]);

    Serial.printf("  %-16s %-18s %-4u %-6u %-5u %s%s\n", ipStr, fp.osGuess, fp.ttl, fp.windowSize,
                  fp.mss, fp.sackOk ? "SACK " : "",
                  fp.wscaleVal > 0 ? (String("WS=") + String(fp.wscaleVal)).c_str() : "");
  }

  if (count == 0)
    Serial.println("  (no fingerprints yet — waiting for TCP SYN packets)");
  else
    Serial.printf("  %d host(s) fingerprinted\n", count);
}
