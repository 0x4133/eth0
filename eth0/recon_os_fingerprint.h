// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Passive OS fingerprinting. Watches TCP SYN / SYN-ACK packets and
// infers the operating system from a small set of features:
// initial TTL, window size, MSS, SACK-permitted, window scale.
// Doesn't transmit anything — pure capture-side observation.

#pragma once

#include <stdint.h>

#include "config.h"

struct OsFingerprint {
  uint8_t  ip[4];
  uint8_t  ttl;
  uint16_t windowSize;
  uint16_t mss;
  bool     sackOk;
  uint8_t  wscaleVal;
  char     osGuess[20];
  uint32_t lastSeen;
  bool     active;
};

extern OsFingerprint fpTable[FP_TABLE_SIZE];

// Inspect a captured frame; if it's a TCP SYN/SYN-ACK from a host
// we haven't classified yet, run the heuristics and store the result.
void fpAnalyzePacket(const uint8_t* pkt, uint16_t len);

// Print the fingerprinted hosts to Serial.
void fpPrintTable();
