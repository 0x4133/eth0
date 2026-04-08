// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Live packet statistics dashboard. Tracks per-second / per-window
// packet and byte counts, protocol breakdown (TCP/UDP/ICMP/ARP),
// and the top N source-IP "talkers" by volume.

#pragma once

#include <stdint.h>

#include "config.h"

struct StatsTalker {
  uint8_t  ip[4];
  uint32_t packets;
  uint32_t bytes;
  bool     active;
};

// State exposed via extern so the capture loop and the auto-print
// timer in loop() can read/write these directly.
extern StatsTalker statsTalkers[STATS_TALKER_TABLE];
extern bool        statsAutoEnabled;
extern uint32_t    statsAutoInterval;
extern uint32_t    statsLastAuto;
extern uint32_t    statsWindowStart;
extern uint32_t    statsWindowPkts;
extern uint32_t    statsWindowBytes;
extern uint32_t    statsProtoTCP;
extern uint32_t    statsProtoUDP;
extern uint32_t    statsProtoICMP;
extern uint32_t    statsProtoARP;
extern uint32_t    statsProtoOther;

// Called from the capture loop on every received frame.
void statsTrackPacket(const uint8_t* pkt, uint16_t len);

// Print the current snapshot to Serial.
void statsPrint();

// `stats …` serial command dispatcher.
void parseStatsCommand(const char* cmd);
