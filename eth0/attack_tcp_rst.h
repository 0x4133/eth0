// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// TCP connection tracker + RST injector. Watches every TCP packet
// on the wire to record sequence numbers, then on demand sends a
// crafted RST to either side to tear the connection down.

#pragma once

#include <stdint.h>

#include "config.h"

struct TcpConn {
  uint8_t  srcIP[4];
  uint8_t  dstIP[4];
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t lastSeq;
  uint32_t lastAck;
  uint32_t lastSeen;
  bool     active;
};

extern TcpConn tcpConnTable[TCP_CONN_TABLE_SIZE];

// Called from the capture loop on every received frame; updates
// the connection table.
void tcpTrackPacket(const uint8_t* pkt, uint16_t len);

// Inject KILL_RST_COUNT RSTs to tear down a tracked connection.
void killConnection(const uint8_t* targetIP, uint16_t port);

// `kill …` serial command dispatcher.
void parseKillCommand(const char* cmd);
