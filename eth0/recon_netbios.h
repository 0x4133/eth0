// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// NetBIOS Name Service reconnaissance.
//
//   - reconNetbiosSweep():     broadcast NBNS name query to discover
//                              every Windows host on the segment.
//   - reconNbstat():           unicast NBSTAT (Node Status) query —
//                              equivalent to `nbtstat -A` on Windows.
//   - netbiosParseResponse():  passive harvest of NBNS / NBSTAT
//                              responses seen by the capture loop.
//   - netbiosPrintTable():     dump the discovered host table.

#pragma once

#include <stdint.h>

#include "config.h"

struct NetbiosHost {
  uint8_t  ip[4];
  uint8_t  mac[6];
  char     name[16];     // NetBIOS name (15 chars + null)
  char     group[16];    // Workgroup/domain
  uint8_t  nameType;     // suffix byte (0x00=workstation, 0x20=server, …)
  uint8_t  flags;        // name flags
  uint32_t lastSeen;
  bool     active;
};

extern NetbiosHost netbiosTable[NETBIOS_TABLE_SIZE];
extern uint8_t     netbiosCount;

void reconNetbiosSweep();
void reconNbstat(const uint8_t* targetIP);
void netbiosParseResponse(const uint8_t* pkt, uint16_t len);
void netbiosPrintTable();
