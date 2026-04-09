// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// LLDP / CDP passive parser. Listens for the EtherType 0x88CC LLDP
// frames sent by managed switches (and the SNAP-encapsulated CDP
// frames Cisco gear emits) and harvests neighbor info: chassis ID,
// port ID, system name and description, native VLAN.

#pragma once

#include <stdint.h>

#include "config.h"

struct LldpNeighbor {
  char     chassisId[32];
  char     portId[32];
  char     sysName[32];
  char     sysDesc[48];
  uint16_t vlanId;
  uint8_t  srcMAC[6];
  bool     isCDP;        // true = CDP, false = LLDP
  uint32_t lastSeen;
  bool     active;
};

extern LldpNeighbor lldpTable[LLDP_TABLE_SIZE];

// Inspect a captured frame for an LLDP/CDP packet. Updates the
// neighbor table on a hit.
void lldpCheckFrame(const uint8_t* pkt, uint16_t len);

// Print the discovered neighbors to Serial.
void lldpPrintTable();
