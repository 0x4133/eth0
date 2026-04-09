// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Passive mDNS / NBNS sniffer. Watches multicast DNS (port 5353)
// and NetBIOS Name Service (port 137) traffic and harvests
// hostnames and service strings without sending anything.

#pragma once

#include <stdint.h>

#include "config.h"

struct MdnsHost {
  uint8_t  ip[4];
  char     hostname[40];
  char     service[32];
  uint32_t lastSeen;
  bool     active;
};

extern MdnsHost mdnsTable[MDNS_TABLE_SIZE];

// Inspect a captured frame for mDNS or NBNS traffic. Updates the
// host table on responses (and on queries to record the asker).
void mdnsCheckPacket(const uint8_t* pkt, uint16_t len);

// Print the discovered hosts to Serial.
void mdnsPrintTable();
