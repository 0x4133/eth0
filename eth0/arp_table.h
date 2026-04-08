// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// ARP cache shared between the IDS (which populates and validates
// it) and the injection code (which queries it for destination MAC
// resolution before sending unicast frames).
//
// This header is a temporary home for the type and the storage
// extern. Phase 5c will move the storage into ids.cpp and tighten
// the interface.

#pragma once

#include <stdint.h>

#include "config.h"

struct ArpEntry {
  uint8_t  ip[4];
  uint8_t  mac[6];
  uint32_t lastSeen;  // millis()
  bool     active;
};

// Defined in eth0.ino for now; moves to ids.cpp in Phase 5c.
extern ArpEntry arpTable[ARP_TABLE_SIZE];
