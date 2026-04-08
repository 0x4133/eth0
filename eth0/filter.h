// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Capture packet filter.
//
// The filter engine decides which frames get written to the PCAP
// file. IDS analysis always runs on every packet regardless of the
// filter; only the *write* side is gated.
//
// Only one filter is active at a time (matching the existing serial
// `f` command semantics). Multi-condition filters would be a
// behavior change and are out of scope for the restructure.

#pragma once

#include <stdint.h>

// ── Filter kinds ──

enum FilterType {
  FILTER_NONE,
  FILTER_ETHERTYPE,
  FILTER_PROTOCOL,
  FILTER_PORT,
  FILTER_IP,
  FILTER_MAC,
};

struct PacketFilter {
  FilterType type;
  uint16_t   ethertype;
  uint8_t    protocol;
  uint16_t   port;
  uint8_t    ip[4];
  uint8_t    macAddr[6];
};

// The currently active filter. Read by the capture hot path and
// written by the `f` serial command and the NVS config loader.
// Exposed as extern for Phase 4; Phase 8 will hide it behind a
// module-local state struct.
extern PacketFilter activeFilter;

// ── API ──

// Returns true if the given Ethernet frame should be written to the
// PCAP file under the currently active filter. Safe to call on
// truncated frames.
bool packetMatchesFilter(const uint8_t* pkt, uint16_t len);

// Parse a `f …` serial command tail (everything after the leading
// `f `). Applies the new filter to `activeFilter` and prints a
// confirmation or help line to Serial. Also resets `droppedCount`.
void parseFilterCommand(const char* cmd);

// Print the active filter and the capture counters to Serial.
void printCurrentFilter();
