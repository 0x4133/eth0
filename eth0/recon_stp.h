// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Passive STP/RSTP topology mapping. Listens for 802.1D BPDUs sent
// to the spanning-tree multicast MAC (01:80:C2:00:00:00) over LLC
// (DSAP/SSAP = 0x42/0x42, control = 0x03) rather than a standard
// EtherType, and records the bridges it sees.

#pragma once

#include <stdint.h>

#include "config.h"

// Tracked spanning-tree bridge.
struct StpBridge {
  uint8_t  bridgeMAC[6];     // Bridge ID MAC portion
  uint16_t bridgePriority;   // Bridge priority
  uint8_t  rootMAC[6];       // Root bridge MAC
  uint16_t rootPriority;     // Root bridge priority
  uint32_t rootPathCost;     // Cost to root
  uint16_t portID;           // Port identifier
  uint8_t  stpVersion;       // 0=STP, 2=RSTP, 3=MSTP
  uint8_t  flags;            // BPDU flags (topology change, etc.)
  uint16_t messageAge;       // in 1/256 seconds
  uint16_t maxAge;
  uint16_t helloTime;
  uint16_t forwardDelay;
  uint32_t lastSeen;         // millis
  bool     active;
};

// Tracking table and the live-monitor toggle.
extern StpBridge stpTable[STP_BRIDGE_TABLE_SIZE];
extern uint8_t   stpBridgeCount;
extern bool      stpMonitorEnabled;

// Wipe the bridge table back to its boot state.
void stpInitTable();

// Inspect a captured frame for an STP/RSTP BPDU. No-op if it isn't
// one. Called unconditionally from the capture loop.
void stpCheckBpdu(const uint8_t* pkt, uint16_t len);

// Print the current bridge table to Serial.
void stpPrintTopology();
