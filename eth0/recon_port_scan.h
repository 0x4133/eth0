// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// TCP SYN port probe. Sends a SYN to each port in a list and
// classifies the response: SYN-ACK = open, RST = closed, no
// response within ~200 ms = filtered.

#pragma once

#include <stdint.h>

// Probe `numPorts` TCP ports against `targetIP`. Resolves the
// target's MAC from the IDS ARP table; falls back to the gateway
// MAC for off-subnet targets and ARP-resolves the gateway if it's
// not yet cached.
void reconSynProbe(const uint8_t* targetIP, const uint16_t* ports, uint8_t numPorts);
