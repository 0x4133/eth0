// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// ARP host discovery sweep. Sends ARP "who-has" requests for every
// address in a given range and listens for replies, logging each
// discovered host and feeding it back into the IDS ARP table.

#pragma once

#include <stdint.h>

// Sweep an inclusive 32-bit IPv4 address range. The range size must
// be at least 3 IPs (i.e. /30 or larger). The first and last IPs of
// the range are skipped (network and broadcast). Wrap-safe at
// 0xFFFFFFFF.
void reconArpSweep(uint32_t startIP, uint32_t endIP);
