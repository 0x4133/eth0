// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Replay PCAP files captured from SD card by injecting their
// records back onto the wire one by one. Useful for replaying
// known-good attack packets in lab environments.

#pragma once

#include <stdint.h>

void replayPcap(const char* filename, uint32_t delayMs);
void parseReplayCommand(const char* cmd);
