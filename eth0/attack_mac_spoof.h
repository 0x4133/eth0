// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// MAC address spoofing and randomizer. Lets the user manually set
// the W5500's source MAC, generate a random one, restore the
// original, or auto-rotate on a timer.

#pragma once

#include <stdint.h>

extern uint8_t  originalMAC[6];
extern bool     macAutoEnabled;
extern uint32_t macAutoIntervalMs;
extern uint32_t macAutoLastRotate;

void macSet(const uint8_t* newMAC);
void macRandom();
void macReset();
void parseMacCommand(const char* cmd);
