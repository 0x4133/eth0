// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// NBNS / LLMNR name-resolution poisoning. Watches for NetBIOS Name
// Service (UDP 137) and LLMNR (UDP 5355) name queries on the wire
// and races the legitimate responder with a spoofed answer that
// claims our IP for whatever name was asked for.

#pragma once

#include <stdint.h>

extern bool     poisonEnabled;
extern uint32_t poisonCount;

// Called from the capture loop on every received frame.
void poisonCheckPacket(const uint8_t* pkt, uint16_t len);

// `poison …` serial command dispatcher.
void parsePoisonCommand(const char* cmd);
