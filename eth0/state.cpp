// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Storage for the cross-module globals declared in state.h.

#include "state.h"

#include "config.h"

uint8_t mac[6] = {0x02, 0xCA, 0xFE, 0xBA, 0xBE, 0x01};

uint8_t ourIP[4]     = {0, 0, 0, 0};
uint8_t ourGW[4]     = {0, 0, 0, 0};
uint8_t ourSubnet[4] = {0, 0, 0, 0};
uint8_t ourDNS[4]    = {0, 0, 0, 0};

uint8_t packetBuf[MAX_FRAME_SIZE];
uint8_t txBuf[MAX_FRAME_SIZE];

bool capturing = false;
