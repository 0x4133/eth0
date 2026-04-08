// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// TP-Link Kasa smart-device query.
//
// Protocol: XOR-encrypted JSON over TCP/9999. The framing is a
// 4-byte big-endian length prefix followed by an XOR chain where
// the first key byte is 171 and each subsequent key is the
// previous ciphertext byte.
//
// We use the Ethernet2 client API for the TCP connection (not
// MACRAW), so this module is independent of the capture loop.

#pragma once

#include <stdint.h>

uint16_t kasaEncrypt(const char* json, uint8_t* out, uint16_t maxOut);
uint16_t kasaDecrypt(const uint8_t* data, uint16_t len, char* out, uint16_t maxOut);
int16_t  kasaSendRecv(const uint8_t* targetIP, const char* jsonCmd, char* outJson, uint16_t maxOut);
void     kasaQuerySysinfo(const uint8_t* targetIP);
void     kasaQueryCloud(const uint8_t* targetIP);
void     parseKasaCommand(const char* cmd);
