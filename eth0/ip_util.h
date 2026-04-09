// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// IPv4 and MAC address parsing and formatting helpers. Free functions
// with no global state; safe to call from anywhere.

#pragma once

#include <stdint.h>

// Parse a dotted-decimal IPv4 address ("192.168.1.1") into a 4-byte
// big-endian array. Returns true on success, false on any malformed
// input (non-numeric, >255 component, wrong component count).
bool parseIP(const char* str, uint8_t* out);

// Parse a MAC address ("aa:bb:cc:dd:ee:ff" or "aa-bb-cc-dd-ee-ff",
// hex, case-insensitive) into a 6-byte array. Returns true on success.
bool parseMAC(const char* str, uint8_t* out);

// Print a 4-byte IPv4 address to the Arduino Serial as "a.b.c.d"
// (no trailing newline).
void printIP(const uint8_t* addr);

// Print a 6-byte MAC address to the Arduino Serial as
// "aa:bb:cc:dd:ee:ff" (uppercase hex, no trailing newline).
void printMAC(const uint8_t* addr);
