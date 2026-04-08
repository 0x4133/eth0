// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Minimal Arduino API stub for host-side unit tests. Provides just
// enough of <Arduino.h> for the pure helper modules (ip_util,
// eth_frame, dns_util, svc_kasa) to compile under plain g++ on
// Linux without pulling in the ESP32 toolchain.

#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Arduino's `byte` typedef.
using byte = uint8_t;

// Stubbed millis() — host tests don't need real time.
inline unsigned long millis() {
  return 0;
}

inline unsigned long micros() {
  return 0;
}

inline void delay(unsigned long) {}

// Print constants
constexpr int HEX = 16;
constexpr int DEC = 10;
constexpr int BIN = 2;

// Minimal Serial sink so pure functions that happen to call
// Serial.print* don't blow up. Tests should not assert on Serial
// output — that's a deliberate limitation of host-mode tests.
struct SerialStub {
  void print(const char*) {}
  void print(int) {}
  void print(int, int) {}
  void println() {}
  void println(const char*) {}
  void println(int) {}
  template <typename... Args>
  int printf(const char*, Args...) { return 0; }
};
extern SerialStub Serial;
