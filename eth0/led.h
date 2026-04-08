// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// NeoPixel handle. Defined in eth0.ino for now (will move to a
// dedicated led.cpp once the boot/init code is extracted in a
// later phase). The IDS module reads and writes this directly to
// indicate alert state.

#pragma once

#include <Adafruit_NeoPixel.h>

extern Adafruit_NeoPixel pixel;
