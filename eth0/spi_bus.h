// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// SPI bus ownership.
//
// The ESP32-S3 has two SPI peripherals wired on the Waveshare board:
//   - Default SPI (FSPI/SPI2) — owned by the Ethernet2 library / W5500.
//   - HSPI (SPI3)             — owned by the SD card.
//
// Because each bus has dedicated pins there is no switching needed at
// runtime; `switchToEthSPI()` and `switchToSdSPI()` are no-ops kept
// for API compatibility with callers that were written back when the
// two buses shared pins.

#pragma once

#include <SPI.h>

// HSPI instance reserved for the SD card. Defined in spi_bus.cpp.
extern SPIClass sdSPI;

// Hand the shared SPI bus to the W5500 driver. Currently a no-op.
void switchToEthSPI();

// Hand the shared SPI bus to the SD card driver. Currently a no-op.
void switchToSdSPI();
