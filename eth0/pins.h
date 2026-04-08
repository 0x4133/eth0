// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Pin assignments for the Waveshare ESP32-S3-ETH board.
//
// Two separate SPI peripherals are wired so the Ethernet and SD buses
// never contend:
//   Default SPI (FSPI/SPI2) -> Ethernet2 library / W5500
//   HSPI (SPI3)             -> SD card
//
// Keep in sync with docs/HARDWARE.md.

#pragma once

// ── W5500 Ethernet pins (SPI2 / HSPI) ──
#define ETH_MISO 12
#define ETH_MOSI 11
#define ETH_SCK  13
#define ETH_CS   14
#define ETH_RST   9
#define ETH_INT  10

// ── SD Card pins (SPI3 / VSPI) ──
#define SD_MISO 5
#define SD_MOSI 6
#define SD_SCK  7
#define SD_CS   4

// ── Onboard NeoPixel ──
#define NEOPIXEL_PIN 21
