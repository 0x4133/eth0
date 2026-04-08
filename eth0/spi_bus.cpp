// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "spi_bus.h"

// HSPI instance for the SD card. The W5500 uses the default SPI
// instance owned by the Ethernet2 library, which does not need a
// SPIClass handle from us.
SPIClass sdSPI(HSPI);

void switchToEthSPI() {
  // no-op: the default SPI is permanently mapped to the ETH pins.
}

void switchToSdSPI() {
  // no-op: the SD card uses sdSPI (SPI3), always available.
}
