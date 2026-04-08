# Hardware

eth0 runs on the **Waveshare ESP32-S3-ETH** development board. This
document captures the pin map, board-level configuration, and notes
for anyone building or repairing hardware.

![ESP32-S3-ETH](images/esp32-s3-eth.png)

---

## Board

| | |
|---|---|
| Vendor | Waveshare |
| Product | ESP32-S3-ETH |
| MCU | ESP32-S3 (dual Xtensa LX7, 240 MHz) |
| Flash | 16 MB |
| PSRAM | 8 MB |
| Ethernet PHY/MAC | WIZnet W5500 (SPI) |
| Storage | microSD slot (SPI) |
| Indicator | 1× WS2812 / NeoPixel |
| USB | USB-C, native CDC |

The W5500 gives us raw Ethernet access through MACRAW mode on socket 0,
which is what makes promiscuous capture and arbitrary frame injection
possible without a custom MAC driver.

---

## Pin map

Two separate SPI peripherals are used so the Ethernet and SD buses
never contend. This is important: the Ethernet2 library holds the bus
while a MACRAW read is in flight, and multiplexing with SD would drop
packets.

### W5500 Ethernet (SPI2 / FSPI — default SPI)

| Signal | GPIO | Direction |
|---|---|---|
| MISO | 12 | in  |
| MOSI | 11 | out |
| SCK  | 13 | out |
| CS   | 14 | out |
| RST  |  9 | out |
| INT  | 10 | in  |

### microSD Card (SPI3 / HSPI)

| Signal | GPIO | Direction |
|---|---|---|
| MISO |  5 | in  |
| MOSI |  6 | out |
| SCK  |  7 | out |
| CS   |  4 | out |

### Status LED

| Signal | GPIO |
|---|---|
| NeoPixel DIN | 21 |

---

## NeoPixel color semantics

The onboard NeoPixel reflects the device state so you can triage
remotely. The current scheme:

| Color | Meaning |
|---|---|
| off       | Idle / startup before DHCP |
| blue      | Info / boot complete, not capturing |
| green     | Capturing normally |
| yellow    | Low-severity IDS alert active |
| red       | High-severity IDS alert active |
| purple    | Cleartext credentials detected |
| orange    | ARP MitM is active on this device |

The alert colors latch for `ALERT_LED_MS` milliseconds (default 3
seconds) and then return to the capture state color.

---

## Arduino IDE board configuration

When flashing from the Arduino IDE, use these exact settings. They
are what CI tests against:

| Menu | Value |
|---|---|
| Board | ESP32S3 Dev Module |
| USB CDC On Boot | Enabled |
| CPU Frequency | 240 MHz (WiFi) |
| Flash Mode | QIO 80 MHz |
| Flash Size | 16 MB (128 Mb) |
| Partition Scheme | 16M Flash (3MB APP / 9.9MB FATFS) |
| PSRAM | OPI PSRAM |
| Upload Speed | 921600 |
| USB Mode | Hardware CDC and JTAG |

Serial monitor baud rate is **460800**.

---

## Power

- USB-C at 5 V for development.
- Target draw: ~250 mA idle, ~400 mA during active injection bursts.
- The W5500 and SD card share the 3.3 V LDO on the Waveshare board.
  Under-powered USB hubs have been observed to cause SD write
  corruption — use a powered hub or a direct host port.

---

## Known hardware quirks

1. **W5500 reset is active-low** and takes ~150 ms to come back. The
   boot sequence enforces this; do not shorten it.
2. **SD cards larger than 32 GB must be reformatted as FAT32** — the
   `SD.h` library in the Arduino ESP32 core does not speak exFAT.
3. **The NeoPixel data line (GPIO 21)** is adjacent to the USB
   differential pair. Cheap USB cables can couple noise into the
   LED and cause glitching; the LED state is cosmetic so this is not
   a functional problem.

---

## Bill of materials (for a single unit)

| Part | Source | Notes |
|---|---|---|
| Waveshare ESP32-S3-ETH | Waveshare | Main board |
| microSD card, 8–32 GB, FAT32 | any | Capture storage |
| USB-C cable | any | Data, not charge-only |
| Ethernet cable | any | Cat5e+ |

Optional for field deployment:

| Part | Purpose |
|---|---|
| 5 V power bank | Untethered operation |
| 3D-printed case | Physical protection |
| USB OTG adapter | Connect to phone for console via an Android terminal |
