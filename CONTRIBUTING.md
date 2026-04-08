# Contributing to eth0

Thank you for wanting to help. This document describes how to set up a
development environment, how code is formatted, how to propose changes,
and how to report problems.

Before you start, please read `SECURITY.md`. eth0 is an offensive
network-security tool intended for authorized testing. Do not contribute
features designed for unauthorized use.

---

## 1. Hardware & build

### Required hardware

- **Waveshare ESP32-S3-ETH** (ESP32-S3 + WIZnet W5500 + microSD)
- USB-C cable
- microSD card (FAT32)
- Ethernet connection to the network you are authorized to test

Pinout and wiring are documented in [`docs/HARDWARE.md`](docs/HARDWARE.md).

### Toolchain

eth0 is built with the **Arduino IDE 2.x**.

1. Install Arduino IDE 2.x from https://www.arduino.cc/en/software.
2. Add the ESP32 board package URL to **File → Preferences → Additional
   boards manager URLs**:
   ```
   https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
   ```
3. Install **esp32 by Espressif Systems, version 2.0.17** via
   **Tools → Board → Boards Manager**.
4. Install the libraries listed below via **Sketch → Include Library →
   Manage Libraries**. Versions must match exactly so CI and local
   builds agree.

### Pinned library versions

| Library | Version |
|---|---|
| Adafruit NeoPixel | 1.12.0 |
| Ethernet (arduino-libraries) | 2.0.2 |
| Ethernet2 | 1.0.4 |
| PubSubClient | 2.8 |
| ModbusMaster | 2.0.1 |

### Building

1. Open `eth0/eth0.ino` in the Arduino IDE.
2. **Tools → Board → ESP32 Arduino → ESP32S3 Dev Module**
3. **Tools → USB CDC On Boot → Enabled**
4. **Tools → Flash Size → 16MB**
5. **Tools → Partition Scheme → 16M Flash (3MB APP / 9.9MB FATFS)**
6. **Tools → Upload Speed → 921600**
7. Click **Upload**.

For headless/CI builds, `arduino-cli` produces the same firmware:

```sh
arduino-cli compile \
  --fqbn esp32:esp32:esp32s3:USBMode=default,CDCOnBoot=cdc,FlashSize=16M,PartitionScheme=default_16MB \
  eth0/
```

---

## 2. Code style

eth0 follows the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
with the embedded-firmware deviations documented in
[`docs/STYLE.md`](docs/STYLE.md). The authoritative formatter is
`clang-format` with the project's `.clang-format`.

### Formatting locally

```sh
# Format every tracked C/C++ file in the sketch folder
clang-format -i eth0/*.ino eth0/*.h eth0/*.cpp
```

### Before you commit

- [ ] `clang-format` passes (no diff produced).
- [ ] The sketch compiles cleanly in the Arduino IDE with no new
      warnings.
- [ ] Any new runtime state is owned by a single subsystem, not added
      to the global namespace.
- [ ] New serial commands are documented in the help text and in
      `docs/FEATURES.md`.
- [ ] The `CHANGELOG.md` `[Unreleased]` section has an entry.

---

## 3. Commit messages

Use the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
format:

```
<type>(<scope>): <summary>

<body, wrapped at 72 columns>

<footer: Fixes #123, Refs #456, etc.>
```

Accepted types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`,
`style`, `perf`, `build`, `ci`.

Example:

```
fix(recon): handle 0xFFFFFFFF broadcast in ARP sweep

The range loop wrapped when endIP was 0xFFFFFFFF. Restructure to
break before the final increment so 255.255.255.0/24 sweeps finish
instead of hanging the device.
```

---

## 4. Pull requests

1. Fork the repository and create a feature branch from `main`.
2. Make your change in small, reviewable commits.
3. Update `docs/` and `CHANGELOG.md` alongside the code change.
4. Open a PR against `main`. Fill out the PR template.
5. Respond to review comments within a reasonable timeframe. A PR that
   has been idle for more than 30 days may be closed.

### What makes a PR easy to accept

- It does one thing.
- It includes a clear description of **why**, not just what.
- It compiles green in CI.
- It does not introduce new globals without explanation.
- It does not add a new third-party dependency without discussion in
  an issue first.

---

## 5. Reporting bugs & requesting features

- **Bugs:** open an issue with the "Bug report" template. Include
  firmware version, board revision, Arduino core version, serial log
  excerpt, and reproduction steps.
- **Feature requests:** open an issue with the "Feature request"
  template. Explain the use case before proposing a design.
- **Security issues:** do **not** open a public issue. Follow
  `SECURITY.md`.

---

## 6. Code of conduct

Be kind. Assume good faith. Criticize code, not people. Off-topic,
discriminatory, or harassing content is not welcome.
