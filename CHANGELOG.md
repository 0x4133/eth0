# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `docs/ARCHITECTURE.md` — module map, runtime control flow, state
  ownership rules, and the rationale for the per-subsystem extern
  pattern.
- `docs/PROTOCOLS.md` — wire-format specs for the four custom
  protocols (TP-Link Kasa, AES-128-CBC UDP tunnel, DNS covert
  channel, IRC server) plus the PCAP-on-Serial framing.
- `tests/` host-side unit tests (45 assertions across `parseIP`,
  `parseMAC`, `pktRead16/32`, `pktWrite16/32`, `ipChecksum`,
  `dnsDecodeName`, and CIDR math). Runs under plain `g++` on
  Linux without the ESP32 toolchain.
- `host-tests` GitHub Actions workflow gating every push.
- 35+ new sketch-folder modules under `eth0/` covering capture,
  inject, IDS, recon, attack, services, stats, network map,
  hexdump, and persistent config. The original 9,254-line
  monolithic `eth0.ino` is now ~1,200 lines (entry points +
  serial dispatcher only).
- Apache-2.0 `LICENSE` and `NOTICE` at repository root.
- Repository hygiene: `.gitignore`, `.gitattributes`, `.editorconfig`,
  `.clang-format`.
- Contributor documentation: `CONTRIBUTING.md`, `SECURITY.md`,
  `CHANGELOG.md`, `docs/STYLE.md`, `docs/HARDWARE.md`.
- `docs/images/` directory housing diagrams previously loose in the
  repository root.
- `tools/` directory for host-side helper scripts.
- GitHub Actions `build` workflow compiling the sketch with
  `arduino-cli` on every push and pull request, against pinned ESP32
  core and library versions matching `CONTRIBUTING.md`. Built firmware
  is uploaded as a CI artifact with a 14-day retention.
- `.git-blame-ignore-revs` file recording mechanical reformat commits
  so `git blame` keeps attributing pre-format lines to their true
  authors. GitHub's Blame view honors the file automatically; local
  `git blame` requires `git config blame.ignoreRevsFile
  .git-blame-ignore-revs`.
- ARP sweep now accepts arbitrary CIDRs in the `/16`–`/30` range instead
  of being hard-coded to `/24`.

### Changed
- `README.md` slimmed from 1,697 lines to ~150 lines: project
  overview, quickstart, feature matrix, and links into `docs/`.
  The full feature reference moved verbatim to
  `docs/FEATURES.md`.
- Moved `esp32-s3-ETH.png` from the repository root to
  `docs/images/esp32-s3-eth.png`.
- Moved `chat.ps1` and `eth0-listener.ps1` from the repository root to
  `tools/`.
- `NOTICE` trimmed to list only the libraries actually linked into the
  firmware (`Adafruit NeoPixel`, `Ethernet2`).

### Removed
- Deleted the vendored `libs/` directory (10 third-party library trees,
  484 files, ~182k lines). Dependencies are now resolved via the
  Arduino Library Manager at the versions pinned in `CONTRIBUTING.md`
  and enforced by the `build` CI workflow. Eight of the ten libraries
  (`Ethernet`, `Ethernet_Generic`, `ETHClass2`, `ESP32-BLE-Keyboard`,
  `ESP32-BLE-Mouse`, `ModbusMaster`, `StreamDebugger`, `pubsubclient`)
  were never `#include`d by the sketch and had no runtime effect; the
  remaining two (`Ethernet2`, `Adafruit_NeoPixel`) are now installed
  from the Library Manager.

### Fixed
- `recon sweep` no longer reports an inflated progress denominator;
  `totalHosts` now excludes the network and broadcast addresses to
  match the original `/24` behavior.
- `recon sweep` no longer loops forever when the sweep range ends at
  `0xFFFFFFFF` (e.g. `255.255.255.0/24`, `255.255.255.252/30`). The
  iteration now breaks before the 32-bit increment would wrap.

## [0.1.0] - 2026-03-25

Initial public snapshot. Full feature set documented in `README.md`
and `docs/FEATURES.md`.

[Unreleased]: https://github.com/0x4133/eth0/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/0x4133/eth0/releases/tag/v0.1.0
