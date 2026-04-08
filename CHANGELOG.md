# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Apache-2.0 `LICENSE` and `NOTICE` at repository root.
- Repository hygiene: `.gitignore`, `.gitattributes`, `.editorconfig`,
  `.clang-format`.
- Contributor documentation: `CONTRIBUTING.md`, `SECURITY.md`,
  `CHANGELOG.md`, `docs/STYLE.md`, `docs/HARDWARE.md`.
- `docs/images/` directory housing diagrams previously loose in the
  repository root.
- `tools/` directory for host-side helper scripts.
- ARP sweep now accepts arbitrary CIDRs in the `/16`–`/30` range instead
  of being hard-coded to `/24`.

### Changed
- Moved `esp32-s3-ETH.png` from the repository root to
  `docs/images/esp32-s3-eth.png`.
- Moved `chat.ps1` and `eth0-listener.ps1` from the repository root to
  `tools/`.

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
