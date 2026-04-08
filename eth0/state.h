// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Cross-module runtime state. This header declares (via `extern`)
// the shared globals that genuinely need to cross subsystem
// boundaries. The storage is defined once in eth0.ino.
//
// Keep this file short. Subsystem-local state should live in the
// owning .cpp file, not here. See docs/STYLE.md section 5.

#pragma once

#include <stdint.h>

// ── Identity ──

// The MAC address the W5500 is configured with. Mutable so that the
// MAC spoofing subsystem can rotate it.
extern uint8_t mac[6];
