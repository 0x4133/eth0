// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Cross-module runtime state. This header declares (via `extern`)
// the shared globals that genuinely need to cross subsystem
// boundaries. The storage is defined once in eth0.ino.
//
// Keep this file short. Subsystem-local state lives in the owning
// .cpp file behind a file-scope anonymous-namespace struct, not
// here. See docs/STYLE.md section 5.

#pragma once

#include <stdint.h>

#include "config.h"

// ── Identity ──

// The MAC address the W5500 is configured with. Mutable so the MAC
// spoofing subsystem can rotate it.
extern uint8_t mac[6];

// Populated by DHCP at boot; falls back to hard-coded defaults if
// DHCP fails. Read by many subsystems (capture, recon, attack, IDS,
// services) to identify self vs. peer and to source outgoing frames.
extern uint8_t ourIP[4];
extern uint8_t ourGW[4];
extern uint8_t ourSubnet[4];
extern uint8_t ourDNS[4];

// ── Shared packet buffers ──

// Scratch buffers reused for the hot receive and transmit paths. The
// capture loop, injection path, and several recon/attack modules all
// borrow these; the single-threaded Arduino loop guarantees no
// aliasing.
extern uint8_t packetBuf[MAX_FRAME_SIZE];
extern uint8_t txBuf[MAX_FRAME_SIZE];

// ── Capture flag ──

// True when the device is actively writing PCAP records. Gates the
// write side of the capture pipeline but is consulted by most
// recon/attack modules too so they can opportunistically log the
// frames they generate.
extern bool capturing;
