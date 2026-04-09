// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Full TCP service scan: complete the three-way handshake on each
// open port, optionally send a protocol probe, read whatever banner
// the server sends back, and tear the connection down with RST.
//
// Higher-fidelity than the SYN probe in recon_port_scan.h — this
// confirms the service is alive *and* fingerprints it.

#pragma once

#include <stdint.h>

// Run a service scan against `targetIP` for the given ports. Each
// open port is reported as either "open" or "open <banner>".
void reconServiceScan(const uint8_t* targetIP, const uint16_t* ports, uint8_t numPorts);
