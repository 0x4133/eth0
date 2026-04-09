// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// DNS wire-format helpers used by mDNS sniffer, DNS spoof engine,
// IDS DNS detector, and the DNS covert channel. None of them touch
// global state — they operate on the dns blob the caller hands in.

#pragma once

#include <stdint.h>

// Decode a DNS-encoded name (length-prefixed labels with optional
// compression pointers per RFC 1035 §4.1.4) starting at `offset`
// inside `dns` (which is `dnsLen` bytes long). Writes the dotted
// name into `out` (max `maxOut` bytes including the NUL).
//
// Returns the offset of the byte AFTER the encoded name relative
// to the start of `dns`, accounting for compression jumps. Returns
// 0 on a malformed name.
uint16_t dnsDecodeName(const uint8_t* dns, uint16_t dnsLen, uint16_t offset, char* out,
                       uint16_t maxOut);
