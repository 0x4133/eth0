// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// 802.1Q VLAN discovery via tagged ARP probes. If the upstream port
// is in trunk mode, tagged frames will be allowed onto the wire and
// any active VLANs will reply with their own tag intact.

#pragma once

#include <stdint.h>

// Build an 802.1Q-tagged Ethernet header (no payload). Returns the
// header length (18 bytes: dst+src+TPID+TCI+inner ethertype). Caller
// fills in the inner payload starting at the returned offset.
uint16_t buildVlanFrame(uint8_t* buf, const uint8_t* dstMAC, uint16_t vlanID,
                        uint16_t innerEthertype);

// Probe VLANs 1..100 with tagged ARP who-has requests for the
// gateway. Reports any VLAN ID that returns a tagged reply.
void reconVlanDiscover();
