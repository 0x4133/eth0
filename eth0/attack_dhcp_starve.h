// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// DHCP starvation attack. Floods the DHCP server with DISCOVER
// packets each carrying a fake client MAC, exhausting the lease
// pool so legitimate clients can't get an address.

#pragma once

#include <stdint.h>

extern bool     dhcpStarveActive;
extern uint32_t dhcpStarveCount;
extern uint32_t dhcpStarveLastSend;

void dhcpStarveSendDiscover();
void parseDhcpStarveCommand(const char* cmd);
