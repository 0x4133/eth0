// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// UDP syslog forwarder. When enabled, every IDS alert is shipped
// as an RFC 5424 syslog message to the configured collector.

#pragma once

#include <stdint.h>

#include "ids.h"  // for AlertLevel

extern bool     syslogEnabled;
extern uint8_t  syslogServerIP[4];
extern uint16_t syslogPort;
extern uint32_t syslogSentCount;

// Send a single alert to the syslog collector. No-op if
// `syslogEnabled` is false.
void syslogSend(AlertLevel level, const char* msg);

// `syslog …` serial command dispatcher.
void parseSyslogCommand(const char* cmd);
