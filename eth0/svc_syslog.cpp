// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "svc_syslog.h"

#include <string.h>

#include <Arduino.h>

#include "config.h"
#include "ids.h"
#include "inject.h"
#include "ip_util.h"
#include "state.h"

bool     syslogEnabled       = false;
uint8_t  syslogServerIP[4]   = {0};
uint16_t syslogPort          = SYSLOG_DEFAULT_PORT;
uint32_t syslogSentCount     = 0;

void syslogSend(AlertLevel level, const char* msg) {
  // RFC 5424 priority = facility * 8 + severity
  // Facility 4 = LOG_AUTH
  // Severity: 2=CRIT, 4=WARN, 6=INFO
  uint8_t severity;
  switch (level) {
    case ALERT_CRIT:
      severity = 2;
      break;  // Critical
    case ALERT_WARN:
      severity = 4;
      break;  // Warning
    case ALERT_INFO:
      severity = 6;
      break;  // Informational
    default:
      severity = 5;
      break;  // Notice
  }
  uint8_t priority = SYSLOG_FACILITY * 8 + severity;

  // Build syslog message: <PRI>HOSTNAME APP: MSG
  char syslogMsg[SYSLOG_MAX_MSG + 32];
  int len = snprintf(syslogMsg, sizeof(syslogMsg), "<%u>eth0 IDS: %s", priority, msg);

  if (len > 0) {
    sendUDP(syslogServerIP, syslogPort, syslogMsg, (uint16_t)len);
    syslogSentCount++;
  }
}

void parseSyslogCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "off", 3) == 0) {
    syslogEnabled = false;
    Serial.printf("[SYSLOG] Disabled. %u messages sent.\n", syslogSentCount);
    return;
  }

  if (strncmp(cmd, "test", 4) == 0) {
    if (!syslogEnabled) {
      Serial.println("[SYSLOG] Not enabled. Set server first: syslog X.X.X.X");
      return;
    }
    syslogSend(ALERT_INFO, "eth0 syslog test message");
    Serial.println("[SYSLOG] Test message sent");
    return;
  }

  if (*cmd == '\0') {
    // Status
    if (syslogEnabled) {
      Serial.printf("[SYSLOG] ACTIVE -> %u.%u.%u.%u:%u (%u msgs sent)\n", syslogServerIP[0],
                    syslogServerIP[1], syslogServerIP[2], syslogServerIP[3], syslogPort,
                    syslogSentCount);
    } else {
      Serial.println("[SYSLOG] Disabled");
      Serial.println("  syslog X.X.X.X [port]  - forward IDS alerts");
      Serial.println("  syslog off              - stop forwarding");
      Serial.println("  syslog test             - send test message");
    }
    return;
  }

  // Parse: X.X.X.X [port]
  char ipStr[20];
  const char* space = strchr(cmd, ' ');
  int ipLen = space ? (space - cmd) : strlen(cmd);

  if (ipLen <= 0 || ipLen >= (int)sizeof(ipStr)) {
    Serial.println("[SYSLOG] Usage: syslog X.X.X.X [port]");
    return;
  }
  memcpy(ipStr, cmd, ipLen);
  ipStr[ipLen] = '\0';

  if (!parseIP(ipStr, syslogServerIP)) {
    Serial.println("[SYSLOG] Invalid IP. Usage: syslog 192.168.1.100 [514]");
    return;
  }

  // Optional port
  syslogPort = SYSLOG_DEFAULT_PORT;
  if (space) {
    const char* portStr = space + 1;
    while (*portStr == ' ')
      portStr++;
    int port = atoi(portStr);
    if (port > 0 && port <= 65535)
      syslogPort = (uint16_t)port;
  }

  syslogEnabled = true;
  syslogSentCount = 0;
  Serial.printf("[SYSLOG] ACTIVE — forwarding alerts to %u.%u.%u.%u:%u\n", syslogServerIP[0],
                syslogServerIP[1], syslogServerIP[2], syslogServerIP[3], syslogPort);
  Serial.println("[SYSLOG] Use 'syslog test' to verify connectivity");
}
