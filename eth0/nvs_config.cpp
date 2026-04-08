// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "nvs_config.h"

#include <string.h>

#include <Arduino.h>
#include <Preferences.h>

#include "config.h"
#include "filter.h"
#include "ids.h"
#include "state.h"
#include "svc_syslog.h"

Preferences nvsPrefs;

void configSave() {
  nvsPrefs.begin(NVS_NAMESPACE, false);  // read-write

  // Network config
  nvsPrefs.putBytes("ourIP", ourIP, 4);
  nvsPrefs.putBytes("ourGW", ourGW, 4);
  nvsPrefs.putBytes("ourSubnet", ourSubnet, 4);
  nvsPrefs.putBytes("ourDNS", ourDNS, 4);

  // IDS
  nvsPrefs.putBool("idsEnabled", idsEnabled);

  // Filter
  nvsPrefs.putUChar("filterType", (uint8_t)activeFilter.type);
  nvsPrefs.putUShort("filterEtype", activeFilter.ethertype);
  nvsPrefs.putUChar("filterProto", activeFilter.protocol);
  nvsPrefs.putUShort("filterPort", activeFilter.port);
  nvsPrefs.putBytes("filterIP", activeFilter.ip, 4);
  nvsPrefs.putBytes("filterMAC", activeFilter.macAddr, 6);

  // Stats
  nvsPrefs.putBool("statsAuto", statsAutoEnabled);
  nvsPrefs.putUInt("statsIntv", statsAutoInterval);

  // Syslog
  nvsPrefs.putBool("syslogOn", syslogEnabled);
  nvsPrefs.putBytes("syslogIP", syslogServerIP, 4);
  nvsPrefs.putUShort("syslogPort", syslogPort);

  // Marker that config exists
  nvsPrefs.putBool("saved", true);

  nvsPrefs.end();
  Serial.println("[CONFIG] Settings saved to flash (NVS)");
}

void configLoad() {
  nvsPrefs.begin(NVS_NAMESPACE, true);  // read-only

  if (!nvsPrefs.getBool("saved", false)) {
    nvsPrefs.end();
    Serial.println("[CONFIG] No saved config found (using defaults)");
    return;
  }

  // IDS
  idsEnabled = nvsPrefs.getBool("idsEnabled", IDS_ENABLED_DEFAULT);

  // Filter
  activeFilter.type = (FilterType)nvsPrefs.getUChar("filterType", FILTER_NONE);
  activeFilter.ethertype = nvsPrefs.getUShort("filterEtype", 0);
  activeFilter.protocol = nvsPrefs.getUChar("filterProto", 0);
  activeFilter.port = nvsPrefs.getUShort("filterPort", 0);
  nvsPrefs.getBytes("filterIP", activeFilter.ip, 4);
  nvsPrefs.getBytes("filterMAC", activeFilter.macAddr, 6);

  // Stats
  statsAutoEnabled = nvsPrefs.getBool("statsAuto", false);
  statsAutoInterval = nvsPrefs.getUInt("statsIntv", STATS_INTERVAL_DEFAULT);

  // Syslog
  syslogEnabled = nvsPrefs.getBool("syslogOn", false);
  nvsPrefs.getBytes("syslogIP", syslogServerIP, 4);
  syslogPort = nvsPrefs.getUShort("syslogPort", SYSLOG_DEFAULT_PORT);

  nvsPrefs.end();

  Serial.println("[CONFIG] Settings loaded from flash");
  if (activeFilter.type != FILTER_NONE) {
    Serial.print("[CONFIG] Restored filter: ");
    printCurrentFilter();
  }
  if (statsAutoEnabled) {
    Serial.printf("[CONFIG] Auto-stats: every %us\n", statsAutoInterval / 1000);
    statsLastAuto = millis();
  }
  if (syslogEnabled) {
    Serial.printf("[CONFIG] Syslog: -> %u.%u.%u.%u:%u\n", syslogServerIP[0], syslogServerIP[1],
                  syslogServerIP[2], syslogServerIP[3], syslogPort);
  }
}

void configClear() {
  nvsPrefs.begin(NVS_NAMESPACE, false);
  nvsPrefs.clear();
  nvsPrefs.end();
  Serial.println("[CONFIG] Flash config cleared. Defaults will be used on next boot.");
}

void parseConfigCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  if (strncmp(cmd, "save", 4) == 0) {
    configSave();
  } else if (strncmp(cmd, "load", 4) == 0) {
    configLoad();
    Serial.println("[CONFIG] Settings reloaded from flash");
  } else if (strncmp(cmd, "clear", 5) == 0) {
    configClear();
  } else {
    Serial.println("[CONFIG] Persistent settings (ESP32 NVS flash):");
    Serial.println("  config save   - save current settings");
    Serial.println("  config load   - reload from flash");
    Serial.println("  config clear  - erase saved config");
    Serial.println();
    Serial.println("  Saves: IP, IDS, filter, auto-stats, syslog");
  }
}
