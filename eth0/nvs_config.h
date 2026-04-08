// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Persistent configuration via the ESP32 Preferences (NVS) library.
// Saves the active capture filter, IDS toggle, syslog settings,
// MAC address, and a few other knobs so they survive reboot.

#pragma once

#include <Preferences.h>

extern Preferences nvsPrefs;

void configSave();
void configLoad();
void configClear();
void parseConfigCommand(const char* cmd);
