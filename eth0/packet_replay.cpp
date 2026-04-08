// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "packet_replay.h"

#include <string.h>

#include <Arduino.h>
#include <SD.h>

#include "config.h"
#include "ids.h"
#include "inject.h"
#include "pcap_writer.h"
#include "state.h"

void replayPcap(const char* filename, uint32_t delayMs) {
  // Ensure path starts with /
  char path[64];
  if (filename[0] != '/') {
    snprintf(path, sizeof(path), "/%s", filename);
  } else {
    strncpy(path, filename, sizeof(path) - 1);
    path[sizeof(path) - 1] = '\0';
  }

  File f = SD.open(path, FILE_READ);
  if (!f) {
    Serial.printf("[REPLAY] Cannot open %s\n", path);
    return;
  }

  // Read and validate PCAP global header
  PcapGlobalHeader ghdr;
  if (f.read((uint8_t*)&ghdr, sizeof(ghdr)) != sizeof(ghdr)) {
    Serial.println("[REPLAY] Failed to read PCAP header");
    f.close();
    return;
  }

  bool swap = false;
  if (ghdr.magic_number == 0xa1b2c3d4) {
    swap = false;
  } else if (ghdr.magic_number == 0xd4c3b2a1) {
    swap = true;
  } else {
    Serial.printf("[REPLAY] Not a PCAP file (magic: 0x%08X)\n", ghdr.magic_number);
    f.close();
    return;
  }

  Serial.printf("[REPLAY] Playing %s (delay=%ums)...\n", path, delayMs);
  idsSetLed(COLOR_YELLOW);

  uint32_t count = 0;
  uint32_t errors = 0;

  while (f.available() >= (int)sizeof(PcapPacketHeader)) {
    PcapPacketHeader phdr;
    if (f.read((uint8_t*)&phdr, sizeof(phdr)) != sizeof(phdr))
      break;

    uint32_t inclLen = swap ? __builtin_bswap32(phdr.incl_len) : phdr.incl_len;

    if (inclLen == 0 || inclLen > MAX_FRAME_SIZE) {
      errors++;
      f.seek(f.position() + inclLen);  // skip bad packet
      continue;
    }

    if (f.read(txBuf, inclLen) != inclLen)
      break;

    if (sendRawFrame(txBuf, inclLen)) {
      count++;
    } else {
      errors++;
    }

    if (count % 100 == 0 && count > 0) {
      Serial.printf("[REPLAY] %u packets sent...\n", count);
    }

    if (delayMs > 0)
      delay(delayMs);

    // Check for abort (any serial input stops replay)
    if (Serial.available()) {
      Serial.read();
      Serial.println("[REPLAY] Aborted by user");
      break;
    }
  }

  f.close();
  Serial.printf("[REPLAY] Done. %u sent, %u errors.\n", count, errors);
  idsSetLed(capturing ? COLOR_GREEN : COLOR_BLUE);
}

void parseReplayCommand(const char* cmd) {
  while (*cmd == ' ')
    cmd++;

  // Parse: filename [delay_ms]
  char filename[64];
  uint32_t delayMs = REPLAY_DEFAULT_DELAY;

  const char* space = strchr(cmd, ' ');
  int nameLen = space ? (space - cmd) : strlen(cmd);
  if (nameLen <= 0 || nameLen >= (int)sizeof(filename)) {
    Serial.println("[REPLAY] Usage: replay capture_0000.pcap [delay_ms]");
    return;
  }
  memcpy(filename, cmd, nameLen);
  filename[nameLen] = '\0';

  if (space) {
    delayMs = atoi(space + 1);
  }

  replayPcap(filename, delayMs);
}
