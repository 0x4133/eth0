// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "pcap_writer.h"

#include <stdio.h>

#include <Arduino.h>
#include <SD.h>

#include "config.h"
#include "state.h"

// ── Storage for the externs in pcap_writer.h ──

File captureFile;
uint32_t packetCount     = 0;
uint32_t droppedCount    = 0;
uint32_t txCount         = 0;
uint32_t fileIndex       = 0;
uint32_t lastCommit      = 0;
uint32_t uncommittedPkts = 0;
char     currentFilename[32];

// ── Implementations ──

bool openNewCaptureFile() {
  do {
    snprintf(currentFilename, sizeof(currentFilename), "/capture_%04u.pcap", fileIndex);
    fileIndex++;
  } while (SD.exists(currentFilename) && fileIndex < 9999);

  captureFile = SD.open(currentFilename, FILE_WRITE);
  if (!captureFile)
    return false;

  writePcapGlobalHeader();
  captureFile.close();  // commit the header immediately

  // Reopen for append
  captureFile = SD.open(currentFilename, FILE_APPEND);
  if (!captureFile)
    return false;

  uncommittedPkts = 0;
  lastCommit = millis();

  Serial.printf("[SD] Opened %s\n", currentFilename);
  return true;
}

// Close and reopen the current capture file.
// close() forces the FAT directory entry (file size, cluster chain) to disk.
// If power dies after close(), the file is intact and readable.
// We reopen in append mode to continue writing.
void commitCaptureFile() {
  captureFile.close();
  captureFile = SD.open(currentFilename, FILE_APPEND);
  if (!captureFile) {
    Serial.println("[ERROR] Failed to reopen capture file after commit!");
    capturing = false;
    return;
  }
  uncommittedPkts = 0;
  lastCommit = millis();
}

void writePcapGlobalHeader() {
  PcapGlobalHeader hdr;
  hdr.magic_number = 0xa1b2c3d4;
  hdr.version_major = 2;
  hdr.version_minor = 4;
  hdr.thiszone = 0;
  hdr.sigfigs = 0;
  hdr.snaplen = MAX_FRAME_SIZE;
  hdr.network = 1;

  captureFile.write((const uint8_t*)&hdr, sizeof(hdr));
}

void writePcapPacket(const uint8_t* data, uint16_t len) {
  uint32_t ms = millis();

  PcapPacketHeader phdr;
  phdr.ts_sec = ms / 1000;
  phdr.ts_usec = (ms % 1000) * 1000;
  phdr.incl_len = len;
  phdr.orig_len = len;

  captureFile.write((const uint8_t*)&phdr, sizeof(phdr));
  captureFile.write(data, len);
}
