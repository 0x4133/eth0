// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// PCAP file writer. Owns the on-disk capture state: the active File
// handle, rotating file index, commit counters, and the wire-format
// PCAP global / record headers.
//
// Many subsystems still read or increment `packetCount`,
// `uncommittedPkts`, etc. during Phase 4 — those symbols are exposed
// via `extern` here rather than hidden behind accessor functions.
// Phase 8 will convert them to a single `State` struct and narrow
// the API; right now the point is just to move the storage out of
// eth0.ino without churning 65 call sites.

#pragma once

#include <stdint.h>

#include <SD.h>

// ── Wire-format structures (little-endian, as stored in the file) ──

struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// ── Capture-internal state (defined in pcap_writer.cpp) ──

extern File     captureFile;
extern uint32_t packetCount;
extern uint32_t droppedCount;
extern uint32_t txCount;
extern uint32_t fileIndex;
extern uint32_t lastCommit;
extern uint32_t uncommittedPkts;
extern char     currentFilename[32];

// ── API ──

// Open a new /capture_NNNN.pcap file on the SD card, write the PCAP
// global header, and leave it open in append mode ready for packet
// records. Returns false if SD access fails or the 9999-file naming
// space is exhausted.
bool openNewCaptureFile();

// Close and reopen the current capture file to force the FAT
// directory entry to disk. Called every COMMIT_INTERVAL ms and every
// COMMIT_PKT_BATCH packets so that an unexpected power loss leaves
// the file intact and readable up to the last commit. Sets
// `capturing` to false if reopen fails.
void commitCaptureFile();

// Write the 24-byte PCAP global header to `captureFile` using
// MAX_FRAME_SIZE as snaplen and linktype 1 (Ethernet).
void writePcapGlobalHeader();

// Append a single PCAP record (16-byte header + `len` bytes of
// payload) to `captureFile`. Timestamp is derived from millis().
void writePcapPacket(const uint8_t* data, uint16_t len);
