// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133
//
// Host-side unit tests for the pure helper modules.
//
// Usage:
//   cd tests && ./build.sh
//
// The tests do not depend on the ESP32 toolchain and can run on any
// Linux box with g++. Coverage is intentionally narrow: pure
// functions whose behavior we can verify without Arduino I/O.
//
// To add a test, write a `static void test_…()` function and call
// it from main(). Failures call exit(1) so CI catches them.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "arduino_shim.h"

// Provide the Serial instance the shim declares as extern.
SerialStub Serial;

// ── Pull in the modules under test ──
//
// We compile these source files directly into the test binary
// rather than linking them, so the ESP32-only includes don't
// matter — they're never reached because Arduino.h is replaced by
// arduino_shim.h via -I ordering in build.sh.

#include "../eth0/dns_util.cpp"     // dnsDecodeName
#include "../eth0/eth_frame.cpp"    // ipChecksum, tcpChecksum, builders
#include "../eth0/ip_util.cpp"      // parseIP, parseMAC, printIP, printMAC

// state.h externs that eth_frame.cpp references — define them
// as test fixtures so the linker is happy.
uint8_t mac[6] = {0x02, 0xCA, 0xFE, 0xBA, 0xBE, 0x01};
uint8_t ourIP[4]     = {192, 168, 1, 100};
uint8_t ourGW[4]     = {192, 168, 1, 1};
uint8_t ourSubnet[4] = {255, 255, 255, 0};
uint8_t ourDNS[4]    = {192, 168, 1, 1};
uint8_t packetBuf[1518];
uint8_t txBuf[1518];
bool capturing = false;

// ── Test counter ──
static int g_passed = 0;
static int g_failed = 0;

#define EXPECT(cond)                                                                              \
  do {                                                                                            \
    if (!(cond)) {                                                                                \
      fprintf(stderr, "FAIL  %s:%d: %s\n", __FILE__, __LINE__, #cond);                            \
      g_failed++;                                                                                 \
    } else {                                                                                      \
      g_passed++;                                                                                 \
    }                                                                                             \
  } while (0)

#define EXPECT_EQ(a, b)                                                                           \
  do {                                                                                            \
    auto _aa = (a);                                                                               \
    auto _bb = (b);                                                                               \
    if (_aa != _bb) {                                                                             \
      fprintf(stderr, "FAIL  %s:%d: expected %lld == %lld\n", __FILE__, __LINE__,                 \
              (long long)_aa, (long long)_bb);                                                    \
      g_failed++;                                                                                 \
    } else {                                                                                      \
      g_passed++;                                                                                 \
    }                                                                                             \
  } while (0)

// ══════════════════════════════════════════════════════════════
//  parseIP / parseMAC
// ══════════════════════════════════════════════════════════════

static void test_parseIP_basic() {
  uint8_t out[4];
  EXPECT(parseIP("192.168.1.1", out));
  EXPECT_EQ(out[0], 192);
  EXPECT_EQ(out[1], 168);
  EXPECT_EQ(out[2], 1);
  EXPECT_EQ(out[3], 1);
}

static void test_parseIP_zero() {
  uint8_t out[4];
  EXPECT(parseIP("0.0.0.0", out));
  EXPECT_EQ(out[0], 0);
  EXPECT_EQ(out[3], 0);
}

static void test_parseIP_max() {
  uint8_t out[4];
  EXPECT(parseIP("255.255.255.255", out));
  EXPECT_EQ(out[0], 255);
  EXPECT_EQ(out[3], 255);
}

static void test_parseIP_overflow_rejected() {
  uint8_t out[4];
  EXPECT(!parseIP("256.0.0.0", out));
  EXPECT(!parseIP("0.0.0.300", out));
}

static void test_parseIP_malformed_rejected() {
  uint8_t out[4];
  EXPECT(!parseIP("1.2.3", out));
  EXPECT(!parseIP("not an ip", out));
  EXPECT(!parseIP("", out));
}

static void test_parseMAC_colons() {
  uint8_t out[6];
  EXPECT(parseMAC("aa:bb:cc:dd:ee:ff", out));
  EXPECT_EQ(out[0], 0xaa);
  EXPECT_EQ(out[5], 0xff);
}

static void test_parseMAC_dashes() {
  uint8_t out[6];
  EXPECT(parseMAC("AA-BB-CC-DD-EE-FF", out));
  EXPECT_EQ(out[0], 0xAA);
  EXPECT_EQ(out[5], 0xFF);
}

static void test_parseMAC_malformed_rejected() {
  uint8_t out[6];
  EXPECT(!parseMAC("not a mac", out));
  EXPECT(!parseMAC("aa:bb:cc:dd:ee", out));  // too short
}

// ══════════════════════════════════════════════════════════════
//  pktRead16 / pktRead32 / pktWrite16 / pktWrite32
// ══════════════════════════════════════════════════════════════

static void test_pktRead16_be() {
  const uint8_t bytes[2] = {0x12, 0x34};
  EXPECT_EQ(pktRead16(bytes), 0x1234);
}

static void test_pktRead32_be() {
  const uint8_t bytes[4] = {0x12, 0x34, 0x56, 0x78};
  EXPECT_EQ(pktRead32(bytes), 0x12345678u);
}

static void test_pktWrite16_be() {
  uint8_t buf[2] = {0};
  pktWrite16(buf, 0xCAFE);
  EXPECT_EQ(buf[0], 0xCA);
  EXPECT_EQ(buf[1], 0xFE);
}

static void test_pktWrite32_be() {
  uint8_t buf[4] = {0};
  pktWrite32(buf, 0xDEADBEEFu);
  EXPECT_EQ(buf[0], 0xDE);
  EXPECT_EQ(buf[1], 0xAD);
  EXPECT_EQ(buf[2], 0xBE);
  EXPECT_EQ(buf[3], 0xEF);
}

static void test_pkt_round_trip() {
  uint8_t buf[6];
  pktWrite16(buf, 0xAABB);
  pktWrite32(buf + 2, 0x11223344u);
  EXPECT_EQ(pktRead16(buf), 0xAABB);
  EXPECT_EQ(pktRead32(buf + 2), 0x11223344u);
}

// ══════════════════════════════════════════════════════════════
//  ipChecksum
// ══════════════════════════════════════════════════════════════

static void test_ipChecksum_zero_buffer() {
  uint8_t buf[20] = {0};
  // The complement of 0 over a zero buffer is 0xFFFF.
  EXPECT_EQ(ipChecksum(buf, 20), 0xFFFFu);
}

static void test_ipChecksum_known_header() {
  // RFC 1071 example header (without checksum):
  //   45 00 00 30 44 22 40 00 80 06 00 00 8c 7c 19 ac ae 24 1e 2b
  // Checksum should be 0x442E.
  // Our function operates with the checksum field already zeroed.
  uint8_t hdr[20] = {0x45, 0x00, 0x00, 0x30, 0x44, 0x22, 0x40, 0x00, 0x80, 0x06,
                     0x00, 0x00, 0x8c, 0x7c, 0x19, 0xac, 0xae, 0x24, 0x1e, 0x2b};
  EXPECT_EQ(ipChecksum(hdr, 20), 0x442Eu);
}

// ══════════════════════════════════════════════════════════════
//  dnsDecodeName
// ══════════════════════════════════════════════════════════════

static void test_dnsDecodeName_simple() {
  // 3-byte length-prefixed labels: "www.example.com"
  uint8_t dns[64] = {0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p',
                     'l', 'e', 0x03, 'c', 'o', 'm', 0x00};
  char out[64];
  uint16_t consumed = dnsDecodeName(dns, sizeof(dns), 0, out, sizeof(out));
  EXPECT(strcmp(out, "www.example.com") == 0);
  EXPECT_EQ(consumed, 17u);  // 3+1+7+1+3+1+1
}

static void test_dnsDecodeName_truncates_safely() {
  uint8_t dns[64] = {0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p',
                     'l', 'e', 0x03, 'c', 'o', 'm', 0x00};
  char tiny[6];
  dnsDecodeName(dns, sizeof(dns), 0, tiny, sizeof(tiny));
  // Should have written at most sizeof(tiny)-1 chars and a NUL.
  EXPECT_EQ((int)tiny[sizeof(tiny) - 1], 0);
}

// ══════════════════════════════════════════════════════════════
//  CIDR math (inlined in parseReconCommand — replicate it here)
// ══════════════════════════════════════════════════════════════

static void test_cidr_24() {
  uint8_t base[4] = {192, 168, 1, 50};
  int cidr = 24;
  uint32_t baseU32 = ((uint32_t)base[0] << 24) | ((uint32_t)base[1] << 16) |
                     ((uint32_t)base[2] << 8) | (uint32_t)base[3];
  uint32_t mask      = (cidr == 0) ? 0 : (0xFFFFFFFFUL << (32 - cidr));
  uint32_t network   = baseU32 & mask;
  uint32_t broadcast = network | ~mask;
  EXPECT_EQ(network, 0xC0A80100u);    // 192.168.1.0
  EXPECT_EQ(broadcast, 0xC0A801FFu);  // 192.168.1.255
}

static void test_cidr_30() {
  uint8_t base[4] = {10, 0, 0, 5};
  int cidr = 30;
  uint32_t baseU32 = ((uint32_t)base[0] << 24) | ((uint32_t)base[1] << 16) |
                     ((uint32_t)base[2] << 8) | (uint32_t)base[3];
  uint32_t mask      = (cidr == 0) ? 0 : (0xFFFFFFFFUL << (32 - cidr));
  uint32_t network   = baseU32 & mask;
  uint32_t broadcast = network | ~mask;
  EXPECT_EQ(network, 0x0A000004u);    // 10.0.0.4
  EXPECT_EQ(broadcast, 0x0A000007u);  // 10.0.0.7
}

static void test_cidr_22() {
  uint8_t base[4] = {172, 16, 5, 1};
  int cidr = 22;
  uint32_t baseU32 = ((uint32_t)base[0] << 24) | ((uint32_t)base[1] << 16) |
                     ((uint32_t)base[2] << 8) | (uint32_t)base[3];
  uint32_t mask      = (cidr == 0) ? 0 : (0xFFFFFFFFUL << (32 - cidr));
  uint32_t network   = baseU32 & mask;
  uint32_t broadcast = network | ~mask;
  EXPECT_EQ(network, 0xAC100400u);    // 172.16.4.0
  EXPECT_EQ(broadcast, 0xAC1007FFu);  // 172.16.7.255
}

// ══════════════════════════════════════════════════════════════
//  main
// ══════════════════════════════════════════════════════════════

int main() {
  test_parseIP_basic();
  test_parseIP_zero();
  test_parseIP_max();
  test_parseIP_overflow_rejected();
  test_parseIP_malformed_rejected();
  test_parseMAC_colons();
  test_parseMAC_dashes();
  test_parseMAC_malformed_rejected();

  test_pktRead16_be();
  test_pktRead32_be();
  test_pktWrite16_be();
  test_pktWrite32_be();
  test_pkt_round_trip();

  test_ipChecksum_zero_buffer();
  test_ipChecksum_known_header();

  test_dnsDecodeName_simple();
  test_dnsDecodeName_truncates_safely();

  test_cidr_24();
  test_cidr_30();
  test_cidr_22();

  printf("\n");
  printf("──────────────────────────────────────\n");
  printf("  Tests passed:  %d\n", g_passed);
  printf("  Tests failed:  %d\n", g_failed);
  printf("──────────────────────────────────────\n");

  return g_failed == 0 ? 0 : 1;
}
