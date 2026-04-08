// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 0x4133

#include "dns_util.h"

uint16_t dnsDecodeName(const uint8_t* dns, uint16_t dnsLen, uint16_t offset, char* out,
                       uint16_t maxOut) {
  uint16_t pos = offset;
  uint16_t outPos = 0;
  uint16_t startPos = offset;
  bool jumped = false;
  uint16_t jumpedFrom = 0;
  int safety = 64;  // max labels to prevent infinite loops

  while (pos < dnsLen && safety-- > 0) {
    uint8_t labelLen = dns[pos];

    if (labelLen == 0) {
      // End of name
      if (!jumped)
        startPos = pos + 1 - offset;
      else
        startPos = jumpedFrom + 2 - offset;
      break;
    }

    // Compression pointer (top 2 bits set)
    if ((labelLen & 0xC0) == 0xC0) {
      if (pos + 1 >= dnsLen)
        break;
      uint16_t ptr = ((labelLen & 0x3F) << 8) | dns[pos + 1];
      if (!jumped)
        jumpedFrom = pos;
      jumped = true;
      pos = ptr;
      continue;
    }

    // Regular label
    if (pos + 1 + labelLen > dnsLen)
      break;

    if (outPos > 0 && outPos < maxOut - 1)
      out[outPos++] = '.';
    for (uint8_t i = 0; i < labelLen && outPos < maxOut - 1; i++) {
      out[outPos++] = dns[pos + 1 + i];
    }
    pos += 1 + labelLen;
  }

  out[outPos] = '\0';
  return startPos;
}
