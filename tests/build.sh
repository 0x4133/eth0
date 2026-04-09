#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 0x4133
#
# Build and run the host-side unit tests with plain g++. No Arduino
# core, no ESP32 toolchain — pure x86 Linux. The tests cover the
# pure helper modules (ip_util, eth_frame, dns_util, CIDR math).

set -eu

cd "$(dirname "$0")"

CXX=${CXX:-g++}
OUT=test_runner

# arduino_includes/ contains a stub Arduino.h that forwards to
# arduino_shim.h, which provides the minimal Serial / millis / etc
# the test sources reference. We put it FIRST in the include path so
# real Arduino headers (which don't exist in this environment) are
# never reached.

"${CXX}" \
  -std=c++17 \
  -Wall -Wextra -Wno-unused-parameter \
  -O0 -g \
  -I arduino_includes \
  -I . \
  test_main.cpp \
  -o "${OUT}"

./"${OUT}"
