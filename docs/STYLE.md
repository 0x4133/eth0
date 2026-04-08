# eth0 C++ Style Guide

eth0 follows the
[Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html)
with the embedded-firmware deviations listed below. `clang-format`
(configured in `.clang-format` at the repository root) is the
authoritative formatter; anything this document and `.clang-format`
disagree on is a bug in the document.

Run the formatter before every commit:

```sh
clang-format -i eth0/*.ino eth0/*.h eth0/*.cpp
```

---

## 1. Deviations from Google C++

| Topic | Google rule | eth0 rule | Why |
|---|---|---|---|
| Line length | 80 cols | **100 cols** | Packet-builder code is denser than application code and reads better at 100. |
| Exceptions | Forbidden | **Forbidden** (aligned) | Arduino-ESP32 has exceptions off by default. |
| RTTI | Forbidden | **Forbidden** (aligned) | Flash and RAM budgets. |
| Dynamic allocation | Allowed | **Forbidden on hot paths**. `new`/`malloc` only in `setup()`. | Heap fragmentation kills long-running sketches. |
| Header guards | `<PATH>_<FILE>_H_` macros | **`#pragma once`** | Arduino toolchain supports it; guard macros would have to encode the sketch folder. |
| Header extension | `.h` | **`.h`** (aligned) | Arduino IDE requires `.h`. |
| Source extension | `.cc` | **`.cpp`** | Arduino IDE convention. |
| File naming | `snake_case` | **`snake_case`** (aligned) | |
| Function naming | `PascalCase` | **`lowerCamelCase`** | Matches the existing codebase (`sendArpRequest`, `idsCheckArp`); changing 300+ names would thrash git blame. Documented deviation. |
| Variable naming | `snake_case` | **`lowerCamelCase`** | Matches existing code. |
| Type naming | `PascalCase` | **`PascalCase`** (aligned) | Already consistent (`IrcClient`, `ArpEntry`). |
| Constant naming | `kPascalCase` | **`kPascalCase`** for `constexpr` / `const`; **`UPPER_SNAKE_CASE`** only for macros that must stay macros (pins, conditional compilation) | |
| Member variables | trailing `_` | **trailing `_`** (aligned) | |
| `auto` | Encouraged for obvious types | **Discouraged except for iterators and lambdas** | Embedded code benefits from being able to eyeball every integer width. |
| Include order | Own → C → C++ → Other → Project | **Own → C system → C++ std → Arduino/libs → Project**, alphabetized within each group | Matches `.clang-format` `IncludeCategories`. |
| Function length | ≤ 40 lines preferred | **≤ 150 lines hard cap** | Some packet builders legitimately exceed 40. |
| `goto` | Strongly discouraged | **Forbidden** | |
| Global variables | Discouraged | **Forbidden in new code** except via the `state.h` aggregate (see §5). |

---

## 2. Naming conventions, cheat sheet

```cpp
// Constants
inline constexpr uint16_t kMaxFrameSize = 1518;
inline constexpr uint16_t kIrcPort      = 6667;

// Enums
enum class AlertLevel : uint8_t {
  kInfo,
  kWarn,
  kCrit,
};

// Types
struct ArpEntry {
  uint8_t  ip[4];
  uint8_t  mac[6];
  uint32_t lastSeen;
  bool     active;
};

class PcapWriter {
 public:
  bool open(const char* path);
  void writePacket(const uint8_t* data, uint16_t len);
  void close();

 private:
  File    file_;
  uint32_t packetCount_ = 0;
};

// Free functions
bool parseIp(const char* str, uint8_t* out);
void sendArpRequest(const uint8_t* targetIp);

// Locals
void reconArpSweep(uint32_t startIp, uint32_t endIp) {
  uint32_t sent = 0;
  uint32_t found = 0;
  // ...
}
```

---

## 3. Headers

- One top-level subsystem per `.h`/`.cpp` pair. Match the filename to
  the subsystem: `arp_mitm.h` / `arp_mitm.cpp`.
- Every header begins with:
  ```cpp
  // SPDX-License-Identifier: Apache-2.0
  // Copyright 2026 0x4133

  #pragma once
  ```
- Header contents in order: includes, macros (if unavoidable),
  constants, types, free-function declarations.
- A `.cpp` file includes its own header first, then a blank line, then
  the other groups in the `.clang-format`-specified order.

---

## 4. Constants

Prefer `inline constexpr` over `#define`. Macros remain only for:

1. Pin assignments (they participate in Arduino's hardware abstraction).
2. Preprocessor toggles (`#ifdef ETH0_ENABLE_FOO`).
3. String-token pasting.

```cpp
// GOOD
inline constexpr uint16_t kCommitInterval = 2000;

// BAD (unless it's a pin or a toggle)
#define COMMIT_INTERVAL 2000
```

---

## 5. Global state

eth0 is single-threaded (Arduino `loop()` + ISRs with minimal work),
so we do not need locks, but we do need discipline to keep modules
independent.

**Rules:**

1. Each subsystem owns its state in a file-scope anonymous-namespace
   struct inside its `.cpp`. The header exposes only functions.
2. Cross-module wiring that genuinely must be shared (our MAC, our IP,
   capture flag, packet buffer) lives in `state.h` behind accessor
   functions — not raw `extern` arrays.
3. New global variables require justification in the PR description.
4. No `using namespace std;` anywhere.

Example:

```cpp
// arp_mitm.h
#pragma once
#include <stdint.h>

namespace eth0::attack {

void arpMitmInit();
bool arpMitmStart(const uint8_t* victimIp);
void arpMitmStop();
void arpMitmTick(uint32_t nowMs);
bool arpMitmActive();

}  // namespace eth0::attack
```

```cpp
// arp_mitm.cpp
#include "arp_mitm.h"

#include <string.h>

#include "state.h"

namespace eth0::attack {
namespace {

struct State {
  bool     active = false;
  uint8_t  victimIp[4]  = {0};
  uint8_t  victimMac[6] = {0};
  uint32_t lastPoison   = 0;
  uint32_t packetCount  = 0;
};

State g;

}  // namespace

void arpMitmInit() { g = State{}; }

bool arpMitmActive() { return g.active; }

// ... rest of the module
}  // namespace eth0::attack
```

---

## 6. Error handling

- No exceptions. Return `bool` for success/failure, or an explicit
  error enum.
- Log errors via the existing `Serial.println` / `idsAlert` paths; do
  not invent new log formats.
- Never silently swallow an error. A `// ignored` comment explaining
  *why* is acceptable at the call site.

---

## 7. Integer types

- Use fixed-width integers (`uint8_t`, `uint16_t`, `uint32_t`) for
  anything that touches a wire format, a register, or a length field.
- Use `size_t` for sizes of in-memory buffers.
- Use `int` only for local loop counters that cannot underflow.
- Never rely on `char` signedness.

---

## 8. Comments

- `//` comments only. No `/* ... */` except for block-quoted SPDX/
  license headers.
- Public header declarations get a short Doxygen-style `///` comment
  explaining ownership and side effects.
- Inline comments explain **why**, not **what**. The code already
  says what.
- TODO comments use the format:
  ```cpp
  // TODO(handle): description of the work.
  ```
  where `handle` is a GitHub username or an issue number.

---

## 9. What `clang-format` will not fix

`clang-format` handles whitespace. It does **not**:

- Sort `#define` blocks into `inline constexpr`.
- Rename identifiers.
- Move files out of the monolithic `eth0.ino`.
- Catch global-variable drift.

These are review responsibilities.
