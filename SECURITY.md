# Security Policy

## Authorized use only

eth0 is an **offensive network-security tool**. It can capture traffic,
inject crafted frames, poison ARP caches, spoof DNS responses, starve
DHCP pools, kill TCP connections, tunnel data over DNS, and perform
other actions that are disruptive, detectable, and in most
jurisdictions illegal to run against networks you do not own or are
not explicitly authorized to test.

**By building, flashing, or running this firmware you represent that:**

1. You own the network you are testing, **or**
2. You have **written authorization** from the network's owner
   (for example a penetration-testing engagement letter, red-team
   rules of engagement, or an employment agreement covering internal
   testing), **and**
3. Your use complies with all applicable laws in your jurisdiction
   (in the United States: the Computer Fraud and Abuse Act, Wiretap
   Act, state computer-crime statutes; in the EU: national
   implementations of Directive 2013/40/EU; equivalents elsewhere).

The maintainers and contributors of eth0 accept **no liability** for
damages, legal or otherwise, arising from misuse of this software.
See the `LICENSE` file for the full disclaimer.

## Supported versions

Only the latest tagged release receives security fixes. Pre-release
firmware from `main` is provided as-is.

| Version | Supported |
|---------|-----------|
| latest release | yes |
| older releases | no  |
| `main`         | best-effort |

## Reporting a vulnerability

If you discover a vulnerability **in eth0 itself** (for example a
stack overflow in the packet parsers, an authentication bypass in the
IRC server, a flaw in the AES tunnel, an attack against the web UI's
serial protocol), please report it privately.

**Do not open a public issue.**

### How to report

1. Use GitHub's private vulnerability reporting:
   <https://github.com/0x4133/eth0/security/advisories/new>
2. Include:
   - A clear description of the vulnerability.
   - Reproduction steps or a proof-of-concept.
   - The affected firmware commit or tag.
   - The attack prerequisites (network access, physical access, etc.).
   - Your suggested severity and impact assessment.

### What to expect

- Acknowledgement within **5 business days**.
- An initial triage and severity assessment within **14 days**.
- A coordinated fix and disclosure timeline — typically 60–90 days
  depending on complexity.
- Credit in the `CHANGELOG.md` and release notes (unless you prefer
  to remain anonymous).

## Out of scope

The following are **not** considered security vulnerabilities in eth0:

- The ability of eth0 to observe, inject, or manipulate traffic on a
  network you have given it access to. That is the stated purpose of
  the tool.
- Weaknesses in protocols eth0 implements faithfully (for example the
  fact that ARP has no authentication).
- Issues in third-party libraries listed in `NOTICE` — please report
  those upstream.
- Running eth0 on a network without authorization. That is a misuse
  issue, not a vulnerability.

## Defensive use

If you are a defender and you have detected eth0 on your network,
please treat it exactly as you would any unknown offensive tool:
isolate the device, preserve evidence, and investigate through your
normal incident-response channels. The maintainers are happy to
answer questions about detection signatures via the reporting
channel above.
