<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Aether-U — UWB / RTLS Penetration Test Orchestrator

> [!CAUTION]
> **Under Development — Untested.** This tool has not been validated in production engagements. Features may be incomplete, unstable, or produce unreliable results. Do not rely on its output for deliverables without independent verification.

**Version:** 1.0.0
**Part of the Aether family** | Integrates with Spectre via protocol tokens

---

## Overview

Aether-U is an automated penetration testing orchestrator targeting Ultra-Wideband (UWB) and Real-Time Location System (RTLS) infrastructure. It covers the full attack surface of enterprise UWB deployments, from physical-layer ranging manipulation through to web application vulnerabilities in RTLS management consoles.

UWB (IEEE 802.15.4z) is a radio technology used for centimetre-accurate positioning in:
- **Industrial RTLS** — personnel and asset tracking in manufacturing, logistics, and healthcare (Sewio, Pozyx, Avalue RTLS systems)
- **Access control** — CCC Digital Key (car keys, building entry) on iOS/Android devices
- **Contact tracing and indoor navigation**

### Ghost Peak Attack

The most significant UWB-specific threat is the **Ghost Peak** attack, published in 2022 by Jansen and Leu. It is a physical-layer distance reduction attack that works against IEEE 802.15.4z HRP UWB devices operating in SP0 mode (no STS integrity protection):

1. The attacker positions RF hardware within range of the target UWB ranging session
2. A forged early leading pulse is injected into the Two-Way Ranging (TWR) exchange
3. The victim receiver latches onto the attacker-injected pulse rather than the authentic signal
4. The measured distance is reported as shorter than the true physical separation — by centimetres to several metres
5. **No cryptography is broken** — the attack manipulates the physical timing measurement before any authentication layer

Affected hardware: DW1000 and DW3000 chip families from Qorvo (formerly DecaWave). Mitigation requires IEEE 802.15.4z STS SP3 mode enforcement via firmware update.

---

## Target Platforms

| Platform | Management Interface | Default Port | Protocol |
|---|---|---|---|
| **Sewio RTLS Studio** | Web + REST API | 443/80 | HTTPS / MQTT |
| **Pozyx Creator** | Web + REST API | 443/80 | HTTPS / MQTT |
| **Avalue RTLS Manager** | Web + CGI | 443/80 | HTTPS / MQTT |
| **Generic RTLS** | Web + REST API | 443/80/8080 | HTTPS / MQTT / CoAP |

---

## Prerequisites

### Network Access
- Ethernet or Wi-Fi connectivity to the RTLS management VLAN
- Direct IP reachability to the RTLS management console and MQTT broker

### Software (installed automatically by `install.py`)
- `nmap` — port scanning and service version detection
- `tshark` — network packet capture
- `mosquitto-clients` — MQTT subscribe/publish (`mosquitto_sub`, `mosquitto_pub`)
- `sqlmap` — SQL injection testing
- `curl` — HTTP/REST API interaction
- `python3` — runtime (3.8+)
- `paho-mqtt` — optional Python MQTT library

### Hardware (optional — physical_attacks phase only)
- **HackRF One** or equivalent SDR with UWB-capable frontend (for `physical_attacks` phase)
- **DWM3000EVB** evaluation board with custom firmware (for full Ghost Peak demonstration)
- GNU Radio + gr-osmosdr for SDR signal processing

> Physical attack testing requires explicit written authorisation from the client for RF transmission in the target environment.

---

## Installation

```bash
# Clone or copy Aether-U to /Users/pr0t31n/Aether-U/
# Then install dependencies:

sudo python3 install.py

# Dry-run (no changes):
python3 install.py --check

# Skip system packages (if already installed):
sudo python3 install.py --skip-apt

# Skip GNU Radio / SDR tools:
sudo python3 install.py --skip-git
```

---

## Phases

| # | Phase Name | Key | Description | Auth Required |
|---|---|---|---|---|
| 1 | `survey` | `survey` | nmap discovery, platform detection, default credential testing, REST API anchor/tag enumeration | None |
| 2 | `protocol_analysis` | `protocol_analysis` | Passive MQTT capture, unauthenticated broker test, position data parsing, tshark capture | None (passive) |
| 3 | `active_interaction` | `active_interaction` | MQTT injection, API unauthenticated endpoint scan, SQLi (sqlmap), XSS in tag labels, IDOR testing | `active_testing_authorized: true` |
| 4 | `physical_attacks` | `physical_attacks` | Ghost Peak susceptibility assessment, firmware version check via API, OTA firmware endpoint detection, physical frame injection documentation | `physical_access: true` (injection also needs `injection_authorized: true`) |
| 5 | `network_app` | `network_app` | JWT/session token analysis, HTTP vs HTTPS check, full API enumeration, MQTT broker version disclosure, cleartext credential detection | None |

---

## Findings Catalogue

| ID | Title | Severity | CVSS |
|---|---|---|---|
| AETHU-001 | Ghost Peak Distance Reduction Attack | CRITICAL | 9.2 |
| AETHU-002 | RTLS Management Console Default Credentials | CRITICAL | 9.8 |
| AETHU-003 | Unauthenticated MQTT Broker | HIGH | 8.6 |
| AETHU-004 | RTLS Position Data Injection via MQTT | HIGH | 8.1 |
| AETHU-005 | SQL Injection in RTLS Reporting Module | HIGH | 8.5 |
| AETHU-006 | Unauthenticated RTLS REST API Endpoints | HIGH | 7.5 |
| AETHU-007 | UWB STS Key Weakness | HIGH | 7.8 |
| AETHU-008 | Cleartext UWB Ranging Exchange | MEDIUM | 6.5 |
| AETHU-009 | RTLS Anchor Firmware Update Without Signature Verification | HIGH | 7.9 |
| AETHU-010 | MQTT Cleartext Credential Transmission | MEDIUM | 6.8 |
| AETHU-011 | RTLS Zone Boundary Bypass | HIGH | 7.6 |
| AETHU-012 | Anchor RF Flooding / Denial of Service | MEDIUM | 5.8 |
| AETHU-013 | RTLS Cross-Site Scripting (XSS) in Dashboard | MEDIUM | 6.1 |
| AETHU-014 | Insecure Direct Object Reference in RTLS API | MEDIUM | 6.5 |
| AETHU-015 | Physical UWB Frame Injection | HIGH | 7.4 |

---

## Usage

### Full assessment

```bash
python3 aether_u.py --config config.json --project /tmp/rtls_audit
```

### Single phase

```bash
python3 aether_u.py --phase survey --config config.json --project /tmp/output
python3 aether_u.py --phase protocol_analysis --config config.json
python3 aether_u.py --phase network_app --config config.json --project /tmp/output
```

### List phases

```bash
python3 aether_u.py --list-phases
```

### Spectre managed mode

```bash
SPECTRE_MANAGED=1 python3 aether_u.py --config config.json --project /tmp/rtls_audit
```

In managed mode all output is prefixed with protocol tokens (`__SPECTRE_LOG__`, `__SPECTRE_FINDING__`, etc.) for consumption by the Spectre frontend.

---

## Configuration Reference

Edit `config.json` before running an assessment. All fields are optional — only `rtls_host` is required for network phases.

| Field | Type | Default | Description |
|---|---|---|---|
| `rtls_host` | string | `""` | IP or hostname of the RTLS management console |
| `rtls_port` | int | `443` | RTLS management port (443=HTTPS, 80=HTTP) |
| `rtls_platform` | string | `"sewio"` | Platform hint: `sewio`, `pozyx`, `avalue`, `generic` |
| `mqtt_host` | string | `""` | MQTT broker host (defaults to `rtls_host` if empty) |
| `mqtt_port` | int | `1883` | MQTT broker port (1883=plain, 8883=TLS) |
| `mqtt_topics` | array | `["#"]` | MQTT topics to subscribe to during protocol analysis |
| `target_anchors` | array | `[]` | Anchor IDs in scope (empty = all) |
| `target_tags` | array | `[]` | Tag IDs in scope (empty = all) |
| `gnuradio_device` | string | `"driver=hackrf"` | GNU Radio device string for SDR |
| `uwb_channel` | int | `5` | UWB channel number (1–9, as per IEEE 802.15.4z) |
| `uwb_prf` | int | `64` | UWB pulse repetition frequency in MHz (16 or 64) |
| `timeout_per_phase` | int | `300` | Max seconds per phase |
| `capture_duration` | int | `1800` | MQTT/tshark capture window in seconds |
| `phases.*` | bool | varies | Enable/disable individual phases |
| `credentials.username` | string | `"admin"` | RTLS console username for API testing |
| `credentials.password` | string | `"admin"` | RTLS console password for API testing |
| `scope.hosts` | array | `[]` | IP/host allowlist for testing (empty = all configured hosts) |
| `scope.eui64s` | array | `[]` | UWB device EUI-64 allowlist (empty = all) |
| `output_dir` | string | `"aether_u_output"` | Default output directory |
| `physical_access` | bool | `false` | Enables physical RF attack tests |
| `injection_authorized` | bool | `false` | Enables RF/MQTT injection tests |
| `dos_authorized` | bool | `false` | Enables DoS/RF flooding assessment |
| `active_testing_authorized` | bool | `false` | Enables active API testing, SQLi, XSS |

### Example configuration (Sewio RTLS Studio)

```json
{
  "rtls_host": "192.168.100.10",
  "rtls_port": 443,
  "rtls_platform": "sewio",
  "mqtt_host": "192.168.100.10",
  "mqtt_port": 1883,
  "timeout_per_phase": 300,
  "capture_duration": 600,
  "credentials": {
    "username": "admin",
    "password": "admin"
  },
  "scope": {
    "hosts": ["192.168.100.10"],
    "eui64s": []
  },
  "active_testing_authorized": true,
  "physical_access": false,
  "injection_authorized": false,
  "dos_authorized": false
}
```

---

## Output

All phase outputs are saved to the project directory:

```
aether_u_output/
├── run_meta.json                     # Assessment metadata
├── findings_spectre.json             # All findings (Spectre-compatible)
├── survey/
│   ├── nmap_*.xml / *.txt            # Port scan results
│   ├── survey_capture.pcap           # Passive tshark capture
│   ├── default_creds.json            # Default credential findings
│   ├── platform.txt                  # Detected RTLS platform
│   └── api_enum.json                 # REST API enumeration
├── protocol_analysis/
│   ├── mqtt_unauth_test.txt          # Unauthenticated MQTT test result
│   ├── mqtt_capture.txt              # Full MQTT message capture
│   ├── mqtt_analysis.json            # Parsed tags, anchors, zones
│   └── uwb_gateway_capture.pcap      # UWB gateway traffic
├── active_interaction/
│   ├── mqtt_injection.json           # Injection test results
│   ├── api_unauth.json               # Unauthenticated API endpoints
│   ├── sqlmap/                       # sqlmap output directory
│   ├── xss_results.json              # XSS test results
│   └── idor_results.json             # IDOR test results
├── physical_attacks/
│   ├── ghost_peak_assessment.json    # Ghost Peak susceptibility
│   ├── firmware_endpoints.json       # OTA update endpoints
│   ├── sts_config.json               # UWB STS configuration
│   └── physical_injection_report.txt # Frame injection documentation
└── network_app/
    ├── jwt_analysis.json             # JWT/token findings
    ├── cleartext_http.txt            # HTTP exposure
    ├── api_enumeration.json          # Full API path enumeration
    ├── mqtt_sys_topics.txt           # MQTT $SYS topics / version
    └── mqtt_cleartext.txt            # Cleartext credential finding
```

---

## Spectre Integration

Aether-U emits protocol tokens to stdout when `SPECTRE_MANAGED=1` is set. The Spectre frontend listens for these tokens and renders findings, status updates, and prompts in the Spectre UI.

| Token | Purpose |
|---|---|
| `__SPECTRE_LOG__ <message>` | Informational log line |
| `__SPECTRE_ERR__ <message>` | Error message |
| `__SPECTRE_STATUS__ <json>` | Phase status update with `phase`, `status`, `step`, `ts` |
| `__SPECTRE_FINDING__ <json>` | Finding record with full catalogue entry data |
| `__SPECTRE_PROMPT__ <message>` | User prompt (suppressed in managed mode) |

Finding records emitted via `__SPECTRE_FINDING__` include the full finding entry from `findings_catalogue.json` plus `data`, `output_file`, and `ts` fields.

---

## Legal Disclaimer

Aether-U is a professional penetration testing tool. Use is restricted to:
- Systems you own, or
- Systems for which you have explicit written authorisation from the system owner

Unauthorised use against UWB/RTLS infrastructure may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, GDPR (interception of location data), and equivalent laws in your jurisdiction.

RF transmission tests (Ghost Peak, frame injection, RF flooding) require:
- Written client authorisation specifically covering RF transmission
- Compliance with applicable radio frequency regulations (FCC Part 15 in the US, ETSI in Europe)
- Coordination with site safety personnel in industrial environments where UWB is used for safety interlocks

The authors accept no liability for misuse of this tool.
