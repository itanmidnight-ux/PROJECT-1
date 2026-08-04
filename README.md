# CyberScope AI Security Platform

An intelligent, modular security auditing platform for Linux (including
Termux/Android). CyberScope detects what capabilities a system actually has
— WiFi, Bluetooth, network interfaces, SDR, root — and only offers the
audits that are technically possible on that host. It runs detection
modules, aggregates findings through a rule-based AI risk engine, and
produces professional JSON/HTML/Markdown reports.

CyberScope evolved from the standalone `ss7-security-framework` project.
That framework — SS7/SIGTRAN protocol modeling, HLR/VLR/MSC/SMSC
simulation, MAP/TCAP/SCCP analysis — is preserved in full and now lives as
the **Telecom Security module** inside this larger platform.

> Authorized use only. CyberScope performs detection, analysis, and
> reporting — it does not perform destructive or offensive actions
> (no deauth, no injection, no exploitation).

## Architecture

```
cyberscope/
├── main.py                  # interactive + CLI entry point
├── core/
│   ├── engine.py             # orchestrator: discovery → modules → AI → DB → reports
│   ├── discovery.py           # hardware/capability detection
│   ├── config.py               # config.yaml loading with defaults
│   └── types.py                 # Finding, ModuleResult, Severity, CapabilityInfo
├── modules/
│   ├── telecom/                # SS7 / SIGTRAN — the original framework
│   │   ├── ss7_engine.py
│   │   ├── protocols.py         # MAP / TCAP / SCCP / M3UA / SCTP / BER
│   │   ├── analyzer.py            # anomaly detection + findings
│   │   ├── simulator.py             # HLR / VLR / MSC / SMSC simulation
│   │   ├── device_telephony.py      # real device radio state (Termux:API / root / getprop)
│   │   └── monitor.py               # live subscriber-activity + device-radio registry
│   ├── wifi/
│   │   ├── scanner.py          # nmcli / iw / iwlist based scanning + analysis
│   │   └── monitor.py          # live scan registry + monitor-mode toggle
│   ├── bluetooth/
│   │   ├── scanner.py          # hciconfig / bluetoothctl based scanning + analysis
│   │   └── monitor.py          # live scan registry
│   ├── network/
│   │   ├── discovery.py        # interfaces, listening services, config
│   │   └── monitor.py          # live ARP/NDP host registry + port probe
│   └── device/system.py        # OS / CPU / kernel hardening checks
├── ai/
│   └── engine.py             # RiskEngine: scoring, attack surface, recommendations
├── ui/
│   └── live_view.py           # list → detail live TUI (rich.Live based)
├── reports/
│   └── generator.py          # JSON / HTML / Markdown report rendering
├── database/
│   └── db.py                  # SQLite persistence (sessions, findings, results)
├── config.yaml
├── requirements.txt
├── setup.sh
└── tests/
```

```
Telecom Security Module
        │
SS7 Analyzer
        │
Protocol Engine
        │
Reports
```

## Design principles

- **Modularity** — each technology (WiFi, Bluetooth, network, telecom,
  device) is an independent module behind a common `ModuleResult` contract.
- **Intelligence, not guesswork** — `core/discovery.py` probes real
  hardware (sysfs, `ip`, `iw`, `lsusb`, `/proc`) before anything is
  offered. Unavailable capabilities are reported as unavailable with a
  reason, never hidden or faked.
- **Detect → Analyze → Report** — no destructive or offensive actions.
- **Explainability** — every finding carries a description, evidence, and
  a concrete recommendation.

## Privilege detection (`core/permissions.py`)

CyberScope never assumes root — it probes for it, the same way on plain
Linux and Termux/Android:

1. Already root (`euid == 0`)?
2. Passwordless `sudo` available? (`sudo -n true` — this **never** prompts
   for a password; it just fails immediately if one would be required)
3. `su` already granted? (probed with stdin closed and a short timeout, so
   it can't hang waiting on a password — on a rooted/Magisk device that's
   already granted access it returns instantly)
4. Termux's `tsu` wrapper present?

None of this escalates anything — it only reports what's *already*
possible, so modules that need elevated access (like WiFi monitor mode)
know whether to offer it. The result is exposed as `caps.privileges` and
shown in the capabilities table on startup.

## Capabilities file

Every run writes the complete discovery + privilege result to
`logs/capabilities.json` (path configurable under `discovery:` in
`config.yaml`) — OS info, every interface, WiFi/Bluetooth/SDR status and
reasons, monitor-mode support, and the privilege probe. This is the
device's capability record: what CyberScope found, and why anything
unavailable is unavailable.

## Live monitor mode (every module with something to list)

The menu has one entry per module that has a natural list of "devices" to
watch — **Network**, **WiFi**, **Bluetooth**, and **Telecom/SS7** — each
gated by capability so it only appears when the device can actually do
it. Picking one does both halves in sequence, not two separate menu
items: first the static scan (so its findings still feed the AI risk
engine, `Generar reporte`, and audit history), then a progress bar while
the live detection engine starts, then an auto-refreshing, numbered list
of what's actually there:

| Module | List shows | Detail view adds |
|---|---|---|
| **Network** | IP, MAC, ARP state, times seen (from the kernel neighbor table — read-only, no packets sent) | ICMP reachability + a short, non-destructive TCP connect check of common ports |
| **WiFi** | SSID, BSSID, signal, channel, security | first/last seen, times seen |
| **Bluetooth** | name, address, classic/BLE, times seen | first/last seen, times seen |
| **Telecom/SS7** | source (📱 real device / 🧪 lab sim), id, event count, alert flag — see below | operator/radio fields for the device row; roaming/LAC/last-op for lab subscribers |

Typing a number "locks" onto that one item — a live-updating detail panel
takes over showing every known field, plus the result of an automatic
**non-destructive security probe** scoped to that single item (the same
defensive analysis the one-shot scanner already runs — no connection
attempt, no pairing, no exploitation, no payloads). Press `q` at any point
to back out.

For WiFi, if root/privileged access is available *and* the adapter's
driver advertises monitor-mode support (checked via `iw list`), CyberScope
can reversibly switch the interface into monitor mode for the session
(`modules/wifi/monitor.py::MonitorModeSession`) and always restores it to
managed mode on exit. Without root or driver support, it falls back to
active scanning automatically — the header always shows which mode is in
effect.

### Telecom/SS7 live monitor — two clearly-labeled sources

The Telecom/SS7 live monitor is always available, the same way the
one-shot telecom scan is, and combines two data sources that are never
mixed together or mistaken for one another:

- **📱 Device (real)** — the actual cellular state of the device
  CyberScope is running on, via `modules/telecom/device_telephony.py`.
  Tried in order of how much access each needs, degrading gracefully
  (a source that isn't reachable is simply skipped, never faked):
  1. **Termux:API** (`pkg install termux-api` + the companion app) —
     `termux-telephony-info` / `termux-telephony-cellinfo`. No root
     needed beyond the one-time Android permission grant.
  2. **Root** — `su -c "dumpsys telephony.registry"` on a rooted
     device/Termux (e.g. Magisk). Best-effort text parsing since the
     format varies by Android version.
  3. **`getprop gsm.*`** — a handful of read-only properties available
     without any special permission on most Android builds.

  When reachable, it's pinned first in the list and refreshed live each
  cycle (operator, network type, serving cell, signal). Its security
  probe flags real, well-known mobile-security issues: registration on
  a legacy 2G/GSM-class network (no mutual authentication — the
  precondition for fake base station / IMSI-catcher attacks) and weak
  signal that could push a fallback to a less secure network.

- **🧪 Lab (simulado)** — the module's own laboratory simulator (no real
  SIGTRAN/operator connectivity). A background generator drives
  realistic synthetic subscriber activity — SendRoutingInfo,
  UpdateLocation, occasional InsertSubscriberData attempts — against
  the same HLR/VLR/SMSC handlers real MAP traffic would hit. The HLR
  rejects and flags ISD attempts exactly like a real network element
  would, and that's what the security probe surfaces per subscriber.

To analyze *real captured* SS7 traffic (a PCAP from a SIGTRAN link),
feed it through the existing `SS7Analyzer` (`modules/telecom/analyzer.py`)
directly.

## Quick start

```bash
./setup.sh                  # detects env (Termux/Debian/Arch/Alpine), installs deps, runs tests
python3 main.py              # interactive menu
python3 main.py --auto       # full auto-audit of all available modules
python3 main.py --module wifi --report html
```

## Modules

| Module | Detects | Notes |
|---|---|---|
| **Network** | interfaces, listening services, promisc mode | via `ip`, `/proc/net` |
| **WiFi** | nearby networks, security type, channel, signal | via `nmcli`/`iw`/`iwlist`; passive by default |
| **Bluetooth** | adapters, nearby devices, BLE, discoverability | via sysfs, `hciconfig`, `bluetoothctl` |
| **Device** | OS/kernel info, CPU, ASLR, firewall presence | via `/proc`, `/sys`, `sysctl` |
| **Telecom/SS7** | MAP/TCAP/SCCP anomalies, SRI/ISD abuse, PCAP analysis | simulator always available; PCAP analysis when a capture is supplied |
| **SDR** | RTL-SDR / HackRF / LimeSDR presence | reported unavailable when no compatible USB hardware is found |

## AI Risk Engine (`ai/engine.py`)

Aggregates findings from every module that ran into:

- an overall **risk score** (0–100) and level (INFO → CRITICAL) with a
  confidence rating based on how many modules contributed,
- a mapped **attack surface** (wireless / Bluetooth / network / telecom /
  exposed services),
- a prioritized, **actionable recommendation list**,
- an executive summary.

## Reports (`reports/generator.py`)

Every audit can be exported as:

- **JSON** — full machine-readable record (`meta`, `ai_analysis`, `module_results`)
- **HTML** — dark-themed report with severity-colored findings table
- **Markdown** — findings table + per-finding evidence/recommendation detail

Reports are written to `reports/` (configurable via `config.yaml`) and are
not committed to version control.

## Database

Audit sessions, findings, and per-module results are persisted to SQLite
(`database/cyberscope.db`) so `python3 main.py` → option 8 can show audit
history and cumulative statistics across runs.

## Testing

```bash
python3 -m pytest tests/ -q
```

Covers core types, discovery, every module's parsing/analysis logic, the
AI risk engine, report generation, and the database layer.
