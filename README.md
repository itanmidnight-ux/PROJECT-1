<div align="center">

# 🛡️ CyberScope AI Security Platform

**Intelligent, modular WiFi security auditing with a guided 3-phase pentest engine**

`v2.0.0` · Linux · Kali / Debian / Arch / Alpine / Termux (Android)

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Termux-006E74?style=for-the-badge&logo=linux&logoColor=white)](#)
[![License](https://img.shields.io/badge/License-Authorized%20Use%20Only-CC0000?style=for-the-badge)](#-authorized-use--disclaimer)
[![CLI](https://img.shields.io/badge/CLI-Full-0A7EA4?style=for-the-badge&logo=gnubash&logoColor=white)](#-command-line-interface)

</div>

---

CyberScope is a **capability-aware WiFi security auditing platform**. It first
probes the real hardware and privileges of the host — and only then offers the
audits that are technically possible on that machine. Its flagship feature is a
guided **3-phase attack pipeline** (Attack → Recon → Report) that chains real
WiFi attack techniques — PMKID capture, WPS attacks, deauthentication + 4-way
handshake capture, and offline cracking — into a single, cleanly gated workflow,
and documents everything in a professional report.

> ⚠️ **Authorized use only.** This tool performs security assessments that must
> only be run against **networks you own or are explicitly authorized to test**.
> Unauthorized access to networks is illegal in most jurisdictions. See
> [Authorized use & disclaimer](#-authorized-use--disclaimer).

---

## ✨ Highlights

- 🔎 **Capability-aware** — detects interfaces, monitor-mode support and
  privilege level before offering anything, and never fakes an unavailable
  capability.
- 🎯 **Guided 3-phase pentest** — *Phase 1: Attack & Access → Phase 2:
  Internal Recon → Phase 3: Report*, with strict phase gating (Phase 2 only
  runs if Phase 1 succeeded).
- 🔒 **Safe by default** — active attacks that require monitor mode (PMKID,
  WPS, deauth) are **opt-in**; a clear warning is shown because switching to
  monitor mode disconnects the current WiFi connection.
- ♻️ **Capture reuse** — existing handshake/PMKID captures on disk are found
  and cracked offline first, with no network risk.
- 🧠 **AI risk engine** — aggregates every finding into a 0–100 risk score,
  attack-surface mapping, executive summary and prioritized recommendations.
- 🧾 **Professional reports** — Markdown, JSON and HTML output, including a
  dedicated phased-audit report.
- ⚙️ **Auto-configuration** — verifies and reports WiFi tooling and
  monitor-mode readiness without ever disconnecting your network.

---

## 📦 Features

| Area | What it does |
|------|--------------|
| **WiFi scanning** | Nearby networks: SSID, BSSID, channel, band, signal, security type; risk-tagged |
| **Live monitoring** | Auto-refreshing network registry with per-AP detail views |
| **PMKID attack** | Captures the PMKID via `hcxdumptool`, converts with `hcxpcapngtool`, cracks with `hashcat` (mode 22000, legacy 16800 auto-converted) |
| **WPS attack** | Pixie-Dust + brute-force PIN recovery via `reaver` / `wpspin` |
| **Deauth + handshake** | Deauthenticates clients with `aireplay-ng` while `airodump-ng` captures the 4-way handshake |
| **Offline cracking** | `aircrack-ng` (CPU) or `hashcat` (GPU) dictionary attacks against captured material |
| **Internal recon** | `nmap` host discovery + top-ports service scan across the connected subnet |
| **Auto-config** | Validates tools and monitor-mode readiness; installs missing packages |
| **Reporting** | Markdown / JSON / HTML reports + dedicated phased-audit Markdown report |

---

## 🏗️ Architecture

```
cyberscope-ai-security/
├── main.py                     # interactive menu + CLI entry point
├── setup.sh                    # cross-platform installer (Termux/Debian/Arch/Alpine)
├── config.yaml                 # configuration (interfaces, paths, scan options)
├── requirements.txt
│
├── core/                       # framework layer
│   ├── engine.py               # orchestrator: discovery → modules → AI → reports
│   ├── discovery.py            # hardware / capability detection
│   ├── permissions.py          # root / sudo / su / tsu privilege probing
│   ├── shell.py                # single, never-raising subprocess layer
│   ├── auto_config.py          # WiFi auto-configuration actions
│   ├── types.py                # Finding, ModuleResult, Severity, CapabilityInfo
│   ├── config.py               # config.yaml loader
│   ├── event_bus.py            # in-process pub/sub
│   ├── asset_manager.py        # persisted asset knowledge base
│   ├── net_vendor.py           # IEEE-802 MAC classification + OUI vendors
│   └── authorization.py        # authorized-use guardrails
│
├── modules/
│   ├── wifi/
│   │   ├── scanner.py          # nmcli / iw based scanning + analysis
│   │   └── monitor.py          # live scan registry + monitor-mode session
│   └── pentest/                # ← the 3-phase attack engine
│       ├── phased_attack.py    # orchestrator + Phase 1/2/3 integration
│       ├── wifi_attack.py      # PMKID / WPS / deauth / crack / enum primitives
│       └── wpa_capture.py      # capture-format handling
│
├── ai/
│   └── engine.py               # RiskEngine: scoring, attack surface, recommendations
├── ui/
│   └── live_view.py            # live TUI (rich.Live based)
├── reports/
│   └── generator.py            # Markdown / JSON / HTML rendering
├── tests/                      # pytest suite
├── reports/                    # generated reports (not committed)
└── database/                   # SQLite persistence
```

---

## 🎯 The 3-Phase Attack Pipeline

The targeted-attack engine is the core of CyberScope. It is fully **phase-gated**:
a phase only runs if the one before it succeeded, so no step is attempted on an
invalid precondition.

```
                    ┌─────────────────────────────────────────────┐
                    │        TARGETED ATTACK SELECTED            │
                    │  BSSID · Channel · SSID · Wordlist          │
                    └──────────────────┬──────────────────────────┘
                                       │
              ┌────────────────────────▼─────────────────────────┐
              │  ⚠️ MONITOR-MODE CHECK (opt-in)                  │
              │  Active attacks need monitor mode, which         │
              │  DISCONNECTS the current WiFi connection.        │
              │  [s] enable   |   [N] passive/offline only       │
              └────────────────────────┬─────────────────────────┘
                                       │
              ┌────────────────────────▼─────────────────────────┐
              │  PHASE 1 · ATTACK & ACCESS                       │
              │  1. Reuse existing captures on disk (offline)    │
              │     - crack handshake (aircrack-ng)              │
              │     - crack PMKID   (hashcat mode 22000/16800)   │
              │  2. If monitor enabled, active attacks:          │
              │     PMKID → WPS → DEAUTH+handshake               │
              │  3. Crack any newly captured material            │
              └───────────────┬─────────────────────────────────┘
                              │ success?
              ┌───────────────▼──────────────┐        ┌─────────────┐
              │ YES → creds obtained         │        │ NO → stopped│
              │        ▼                     │        │  cleanly    │
              │  PHASE 2 · INTERNAL RECON    │        └──────┬──────┘
              │  (only if Phase 1 succeeded) │               │
              │  - confirm connection (IP)   │               │
              │  - nmap host discovery       │               │
              │  - top-ports service scan    │               │
              │        ▼                     │               │
              │  PHASE 3 · REPORT            │◄──────────────┘
              │  - always generated          │
              └──────────────────────────────┘
```

### Phase 1 — Attack & Access

Strategically ordered to get credentials with minimal noise:

1. **Offline capture reuse** — searches `/tmp/cyberscope_*` for existing
   handshake (`.cap`) and PMKID (`.16800` / `.22000` / `.hccapx`) captures for
   the **exact target BSSID** and cracks them immediately. No network risk.
2. **PMKID** — attacks the AP directly (no client needed) using
   `hcxdumptool`, converts the capture with `hcxpcapngtool` to hashcat format
   and cracks it (`hashcat -m 22000`; legacy `16800` files are auto-converted).
3. **WPS** — Pixie-Dust first (seconds), falling back to PIN brute force,
   via `reaver`.
4. **Deauth + handshake** — deauthenticates clients with `aireplay-ng` while
   `airodump-ng` captures the WPA 4-way handshake, then cracks it offline.

### Phase 2 — Internal Recon

Runs **only if Phase 1 succeeded**. Waits for the interface to obtain an IP,
normalizes the subnet (e.g. `192.168.1.0/24`), performs an `nmap` host
discovery sweep and a bounded top-ports service scan per host.

### Phase 3 — Report

Always generated. Produces a professional Markdown report covering both
succeeded and failed phases, every attack attempt, discovered devices and any
vulnerabilities.

---

## 🚀 Installation

### Option A — Automated installer (recommended)

```bash
git clone https://github.com/itanmidnight-ux/PROJECT-1.git
cd PROJECT-1
./setup.sh        # detects environment, installs deps, runs tests
```

### Option B — Manual (Debian / Kali)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip \
    aircrack-ng hcxtools reaver hashcat nmap iw \
    wireless-tools wpasupplicant
pip3 install -r requirements.txt
```

### Option C — Termux (Android)

```bash
pkg install -y python python-pip aircrack-ng hcxtools reaver hashcat nmap iw
pip install -r requirements.txt
```

### Required external tools

| Tool | Purpose | Used by |
|------|---------|---------|
| `nmcli` / `iw` / `iwlist` | Scanning, interface info | Scan, monitor |
| `airodump-ng` / `aireplay-ng` / `aircrack-ng` | Handshake capture & crack | Phase 1 |
| `airmon-ng` | Monitor-mode switching | Phase 1 (active) |
| `hcxdumptool` / `hcxpcapngtool` | PMKID capture & conversion | Phase 1 |
| `reaver` / `wash` | WPS attacks | Phase 1 |
| `hashcat` | GPU/high-speed cracking | Phase 1 |
| `nmap` | Network discovery | Phase 2 |

> Missing tools are detected at audit start and an automatic `apt-get`
> install is attempted. Unavailable optional tools degrade gracefully.

---

## 🖥️ Usage

### Interactive menu

```bash
python3 main.py
```

```
┌────────── CyberScope WiFi — Main Menu ──────────┐
│ 1  Scan Networks                                 │
│ 2  Monitor Networks (live)                       │
│ 3  Full Auto-Audit                               │
│ 4  Targeted Attack   ← 3-phase pentest engine    │
│ 5  Auto-Configuration                            │
│ 6  Generate Report                               │
│ q  Quit                                          │
└──────────────────────────────────────────────────┘
```

The **Targeted Attack** flow walks you through:

1. Network selection from the live scan table.
2. Attack selection (`pmkid`, `deauth`, `wps`, `crack`, `enum`, or all).
3. The **monitor-mode confirmation** panel (opt-in, disconnects WiFi).
4. Phase 1 → Phase 2 → Phase 3 execution with live progress.
5. A rich summary panel with per-phase results and attack-attempt table.

### Command-line interface

```bash
# Full auto-audit of all available capabilities
python3 main.py --auto

# Scan nearby WiFi networks
python3 main.py --scan

# Live-monitor networks for 30s
python3 main.py --monitor --duration 30

# Targeted 3-phase attack (interactive network/attack selection)
python3 main.py --attack

# Targeted attack, non-interactive
python3 main.py --attack \
    --target "64:58:AD:88:9B:0B,8,ADC-cac7" \
    --attacks "pmkid,crack" \
    --wordlist /usr/share/wordlists/rockyou.txt

# Auto-configuration (tooling + monitor readiness check)
python3 main.py --autoconfig

# Generate reports from the last audit
python3 main.py --report all
```

#### CLI reference

| Flag | Description |
|------|-------------|
| `--config, -c` | Path to `config.yaml` |
| `--auto, -a` | Run a full auto-audit |
| `--scan, -s` | Scan WiFi networks |
| `--monitor, -m` | Live-monitor networks |
| `--duration, -d` | Monitor duration in seconds (default `30`) |
| `--attack` | Launch the targeted 3-phase attack |
| `--target, -t` | `BSSID,CHANNEL,SSID` (comma-separated) |
| `--attacks` | Comma-separated: `pmkid,deauth,wps,crack,enum` |
| `--wordlist, -w` | Custom wordlist path |
| `--autoconfig` | Run intelligent auto-configuration |
| `--report, -r` | `json` / `markdown` / `all` |
| `--interface, -i` | WiFi interface override |
| `--verbose, -v` | Debug logging |

---

## 🛠️ Safety & Monitor Mode

WiFi attacks fall into two categories:

- **Passive / offline** (always safe) — scanning, capture reuse, offline
  cracking, internal recon. These never touch the airwaves and never
  disconnect you.
- **Active** (monitor mode required) — PMKID capture, WPS, deauth + handshake.
  These switch the interface to monitor mode, which **disconnects it from the
  current network**.

Because CyberScope must not silently cut your connection, active attacks are
**always opt-in**:

- A clear warning panel explains that a single-adapter machine will lose its
  WiFi connection and that a **second USB adapter with monitor + injection
  support** (Atheros / Ralink chipsets are typical) is recommended.
- With **one adapter**: the interface disconnects for the duration of the
  attack, then monitor mode is disabled and you reconnect manually — Phase 2
  waits for you to confirm connectivity before running.
- With **two adapters**: keep one connected (managed mode) and dedicate the
  second to monitor mode.

> CyberScope **never** enables monitor mode automatically — not in the
> auto-configurator, and not without an explicit confirmation in the attack
> flow.

---

## 🔐 Authorized Use & Disclaimer

CyberScope is a **security assessment tool**. Use it only on networks for
which you hold **explicit written authorization**. Unauthorized scanning,
capturing, or attacking of wireless networks may violate local laws
(computer-misuse and wiretap statutes in most jurisdictions).

- The authors provide this software for **educational and authorized
  penetration-testing purposes only**.
- You are solely responsible for ensuring your use complies with all
  applicable laws and regulations.
- No warranty is provided, express or implied; the tool is provided "as is".

---

## 🧪 Testing

```bash
python3 -m pytest tests/ -q
```

The suite covers core types, discovery, scanning/parsing, the pentest attack
primitives, the phased-audit gating logic, the AI risk engine and report
generation.

---

## 🗂️ Configuration

`config.yaml` controls interfaces, scan options, report output paths and
discovery settings. The most commonly used knobs:

- `wifi:` — default interface, scan duration, channel behavior.
- `reports:` — output directory (`reports/` by default).
- `discovery:` — capabilities JSON output path.

Reports are written to `reports/` and are **not** committed to version
control.

---

## 📄 License

**Authorized use only.** This project is provided for legal, authorized
security testing and education. Redistribution requires retaining this notice
and the authorized-use disclaimer above.
