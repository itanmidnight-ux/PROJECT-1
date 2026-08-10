"""
CyberScope — modules/wifi/scanner.py

Real WiFi scanning via:
  1. nmcli dev wifi list     (NetworkManager, no root)
  2. iw dev <iface> scan     (requires root / CAP_NET_ADMIN)
  3. iwlist <iface> scan     (older systems, often no root)
  4. /proc/net/wireless      (passive, statistics only)

Defensive analysis only — no injection, no deauth.
"""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.types import CapabilityInfo, Finding, ModuleResult, ModuleStatus, Severity
from core.shell import run as _shell_run
from core.shell import safe_iterdir as _safe_iterdir
from core.net_vendor import classify_mac


def _run(cmd: List[str], timeout: int = 15) -> tuple[int, str]:
    r = _shell_run(cmd, timeout)
    return r.returncode, (r.stderr if r.returncode == -1 and not r.stdout else r.combined)


# ── Network model ─────────────────────────────────────────────────────────────

@dataclass
class WiFiNetwork:
    ssid:      str
    bssid:     str     = ""
    channel:   int     = 0
    frequency: float   = 0.0   # GHz
    signal:    int     = -100  # dBm
    security:  str     = "UNKNOWN"
    mode:      str     = "infrastructure"
    vendor:    str     = ""

    def __post_init__(self) -> None:
        # BSSID is the AP's MAC -- derive vendor once, here, so every
        # construction path (nmcli/iw/iwlist parsing) gets it for free.
        if not self.vendor and self.bssid:
            self.vendor = classify_mac(self.bssid).label

    @property
    def security_level(self) -> str:
        s = self.security.upper()
        if "WPA3" in s:  return "STRONG"
        if "WPA2" in s:  return "GOOD"
        if "WPA" in s:   return "WEAK"
        if "WEP" in s:   return "BROKEN"
        if "OPEN" in s or not s or s == "UNKNOWN": return "OPEN"
        return "UNKNOWN"

    @property
    def risk_level(self) -> str:
        """Severity-string equivalent of security_level -- the single
        source of truth other layers (asset manager, live monitor UI)
        map a network's security posture to a risk label from."""
        return {
            "BROKEN": "CRITICAL", "OPEN": "HIGH", "WEAK": "MEDIUM",
            "GOOD": "LOW", "STRONG": "INFO", "UNKNOWN": "INFO",
        }[self.security_level]


# ── Scanner ───────────────────────────────────────────────────────────────────

class WiFiScanner:
    MODULE = "wifi"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg.get("wifi", {})
        self._ifaces = self._detect_wifi_interfaces()

    def run(self, iface: Optional[str] = None) -> ModuleResult:
        if not self._ifaces:
            return ModuleResult(
                module=self.MODULE,
                status=ModuleStatus.UNAVAILABLE,
                raw_data={"reason": "No wireless interfaces detected"},
            )

        t0  = time.monotonic()
        target = iface or self._ifaces[0]
        networks = self._scan(target)
        findings = self._analyze(networks)

        return ModuleResult(
            module=self.MODULE,
            status=ModuleStatus.AVAILABLE,
            findings=findings,
            raw_data={
                "interface":      target,
                "networks_found": len(networks),
                "networks":       [vars(n) for n in networks],
            },
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    # ── Scanning strategies ──────────────────────────────────────────────

    def _scan(self, iface: str) -> List[WiFiNetwork]:
        """Try multiple scan strategies, return first that works."""
        # Strategy 1: nmcli (no root, most reliable)
        nets = self._scan_nmcli()
        if nets: return nets

        # Strategy 2: iw (root or CAP_NET_ADMIN)
        nets = self._scan_iw(iface)
        if nets: return nets

        # Strategy 3: iwlist (older, sometimes no root)
        nets = self._scan_iwlist(iface)
        if nets: return nets

        # Strategy 4: passive — /proc/net/wireless stats
        return self._passive_proc()

    def _scan_nmcli(self) -> List[WiFiNetwork]:
        rc, out = _run(["nmcli", "-t", "-f",
                         "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                         "dev", "wifi", "list"])
        if rc != 0: return []
        nets = []
        for line in out.splitlines():
            if not line.strip():
                continue
            # nmcli -t escapes colons as \: and backslashes as \\
            # We need to parse carefully: split on unescaped colons
            # First, replace escaped sequences with placeholders
            line_escaped = line.replace("\\:", "\x01").replace("\\\\", "\x02")
            parts = line_escaped.split(":")
            # Restore escaped chars in each part
            parts = [p.replace("\x01", ":").replace("\x02", "\\") for p in parts]
            
            if len(parts) < 6:
                continue
            ssid = parts[0]
            bssid = parts[1]
            chan = parts[2]
            freq = parts[3]
            sig = parts[4]
            sec = ":".join(parts[5:])
            
            # Parse channel
            try:
                channel = int(chan) if chan.isdigit() else 0
            except ValueError:
                channel = 0
            
            # Parse frequency (MHz to GHz)
            try:
                freq_val = float(re.sub(r'[^\d.]', '', freq)) if freq else 0
                if freq_val > 1000:  # MHz to GHz
                    freq_val = freq_val / 1000
            except ValueError:
                freq_val = 0.0
            
            # Parse signal (nmcli quality 0-100 to dBm)
            try:
                signal_raw = int(re.sub(r'[^\d-]', '', sig)) if sig else -100
                if signal_raw >= 0 and signal_raw <= 100:
                    signal = -100 + (signal_raw * 0.7)
                else:
                    signal = signal_raw
            except ValueError:
                signal = -100
            
            security = sec.strip() or "OPEN"
            security = re.sub(r'\s+', ' ', security).strip()
            
            nets.append(WiFiNetwork(
                ssid=ssid or "<hidden>",
                bssid=bssid,
                channel=channel,
                frequency=freq_val,
                signal=signal,
                security=security,
            ))
        return nets

    def _scan_iw(self, iface: str) -> List[WiFiNetwork]:
        if os.geteuid() != 0: return []
        rc, out = _run(["iw", "dev", iface, "scan"], timeout=20)
        if rc != 0: return []
        return self._parse_iw_output(out)

    def _parse_iw_output(self, text: str) -> List[WiFiNetwork]:
        nets: List[WiFiNetwork] = []
        current: Optional[Dict[str, Any]] = None

        for line in text.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if current: nets.append(self._dict_to_network(current))
                bssid = line.split()[1].rstrip("(associated)")
                current = {"bssid": bssid, "ssid": "", "channel": 0,
                           "frequency": 0.0, "signal": -100, "security": "OPEN"}
            if current is None: continue
            if "SSID:" in line and not line.startswith("Extended"):
                current["ssid"] = line.split("SSID:")[1].strip()
            if "freq:" in line.lower():
                try: current["frequency"] = float(re.findall(r'[\d.]+', line)[0]) / 1000
                except: pass
            if "signal:" in line.lower():
                m = re.search(r'([-\d.]+)\s*dBm', line)
                if m:
                    try: current["signal"] = int(float(m.group(1)))
                    except: pass
            if "DS Parameter set:" in line:
                m = re.search(r'channel (\d+)', line)
                if m: current["channel"] = int(m.group(1))
            for proto in ("WPA3", "WPA2", "WPA", "WEP"):
                if proto in line.upper():
                    current["security"] = proto
                    break  # stop at first / most specific match

        if current: nets.append(self._dict_to_network(current))
        return nets

    def _dict_to_network(self, d: Dict) -> WiFiNetwork:
        return WiFiNetwork(
            ssid=d.get("ssid","<hidden>"),
            bssid=d.get("bssid",""),
            channel=d.get("channel",0),
            frequency=d.get("frequency",0.0),
            signal=d.get("signal",-100),
            security=d.get("security","OPEN"),
        )

    def _scan_iwlist(self, iface: str) -> List[WiFiNetwork]:
        rc, out = _run(["iwlist", iface, "scan"], timeout=15)
        if rc != 0 or "Interface doesn't support" in out: return []
        nets = []
        current: Optional[Dict] = None
        for line in out.splitlines():
            line = line.strip()
            if "Cell " in line:
                if current: nets.append(self._dict_to_network(current))
                bssid = line.split("Address:")[1].strip() if "Address:" in line else ""
                current = {"bssid":bssid,"ssid":"","channel":0,"frequency":0.0,"signal":-100,"security":"OPEN"}
            if current is None: continue
            if "ESSID:" in line:
                current["ssid"] = line.split("ESSID:")[1].strip('"')
            if "Channel:" in line:
                try: current["channel"] = int(re.findall(r'\d+', line)[0])
                except: pass
            if "Signal level" in line:
                m = re.search(r'Signal level[=:]([- \d]+)dBm', line)
                if m:
                    try: current["signal"] = int(m.group(1).strip())
                    except: pass
            for proto in ("WPA3","WPA2","WPA","WEP"):
                if proto in line: current["security"] = proto
        if current: nets.append(self._dict_to_network(current))
        return nets

    def _passive_proc(self) -> List[WiFiNetwork]:
        """Read /proc/net/wireless for associated network stats only."""
        p = Path("/proc/net/wireless")
        if not p.exists(): return []
        nets = []
        for line in p.read_text().splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[0].rstrip(":")
                try: signal = int(float(parts[3].rstrip(".")))
                except: signal = -100
                nets.append(WiFiNetwork(
                    ssid=f"<associated-on-{iface}>",
                    signal=signal,
                    security="UNKNOWN",
                ))
        return nets

    # ── Analysis ──────────────────────────────────────────────────────────

    def _analyze(self, networks: List[WiFiNetwork]) -> List[Finding]:
        findings: List[Finding] = []
        for net in networks:
            # Parse security string to determine actual security level
            sec_upper = net.security.upper()
            has_wpa3 = "WPA3" in sec_upper or "SAE" in sec_upper
            has_wpa2 = "WPA2" in sec_upper or "RSN" in sec_upper or "CCMP" in sec_upper
            has_wpa = "WPA" in sec_upper and not has_wpa2 and not has_wpa3
            has_wep = "WEP" in sec_upper
            is_open = "OPEN" in sec_upper or "NONE" in sec_upper or not sec_upper.strip()
            
            # Determine security level
            if has_wpa3:
                sec_level = "STRONG"
            elif has_wpa2:
                sec_level = "GOOD"
            elif has_wpa:
                sec_level = "WEAK"
            elif has_wep:
                sec_level = "BROKEN"
            elif is_open:
                sec_level = "OPEN"
            else:
                sec_level = "UNKNOWN"
            
            # The security level was already derived above; use it directly.
            lvl = sec_level
            
            if lvl == "OPEN":
                findings.append(Finding(
                    type="WIFI_OPEN_NETWORK",
                    severity=Severity.HIGH,
                    description=f'Open WiFi network detected: "{net.ssid}" ({net.security})',
                    evidence=f"BSSID={net.bssid} SSID={net.ssid} security={net.security}",
                    recommendation=(
                        "Open networks transmit data unencrypted. "
                        "Do not connect to open networks for sensitive operations. "
                        "Consider WPA3 for any networks you operate."
                    ),
                    module=self.MODULE,
                    mitre="T1040",
                ))
            elif lvl == "BROKEN":
                findings.append(Finding(
                    type="WIFI_WEP_NETWORK",
                    severity=Severity.CRITICAL,
                    description=f'WEP-encrypted network: "{net.ssid}" — WEP is broken',
                    evidence=f"BSSID={net.bssid} security=WEP",
                    recommendation=(
                        "WEP can be cracked in minutes. "
                        "Upgrade immediately to WPA2 or WPA3."
                    ),
                    module=self.MODULE,
                    mitre="T1040",
                ))
            elif lvl == "WEAK":
                findings.append(Finding(
                    type="WIFI_WPA_TKIP",
                    severity=Severity.MEDIUM,
                    description=f'WPA (TKIP) network: "{net.ssid}" — outdated protocol',
                    evidence=f"BSSID={net.bssid} security=WPA",
                    recommendation="Upgrade to WPA2-AES or WPA3.",
                    module=self.MODULE,
                ))
            elif lvl == "GOOD":
                findings.append(Finding(
                    type="WIFI_WPA2_NETWORK",
                    severity=Severity.LOW,
                    description=f'WPA2 network: "{net.ssid}" — good security',
                    evidence=f"BSSID={net.bssid} security={net.security}",
                    recommendation="Consider upgrading to WPA3 for enhanced security.",
                    module=self.MODULE,
                ))
            elif lvl == "STRONG":
                findings.append(Finding(
                    type="WIFI_WPA3_NETWORK",
                    severity=Severity.INFO,
                    description=f'WPA3 network: "{net.ssid}" — strong security',
                    evidence=f"BSSID={net.bssid} security={net.security}",
                    recommendation="WPA3 is the current best practice for WiFi security.",
                    module=self.MODULE,
                ))

            # Signal strength analysis
            if net.signal > -40:
                findings.append(Finding(
                    type="WIFI_STRONG_SIGNAL",
                    severity=Severity.INFO,
                    description=f'Very strong signal from "{net.ssid}" ({net.signal:.0f} dBm)',
                    evidence=f"signal={net.signal:.0f}dBm BSSID={net.bssid}",
                    recommendation="Strong signal suggests the AP is nearby.",
                    module=self.MODULE,
                ))
            elif net.signal < -80:
                findings.append(Finding(
                    type="WIFI_WEAK_SIGNAL",
                    severity=Severity.INFO,
                    description=f'Weak signal from "{net.ssid}" ({net.signal:.0f} dBm)',
                    evidence=f"signal={net.signal:.0f}dBm BSSID={net.bssid}",
                    recommendation="Weak signal may indicate distance or obstruction.",
                    module=self.MODULE,
                ))

        # Count open/broken networks
        open_count = sum(1 for n in networks if n.security_level in ("OPEN", "BROKEN"))
        if open_count > 3:
            findings.append(Finding(
                type="WIFI_HIGH_OPEN_COUNT",
                severity=Severity.MEDIUM,
                description=f"{open_count} insecure networks in range",
                evidence=f"open_networks={open_count} total={len(networks)}",
                recommendation="Be aware of your wireless environment.",
                module=self.MODULE,
            ))
            
        # Check for WPA3 adoption
        wpa3_count = sum(1 for n in networks if "WPA3" in n.security.upper() or "SAE" in n.security.upper())
        total = len(networks)
        if total > 0 and wpa3_count == 0 and total > 5:
            findings.append(Finding(
                type="WIFI_NO_WPA3",
                severity=Severity.LOW,
                description=f"No WPA3 networks found among {total} detected networks",
                evidence=f"wpa3_networks=0 total_networks={total}",
                recommendation="Consider upgrading APs to WPA3 for improved security posture.",
                module=self.MODULE,
            ))

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────

    def _detect_wifi_interfaces(self) -> List[str]:
        ifaces = []
        p = Path("/sys/class/net")
        if p.exists():
            for iface in _safe_iterdir(p):
                if (iface / "wireless").exists() or (iface / "phy80211").exists():
                    ifaces.append(iface.name)
        if not ifaces:
            rc, out = _run(["iw", "dev"])
            for line in out.splitlines():
                m = re.search(r"Interface\s+(\S+)", line)
                if m: ifaces.append(m.group(1))
        return ifaces
