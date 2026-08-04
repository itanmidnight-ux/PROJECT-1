"""
CyberScope — modules/bluetooth/scanner.py

Real Bluetooth discovery via hcitool, bluetoothctl, and sysfs.
Detects classic BT and BLE devices, analyzes discoverability and services.
"""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.types import Finding, ModuleResult, ModuleStatus, Severity


def _run(cmd: List[str], timeout: int = 15) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.returncode, r.stdout + r.stderr
    except Exception as e:
        return -1, str(e)


# ── Models ────────────────────────────────────────────────────────────────────

@dataclass
class BTDevice:
    address:  str
    name:     str     = "Unknown"
    cls:      str     = ""        # Device class
    rssi:     int     = 0
    le:       bool    = False     # BLE device
    services: List[str] = field(default_factory=list)


@dataclass
class BTAdapter:
    name:      str
    address:   str  = ""
    powered:   bool = False
    discoverable: bool = False
    pairable:  bool = False
    bd_address: str = ""


# ── Scanner ───────────────────────────────────────────────────────────────────

class BluetoothScanner:
    MODULE = "bluetooth"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg     = cfg.get("bluetooth", {})
        self.timeout = int(self.cfg.get("scan_timeout", 10))
        self.adapters= self._detect_adapters()

    def run(self) -> ModuleResult:
        if not self.adapters:
            return ModuleResult(
                module=self.MODULE,
                status=ModuleStatus.UNAVAILABLE,
                raw_data={"reason": "No Bluetooth adapters detected"},
            )

        t0       = time.monotonic()
        adapter  = self.adapters[0]
        raw: Dict[str, Any] = {"adapter": vars(adapter)}

        # Scan for devices
        devices = self._scan_classic() or self._scan_bluetoothctl()
        ble_devs= self._scan_ble()
        all_devs= devices + ble_devs
        raw["devices"] = [vars(d) for d in all_devs]
        raw["adapter_analysis"] = self._analyze_adapter_sysfs(adapter.name)

        findings = self._analyze(adapter, all_devs)

        return ModuleResult(
            module=self.MODULE,
            status=ModuleStatus.AVAILABLE,
            findings=findings,
            raw_data=raw,
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    # ── Adapter detection ────────────────────────────────────────────────

    def _detect_adapters(self) -> List[BTAdapter]:
        adapters: List[BTAdapter] = []

        # sysfs — always works
        p = Path("/sys/class/bluetooth")
        if p.exists():
            for d in p.iterdir():
                a = BTAdapter(name=d.name)
                addr_f = d / "address"
                if addr_f.exists():
                    a.address = addr_f.read_text().strip()
                adapters.append(a)

        # hciconfig for more details
        if adapters:
            rc, out = _run(["hciconfig", "-a"])
            if rc == 0:
                self._enrich_from_hciconfig(out, adapters)

        return adapters

    def _enrich_from_hciconfig(self, text: str, adapters: List[BTAdapter]) -> None:
        current: Optional[BTAdapter] = None
        for line in text.splitlines():
            m = re.match(r'^(hci\d+):', line)
            if m:
                name = m.group(1)
                current = next((a for a in adapters if a.name == name), None)
            if current is None: continue
            if "BD Address:" in line:
                m2 = re.search(r'BD Address: (\S+)', line)
                if m2: current.bd_address = m2.group(1)
            if "UP" in line and "RUNNING" in line:
                current.powered = True
            if "PSCAN" in line:
                current.discoverable = True

    def _analyze_adapter_sysfs(self, name: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        p = Path(f"/sys/class/bluetooth/{name}")
        if not p.exists(): return result
        for attr in ("address", "name", "manufacturer", "hci_version"):
            f = p / attr
            if f.exists():
                try: result[attr] = f.read_text().strip()
                except: pass
        return result

    # ── Classic BT scanning ──────────────────────────────────────────────

    def _scan_classic(self) -> List[BTDevice]:
        rc, out = _run(["hcitool", "scan", "--flush"], timeout=self.timeout + 5)
        if rc != 0 or "Scanning ..." not in out: return []
        devices = []
        for line in out.splitlines():
            m = re.match(r'\s+([0-9A-F:]{17})\s+(.*)', line)
            if m:
                devices.append(BTDevice(address=m.group(1), name=m.group(2).strip()))
        return devices

    def _scan_bluetoothctl(self) -> List[BTDevice]:
        """Use bluetoothctl for scanning (more modern)."""
        # Send scan on then get devices
        try:
            proc = subprocess.Popen(
                ["bluetoothctl"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
            )
            cmds = f"scan on\n"
            time.sleep(min(self.timeout, 8))
            cmds += "devices\nquit\n"
            out, _ = proc.communicate(input=cmds, timeout=15)
        except Exception:
            return []

        devices = []
        for line in out.splitlines():
            m = re.search(r'Device\s+([0-9A-F:]{17})\s+(.*)', line)
            if m:
                devices.append(BTDevice(address=m.group(1), name=m.group(2).strip()))
        return devices

    def _scan_ble(self) -> List[BTDevice]:
        """Scan for BLE devices with hcitool lescan."""
        # lescan requires root; timeout after a few seconds
        rc, out = _run(["timeout", str(min(self.timeout, 5)),
                        "hcitool", "lescan", "--duplicates"],
                       timeout=self.timeout + 2)
        devices: List[BTDevice] = []
        seen = set()
        for line in out.splitlines():
            m = re.match(r'([0-9A-F:]{17})\s+(.*)', line)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                devices.append(BTDevice(
                    address=m.group(1),
                    name=m.group(2).strip() or "Unknown BLE",
                    le=True,
                ))
        return devices

    # ── Analysis ──────────────────────────────────────────────────────────

    def _analyze(self, adapter: BTAdapter, devices: List[BTDevice]) -> List[Finding]:
        findings: List[Finding] = []

        # Check if adapter itself is discoverable
        if adapter.discoverable:
            findings.append(Finding(
                type="BT_ADAPTER_DISCOVERABLE",
                severity=Severity.MEDIUM,
                description=f"Bluetooth adapter {adapter.name} is in discoverable mode",
                evidence=f"adapter={adapter.name} address={adapter.bd_address or adapter.address}",
                recommendation=(
                    "Disable discoverable mode when not pairing. "
                    "Discoverable devices are visible to all nearby attackers. "
                    "Use `bluetoothctl` → `discoverable off`."
                ),
                module=self.MODULE,
                mitre="T1119",
            ))

        # Discovered devices
        if devices:
            findings.append(Finding(
                type="BT_DEVICES_FOUND",
                severity=Severity.INFO,
                description=f"{len(devices)} Bluetooth device(s) detected in range",
                evidence="; ".join(f"{d.address} ({d.name})" for d in devices[:5]),
                recommendation=(
                    "Review detected devices. "
                    "Unknown devices in corporate environments may warrant investigation."
                ),
                module=self.MODULE,
            ))

        # Unknown / unnamed devices
        unnamed = [d for d in devices if d.name in ("Unknown", "", "Unknown BLE")]
        if unnamed:
            findings.append(Finding(
                type="BT_UNNAMED_DEVICES",
                severity=Severity.LOW,
                description=f"{len(unnamed)} Bluetooth devices with no readable name",
                evidence="; ".join(d.address for d in unnamed[:5]),
                recommendation="Unknown devices may be tracking beacons or rogue devices.",
                module=self.MODULE,
            ))

        # BLE beacons
        ble = [d for d in devices if d.le]
        if ble:
            findings.append(Finding(
                type="BLE_DEVICES_DETECTED",
                severity=Severity.INFO,
                description=f"{len(ble)} BLE device(s) detected",
                evidence="; ".join(d.address for d in ble[:5]),
                recommendation=(
                    "BLE devices may include tracking beacons (iBeacon, Eddystone). "
                    "Review in environments with strict privacy requirements."
                ),
                module=self.MODULE,
            ))

        return findings
