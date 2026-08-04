"""
CyberScope — modules/bluetooth/monitor.py

Live Bluetooth monitoring built on top of modules.bluetooth.scanner:
repeated classic + BLE scanning folded into a persistent registry
(first/last seen, seen count), plus a per-device non-destructive
security probe reusing the scanner's existing defensive analysis.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.types import Finding
from modules.bluetooth.scanner import BluetoothScanner, BTDevice


@dataclass
class TrackedDevice:
    address:    str
    name:       str
    le:         bool
    first_seen: float
    last_seen:  float
    seen_count: int = 1

    def update(self, dev: BTDevice, now: float) -> None:
        if dev.name not in ("", "Unknown", "Unknown BLE"):
            self.name = dev.name
        self.le = self.le or dev.le
        self.last_seen = now
        self.seen_count += 1


def merge_scan(
    registry: Dict[str, TrackedDevice],
    devices: List[BTDevice],
    now: Optional[float] = None,
) -> Dict[str, TrackedDevice]:
    """Fold a fresh scan into a live registry keyed by BD address. Pure
    function — testable without any Bluetooth hardware."""
    now = now if now is not None else time.time()
    for dev in devices:
        key = dev.address
        if key in registry:
            registry[key].update(dev, now)
        else:
            registry[key] = TrackedDevice(
                address=dev.address, name=dev.name or "Unknown",
                le=dev.le, first_seen=now, last_seen=now,
            )
    return registry


class BluetoothMonitor:
    """Continuous classic + BLE scanning session with a live registry."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.scanner  = BluetoothScanner(cfg)
        self.registry: Dict[str, TrackedDevice] = {}

    @property
    def available(self) -> bool:
        return bool(self.scanner.adapters)

    def poll(self) -> List[TrackedDevice]:
        """Run one scan cycle, merge into the registry, return the
        current live list, most recently seen first."""
        if not self.available:
            return []
        devices = self.scanner._scan_classic() or self.scanner._scan_bluetoothctl()
        devices += self.scanner._scan_ble()
        merge_scan(self.registry, devices)
        return sorted(self.registry.values(), key=lambda d: d.last_seen, reverse=True)

    def probe(self, address: str) -> List[Finding]:
        """Run the existing defensive BT_*/BLE_* analysis scoped to a
        single tracked device — no pairing, no service exploitation."""
        tracked = self.registry.get(address)
        if not tracked or not self.scanner.adapters:
            return []
        dev = BTDevice(address=tracked.address, name=tracked.name, le=tracked.le)
        return self.scanner._analyze(self.scanner.adapters[0], [dev])
