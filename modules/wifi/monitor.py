"""
CyberScope — modules/wifi/monitor.py

Live WiFi monitoring built on top of modules.wifi.scanner: repeated
scanning folded into a persistent registry (first/last seen, signal),
best-effort reversible monitor-mode activation when root + driver
support allow it, and a per-network non-destructive security probe
(the same defensive WIFI_* analysis the one-shot scanner runs, scoped
to a single tracked network -- no connection attempt is ever made).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from core.discovery import detect_monitor_mode_support
from core.permissions import PrivilegeStatus
from core.types import Finding
from core.shell import run as _shell_run
from modules.wifi.scanner import WiFiNetwork, WiFiScanner


def _run(cmd: List[str], timeout: int = 10) -> tuple[int, str]:
    r = _shell_run(cmd, timeout)
    return r.returncode, (r.stderr if r.returncode == -1 and not r.stdout else r.combined)


@dataclass
class TrackedNetwork:
    key:        str
    ssid:       str
    bssid:      str
    channel:    int
    frequency:  float
    signal:     int
    security:   str
    first_seen: float
    last_seen:  float
    vendor:     str = ""   # copied from WiFiNetwork.vendor -- see core.net_vendor
    seen_count: int = 1

    def update(self, net: WiFiNetwork, now: float) -> None:
        self.signal    = net.signal
        self.channel   = net.channel or self.channel
        self.frequency = net.frequency or self.frequency
        self.security  = net.security or self.security
        self.vendor    = net.vendor or self.vendor
        self.last_seen = now
        self.seen_count += 1


def merge_scan(
    registry: Dict[str, TrackedNetwork],
    networks: List[WiFiNetwork],
    now: Optional[float] = None,
) -> Dict[str, TrackedNetwork]:
    """Fold a fresh scan into a live registry keyed by BSSID (falling
    back to SSID when a BSSID isn't available). Pure function — testable
    without any wireless hardware."""
    now = now if now is not None else time.time()
    for net in networks:
        key = net.bssid or f"ssid:{net.ssid}"
        if key in registry:
            registry[key].update(net, now)
        else:
            registry[key] = TrackedNetwork(
                key=key, ssid=net.ssid or "<hidden>", bssid=net.bssid,
                channel=net.channel, frequency=net.frequency,
                signal=net.signal, security=net.security, vendor=net.vendor,
                first_seen=now, last_seen=now,
            )
    return registry


class MonitorModeSession:
    """
    Best-effort, fully-reversible monitor-mode toggle for a WiFi
    interface (the same technique tools like airmon-ng use: bring the
    interface down, switch type, bring it back up). Falls back silently
    to normal active scanning if root or driver support isn't available
    — it never crashes the caller. Use as a context manager: interface
    state is always restored to 'managed' on exit.
    """

    def __init__(self, iface: str, privileges: PrivilegeStatus) -> None:
        self.iface       = iface
        self.privileges  = privileges
        self.active      = False
        self.reason      = ""

    def _supported(self) -> bool:
        ok, reason = detect_monitor_mode_support(self.iface)
        if not ok:
            self.reason = reason
        return ok

    def __enter__(self) -> "MonitorModeSession":
        if not self.privileges.can_escalate:
            self.reason = "Root/privileged access not available — using active scan instead"
            return self
        if not self._supported():
            return self
        try:
            _run(["ip", "link", "set", self.iface, "down"])
            rc, out = _run(["iw", "dev", self.iface, "set", "type", "monitor"])
            _run(["ip", "link", "set", self.iface, "up"])
            if rc == 0:
                self.active = True
            else:
                self.reason = f"Driver rejected monitor mode: {out.strip()[:120]}"
                self._restore()
        except Exception as exc:
            self.reason = f"Monitor mode activation failed: {exc}"
        return self

    def _restore(self) -> None:
        _run(["ip", "link", "set", self.iface, "down"])
        _run(["iw", "dev", self.iface, "set", "type", "managed"])
        _run(["ip", "link", "set", self.iface, "up"])

    def __exit__(self, *exc_info) -> None:
        if self.active:
            try:
                self._restore()
            except Exception:
                pass
            self.active = False


class WiFiMonitor:
    """Continuous scanning session with a live, deduplicated registry."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.scanner  = WiFiScanner(cfg)
        self.registry: Dict[str, TrackedNetwork] = {}

    @property
    def available(self) -> bool:
        return bool(self.scanner._ifaces)

    @property
    def interface(self) -> str:
        return self.scanner._ifaces[0] if self.scanner._ifaces else ""

    def poll(self) -> List[TrackedNetwork]:
        """Run one scan cycle, merge into the registry, return the
        current live list sorted strongest-signal first."""
        if not self.available:
            return []
        networks = self.scanner._scan(self.interface)
        merge_scan(self.registry, networks)
        return sorted(self.registry.values(), key=lambda n: n.signal, reverse=True)

    def probe(self, key: str) -> List[Finding]:
        """Run the existing defensive WIFI_* analysis scoped to a single
        tracked network — no connection attempt, no injection."""
        tracked = self.registry.get(key)
        if not tracked:
            return []
        net = WiFiNetwork(
            ssid=tracked.ssid, bssid=tracked.bssid, channel=tracked.channel,
            frequency=tracked.frequency, signal=tracked.signal,
            security=tracked.security,
        )
        return self.scanner._analyze([net])
