"""
CyberScope — modules/network/monitor.py

Live LAN host monitor: polls the kernel's neighbor (ARP/NDP) table —
read-only, no packets sent — to track hosts as they communicate on the
local network, plus an on-demand, non-destructive per-host probe (a
single ICMP ping + a short TCP connect check of common ports) run only
when a host is explicitly selected. Same "ping before accessing"
principle as the rest of the platform: read-only checks, no payloads,
no exploitation.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.types import Finding, Severity
from core.shell import run as _shell_run
from core.net_vendor import classify_mac


def _run(cmd: List[str], timeout: int = 5) -> Tuple[int, str]:
    r = _shell_run(cmd, timeout)
    return r.returncode, (r.stderr if r.returncode == -1 and not r.stdout else r.stdout)


_COMMON_PORTS: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt",
}


@dataclass
class TrackedHost:
    ip:         str
    mac:        str   = ""
    state:      str   = ""
    vendor:     str   = ""   # from core.net_vendor -- "" until a MAC is known
    first_seen: float = 0.0
    last_seen:  float = 0.0
    seen_count: int   = 1

    def update(self, mac: str, state: str, now: float) -> None:
        if mac:
            self.mac = mac
            self.vendor = classify_mac(mac).label
        self.state = state or self.state
        self.last_seen = now
        self.seen_count += 1


def parse_ip_neigh(text: str) -> List[Dict[str, str]]:
    """Parse `ip neigh show` output. Pure — testable with sample text,
    no live network required."""
    hosts: List[Dict[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip    = parts[0]
        mac   = parts[parts.index("lladdr") + 1] if "lladdr" in parts else ""
        state = parts[-1]
        hosts.append({"ip": ip, "mac": mac, "state": state})
    return hosts


def merge_scan(
    registry: Dict[str, TrackedHost],
    hosts: List[Dict[str, str]],
    now: Optional[float] = None,
) -> Dict[str, TrackedHost]:
    """Fold a fresh `ip neigh` read into a live registry keyed by IP.
    Pure function — testable without any network access."""
    now = now if now is not None else time.time()
    for h in hosts:
        ip = h.get("ip", "")
        if not ip:
            continue
        mac = h.get("mac", "")
        if ip in registry:
            registry[ip].update(mac, h.get("state", ""), now)
        else:
            registry[ip] = TrackedHost(
                ip=ip, mac=mac, state=h.get("state", ""),
                vendor=classify_mac(mac).label if mac else "",
                first_seen=now, last_seen=now,
            )
    return registry


class NetworkMonitor:
    """Continuous, passive LAN host discovery via the kernel neighbor
    table, plus an on-demand non-destructive per-host security probe."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg.get("network", {})
        self.registry: Dict[str, TrackedHost] = {}

    @property
    def available(self) -> bool:
        rc, _ = _run(["ip", "neigh", "show"])
        return rc == 0

    def poll(self) -> List[TrackedHost]:
        rc, out = _run(["ip", "neigh", "show"])
        if rc == 0:
            merge_scan(self.registry, parse_ip_neigh(out))
        return sorted(self.registry.values(), key=lambda h: h.last_seen, reverse=True)

    def probe(self, ip: str) -> List[Finding]:
        """Non-destructive reachability + common-port check: a single
        ICMP ping and short TCP connect() attempts on well-known ports.
        No exploitation, no payloads sent, read-only connect probes."""
        t = self.registry.get(ip)
        if not t:
            return []

        findings: List[Finding] = []
        rc, out = _run(["ping", "-c", "1", "-W", "1", ip], timeout=3)
        reachable = (rc == 0)
        findings.append(Finding(
            type="HOST_REACHABLE" if reachable else "HOST_UNREACHABLE",
            severity=Severity.INFO,
            description=f"{ip} is {'reachable' if reachable else 'not responding'} to ICMP ping.",
            evidence=out.strip().splitlines()[-1] if reachable and out.strip() else "",
            module="network",
        ))

        open_ports = self._scan_common_ports(ip)
        for port, label in open_ports:
            sev = Severity.MEDIUM if port in (21, 23, 139, 445, 3389) else Severity.LOW
            findings.append(Finding(
                type="HOST_OPEN_PORT",
                severity=sev,
                description=f"{ip}:{port} ({label}) is open.",
                evidence=f"ip={ip} port={port}",
                recommendation=(
                    "Confirm this service is intentionally exposed to the LAN; "
                    "restrict it with a firewall if not."
                ),
                module="network",
            ))
        if not open_ports:
            findings.append(Finding(
                type="HOST_NO_COMMON_PORTS_OPEN",
                severity=Severity.INFO,
                description=f"No commonly-probed ports open on {ip}.",
                module="network",
            ))
        return findings

    def _scan_common_ports(self, ip: str, timeout: float = 0.4) -> List[Tuple[int, str]]:
        open_ports: List[Tuple[int, str]] = []
        for port, label in _COMMON_PORTS.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((ip, port)) == 0:
                        open_ports.append((port, label))
            except OSError:
                continue
        return open_ports
