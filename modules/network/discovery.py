"""
CyberScope — modules/network/discovery.py

Real network analysis using standard Linux tools:
  ip addr, ip route, ss, /proc/net/
No root required for most operations.
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.types import CapabilityInfo, Finding, ModuleResult, ModuleStatus, Severity


def _run(cmd: List[str], timeout: int = 10) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.returncode, r.stdout
    except Exception as e:
        return -1, ""


# ── Data models ───────────────────────────────────────────────────────────────

class NetworkDiscovery:
    """Passive network analysis — no active probing unless configured."""

    MODULE = "network"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg.get("network", {})

    # ------------------------------------------------------------------
    def run(self) -> ModuleResult:
        t0 = time.monotonic()
        raw: Dict[str, Any] = {}
        findings: List[Finding] = []

        # 1. Interfaces
        ifaces = self._get_interfaces()
        raw["interfaces"] = ifaces

        # 2. Routes
        routes = self._get_routes()
        raw["routes"] = routes

        # 3. Listening services (no root needed for ss)
        services = self._get_listening_services()
        raw["listening_services"] = services

        # 4. DNS config
        dns = self._get_dns()
        raw["dns"] = dns

        # 5. Findings
        findings.extend(self._analyze_interfaces(ifaces))
        findings.extend(self._analyze_services(services))
        findings.extend(self._analyze_routes(routes))

        return ModuleResult(
            module=self.MODULE,
            status=ModuleStatus.AVAILABLE,
            findings=findings,
            raw_data=raw,
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    # ── Data collection ────────────────────────────────────────────────

    def _get_interfaces(self) -> List[Dict[str, Any]]:
        rc, out = _run(["ip", "-j", "addr", "show"])
        if rc == 0:
            import json
            try:
                return json.loads(out)
            except Exception:
                pass

        # Fallback: text parsing
        rc2, out2 = _run(["ip", "addr", "show"])
        return self._parse_ip_addr(out2)

    def _parse_ip_addr(self, text: str) -> List[Dict[str, Any]]:
        ifaces = []
        current: Optional[Dict] = None
        for line in text.splitlines():
            m = re.match(r'^\d+:\s+(\S+?)(@\S+)?:\s+<([^>]*)>', line)
            if m:
                if current: ifaces.append(current)
                current = {
                    "ifname": m.group(1), "flags": m.group(3).split(","),
                    "addr_info": [], "mac": ""
                }
            if current is None: continue
            m2 = re.search(r'link/ether\s+(\S+)', line)
            if m2: current["mac"] = m2.group(1)
            m3 = re.search(r'inet6?\s+(\S+)', line)
            if m3:
                current["addr_info"].append({
                    "local": m3.group(1),
                    "family": "inet6" if "inet6" in line else "inet"
                })
        if current: ifaces.append(current)
        return ifaces

    def _get_routes(self) -> List[Dict[str, Any]]:
        rc, out = _run(["ip", "-j", "route", "show"])
        if rc == 0:
            import json
            try: return json.loads(out)
            except Exception: pass

        rc2, out2 = _run(["ip", "route", "show"])
        routes = []
        for line in out2.splitlines():
            if line.strip():
                routes.append({"raw": line.strip()})
        return routes

    def _get_listening_services(self) -> List[Dict[str, Any]]:
        """Get listening TCP/UDP services via ss."""
        services = []
        # ss output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
        rc, out = _run(["ss", "-tlnp"])
        if rc != 0:
            rc, out = _run(["netstat", "-tlnp"])

        for line in out.splitlines():
            if "LISTEN" in line or ("0.0.0.0" in line and "ss" in str(line)):
                parts = line.split()
                if len(parts) >= 4:
                    addr_port = parts[-2] if "LISTEN" in line else parts[3]
                    if ":" in addr_port:
                        addr, _, port = addr_port.rpartition(":")
                        try:
                            services.append({
                                "address": addr,
                                "port":    int(port),
                                "proto":   "tcp",
                                "raw":     line.strip(),
                            })
                        except ValueError:
                            pass
        return services

    def _get_dns(self) -> List[str]:
        servers = []
        for path in ("/etc/resolv.conf", "/data/data/com.termux/files/usr/etc/resolv.conf"):
            p = Path(path)
            if p.exists():
                for line in p.read_text(errors="replace").splitlines():
                    m = re.match(r"nameserver\s+(\S+)", line)
                    if m: servers.append(m.group(1))
        return servers

    # ── Analysis ──────────────────────────────────────────────────────

    def _analyze_interfaces(self, ifaces: List[Dict]) -> List[Finding]:
        findings = []
        for iface in ifaces:
            name  = iface.get("ifname") or iface.get("name", "?")
            flags = iface.get("flags", [])
            # Promiscuous mode is suspicious
            if "PROMISC" in str(flags):
                findings.append(Finding(
                    type="INTERFACE_PROMISC",
                    severity=Severity.HIGH,
                    description=f"Interface {name} is in PROMISCUOUS mode",
                    evidence=f"flags={flags}",
                    recommendation=(
                        "Investigate why the interface is in promiscuous mode. "
                        "This may indicate packet sniffing activity."
                    ),
                    module=self.MODULE,
                ))
        return findings

    def _analyze_services(self, services: List[Dict]) -> List[Finding]:
        findings = []
        SENSITIVE_PORTS = {
            21: "FTP (unencrypted)",
            23: "Telnet (unencrypted)",
            80: "HTTP (unencrypted web)",
            135: "MS-RPC",
            139: "NetBIOS",
            445: "SMB",
            512: "rexec",
            513: "rlogin",
            514: "rsh/syslog",
            3306: "MySQL (exposed)",
            5432: "PostgreSQL (exposed)",
            6379: "Redis (exposed)",
            27017: "MongoDB (exposed)",
        }
        seen_ports = set()
        for svc in services:
            port = svc.get("port", 0)
            addr = svc.get("address", "")
            if port in seen_ports: continue
            seen_ports.add(port)
            # Listening on all interfaces
            if addr in ("0.0.0.0", "::", "*"):
                sev = Severity.LOW
                label = SENSITIVE_PORTS.get(port, f"port {port}")
                if port in SENSITIVE_PORTS:
                    sev = Severity.MEDIUM if port not in (23, 512, 513, 514) else Severity.HIGH
                findings.append(Finding(
                    type="EXPOSED_SERVICE",
                    severity=sev,
                    description=f"Service listening on all interfaces: {label}",
                    evidence=f"port={port} addr={addr}",
                    recommendation=(
                        f"Bind service on port {port} to specific interfaces only. "
                        "Use a firewall to restrict access."
                    ),
                    module=self.MODULE,
                ))
        return findings

    def _analyze_routes(self, routes: List[Dict]) -> List[Finding]:
        findings = []
        for r in routes:
            raw = r.get("raw", "") or str(r)
            # Default route via unexpected gateway
            if "default" in raw and "metric" not in raw and routes.count(r) > 1:
                findings.append(Finding(
                    type="MULTIPLE_DEFAULT_ROUTES",
                    severity=Severity.LOW,
                    description="Multiple default routes detected",
                    evidence=raw,
                    recommendation="Review routing configuration for potential misrouting.",
                    module=self.MODULE,
                ))
                break
        return findings
