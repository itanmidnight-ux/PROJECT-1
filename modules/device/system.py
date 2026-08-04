"""
CyberScope — modules/device/system.py

Real device and system information from /proc, /sys, uname, and environment.
No root required.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List

from core.types import Finding, ModuleResult, ModuleStatus, Severity
from core.shell import run as _shell_run


def _run(cmd: List[str], timeout: int = 5) -> str:
    return _shell_run(cmd, timeout).stdout


class DeviceAnalyzer:
    MODULE = "device"

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg

    def run(self) -> ModuleResult:
        t0  = time.monotonic()
        raw = {
            "os":           self._os_info(),
            "cpu":          self._cpu_info(),
            "memory":       self._memory_info(),
            "disk":         self._disk_info(),
            "security":     self._security_config(),
            "environment":  self._env_info(),
            "tools":        self._installed_tools(),
        }
        findings = self._analyze(raw)
        return ModuleResult(
            module=self.MODULE,
            status=ModuleStatus.AVAILABLE,
            findings=findings,
            raw_data=raw,
            duration_ms=(time.monotonic() - t0) * 1000,
        )

    # ── Data collection ───────────────────────────────────────────────────

    def _os_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "system":   platform.system(),
            "release":  platform.release(),
            "version":  platform.version(),
            "machine":  platform.machine(),
            "hostname": platform.node(),
            "python":   platform.python_version(),
            "is_root":  (os.geteuid() == 0),
            "uid":      os.getuid(),
            "pid":      os.getpid(),
        }
        # Termux
        if Path("/data/data/com.termux").exists():
            info["environment"] = "Termux/Android"
            prop = _run(["getprop", "ro.build.version.release"])
            info["android_version"] = prop.strip()
        elif Path("/etc/os-release").exists():
            text = Path("/etc/os-release").read_text(errors="replace")
            m = re.search(r'PRETTY_NAME="?([^"\n]+)', text)
            info["distro"] = m.group(1) if m else "Linux"
        return info

    def _cpu_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "architecture": platform.machine(),
            "processor":    platform.processor(),
            "cores":        os.cpu_count(),
        }
        p = Path("/proc/cpuinfo")
        if p.exists():
            text = p.read_text(errors="replace")
            m = re.search(r'model name\s*:\s*(.+)', text)
            if m: info["model"] = m.group(1).strip()
            m2 = re.search(r'cpu MHz\s*:\s*(.+)', text)
            if m2: info["mhz"] = m2.group(1).strip()
            m3 = re.search(r'Hardware\s*:\s*(.+)', text)
            if m3: info["hardware"] = m3.group(1).strip()
        return info

    def _memory_info(self) -> Dict[str, Any]:
        info: Dict[str, Any] = {}
        p = Path("/proc/meminfo")
        if not p.exists(): return info
        for line in p.read_text().splitlines():
            for key in ("MemTotal", "MemFree", "MemAvailable", "SwapTotal", "SwapFree"):
                if line.startswith(key + ":"):
                    val = re.search(r'(\d+)', line)
                    if val: info[key] = int(val.group(1)) * 1024  # bytes
        if "MemTotal" in info and "MemAvailable" in info:
            info["used_pct"] = round(
                (1 - info["MemAvailable"] / info["MemTotal"]) * 100, 1
            )
        return info

    def _disk_info(self) -> List[Dict[str, Any]]:
        out = _run(["df", "-h", "--output=source,size,used,avail,pcent,target"])
        disks = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                disks.append({
                    "source": parts[0], "size": parts[1],
                    "used":   parts[2], "avail": parts[3],
                    "use_pct":parts[4], "mount": parts[5],
                })
        return disks

    def _security_config(self) -> Dict[str, Any]:
        cfg: Dict[str, Any] = {}

        # SELinux
        for f in ("/sys/fs/selinux/enforce", "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"):
            if Path(f).exists():
                try: cfg["selinux_enforce"] = Path(f).read_text().strip()
                except: pass

        # AppArmor
        p = Path("/sys/kernel/security/apparmor/profiles")
        cfg["apparmor"] = p.exists()

        # Firewall
        for fw in ("ufw", "firewalld", "iptables", "nftables"):
            cfg[f"firewall_{fw}"] = shutil.which(fw) is not None

        # ASLR
        p2 = Path("/proc/sys/kernel/randomize_va_space")
        if p2.exists():
            try: cfg["aslr"] = int(p2.read_text().strip())
            except: pass

        # Core dumps
        p3 = Path("/proc/sys/kernel/core_pattern")
        if p3.exists():
            try: cfg["core_dumps"] = p3.read_text().strip()
            except: pass

        # Password policy (Termux-safe)
        p4 = Path("/etc/login.defs")
        if p4.exists():
            text = p4.read_text(errors="replace")
            m = re.search(r'PASS_MIN_LEN\s+(\d+)', text)
            if m: cfg["pass_min_len"] = int(m.group(1))

        return cfg

    def _env_info(self) -> Dict[str, Any]:
        return {
            "shell":    os.environ.get("SHELL", "unknown"),
            "user":     os.environ.get("USER", os.environ.get("LOGNAME", "unknown")),
            "home":     os.environ.get("HOME", ""),
            "path_dirs":os.environ.get("PATH", "").split(":"),
            "term":     os.environ.get("TERM", ""),
            "lang":     os.environ.get("LANG", ""),
        }

    def _installed_tools(self) -> Dict[str, bool]:
        tools = [
            "nmap","masscan","netcat","nc","tcpdump","tshark","wireshark",
            "iw","iwconfig","hcitool","bluetoothctl",
            "aircrack-ng","airmon-ng","airodump-ng",
            "john","hashcat","hydra",
            "sqlmap","nikto","gobuster",
            "python3","pip3","git","curl","wget",
        ]
        return {t: shutil.which(t) is not None for t in tools}

    # ── Analysis ──────────────────────────────────────────────────────────

    def _analyze(self, raw: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        sec = raw.get("security", {})

        # ASLR
        aslr = sec.get("aslr")
        if aslr is not None and aslr < 2:
            findings.append(Finding(
                type="ASLR_DISABLED",
                severity=Severity.HIGH if aslr == 0 else Severity.MEDIUM,
                description=f"ASLR is {'disabled' if aslr == 0 else 'partial'} (value={aslr})",
                evidence=f"/proc/sys/kernel/randomize_va_space={aslr}",
                recommendation=(
                    "Enable full ASLR: `sysctl -w kernel.randomize_va_space=2`\n"
                    "Add to /etc/sysctl.conf for persistence."
                ),
                module=self.MODULE,
                mitre="T1203",
            ))

        # No firewall
        has_fw = any(sec.get(f"firewall_{fw}") for fw in ("ufw","firewalld","iptables","nftables"))
        if not has_fw:
            findings.append(Finding(
                type="NO_FIREWALL",
                severity=Severity.MEDIUM,
                description="No firewall tool detected on the system",
                evidence="ufw/firewalld/iptables/nftables: not found",
                recommendation="Install and configure a firewall. For Debian: `apt install ufw && ufw enable`.",
                module=self.MODULE,
            ))

        # Weak password policy
        pass_len = sec.get("pass_min_len")
        if pass_len is not None and pass_len < 8:
            findings.append(Finding(
                type="WEAK_PASSWORD_POLICY",
                severity=Severity.MEDIUM,
                description=f"Minimum password length is {pass_len} (recommended: 12+)",
                evidence=f"PASS_MIN_LEN={pass_len}",
                recommendation="Set PASS_MIN_LEN to at least 12 in /etc/login.defs.",
                module=self.MODULE,
            ))

        # Core dumps enabled with pipe
        core = sec.get("core_dumps", "")
        if core.startswith("|"):
            findings.append(Finding(
                type="CORE_DUMP_PIPE",
                severity=Severity.LOW,
                description=f"Core dumps piped to: {core}",
                evidence=f"core_pattern={core}",
                recommendation="Review core dump handling. Piped dumps may expose sensitive memory.",
                module=self.MODULE,
            ))

        # High memory usage
        mem = raw.get("memory", {})
        if mem.get("used_pct", 0) > 90:
            findings.append(Finding(
                type="HIGH_MEMORY_USAGE",
                severity=Severity.LOW,
                description=f"Memory usage is {mem['used_pct']}%",
                evidence=f"used={mem.get('used_pct')}%",
                recommendation="Investigate memory-intensive processes.",
                module=self.MODULE,
            ))

        return findings
