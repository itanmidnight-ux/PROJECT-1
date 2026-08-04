"""
CyberScope — core/discovery.py

Real hardware and capability detection.
No fake data — if hardware isn't present, it's reported as unavailable.

Detects:
  - OS / environment (Linux / Termux / Android)
  - Architecture (x86_64, aarch64, armv7)
  - Network interfaces (via /proc and ip command)
  - WiFi adapters (via iw / iwconfig / sysfs)
  - Bluetooth adapters (via sysfs / hciconfig)
  - SDR hardware (via USB device enumeration)
  - Root / privilege status
  - Installed security tools
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .types import CapabilityInfo, ModuleStatus


# ── Helpers ─────────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 5) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr). Never raises."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError) as e:
        return -1, "", str(e)


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _sysfs_exists(path: str) -> bool:
    return Path(path).exists()


def _safe_iterdir(path: Path) -> List[Path]:
    """List a directory, tolerating sysfs paths SELinux blocks (Termux/Android)."""
    try:
        return list(path.iterdir())
    except (PermissionError, OSError):
        return []


# ── OS / environment ─────────────────────────────────────────────────────────

@dataclass
class OSInfo:
    kernel:      str
    arch:        str
    hostname:    str
    is_termux:   bool
    is_android:  bool
    is_root:     bool
    distro:      str

    @property
    def env_label(self) -> str:
        if self.is_termux:   return "Termux/Android"
        if self.is_android:  return "Android"
        return self.distro or "Linux"


def detect_os() -> OSInfo:
    kernel   = platform.release()
    arch     = platform.machine()
    hostname = platform.node()
    is_root  = (os.geteuid() == 0)

    # Termux detection: $PREFIX env var or filesystem
    is_termux = (
        "com.termux" in os.environ.get("PREFIX", "")
        or Path("/data/data/com.termux").exists()
        or "android" in kernel.lower()
    )
    is_android = is_termux or Path("/system/build.prop").exists()

    # Distro name
    distro = ""
    for f in ("/etc/os-release", "/etc/debian_version", "/etc/arch-release"):
        p = Path(f)
        if p.exists():
            text = p.read_text(errors="replace")
            m = re.search(r'PRETTY_NAME="?([^"\n]+)', text)
            distro = m.group(1) if m else text.splitlines()[0]
            break

    return OSInfo(kernel, arch, hostname, is_termux, is_android, is_root, distro)


# ── Network interfaces ────────────────────────────────────────────────────────

@dataclass
class NetworkInterface:
    name:  str
    mac:   str = ""
    state: str = ""
    ipv4:  List[str] = field(default_factory=list)
    ipv6:  List[str] = field(default_factory=list)
    flags: str = ""


def detect_network_interfaces() -> List[NetworkInterface]:
    """Parse `ip addr show` output into NetworkInterface objects."""
    rc, out, _ = _run(["ip", "addr", "show"])
    if rc != 0:
        # Fallback: /proc/net/dev
        try:
            lines = Path("/proc/net/dev").read_text().splitlines()[2:]
            return [NetworkInterface(name=l.split(":")[0].strip())
                    for l in lines if ":" in l]
        except OSError:
            return []

    interfaces: List[NetworkInterface] = []
    current: Optional[NetworkInterface] = None

    for line in out.splitlines():
        m = re.match(r'^\d+:\s+(\S+):\s+<([^>]*)>', line)
        if m:
            if current: interfaces.append(current)
            current = NetworkInterface(name=m.group(1).rstrip("@0123456789"),
                                       flags=m.group(2))
        if current is None: continue
        m2 = re.search(r'link/ether\s+(\S+)', line)
        if m2: current.mac = m2.group(1)
        m3 = re.search(r'state\s+(\S+)', line)
        if m3: current.state = m3.group(1)
        m4 = re.search(r'inet\s+(\S+)', line)
        if m4 and "inet6" not in line: current.ipv4.append(m4.group(1))
        m5 = re.search(r'inet6\s+(\S+)', line)
        if m5: current.ipv6.append(m5.group(1))

    if current: interfaces.append(current)
    return [i for i in interfaces if i.name not in ("lo",)]


# ── WiFi ─────────────────────────────────────────────────────────────────────

def detect_wifi() -> CapabilityInfo:
    """
    Check for WiFi interfaces via sysfs and iw/iwconfig.
    On Termux without root, scanning is unavailable but interface presence is detectable.
    """
    # Check sysfs for wireless interfaces
    wifi_ifaces: List[str] = []
    p = Path("/sys/class/net")
    if p.exists():
        for iface in _safe_iterdir(p):
            if (iface / "wireless").exists() or (iface / "phy80211").exists():
                wifi_ifaces.append(iface.name)

    # Fallback: iw dev
    if not wifi_ifaces and _tool_exists("iw"):
        rc, out, _ = _run(["iw", "dev"])
        for line in out.splitlines():
            m = re.search(r"Interface\s+(\S+)", line)
            if m: wifi_ifaces.append(m.group(1))

    # Fallback: iwconfig
    if not wifi_ifaces and _tool_exists("iwconfig"):
        rc, out, _ = _run(["iwconfig"])
        for line in out.splitlines():
            if "IEEE 802.11" in line or "ESSID" in line:
                iface = line.split()[0]
                if iface: wifi_ifaces.append(iface)

    if not wifi_ifaces:
        return CapabilityInfo("WiFi", ModuleStatus.UNAVAILABLE,
                              "No wireless interfaces detected")

    # Check if we can scan (requires root/CAP_NET_ADMIN or nm)
    can_scan = (os.geteuid() == 0) or _tool_exists("nmcli")
    status   = ModuleStatus.AVAILABLE if can_scan else ModuleStatus.LIMITED
    reason   = "" if can_scan else "Scanning requires root or NetworkManager (nmcli)"

    return CapabilityInfo(
        "WiFi", status, reason,
        {"interfaces": wifi_ifaces, "can_scan": can_scan},
    )


# ── Bluetooth ────────────────────────────────────────────────────────────────

def detect_bluetooth() -> CapabilityInfo:
    """Detect Bluetooth via sysfs and hciconfig/bluetoothctl."""
    # sysfs — most reliable
    bt_devs: List[str] = []
    p = Path("/sys/class/bluetooth")
    if p.exists():
        bt_devs = [d.name for d in _safe_iterdir(p)]

    # hciconfig fallback
    if not bt_devs and _tool_exists("hciconfig"):
        rc, out, _ = _run(["hciconfig"])
        for line in out.splitlines():
            m = re.match(r'^(hci\d+)', line)
            if m: bt_devs.append(m.group(1))

    if not bt_devs:
        return CapabilityInfo("Bluetooth", ModuleStatus.UNAVAILABLE,
                              "No Bluetooth adapters detected")

    can_scan = _tool_exists("hcitool") or _tool_exists("bluetoothctl")
    status   = ModuleStatus.AVAILABLE if can_scan else ModuleStatus.LIMITED
    reason   = "" if can_scan else "Install bluetoothctl or hcitool for scanning"

    return CapabilityInfo(
        "Bluetooth", status, reason,
        {"adapters": bt_devs, "can_scan": can_scan},
    )


# ── SDR ──────────────────────────────────────────────────────────────────────

# Known SDR USB Vendor:Product IDs
_SDR_USB_IDS = {
    "0bda:2838": "RTL-SDR (RTL2838)",
    "0bda:2832": "RTL-SDR (RTL2832)",
    "1d50:604b": "HackRF One",
    "1d50:6089": "HackRF Jawbreaker",
    "fffe:0002": "USRP B100",
    "04b4:0053": "Cypress FX2 (USRP)",
    "2500:0020": "LimeSDR",
}


def detect_sdr() -> CapabilityInfo:
    rc, out, _ = _run(["lsusb"])
    if rc != 0:
        # Try reading /sys/bus/usb/devices/
        found = _check_sdr_sysfs()
    else:
        found = {}
        for uid, name in _SDR_USB_IDS.items():
            if uid in out:
                found[uid] = name

    if not found:
        return CapabilityInfo("SDR", ModuleStatus.UNAVAILABLE,
                              "No compatible SDR hardware detected (RTL-SDR, HackRF, LimeSDR)")

    tools = {t: _tool_exists(t) for t in ("rtl_test","hackrf_info","limesdr_util","gnuradio-companion")}
    has_tools = any(tools.values())

    return CapabilityInfo(
        "SDR", ModuleStatus.AVAILABLE if has_tools else ModuleStatus.LIMITED,
        "" if has_tools else "SDR hardware found but no SDR tools installed",
        {"devices": found, "tools": tools},
    )


def _check_sdr_sysfs() -> Dict[str, str]:
    found = {}
    base = Path("/sys/bus/usb/devices")
    if not base.exists(): return found
    for dev in _safe_iterdir(base):
        try:
            vid = (dev / "idVendor").read_text().strip()
            pid = (dev / "idProduct").read_text().strip()
            uid = f"{vid}:{pid}"
            if uid in _SDR_USB_IDS:
                found[uid] = _SDR_USB_IDS[uid]
        except OSError:
            pass
    return found


# ── Installed security tools ──────────────────────────────────────────────────

_SECURITY_TOOLS = [
    "nmap", "masscan", "netcat", "nc", "tcpdump", "wireshark", "tshark",
    "aircrack-ng", "aireplay-ng", "airodump-ng", "reaver",
    "john", "hashcat", "hydra", "medusa",
    "sqlmap", "nikto", "dirb", "gobuster",
    "metasploit-framework", "msfconsole",
    "iw", "iwconfig", "iwlist", "nmcli",
    "hcitool", "bluetoothctl", "btscanner",
    "rtl_test", "rtl_sdr", "hackrf_info",
    "scapy", "python3", "pip3",
    "git", "curl", "wget",
]


def detect_tools() -> Dict[str, bool]:
    return {tool: _tool_exists(tool) for tool in _SECURITY_TOOLS}


# ── Full system discovery ─────────────────────────────────────────────────────

@dataclass
class SystemCapabilities:
    os_info:     OSInfo
    network:     List[NetworkInterface]
    wifi:        CapabilityInfo
    bluetooth:   CapabilityInfo
    sdr:         CapabilityInfo
    tools:       Dict[str, bool]
    telecom:     CapabilityInfo  # SS7 module always available

    def available_modules(self) -> List[str]:
        mods = ["network", "device", "telecom"]
        if self.wifi:       mods.append("wifi")
        if self.bluetooth:  mods.append("bluetooth")
        if self.sdr:        mods.append("sdr")
        return mods

    def to_dict(self) -> dict:
        return {
            "os":        vars(self.os_info),
            "network":   [vars(i) for i in self.network],
            "wifi":      self.wifi.to_dict(),
            "bluetooth": self.bluetooth.to_dict(),
            "sdr":       self.sdr.to_dict(),
            "tools":     {k: v for k, v in self.tools.items() if v},
            "telecom":   self.telecom.to_dict(),
        }


def discover_all() -> SystemCapabilities:
    """Run full system discovery. Safe to call without root."""
    return SystemCapabilities(
        os_info   = detect_os(),
        network   = detect_network_interfaces(),
        wifi      = detect_wifi(),
        bluetooth = detect_bluetooth(),
        sdr       = detect_sdr(),
        tools     = detect_tools(),
        telecom   = CapabilityInfo(
            "Telecom/SS7", ModuleStatus.AVAILABLE,
            "Protocol analysis + simulator always available",
        ),
    )
