"""
CyberScope WiFi — core/auto_config.py

WiFi-focused intelligent auto-configuration: detects missing WiFi capabilities
and attempts to enable/fix them automatically.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.shell import run as _shell_run
from core.permissions import PrivilegeStatus, detect_privileges


def _run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    r = _shell_run(cmd, timeout)
    return r.returncode, r.stdout, r.stderr


@dataclass
class ConfigAction:
    """Represents an auto-configuration action."""
    name: str
    description: str
    success: bool
    message: str
    requires_root: bool = False
    requires_reboot: bool = False


class AutoConfigurator:
    """WiFi-focused intelligent auto-configuration for CyberScope."""
    
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.privileges = detect_privileges()
        self.actions: List[ConfigAction] = []
    
    def run_all(self) -> List[ConfigAction]:
        """Run all WiFi auto-configuration checks and fixes."""
        self.actions = []
        
        # Check and fix WiFi monitor mode
        self._configure_wifi_monitor()
        
        # Install missing WiFi security tools
        self._install_missing_wifi_tools()
        
        return self.actions
    
    def _configure_wifi_monitor(self) -> None:
        """Check and configure WiFi monitor mode support."""
        from core.discovery import detect_monitor_mode_support, detect_wifi
        
        wifi_caps = detect_wifi()
        if wifi_caps.status.value != "available":
            self.actions.append(ConfigAction(
                name="wifi_interface",
                description="Check for WiFi interface",
                success=False,
                message="No WiFi interface available",
                requires_root=False,
            ))
            return
        
        iface = wifi_caps.details.get("interfaces", [""])[0]
        monitor_ok, reason = detect_monitor_mode_support(iface)
        
        if monitor_ok:
            self.actions.append(ConfigAction(
                name="wifi_monitor_support",
                description="Check WiFi monitor mode driver support",
                success=True,
                message=f"Interface {iface} driver supports monitor mode",
                requires_root=False,
            ))
            
            # Report current mode WITHOUT enabling monitor (enabling it
            # disconnects the interface from the current network).
            rc, out, _ = _run(["iw", "dev", iface, "info"])
            if "monitor" in out:
                self.actions.append(ConfigAction(
                    name="wifi_monitor_enable",
                    description="Check WiFi monitor mode status",
                    success=True,
                    message=f"Interface {iface} already in monitor mode",
                    requires_root=False,
                ))
            else:
                self.actions.append(ConfigAction(
                    name="wifi_monitor_enable",
                    description="Check WiFi monitor mode readiness",
                    success=True,
                    message=f"Interface {iface} ready for monitor mode (not enabled: enabling disconnects the current network)",
                    requires_root=True,
                ))
        else:
            self.actions.append(ConfigAction(
                name="wifi_monitor_support",
                description="Check WiFi monitor mode driver support",
                success=False,
                message=f"Interface {iface} does not support monitor mode: {reason}",
                requires_root=False,
            ))
    
    def _install_missing_wifi_tools(self) -> None:
        """Install missing WiFi security tools via package manager."""
        # WiFi-specific tools
        wifi_tools = {
            "airodump-ng": "aircrack-ng",
            "aireplay-ng": "aircrack-ng",
            "aircrack-ng": "aircrack-ng",
            "airmon-ng": "aircrack-ng",
            "hcxdumptool": "hcxtools",
            "hcxpcapngtool": "hcxtools",
            "reaver": "reaver",
            "wash": "reaver",
            "hashcat": "hashcat",
            "iw": "iw",
            "nmcli": "network-manager",
        }
        
        missing = []
        for tool, pkg in wifi_tools.items():
            if not shutil.which(tool):
                missing.append((tool, pkg))
        
        if not missing:
            self.actions.append(ConfigAction(
                name="wifi_tools",
                description="Check for missing WiFi security tools",
                success=True,
                message="All WiFi security tools are already installed",
                requires_root=False,
            ))
            return
        
        if not self.privileges.can_escalate:
            tool_names = ", ".join(t for t, _ in missing)
            self.actions.append(ConfigAction(
                name="wifi_tools",
                description="Install missing WiFi security tools",
                success=False,
                message=f"Missing WiFi tools (requires root to install): {tool_names}",
                requires_root=True,
            ))
            return
        
        # Detect package manager
        pm = None
        if shutil.which("apt"):
            pm = "apt"
        elif shutil.which("dnf"):
            pm = "dnf"
        elif shutil.which("pacman"):
            pm = "pacman"
        elif shutil.which("apk"):
            pm = "apk"
        
        if not pm:
            self.actions.append(ConfigAction(
                name="wifi_tools",
                description="Install missing WiFi security tools",
                success=False,
                message="No supported package manager found",
                requires_root=True,
            ))
            return
        
        # Install missing packages
        pkgs = [pkg for _, pkg in missing]
        unique_pkgs = list(set(pkgs))
        
        # Build sudo prefix if we can escalate
        sudo_prefix = ["sudo", "-n"] if self.privileges.can_escalate else []
        
        try:
            if pm == "apt":
                _run(sudo_prefix + ["apt", "update"])
                rc, out, err = _run(sudo_prefix + ["apt", "install", "-y"] + unique_pkgs, timeout=120)
            elif pm == "dnf":
                rc, out, err = _run(sudo_prefix + ["dnf", "install", "-y"] + unique_pkgs, timeout=120)
            elif pm == "pacman":
                rc, out, err = _run(sudo_prefix + ["pacman", "-S", "--noconfirm"] + unique_pkgs, timeout=120)
            elif pm == "apk":
                _run(sudo_prefix + ["apk", "update"])
                rc, out, err = _run(sudo_prefix + ["apk", "add"] + unique_pkgs, timeout=120)
            else:
                rc = 1
                err = "Unknown package manager"
            
            if rc == 0:
                self.actions.append(ConfigAction(
                    name="wifi_tools",
                    description="Install missing WiFi security tools",
                    success=True,
                    message=f"Installed packages: {', '.join(unique_pkgs)}",
                    requires_root=True,
                ))
            else:
                self.actions.append(ConfigAction(
                    name="wifi_tools",
                    description="Install missing WiFi security tools",
                    success=False,
                    message=f"Failed to install some packages: {err}",
                    requires_root=True,
                ))
        except Exception as e:
            self.actions.append(ConfigAction(
                name="wifi_tools",
                description="Install missing WiFi security tools",
                success=False,
                message=f"Installation error: {e}",
                requires_root=True,
            ))


def run_auto_config(cfg: Dict[str, Any]) -> List[ConfigAction]:
    """Run all WiFi auto-configuration steps and return results."""
    configurator = AutoConfigurator(cfg)
    return configurator.run_all()