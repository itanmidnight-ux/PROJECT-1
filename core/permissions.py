"""
CyberScope — core/permissions.py

Detects what privilege level CyberScope actually has on this device —
never assumes, never fakes it. Works the same way on plain Linux and on
Termux/Android:

  1. Already root (euid == 0)?
  2. Passwordless sudo available? (`sudo -n true` — never prompts)
  3. `su` available and already authorized? (probes non-interactively
     with stdin closed and a short timeout, so a Magisk/SuperSU grant
     dialog on Android can be answered by the user out-of-band, but we
     never hang waiting for a password)
  4. Termux-specific `tsu` wrapper present?

Nothing here escalates privileges destructively — it only probes whether
escalation is already possible, so the rest of the platform can decide
which modules to offer.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _probe(cmd: List[str], timeout: float) -> Optional[int]:
    """Run a command with stdin closed so it can never block on a
    password prompt. Returns the exit code, or None if it couldn't run
    or timed out (e.g. an Android su prompt is pending user approval)."""
    try:
        r = subprocess.run(
            cmd, stdin=subprocess.DEVNULL,
            capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return r.returncode
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return None


@dataclass
class PrivilegeStatus:
    is_root:         bool               # already running as euid 0
    method:          str                # "already_root" / "sudo_nopasswd" / "su_granted" / "none"
    sudo_available:  bool
    sudo_nopasswd:   bool
    su_available:    bool
    su_granted:      bool
    tsu_available:   bool                # Termux su wrapper
    is_termux:       bool
    reason:          str = ""
    details:         Dict[str, Any] = field(default_factory=dict)

    @property
    def can_escalate(self) -> bool:
        return self.is_root or self.sudo_nopasswd or self.su_granted

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_root":        self.is_root,
            "method":         self.method,
            "can_escalate":   self.can_escalate,
            "sudo_available": self.sudo_available,
            "sudo_nopasswd":  self.sudo_nopasswd,
            "su_available":   self.su_available,
            "su_granted":     self.su_granted,
            "tsu_available":  self.tsu_available,
            "is_termux":      self.is_termux,
            "reason":         self.reason,
            "details":        self.details,
        }


def detect_privileges(probe_timeout: float = 3.0) -> PrivilegeStatus:
    """Non-destructive, non-interactive probe of available privilege
    escalation paths. Safe to call on every run — never prompts, never
    blocks longer than probe_timeout per check."""
    is_termux = (
        "com.termux" in os.environ.get("PREFIX", "")
        or os.path.exists("/data/data/com.termux")
    )

    if os.geteuid() == 0:
        return PrivilegeStatus(
            is_root=True, method="already_root",
            sudo_available=_tool_exists("sudo"), sudo_nopasswd=True,
            su_available=_tool_exists("su"), su_granted=True,
            tsu_available=_tool_exists("tsu"), is_termux=is_termux,
            reason="Running as root (euid 0)",
        )

    sudo_available = _tool_exists("sudo")
    sudo_nopasswd  = False
    if sudo_available:
        # `sudo -n` never prompts: returns 0 only if a password isn't needed.
        rc = _probe(["sudo", "-n", "true"], probe_timeout)
        sudo_nopasswd = (rc == 0)

    su_available = _tool_exists("su")
    su_granted   = False
    if su_available:
        # stdin is closed, so a plain `su` waiting on a TTY password
        # exits immediately instead of hanging; on rooted
        # Android/Magisk, an already-granted app returns 0 straight away.
        rc = _probe(["su", "-c", "id"], probe_timeout)
        su_granted = (rc == 0)

    tsu_available = is_termux and _tool_exists("tsu")

    if sudo_nopasswd:
        method, reason = "sudo_nopasswd", "Passwordless sudo is configured"
    elif su_granted:
        method, reason = "su_granted", "su access already granted"
    else:
        method = "none"
        if is_termux:
            reason = (
                "No elevated access. On Termux, install tsu/su from a "
                "rooted Android setup (Magisk) to enable it."
            )
        else:
            reason = "No elevated access available without interactive credentials"

    return PrivilegeStatus(
        is_root=False, method=method,
        sudo_available=sudo_available, sudo_nopasswd=sudo_nopasswd,
        su_available=su_available, su_granted=su_granted,
        tsu_available=tsu_available, is_termux=is_termux,
        reason=reason,
    )
