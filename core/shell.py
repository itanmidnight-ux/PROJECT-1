"""
CyberScope — core/shell.py

Single, shared subprocess/tool-detection layer. Every scan/monitor
module used to carry its own near-identical copy of these helpers
(8 copies of a subprocess wrapper, 3 of a tool-exists check, 3 of a
SELinux-tolerant directory listing) — consolidated here so there's
exactly one implementation to trust, with the exact same call/return
contracts each caller already relied on preserved via thin local
aliases at each call site.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class RunResult:
    """Uniform result of a subprocess invocation. Never raises to the
    caller — a command that couldn't even be launched (missing binary,
    timeout, permission denied, ...) comes back as returncode=-1 with
    the error message in `stderr`."""
    returncode: int
    stdout:     str
    stderr:     str

    @property
    def combined(self) -> str:
        return self.stdout + self.stderr

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(
    cmd: List[str],
    timeout: float = 10,
    stdin: Optional[int] = None,
) -> RunResult:
    """Run a command, capturing stdout/stderr separately. Never raises:
    any launch failure, timeout, or permission error comes back as
    RunResult(-1, "", "<error message>")."""
    try:
        r = subprocess.run(
            cmd, stdin=stdin, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return RunResult(r.returncode, r.stdout, r.stderr)
    except Exception as e:
        # Broad on purpose: this is the single call site every module in
        # the platform relies on to *never* raise (missing binary, a
        # timeout, a permission error, or even a malformed cmd list).
        return RunResult(-1, "", str(e))


def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def safe_iterdir(path: Path) -> List[Path]:
    """List a directory, tolerating sysfs paths SELinux blocks (Termux/Android)."""
    try:
        return list(path.iterdir())
    except (PermissionError, OSError):
        return []
