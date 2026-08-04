"""
CyberScope — core/authorization.py

The consent gate every active-testing feature (credential checks, WPA
handshake capture, exploit verification) must pass through before it
touches a real target. Deliberately not a simple yes/no prompt: the
caller must type the target's own identifier back, so a reflexive "y"
can never authorize an action against the wrong host.

Pure and UI-agnostic (no rich/console imports here, matching the rest
of core/) — main.py owns the actual warning text and prompt, and calls
confirm_target() with whatever the user typed back.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("cyberscope.authorization")

WARNING_TEMPLATE = (
    "This action actively tests {target} — it is not passive observation. "
    "Only proceed if you own this device/network or have explicit written "
    "authorization to test it. Unauthorized access attempts are illegal in "
    "most jurisdictions, even with good intentions."
)


@dataclass
class AuthorizationDecision:
    target:     str
    action:     str
    granted:    bool
    reason:     str = ""
    timestamp:  str = ""

    def to_dict(self) -> dict:
        return {
            "target": self.target, "action": self.action,
            "granted": self.granted, "reason": self.reason,
            "timestamp": self.timestamp,
        }


def confirm_target(target: str, action: str, typed: str) -> AuthorizationDecision:
    """
    Grants authorization only when `typed` matches `target` exactly
    (case-insensitive, whitespace-trimmed). Never accepts a bare
    "y"/"yes"/"" — that pattern is too easy to hit reflexively on a
    target the caller didn't actually mean to test. Every decision
    (granted or denied) is logged for the audit trail.
    """
    now = datetime.now(timezone.utc).isoformat()
    granted = bool(typed) and typed.strip().lower() == target.strip().lower()
    decision = AuthorizationDecision(
        target=target, action=action, granted=granted,
        reason="" if granted else "typed confirmation did not match target",
        timestamp=now,
    )
    level = log.info if granted else log.warning
    level(
        "authorization %s: action=%r target=%r",
        "GRANTED" if granted else "DENIED", action, target,
    )
    return decision
