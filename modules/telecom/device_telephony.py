"""
CyberScope — modules/telecom/device_telephony.py

Real (non-simulated) cellular/telephony state of the device CyberScope
is actually running on — as opposed to modules/telecom/simulator.py,
which is a synthetic SS7 laboratory. Tried in order of how much access
each needs, and every source degrades gracefully: if a command isn't
available or its output can't be parsed, that source is skipped —
never faked.

  1. Termux:API (`termux-telephony-info` / `termux-telephony-cellinfo`)
     — no root required, just the Termux:API companion app and its
     one-time Android permission grant.
  2. `su -c "dumpsys telephony.registry"` — requires root (e.g. Magisk
     on a rooted Android/Termux setup); best-effort text parsing since
     the format varies by Android version.
  3. `getprop gsm.*` — a handful of read-only system properties,
     available without any special permission on most Android builds.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def _run(cmd: List[str], timeout: int = 5) -> Tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, errors="replace")
        return r.returncode, r.stdout
    except Exception as e:
        return -1, str(e)


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


@dataclass
class CellInfo:
    cell_type:  str            = ""
    registered: bool           = False
    mcc:        str            = ""
    mnc:        str            = ""
    lac:        str            = ""
    cid:        str            = ""
    tac:        str            = ""
    dbm:        Optional[int]  = None
    level:      Optional[int]  = None

    def to_dict(self) -> Dict[str, Any]:
        return dict(vars(self))


@dataclass
class DeviceTelephony:
    source:                 str                  # "termux-api" / "dumpsys" / "getprop"
    network_operator_name:  str                  = ""
    network_type:           str                  = ""
    sim_state:               str                 = ""
    sim_operator_name:       str                 = ""
    roaming:                 Optional[bool]      = None
    data_state:              str                 = ""
    cells:                   List[CellInfo]      = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source":                self.source,
            "network_operator_name": self.network_operator_name,
            "network_type":          self.network_type,
            "sim_state":             self.sim_state,
            "sim_operator_name":     self.sim_operator_name,
            "roaming":               self.roaming,
            "data_state":            self.data_state,
            "cells":                 [c.to_dict() for c in self.cells],
        }


def detect_real_telephony() -> Optional[DeviceTelephony]:
    """
    Best-effort read of the device's own real telephony state. Returns
    None if no source is available at all (e.g. a plain Linux box, or
    an Android device without Termux:API/root) — callers should fall
    back to the laboratory simulator in that case.
    """
    for probe in (_via_termux_api, _via_dumpsys, _via_getprop):
        dt = probe()
        if dt is not None:
            return dt
    return None


def _via_termux_api() -> Optional[DeviceTelephony]:
    if not _tool_exists("termux-telephony-info"):
        return None
    rc, out = _run(["termux-telephony-info"], timeout=8)
    if rc != 0 or not out.strip():
        return None
    try:
        info = json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None

    dt = DeviceTelephony(
        source="termux-api",
        network_operator_name=str(info.get("network_operator_name", "") or ""),
        network_type=str(info.get("network_type", "") or ""),
        sim_state=str(info.get("sim_state", "") or ""),
        sim_operator_name=str(info.get("sim_operator_name", "") or ""),
        data_state=str(info.get("data_state", "") or ""),
    )

    if _tool_exists("termux-telephony-cellinfo"):
        rc2, out2 = _run(["termux-telephony-cellinfo"], timeout=8)
        if rc2 == 0 and out2.strip():
            try:
                cells = json.loads(out2)
            except (json.JSONDecodeError, ValueError, TypeError):
                cells = []
            for c in cells if isinstance(cells, list) else []:
                if not isinstance(c, dict):
                    continue
                dt.cells.append(CellInfo(
                    cell_type=str(c.get("type", "") or ""),
                    registered=bool(c.get("registered", False)),
                    mcc=str(c.get("mcc", "") or ""),
                    mnc=str(c.get("mnc", "") or ""),
                    lac=str(c.get("lac", "") or ""),
                    cid=str(c.get("cid", "") or ""),
                    tac=str(c.get("tac", "") or ""),
                    dbm=c.get("dbm"),
                    level=c.get("level"),
                ))
    return dt


def _via_dumpsys() -> Optional[DeviceTelephony]:
    if not _tool_exists("su"):
        return None
    rc, out = _run(["su", "-c", "dumpsys telephony.registry"], timeout=8)
    if rc != 0 or not out.strip():
        return None
    return parse_dumpsys_telephony(out)


def parse_dumpsys_telephony(out: str) -> Optional[DeviceTelephony]:
    """Best-effort regex extraction from `dumpsys telephony.registry`
    text. Pure function — testable against a captured sample without
    root or a real device. Returns None if nothing useful was found."""

    def _find(pattern: str) -> str:
        m = re.search(pattern, out)
        return m.group(1).strip() if m else ""

    # Operator names can contain spaces ("Verizon Wireless", "Test Carrier"),
    # so stop at the next dumpsys key=value field (or end of line) instead
    # of the first whitespace.
    _NEXT_FIELD = r"(?=\s+\S+=|\n|$)"
    operator = (_find(r"mOperatorAlphaLong=(.*?)" + _NEXT_FIELD)
                or _find(r"operatorAlphaLong=(.*?)" + _NEXT_FIELD))
    net_type = (_find(r"mDataNetworkType=(\S+)")
                or _find(r"mVoiceNetworkType=(\S+)"))
    dbm      = _find(r"mSignalStrength=.*?(-?\d{2,3})\s*dBm")
    roaming  = _find(r"mIsRoaming=(true|false)") or _find(r"mRoaming=(true|false)")

    if not (operator or net_type or dbm):
        return None  # dumpsys ran but we couldn't parse anything useful

    dt = DeviceTelephony(
        source="dumpsys",
        network_operator_name=operator,
        network_type=net_type,
        roaming=(roaming == "true") if roaming else None,
    )
    if dbm:
        try:
            dt.cells.append(CellInfo(dbm=int(dbm), registered=True))
        except ValueError:
            pass
    return dt


def _via_getprop() -> Optional[DeviceTelephony]:
    if not _tool_exists("getprop"):
        return None

    def _prop(name: str) -> str:
        rc, out = _run(["getprop", name], timeout=3)
        return out.strip() if rc == 0 else ""

    operator  = _prop("gsm.operator.alpha")
    net_type  = _prop("gsm.network.type")
    sim_state = _prop("gsm.sim.state")

    if not (operator or net_type or sim_state):
        return None

    return DeviceTelephony(
        source="getprop",
        network_operator_name=operator,
        network_type=net_type,
        sim_state=sim_state,
    )
