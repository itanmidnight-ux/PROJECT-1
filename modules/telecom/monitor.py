"""
CyberScope — modules/telecom/monitor.py

Live Telecom/SS7 monitor with two data sources, clearly labeled so
neither is ever mistaken for the other:

  1. "device"  — the real cellular state of the device CyberScope is
     running on (modules/telecom/device_telephony.py): operator,
     network type, serving cell, signal strength. Only present when a
     real source is actually reachable (Termux:API, root+dumpsys, or
     getprop) — never faked.

  2. "lab"     — the always-available SS7 laboratory simulator
     (modules/telecom/simulator.py). A background thread generates
     realistic synthetic subscriber activity — SendRoutingInfo,
     UpdateLocation, occasional InsertSubscriberData attempts — against
     the same HLR/VLR/SMSC handlers real MAP traffic would hit; the HLR
     rejects and flags ISD exactly like a real network element would.

Both feed the same live list→detail registry pattern used by the
network/wifi/bluetooth monitors.
"""
from __future__ import annotations

import random
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.types import Finding, Severity
from modules.telecom.device_telephony import DeviceTelephony, detect_real_telephony

_TELECOM_DIR = str(Path(__file__).parent)
if _TELECOM_DIR not in sys.path:
    sys.path.insert(0, _TELECOM_DIR)

from simulator import SimulatedHLR, SimulatedSMSC, SimulatedVLR, Subscriber, SubscriberDB  # noqa: E402

DEVICE_KEY = "__device__"

# Legacy radio access technologies with no mutual network authentication —
# the well-known precondition for fake base station / IMSI-catcher attacks.
_INSECURE_RATS = ("GSM", "EDGE", "GPRS", "2G", "1XRTT", "CDMA", "IDEN")


@dataclass
class TrackedSubscriber:
    msisdn:            str
    imsi:              str
    roaming:           bool
    lac:               str
    active:            bool
    events:            int   = 0
    suspicious_events: int   = 0
    last_op:           str   = ""
    last_seen:         float = 0.0


@dataclass
class TelecomListItem:
    """Uniform row for the live list, whether it came from the real
    device radio or the laboratory simulator."""
    key:        str
    kind:       str    # "device" or "lab"
    label:      str
    secondary:  str
    events:     int
    suspicious: int


def merge_activity(
    registry: Dict[str, TrackedSubscriber],
    subscribers: Dict[str, "Subscriber"],
    new_entries: List[Dict[str, Any]],
    now: Optional[float] = None,
) -> Dict[str, TrackedSubscriber]:
    """Fold newly-appended SubscriberDB.audit() log entries into a live
    registry keyed by MSISDN. Pure function — only ever sees the delta
    since the last poll, so it's safe to call repeatedly, and testable
    without asyncio or real sockets."""
    now = now if now is not None else time.time()
    for entry in new_entries:
        msisdn = entry.get("msisdn")
        t = registry.get(msisdn)
        if t is None:
            sub = subscribers.get(msisdn)
            if sub is None:
                continue
            t = TrackedSubscriber(
                msisdn=sub.msisdn, imsi=sub.imsi, roaming=sub.roaming,
                lac=sub.lac, active=sub.active,
            )
            registry[msisdn] = t
        t.events += 1
        if entry.get("suspicious"):
            t.suspicious_events += 1
        t.last_op = entry.get("op", "")
        t.last_seen = now
    return registry


def device_is_risky(dt: DeviceTelephony) -> bool:
    """Pure check used both to flag the list row and to build the probe
    findings — kept as one function so the two never disagree."""
    nt = (dt.network_type or "").upper()
    if any(rat in nt for rat in _INSECURE_RATS):
        return True
    return any(c.dbm is not None and c.dbm <= -110 for c in dt.cells)


class TelecomMonitor:
    """
    Continuous telecom monitor: real device radio state when a source is
    reachable, plus the laboratory SS7 simulator's live subscriber
    activity (always available).
    """

    def __init__(self, cfg: Dict[str, Any], subscriber_count: int = 15) -> None:
        tc = cfg.get("telecom", {})
        self.db   = SubscriberDB()
        self.db.populate(subscriber_count)
        self.hlr  = SimulatedHLR("127.0.0.1", tc.get("hlr_port", 2905), self.db)
        self.vlr  = SimulatedVLR(tc.get("vlr_port", 2906), self.db)
        self.smsc = SimulatedSMSC(tc.get("smsc_port", 2908))

        self.registry: Dict[str, TrackedSubscriber] = {}
        self._processed = 0
        self._traffic_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

        self._device_info: Optional[DeviceTelephony] = None
        self._device_checked = False   # True once we know real telephony is/isn't reachable

    @property
    def available(self) -> bool:
        return True  # simulator is always available, per the capability report

    @property
    def device_info(self) -> Optional[DeviceTelephony]:
        return self._device_info

    # ── Synthetic traffic ────────────────────────────────────────────

    def start_traffic(self, interval: float = 0.6) -> None:
        """Background generator of mostly-legitimate subscriber activity
        with an occasional external ISD probe — rejected and flagged
        suspicious by the HLR, same as a real network element would."""
        if self._traffic_thread is not None:
            return

        def _loop() -> None:
            msisdns = list(self.db._db.keys())
            while not self._stop.is_set() and msisdns:
                msisdn = random.choice(msisdns)
                roll = random.random()
                if roll < 0.75:
                    self.hlr.handle_sri(msisdn, "127.0.0.50", 1)
                elif roll < 0.92:
                    sub = self.db.lookup(msisdn)
                    if sub:
                        self.vlr.handle_update_location(sub.imsi, sub.msc_address, "127.0.0.51")
                else:
                    self.hlr.handle_isd(msisdn, "203.0.113.9", 2)
                self._stop.wait(interval)

        self._traffic_thread = threading.Thread(target=_loop, daemon=True)
        self._traffic_thread.start()

    def stop_traffic(self) -> None:
        self._stop.set()

    # ── Live registry ─────────────────────────────────────────────────

    def _poll_device(self) -> Optional[TelecomListItem]:
        """Re-probe real telephony each cycle so signal/operator stay
        live — but only while a source is actually reachable. Once a
        probe comes back empty we stop retrying every cycle so an
        Android device without Termux:API/root isn't hit with repeated
        failing subprocess calls on every refresh."""
        if self._device_checked and self._device_info is None:
            return None

        dt = detect_real_telephony()
        self._device_checked = True
        self._device_info = dt
        if dt is None:
            return None

        cell = dt.cells[0] if dt.cells else None
        return TelecomListItem(
            key=DEVICE_KEY, kind="device",
            label=dt.network_operator_name or "This device",
            secondary=dt.network_type or (cell.cell_type if cell else "unknown"),
            events=len(dt.cells),
            suspicious=1 if device_is_risky(dt) else 0,
        )

    def poll(self) -> List[TelecomListItem]:
        """Merge any new audit-log entries into the live registry and
        re-check real device telephony; return the current list with
        the device row (if present) pinned first."""
        items: List[TelecomListItem] = []

        device_item = self._poll_device()
        if device_item is not None:
            items.append(device_item)

        log = self.db.query_log()
        new_entries = log[self._processed:]
        self._processed = len(log)
        merge_activity(self.registry, self.db._db, new_entries)

        for s in sorted(self.registry.values(), key=lambda s: s.last_seen, reverse=True):
            items.append(TelecomListItem(
                key=s.msisdn, kind="lab", label=s.msisdn, secondary=s.imsi,
                events=s.events, suspicious=s.suspicious_events,
            ))
        return items

    # ── Security probes ──────────────────────────────────────────────

    def probe(self, key: str) -> List[Finding]:
        if key == DEVICE_KEY:
            return self._probe_device()
        return self._probe_subscriber(key)

    def _probe_device(self) -> List[Finding]:
        dt = self._device_info
        if dt is None:
            return []

        findings: List[Finding] = []
        nt = (dt.network_type or "").upper()
        if any(rat in nt for rat in _INSECURE_RATS):
            findings.append(Finding(
                type="INSECURE_RADIO_ACCESS_TECHNOLOGY",
                severity=Severity.HIGH,
                description=(
                    f"Device is registered on {dt.network_type}, a legacy radio "
                    f"technology with no mutual network authentication — "
                    f"vulnerable to fake base station / IMSI-catcher attacks."
                ),
                evidence=f"network_type={dt.network_type} operator={dt.network_operator_name}",
                recommendation=(
                    "Disable 2G fallback if supported (Android 12+: Settings > "
                    "Network & Internet > SIMs > Allow 2G), or use a carrier/device "
                    "that enforces LTE/5G-only registration."
                ),
                module="telecom",
                mitre="T1449",
            ))
        if dt.roaming:
            findings.append(Finding(
                type="DEVICE_ROAMING",
                severity=Severity.INFO,
                description=f"Device is currently roaming on {dt.network_operator_name}.",
                module="telecom",
            ))
        for cell in dt.cells:
            if cell.dbm is not None and cell.dbm <= -110:
                findings.append(Finding(
                    type="WEAK_SIGNAL",
                    severity=Severity.LOW,
                    description=(
                        f"Weak signal ({cell.dbm} dBm) — a device with poor "
                        f"coverage is more likely to fall back to a less secure "
                        f"network technology."
                    ),
                    evidence=f"dbm={cell.dbm} type={cell.cell_type}",
                    module="telecom",
                ))
        if not findings:
            findings.append(Finding(
                type="RADIO_NOMINAL",
                severity=Severity.INFO,
                description="No radio access technology or signal issues detected.",
                module="telecom",
            ))
        return findings

    def _probe_subscriber(self, msisdn: str) -> List[Finding]:
        """Flag subscribers with suspicious activity — the same
        defensive signal the HLR itself raises on a rejected ISD,
        scoped to one subscriber."""
        t = self.registry.get(msisdn)
        if not t:
            return []

        findings: List[Finding] = []
        if t.suspicious_events > 0:
            findings.append(Finding(
                type="SUBSCRIBER_DATA_MANIPULATION",
                severity=Severity.CRITICAL,
                description=(
                    f"{t.suspicious_events} suspicious operation(s) observed for "
                    f"{t.msisdn} (e.g. InsertSubscriberData from an external source)."
                ),
                evidence=f"msisdn={t.msisdn} imsi={t.imsi} suspicious_events={t.suspicious_events}",
                recommendation=(
                    "In a real deployment, block ISD/CancelLocation from inter-PLMN "
                    "links and alert the NOC immediately (GSMA FS.11 category 2/3)."
                ),
                module="telecom",
                mitre="T1557.002",
            ))
        if t.roaming:
            findings.append(Finding(
                type="SUBSCRIBER_ROAMING",
                severity=Severity.INFO,
                description=f"{t.msisdn} is currently marked as roaming ({t.lac}).",
                evidence=f"lac={t.lac}",
                module="telecom",
            ))
        if not findings:
            findings.append(Finding(
                type="SUBSCRIBER_NOMINAL",
                severity=Severity.INFO,
                description=f"No suspicious activity observed for {t.msisdn}.",
                module="telecom",
            ))
        return findings
