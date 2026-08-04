"""
CyberScope — modules/telecom/monitor.py

Live Telecom/SS7 monitor. The telecom capability is always available as
a laboratory simulator (no real SIGTRAN/operator connectivity — see
modules/telecom/simulator.py), so "listening for signals" here means
watching subscriber activity as it hits the same HLR/VLR/SMSC handlers
real MAP traffic would: SendRoutingInfo, UpdateLocation, SMS routing,
and occasional InsertSubscriberData attempts, which the HLR already
rejects and flags suspicious exactly like a real network element would.

A background thread generates that synthetic traffic so the live view
has something to show without a physical SIGTRAN capture; each
subscriber's activity is tracked in a live registry the same way
WiFiMonitor/BluetoothMonitor/NetworkMonitor track their devices.

For real captured traffic, feed a PCAP through the existing
SS7Analyzer (modules/telecom/analyzer.py) directly — this module
covers the always-available simulator path.
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

_TELECOM_DIR = str(Path(__file__).parent)
if _TELECOM_DIR not in sys.path:
    sys.path.insert(0, _TELECOM_DIR)

from simulator import SimulatedHLR, SimulatedSMSC, SimulatedVLR, Subscriber, SubscriberDB  # noqa: E402


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


class TelecomMonitor:
    """
    Continuous laboratory SS7 monitor: a synthetic subscriber DB behind
    the same SimulatedHLR/VLR/SMSC handlers the rest of the telecom
    module uses, with a background traffic generator and a live,
    per-subscriber activity registry.
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

    @property
    def available(self) -> bool:
        return True  # simulator is always available, per the capability report

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

    def poll(self) -> List[TrackedSubscriber]:
        """Merge any new audit-log entries into the live registry,
        return current list, most recently active first."""
        log = self.db.query_log()
        new_entries = log[self._processed:]
        self._processed = len(log)
        merge_activity(self.registry, self.db._db, new_entries)
        return sorted(self.registry.values(), key=lambda s: s.last_seen, reverse=True)

    def probe(self, msisdn: str) -> List[Finding]:
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
