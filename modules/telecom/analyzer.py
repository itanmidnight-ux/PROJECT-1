"""
SS7 Security Research Framework — analyzer.py

Defensive analysis engine.

Classes
-------
Finding         — structured security finding with MITRE ATT&CK refs
SS7Analyzer     — stateful anomaly detector + report generator
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from protocols import MAPMessage, MAPOp, SCCPMessage

log = logging.getLogger("ss7analyzer")


# ============================================================
# Finding
# ============================================================

class Severity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: "Severity") -> bool:
        _ord = [e.value for e in Severity]
        return _ord.index(self.value) < _ord.index(other.value)


@dataclass
class Finding:
    """
    A single security finding produced during analysis.

    Matches the format documented in the framework spec:
      Type / Severity / Description / Evidence / Recommendation / MITRE
    """
    type:           str
    severity:       Severity
    description:    str
    evidence:       str = ""
    recommendation: str = ""
    mitre:          Optional[str] = None
    source:         Optional[str] = None
    target:         Optional[str] = None
    timestamp:      datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":           self.type,
            "severity":       self.severity.value,
            "description":    self.description,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "mitre":          self.mitre,
            "source":         self.source,
            "target":         self.target,
            "timestamp":      self.timestamp.isoformat(),
        }


# ============================================================
# SS7Analyzer
# ============================================================

# Operations that must never originate from untrusted/external sources
_RESTRICTED: Dict[int, Severity] = {
    int(MAPOp.INSERT_SUBSCRIBER_DATA):  Severity.CRITICAL,
    int(MAPOp.DELETE_SUBSCRIBER_DATA):  Severity.CRITICAL,
    int(MAPOp.CANCEL_LOCATION):         Severity.CRITICAL,
    int(MAPOp.PURGE_MS):                Severity.HIGH,
    int(MAPOp.PROVIDE_ROAMING_NUMBER):  Severity.HIGH,
    int(MAPOp.SEND_AUTH_INFO):          Severity.HIGH,
    int(MAPOp.ROUTING_INFO_FOR_SM):     Severity.HIGH,
}

# MITRE ATT&CK for Mobile refs per threat type
_MITRE: Dict[str, str] = {
    "RESTRICTED_OPERATION":        "T1600.001",
    "SUBSCRIBER_DATA_MANIPULATION":"T1557.002",
    "SRI_RATE_BURST":              "T1590.001",
    "SUBSCRIBER_TRACKING":         "T1591.001",
    "AUTH_VECTOR_REQUEST":         "T1557",
    "EXTERNAL_MAP_SCCP":           "T1600",
}


class SS7Analyzer:
    """
    Stateful, passive SS7 threat detector.

    Feed messages through check_map() / check_sccp().
    Retrieve all findings via generate_report().
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        ac = cfg.get("analysis", {})
        self._rate_window  = int(ac.get("rate_window_seconds", 60))
        self._sri_thresh   = int(ac.get("sri_burst_threshold", 10))
        self._isd_thresh   = int(ac.get("isd_burst_threshold", 3))
        self._track_thresh = int(ac.get("tracking_threshold", 5))

        # {source_ip: [{t: datetime, op: int}]}
        self._src_events: Dict[str, List[Dict]] = defaultdict(list)
        # {msisdn: [datetime]}  — SRI per MSISDN in last hour
        self._msisdn_sri:  Dict[str, List[datetime]] = defaultdict(list)

    # ------------------------------------------------------------------
    # MAP checks
    # ------------------------------------------------------------------

    def check_map(
        self,
        msg: MAPMessage,
        source: str,
        session: Any,     # AuditSession (avoid circular import)
    ) -> List[Finding]:
        found: List[Finding] = []
        now = datetime.now(timezone.utc)
        op  = msg.operation_code

        # 1. Restricted operation from external source
        if op in _RESTRICTED:
            sev = _RESTRICTED[op]
            f = Finding(
                type="RESTRICTED_OPERATION",
                severity=sev,
                description=(
                    f"Restricted MAP operation {msg.operation_name} received from {source}. "
                    f"This operation should never originate outside the home network."
                ),
                evidence=f"op={op} ({msg.operation_name}) src={source}",
                recommendation=(
                    "Verify SS7 firewall rules. Block or challenge this operation "
                    "at the network boundary (GSMA FS.11 category 2/3)."
                ),
                mitre=_MITRE["RESTRICTED_OPERATION"],
                source=source,
            )
            found.append(f)

        # 2. ISD — subscriber data manipulation
        if op == int(MAPOp.INSERT_SUBSCRIBER_DATA):
            target = self._extract_msisdn(msg)
            f = Finding(
                type="SUBSCRIBER_DATA_MANIPULATION",
                severity=Severity.CRITICAL,
                description=(
                    f"ISD attempt for {target or 'unknown'} from {source}. "
                    f"Possible SMS/call redirect configuration attack."
                ),
                evidence=f"src={source} target={target} raw={msg.raw.hex() if msg.raw else '?'}",
                recommendation=(
                    "Block ISD from inter-PLMN links. Require mutual authentication. "
                    "Alert NOC immediately."
                ),
                mitre=_MITRE["SUBSCRIBER_DATA_MANIPULATION"],
                source=source, target=target,
            )
            found.append(f)

        # 3. SAI — auth vector theft
        if op == int(MAPOp.SEND_AUTH_INFO):
            f = Finding(
                type="AUTH_VECTOR_REQUEST",
                severity=Severity.HIGH,
                description=(
                    f"SendAuthenticationInfo from {source}. Possible attempt to obtain "
                    f"authentication vectors for SIM cloning or man-in-the-middle attacks."
                ),
                evidence=f"src={source}",
                recommendation="Block SAI from untrusted network elements. Enable SAI filtering.",
                mitre=_MITRE["AUTH_VECTOR_REQUEST"],
                source=source,
            )
            found.append(f)

        # 4. SRI rate burst
        if op == int(MAPOp.SEND_ROUTING_INFO):
            self._track(source, op, now)
            count = self._count(source, op, now)
            msisdn = self._extract_msisdn(msg)

            if msisdn:
                self._msisdn_sri[msisdn].append(now)
                self._prune_msisdn(msisdn, now)

            if count > self._sri_thresh:
                f = Finding(
                    type="SRI_RATE_BURST",
                    severity=Severity.HIGH,
                    description=(
                        f"{count} SRI queries in {self._rate_window}s from {source}. "
                        f"Possible bulk subscriber location harvesting."
                    ),
                    evidence=f"src={source} count={count} window={self._rate_window}s",
                    recommendation=(
                        "Implement SRI rate limiting. Throttle > 5 SRI/min per source."
                    ),
                    mitre=_MITRE["SRI_RATE_BURST"],
                    source=source,
                )
                found.append(f)

            # Per-subscriber tracking
            if msisdn:
                msisdn_count = len(self._msisdn_sri.get(msisdn, []))
                if msisdn_count >= self._track_thresh:
                    f = Finding(
                        type="SUBSCRIBER_TRACKING",
                        severity=Severity.HIGH,
                        description=(
                            f"{msisdn_count} SRI queries for {msisdn} in 1 hour from {source}. "
                            f"Possible real-time location tracking."
                        ),
                        evidence=f"msisdn={msisdn} count={msisdn_count} src={source}",
                        recommendation=(
                            "Enable per-subscriber SRI throttling. "
                            "Alert on repetitive location queries."
                        ),
                        mitre=_MITRE["SUBSCRIBER_TRACKING"],
                        source=source, target=msisdn,
                    )
                    found.append(f)

        # Store & return
        for f in found:
            session.add_finding(f.to_dict())
        return found

    # ------------------------------------------------------------------
    # SCCP checks
    # ------------------------------------------------------------------

    def check_sccp(
        self,
        msg: SCCPMessage,
        source: str,
        session: Any,
    ) -> List[Finding]:
        found: List[Finding] = []

        # MAP SSN (147) traffic from external source
        if msg.called and msg.called.ssn == 147:
            f = Finding(
                type="EXTERNAL_MAP_SCCP",
                severity=Severity.MEDIUM,
                description=(
                    f"SCCP UDT to MAP SSN=147 received from external source {source}. "
                    f"Ensure inter-PLMN firewall is active and filtering MAP SSN."
                ),
                evidence=f"src={source} called_ssn=147",
                recommendation=(
                    "Deploy SS7 firewall (IPX/GPRS-backbone level). "
                    "Filter MAP operations at category 1 minimum."
                ),
                mitre=_MITRE["EXTERNAL_MAP_SCCP"],
                source=source,
            )
            found.append(f)

        for f in found:
            session.add_finding(f.to_dict())
        return found

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, session: Any) -> Dict[str, Any]:
        by_sev: Dict[str, List] = defaultdict(list)
        for f in session.findings:
            by_sev[f.get("severity","INFO")].append(f)

        return {
            "meta": {
                "tool":       "SS7 Security Research Framework",
                "version":    "2.0",
                "disclaimer": "Authorized laboratory use only — synthetic/simulated data.",
                "generated":  datetime.now(timezone.utc).isoformat(),
            },
            "session":     session.summary(),
            "total_findings": len(session.findings),
            "by_severity": {
                s.value: len(by_sev.get(s.value, []))
                for s in Severity
            },
            "findings": dict(by_sev),
        }

    def format_text(self, report: Dict[str, Any]) -> str:
        """Render report as human-readable text."""
        lines = ["=" * 70,
                 "  SS7 SECURITY RESEARCH FRAMEWORK — ANALYSIS REPORT",
                 "=" * 70,
                 f"Generated : {report['meta']['generated']}",
                 ""]
        sess = report.get("session", {})
        lines += [
            "SESSION",
            f"  ID      : {sess.get('session_id')}",
            f"  Source  : {sess.get('source')}",
            f"  Packets : {sess.get('stats', {}).get('packets', 0)}",
            f"  MAP msgs: {sess.get('stats', {}).get('map', 0)}",
            "",
            f"FINDINGS  ({report['total_findings']} total)",
        ]
        for sev, lst in report.get("findings", {}).items():
            for f in lst:
                lines += [
                    f"  [{sev}] {f.get('type','?')}",
                    f"    Description: {f.get('description','')}",
                    f"    Evidence   : {f.get('evidence','')}",
                    f"    Recommend  : {f.get('recommendation','')}",
                    f"    MITRE      : {f.get('mitre','—')}",
                    "",
                ]
        lines += ["=" * 70, "End of Report", "=" * 70]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _track(self, source: str, op: int, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._rate_window)
        self._src_events[source] = [
            e for e in self._src_events[source] if e["t"] > cutoff
        ]
        self._src_events[source].append({"t": now, "op": op})

    def _count(self, source: str, op: int, now: datetime) -> int:
        return sum(1 for e in self._src_events.get(source, []) if e["op"] == op)

    def _prune_msisdn(self, msisdn: str, now: datetime) -> None:
        cutoff = now - timedelta(hours=1)
        self._msisdn_sri[msisdn] = [
            t for t in self._msisdn_sri[msisdn] if t > cutoff
        ]

    @staticmethod
    def _extract_msisdn(msg: MAPMessage) -> Optional[str]:
        from protocols import ISDNAddress, ParseError as PE
        for k in ("msisdn", "ctx_0", "ctx_1"):
            v = msg.parameters.get(k)
            if isinstance(v, str): return v
            if isinstance(v, dict) and "hex" in v:
                try: return ISDNAddress.decode(bytes.fromhex(v["hex"])).digits
                except PE: pass
        return None
