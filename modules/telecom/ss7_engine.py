"""
SS7 Security Research Framework — ss7_engine.py

Motor principal: orquesta módulos, gestiona sesiones y flujo de ejecución.

Classes
-------
SS7Engine       — punto de entrada del framework
SessionManager  — ciclo de vida de sesiones
AuditSession    — contexto de una sesión de análisis
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from protocols import (
    BERCodec, MAPCodec, MAPMessage, MAPOp, ProtocolData,
    ParseError, ValidationError,
    parse_m3ua, parse_sccp, parse_sctp, parse_tcap, read_pcap,
    validate_host, validate_port,
)

log = logging.getLogger("ss7engine")


# ============================================================
# Configuration
# ============================================================

_DEFAULTS: Dict[str, Any] = {
    "mode": "laboratory",
    "logging": {"level": "INFO", "file": "logs/ss7framework.log"},
    "simulator": {"hlr_host": "127.0.0.1", "hlr_port": 2905,
                  "subscribers": 100, "timeout": 5},
    "analysis": {"rate_window_seconds": 60, "sri_burst_threshold": 10,
                 "isd_burst_threshold": 3, "tracking_threshold": 5},
    "output": {"report_dir": "reports", "default_format": "json"},
}


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    cfg = json.loads(json.dumps(_DEFAULTS))   # deep copy
    if Path(path).exists():
        with open(path) as f:
            user = yaml.safe_load(f)
        if user:
            _merge(cfg, user)
    return cfg


def _merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _merge(base[k], v)
        else:
            base[k] = v


def setup_logging(cfg: Dict[str, Any]) -> None:
    lc   = cfg.get("logging", {})
    lvl  = getattr(logging, str(lc.get("level","INFO")).upper(), logging.INFO)
    fmt  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=lvl, format=fmt)
    lf   = lc.get("file")
    if lf:
        Path(lf).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(lf)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt, "%Y-%m-%dT%H:%M:%S"))
        logging.getLogger().addHandler(fh)


# ============================================================
# AuditSession
# ============================================================

@dataclass
class AuditSession:
    """Context for a single analysis or simulation run."""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mode: str = "laboratory"
    source: Optional[str] = None      # PCAP path or simulator label
    events: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=lambda: {
        "packets": 0, "sctp": 0, "m3ua": 0,
        "sccp": 0, "tcap": 0, "map": 0, "errors": 0,
    })

    def log_event(self, kind: str, data: Dict[str, Any]) -> None:
        self.events.append({"ts": datetime.now(timezone.utc).isoformat(),
                            "kind": kind, **data})

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)
        log.warning(
            f"[{finding.get('severity','?')}] {finding.get('type','?')}: "
            f"{finding.get('description','')}"
        )

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "mode":       self.mode,
            "source":     self.source,
            "started":    self.created.isoformat(),
            "stats":      self.stats,
            "findings":   len(self.findings),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {**self.summary(), "events": self.events,
                "all_findings": self.findings}


# ============================================================
# SessionManager
# ============================================================

class SessionManager:
    """Tracks multiple audit sessions."""

    def __init__(self) -> None:
        self._sessions: Dict[str, AuditSession] = {}

    def new(self, mode: str = "laboratory", source: Optional[str] = None) -> AuditSession:
        s = AuditSession(mode=mode, source=source)
        self._sessions[s.session_id] = s
        log.info(f"Session {s.session_id} opened (mode={mode}, source={source})")
        return s

    def get(self, sid: str) -> Optional[AuditSession]:
        return self._sessions.get(sid)

    def all_sessions(self) -> List[AuditSession]:
        return list(self._sessions.values())


# ============================================================
# SS7Engine
# ============================================================

class SS7Engine:
    """
    Central orchestrator.

    Connects: PCAP reader / simulator → protocol parsers → analyzer → reporter.
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        self.cfg     = load_config(config_path)
        setup_logging(self.cfg)
        self.mode    = self.cfg.get("mode", "laboratory")
        self.sessions= SessionManager()
        self._map    = MAPCodec()
        self._ber    = BERCodec()

        # Lazy-import to keep engine independent of module availability
        from analyzer import SS7Analyzer
        from simulator import NetworkSimulator
        self.analyzer  = SS7Analyzer(self.cfg)
        self.simulator = NetworkSimulator(self.cfg)

        log.info(f"SS7Engine ready — mode={self.mode}")

    # ------------------------------------------------------------------
    # Analysis mode
    # ------------------------------------------------------------------

    def analyze_pcap(self, pcap_path: str, output_path: Optional[str] = None) -> Dict:
        """Parse a PCAP file through the full SS7 stack and detect threats."""
        session = self.sessions.new("analysis", pcap_path)
        log.info(f"[{session.session_id}] Analyzing {pcap_path}")

        for pkt in read_pcap(pcap_path):
            session.stats["packets"] += 1
            sctp_raw = pkt.sctp_payload()
            if not sctp_raw:
                continue

            try:
                sctp = parse_sctp(sctp_raw)
            except ParseError as exc:
                session.stats["errors"] += 1
                continue

            if not sctp.is_sigtran:
                continue
            session.stats["sctp"] += 1

            for payload in sctp.data_payloads():
                self._process_payload(payload, sctp, session)

        # Finalize
        report = self.analyzer.generate_report(session)
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            log.info(f"Report saved: {output_path}")

        return report

    def _process_payload(
        self,
        payload: bytes,
        sctp_pkt: Any,
        session: AuditSession,
    ) -> None:
        src = str(getattr(sctp_pkt, "src_port", "?"))

        # M3UA
        try:
            m3ua = parse_m3ua(payload)
            session.stats["m3ua"] += 1
        except ParseError:
            session.stats["errors"] += 1
            return

        pd = m3ua.protocol_data
        if not pd or pd.si != 3:          # si=3 → SCCP
            return

        # SCCP
        try:
            sccp = parse_sccp(pd.data)
            session.stats["sccp"] += 1
        except ParseError:
            session.stats["errors"] += 1
            return

        threats = self.analyzer.check_sccp(sccp, src, session)

        if not sccp.data:
            return

        # TCAP (optional — MAP can be embedded directly)
        map_data = sccp.data
        try:
            tcap = parse_tcap(sccp.data)
            session.stats["tcap"] += 1
            # Components hold the MAP payload
            if tcap.components:
                map_data = tcap.components[0]
        except (ParseError, Exception):
            pass

        # MAP
        try:
            msg = self._map.decode(map_data)
            session.stats["map"] += 1
            session.log_event("map_message", msg.to_dict())
            self.analyzer.check_map(msg, src, session)
        except ParseError:
            session.stats["errors"] += 1

    # ------------------------------------------------------------------
    # Decode mode
    # ------------------------------------------------------------------

    def decode_hex(self, hex_str: str, protocol: str = "map") -> Dict:
        """Decode a hex string through the specified protocol layer."""
        try:
            raw = bytes.fromhex(hex_str.replace(" ","").replace(":",""))
        except ValueError as exc:
            raise ValidationError(f"Invalid hex: {exc}") from exc

        proto = protocol.lower()
        if proto == "map":   return self._map.decode(raw).to_dict()
        if proto == "m3ua":  return parse_m3ua(raw).to_dict()
        if proto == "sccp":  return parse_sccp(raw).to_dict()
        if proto == "sctp":  return parse_sctp(raw).to_dict()
        if proto == "tcap":  return parse_tcap(raw).to_dict()
        if proto == "ber":
            elems = self._ber.decode_all(raw)
            return {"elements": [e.to_dict() for e in elems]}
        raise ValidationError(f"Unknown protocol: {protocol}")

    # ------------------------------------------------------------------
    # Simulation mode
    # ------------------------------------------------------------------

    async def run_simulator(self) -> None:
        """Start all simulated network nodes."""
        await self.simulator.start_all()

    # ------------------------------------------------------------------
    # Report mode
    # ------------------------------------------------------------------

    def generate_report(
        self,
        session_id: Optional[str] = None,
        fmt: str = "json",
    ) -> str:
        """Generate a report from the most recent (or specified) session."""
        if session_id:
            session = self.sessions.get(session_id)
        else:
            all_s = self.sessions.all_sessions()
            session = all_s[-1] if all_s else None

        if not session:
            return json.dumps({"error": "No session found"})

        report = self.analyzer.generate_report(session)
        out_dir = Path(self.cfg.get("output", {}).get("report_dir", "reports"))
        out_dir.mkdir(parents=True, exist_ok=True)

        ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        sid = session.session_id

        if fmt == "text":
            path = out_dir / f"report_{sid}_{ts}.txt"
            path.write_text(self.analyzer.format_text(report))
        else:
            path = out_dir / f"report_{sid}_{ts}.json"
            path.write_text(json.dumps(report, indent=2, default=str))

        log.info(f"Report: {path}")
        return str(path)
