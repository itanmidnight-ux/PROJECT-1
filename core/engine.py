"""
CyberScope — core/engine.py

Central orchestrator: connects discovery → modules → AI → database → reports.
"""
from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import load_config
from core.discovery import SystemCapabilities, discover_all, save_capabilities_report
from core.types import ModuleResult, ModuleStatus
from core.event_bus import ASSET_OBSERVED, Event, EventBus

log = logging.getLogger("cyberscope.engine")


def _setup_logging(cfg: Dict[str, Any]) -> None:
    lc  = cfg.get("logging", {})
    lvl = getattr(logging, str(lc.get("level","INFO")).upper(), logging.INFO)
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    logging.basicConfig(level=lvl, format=fmt)
    lf  = lc.get("file")
    if lf:
        Path(lf).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(lf)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(fmt, "%Y-%m-%dT%H:%M:%S"))
        logging.getLogger().addHandler(fh)


class CyberScopeEngine:
    """
    Platform orchestrator.

    Responsibilities:
    - Load configuration
    - Run system discovery
    - Dispatch module scans
    - Run AI analysis
    - Persist results
    - Generate reports
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        self.cfg          = load_config(config_path)
        _setup_logging(self.cfg)
        self.session_id   = str(uuid.uuid4())[:8]
        self.capabilities: Optional[SystemCapabilities] = None
        self._results:     List[ModuleResult] = []

        # Lazy imports to keep startup fast
        from database.db import CyberScopeDB
        from ai.engine   import RiskEngine
        from reports.generator import ReportGenerator
        from core.asset_manager import AssetManager

        self.db       = CyberScopeDB(self.cfg.get("database", {}).get("path", "database/cyberscope.db"))
        self.ai       = RiskEngine()
        self.reporter = ReportGenerator(self.cfg.get("reports", {}).get("output_dir", "reports"))
        self.events   = EventBus()
        self.assets   = AssetManager(self.db, self.events)

        # Create the session row up front — module_results has a FK on
        # sessions(id) and modules may run before analyze() finalizes it.
        self.db.save_session(self.session_id, mode="in_progress")

        log.info(f"CyberScope Engine ready — session={self.session_id}")

    # ── Discovery ─────────────────────────────────────────────────────────

    def discover(self) -> SystemCapabilities:
        log.info("Running system discovery…")
        self.capabilities = discover_all()
        cap_path = self.cfg.get("discovery", {}).get(
            "capabilities_path", "logs/capabilities.json"
        )
        saved = save_capabilities_report(self.capabilities, cap_path)
        if saved:
            log.info(f"Capabilities report written to {saved}")
        return self.capabilities

    # ── Module dispatch ───────────────────────────────────────────────────

    def run_module(self, module: str) -> ModuleResult:
        """Run a single named module and store its result."""
        log.info(f"Running module: {module}")
        t0 = time.monotonic()

        try:
            result = self._dispatch_module(module)
        except Exception as exc:
            log.error(f"Module {module} failed: {exc}", exc_info=True)
            result = ModuleResult(
                module=module,
                status=ModuleStatus.ERROR,
                raw_data={"error": str(exc)},
                duration_ms=(time.monotonic() - t0) * 1000,
            )

        self._results.append(result)
        self.db.save_module_result(
            self.session_id, module, result.status.value,
            result.duration_ms, result.raw_data,
        )
        self._publish_assets(module, result)
        log.info(f"Module {module}: {result.finding_count} findings "
                 f"({result.duration_ms:.0f}ms)")
        return result

    def _publish_assets(self, module: str, result: ModuleResult) -> None:
        """
        Turn a module's raw scan data into Asset observations on the
        event bus. Only wifi/bluetooth static scans currently carry
        other-device identity data -- the network module's static scan
        only describes this host's own interfaces, not other hosts on
        the LAN; those are only visible via the live network monitor,
        which publishes its own observations directly (see main.py).
        """
        m = module.lower()

        if m == "wifi":
            from modules.wifi.scanner import WiFiNetwork
            for net in result.raw_data.get("networks", []):
                bssid = net.get("bssid")
                if not bssid:
                    continue
                self.events.publish(Event(
                    type=ASSET_OBSERVED,
                    payload={
                        "asset_type": "wifi_ap", "identifier": bssid,
                        "vendor": net.get("vendor", ""), "interfaces": ["wifi"],
                        "risk": WiFiNetwork(**net).risk_level,
                        "session_id": self.session_id,
                    },
                    source="wifi_scanner",
                ))

        elif m == "bluetooth":
            for dev in result.raw_data.get("devices", []):
                address = dev.get("address")
                if not address:
                    continue
                unnamed = dev.get("name") in ("", "Unknown", "Unknown BLE", None)
                self.events.publish(Event(
                    type=ASSET_OBSERVED,
                    payload={
                        "asset_type": "bluetooth_device", "identifier": address,
                        "vendor": dev.get("vendor", ""), "interfaces": ["bluetooth"],
                        "risk": "LOW" if unnamed else "INFO",
                        "session_id": self.session_id,
                    },
                    source="bluetooth_scanner",
                ))

    def _dispatch_module(self, module: str) -> ModuleResult:
        m = module.lower()

        if m == "network":
            from modules.network.discovery import NetworkDiscovery
            return NetworkDiscovery(self.cfg).run()

        if m == "wifi":
            from modules.wifi.scanner import WiFiScanner
            return WiFiScanner(self.cfg).run()

        if m == "bluetooth":
            from modules.bluetooth.scanner import BluetoothScanner
            return BluetoothScanner(self.cfg).run()

        if m == "device":
            from modules.device.system import DeviceAnalyzer
            return DeviceAnalyzer(self.cfg).run()

        if m == "telecom":
            return self._run_telecom()

        raise ValueError(f"Unknown module: {module}")

    def _run_telecom(self) -> ModuleResult:
        """Wrap the SS7 engine as a CyberScope module result."""
        import sys, os
        # Ensure telecom subpackage is importable
        telecom_dir = str(Path(__file__).parent.parent / "modules" / "telecom")
        if telecom_dir not in sys.path:
            sys.path.insert(0, telecom_dir)

        from modules.telecom.analyzer import SS7Analyzer
        from modules.telecom.simulator import SimulatedHLR, SubscriberDB
        from core.types import Finding, Severity

        # Minimal demo: show the module is active + functional
        db  = SubscriberDB()
        db.populate(10)
        hlr = SimulatedHLR("127.0.0.1", 2905, db)

        findings = [
            Finding(
                type="SS7_MODULE_ACTIVE",
                severity=Severity.INFO,
                description=(
                    "Telecom / SS7 analysis module active. "
                    "Use 'ss7audit analyze <pcap>' for full PCAP analysis."
                ),
                recommendation=(
                    "Provide a PCAP file captured from a SIGTRAN link "
                    "for detailed MAP threat detection."
                ),
                module="telecom",
            )
        ]

        return ModuleResult(
            module="telecom",
            status=ModuleStatus.AVAILABLE,
            findings=findings,
            raw_data={
                "ss7_opcodes": 20,
                "simulator": "HLR/VLR/MSC/SMSC (loopback)",
                "protocols": ["MAP","TCAP","SCCP","M3UA","SCTP","BER"],
                "subscribers_loaded": 10,
            },
        )

    # ── Auto-audit ────────────────────────────────────────────────────────

    def run_auto_audit(self, modules: Optional[List[str]] = None) -> List[ModuleResult]:
        """Run all available modules in sequence."""
        if self.capabilities is None:
            self.discover()

        caps = self.capabilities
        available = modules or caps.available_modules()  # type: ignore
        log.info(f"Auto-audit: running {available}")

        for mod in available:
            self.run_module(mod)

        return self._results

    # ── AI Analysis ───────────────────────────────────────────────────────

    def analyze(self):
        """Run AI risk engine over collected results."""
        from ai.engine import AIReport
        report = self.ai.analyze(self._results)

        # Persist
        all_findings = [f.to_dict() for r in self._results for f in r.findings]
        self.db.save_session(
            self.session_id,
            mode="auto_audit",
            risk_level=report.risk_score.level,
            risk_score=report.risk_score.overall,
            modules_run=[r.module for r in self._results],
            summary=report.executive_summary,
        )
        self.db.save_findings(self.session_id, all_findings)

        return report

    # ── Report generation ─────────────────────────────────────────────────

    def save_reports(self, ai_report, formats: Optional[List[str]] = None) -> Dict[str, str]:
        fmts   = formats or self.cfg.get("reports", {}).get("formats", ["json","html","markdown"])
        paths: Dict[str, str] = {}

        if "json" in fmts:
            paths["json"] = self.reporter.save_json(
                ai_report, self._results, self.session_id
            )
        if "html" in fmts:
            paths["html"] = self.reporter.save_html(
                ai_report, self._results, self.session_id
            )
        if "markdown" in fmts:
            paths["markdown"] = self.reporter.save_markdown(
                ai_report, self._results, self.session_id
            )
        return paths

    # ── Convenience ───────────────────────────────────────────────────────

    @property
    def results(self) -> List[ModuleResult]:
        return list(self._results)
