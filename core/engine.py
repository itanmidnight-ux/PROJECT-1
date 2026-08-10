"""
CyberScope WiFi — core/engine.py

WiFi-only security auditing engine.
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
    WiFi-only platform orchestrator.

    Responsibilities:
    - Load configuration
    - Run system discovery
    - Dispatch WiFi module scans
    - Run AI analysis
    - Persistributes of the scene and respond appropriately. The user wants me to continue the story as the GMK: "wifi" MODULES ONLY
    """

    def __init__(self, config_path: str = "config.yaml") -> None:
        self.cfg          = load_config(config_path)
        _setup_logging(self.cfg)
        self.session_id   = str(uuid.uuid4())[:8]
        self.capabilities: Optional[SystemCapabilities] = None
        self._results:     List[ModuleResult] = []

        from database.db import CyberScopeDB
        from ai.engine   import RiskEngine
        from reports.generator import ReportGenerator
        from core.asset_manager import AssetManager

        self.db       = CyberScopeDB(self.cfg.get("database", {}).get("path", "database/cyberscope.db"))
        self.ai       = RiskEngine()
        self.reporter = ReportGenerator(self.cfg.get("reports", {}).get("output_dir", "reports"))
        self.events   = EventBus()
        self.assets   = AssetManager(self.db, self.events)

        self.db.save_session(self.session_id, mode="in_progress")

        log.info(f"CyberScope WiFi Engine ready — session={self.session_id}")

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

        elif m == "wifi_attack":
            for attack in result.raw_data.get("attacks_performed", []):
                bssid = attack.get("target_bssid")
                if not bssid:
                    continue
                self.events.publish(Event(
                    type=ASSET_OBSERVED,
                    payload={
                        "asset_type": "wifi_ap", "identifier": bssid,
                        "vendor": attack.get("details", {}).get("vendor", ""), "interfaces": ["wifi"],
                        "risk": "CRITICAL" if attack.get("success") else "INFO",
                        "session_id": self.session_id,
                    },
                    source="wifi_attack",
                ))

    def _dispatch_module(self, module: str) -> ModuleResult:
        m = module.lower()

        if m == "wifi":
            from modules.wifi.scanner import WiFiScanner
            return WiFiScanner(self.cfg).run()

        if m == "wifi_monitor":
            from modules.wifi.monitor import WiFiMonitor
            mon = WiFiMonitor(self.cfg)
            networks = mon.poll()
            return ModuleResult(
                module="wifi_monitor",
                status=ModuleStatus.AVAILABLE if mon.available else ModuleStatus.UNAVAILABLE,
                findings=[],
                raw_data={
                    "interface": mon.interface,
                    "networks_found": len(networks),
                    "networks": [vars(n) for n in networks],
                },
                duration_ms=0,
            )

        if m == "wifi_attack":
            from modules.pentest.wifi_attack import wifi_attack_available, run_full_wifi_audit
            from core.discovery import detect_monitor_mode_support
            from core.permissions import detect_privileges

            caps = self.capabilities or discover_all()
            privs = detect_privileges()

            if not caps.wifi.details:
                return ModuleResult(
                    module=m,
                    status=ModuleStatus.UNAVAILABLE,
                    raw_data={"reason": "No WiFi interface available"},
                )

            iface = caps.wifi.details.get("interfaces", [""])[0]
            monitor_ok, reason = detect_monitor_mode_support(iface)

            ok, reason = wifi_attack_available(privs, monitor_ok)
            if not ok:
                return ModuleResult(
                    module=m,
                    status=ModuleStatus.UNAVAILABLE,
                    raw_data={"reason": reason},
                )

            return ModuleResult(
                module=m,
                status=ModuleStatus.LIMITED,
                raw_data={"reason": "Requires target BSSID, channel, and attack types"},
            )

        if m == "wpa_capture":
            from modules.pentest.wpa_capture import wpa_capture_available, CaptureResult, capture_handshake
            from core.discovery import detect_monitor_mode_support
            from core.permissions import detect_privileges

            caps = self.capabilities or discover_all()
            privs = detect_privileges()

            if not caps.wifi.details:
                return ModuleResult(
                    module=m,
                    status=ModuleStatus.UNAVAILABLE,
                    raw_data={"reason": "No WiFi interface available"},
                )

            iface = caps.wifi.details.get("interfaces", [""])[0]
            monitor_ok, reason = detect_monitor_mode_support(iface)

            ok, reason = wpa_capture_available(privs, monitor_ok)
            if not ok:
                return ModuleResult(
                    module=m,
                    status=ModuleStatus.UNAVAILABLE,
                    raw_data={"reason": reason},
                )

            return ModuleResult(
                module=m,
                status=ModuleStatus.LIMITED,
                raw_data={"reason": "Requires target BSSID and channel"},
            )

        raise ValueError(f"Unknown module: {module}")

    def run_auto_audit(self, modules: Optional[List[str]] = None) -> List[ModuleResult]:
        """Run all available WiFi modules in sequence."""
        if self.capabilities is None:
            self.discover()

        caps = self.capabilities
        available = modules or ["wifi", "wifi_monitor"]
        log.info(f"Auto-audit: running {available}")

        for mod in available:
            self.run_module(mod)

        return self._results

    def analyze(self):
        """Run AI risk engine over collected results."""
        from ai.engine import AIReport
        report = self.ai.analyze(self._results)

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

    def save_reports(self, ai_report, formats: Optional[List[str]] = None) -> Dict[str, str]:
        fmts   = formats or self.cfg.get("reports", {}).get("formats", ["json", "markdown"])
        paths: Dict[str, str] = {}

        if "json" in fmts:
            paths["json"] = self.reporter.save_json(
                ai_report, self._results, self.session_id
            )
        if "markdown" in fmts:
            paths["markdown"] = self.reporter.save_markdown(
                ai_report, self._results, self.session_id
            )
        return paths

    @property
    def results(self) -> List[ModuleResult]:
        return list(self._results)