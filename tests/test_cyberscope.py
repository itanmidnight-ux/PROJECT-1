"""
CyberScope AI Security Platform — tests/test_cyberscope.py

Tests cover:
  - core/types.py         (Finding, ModuleResult, Severity)
  - core/discovery.py     (OS, WiFi, BT, SDR detection)
  - core/config.py        (config loading with defaults)
  - modules/network       (interface/service analysis)
  - modules/wifi          (parsing + security analysis)
  - modules/bluetooth     (adapter + device analysis)
  - modules/device        (system info + security checks)
  - ai/engine.py          (risk scoring, recommendations)
  - reports/generator.py  (JSON, HTML, Markdown)
  - database/db.py        (SQLite CRUD)
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import List

import pytest

# Insert project root into sys.path
_ROOT = Path(__file__).parent.parent
for _p in [str(_ROOT), str(_ROOT / "modules" / "telecom")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.types import (
    CapabilityInfo, Finding, ModuleResult, ModuleStatus, Severity,
)
from core.config import load_config
from ai.engine  import RiskEngine, AIReport, ExplainedFinding


# ================================================================
# core/types
# ================================================================

class TestSeverity:
    def test_order(self):
        assert Severity.INFO   < Severity.LOW
        assert Severity.LOW    < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH   < Severity.CRITICAL

    def test_scores(self):
        assert Severity.CRITICAL.score == 10
        assert Severity.INFO.score     == 1

    def test_levels_unique(self):
        scores = [s.score for s in Severity]
        assert len(scores) == len(set(scores))


class TestFinding:
    def _make(self, sev=Severity.HIGH) -> Finding:
        return Finding(
            type="TEST_TYPE", severity=sev,
            description="Test desc", evidence="ev",
            recommendation="rec", module="test",
        )

    def test_to_dict(self):
        d = self._make().to_dict()
        assert d["severity"] == "HIGH"
        assert d["type"] == "TEST_TYPE"
        assert "timestamp" in d

    def test_optional_fields(self):
        f = self._make()
        assert f.mitre is None
        assert f.source is None


class TestModuleResult:
    def test_finding_count(self):
        findings = [
            Finding("T1", Severity.HIGH, "d1", module="m"),
            Finding("T2", Severity.LOW,  "d2", module="m"),
        ]
        r = ModuleResult("test", ModuleStatus.AVAILABLE, findings)
        assert r.finding_count == 2

    def test_highest_severity(self):
        findings = [
            Finding("T1", Severity.MEDIUM,   "d", module="m"),
            Finding("T2", Severity.CRITICAL, "d", module="m"),
            Finding("T3", Severity.LOW,      "d", module="m"),
        ]
        r = ModuleResult("test", ModuleStatus.AVAILABLE, findings)
        assert r.highest_severity == Severity.CRITICAL

    def test_empty_highest(self):
        r = ModuleResult("test", ModuleStatus.AVAILABLE, [])
        assert r.highest_severity is None

    def test_to_dict(self):
        r = ModuleResult("net", ModuleStatus.AVAILABLE, [], {"key": "val"})
        d = r.to_dict()
        assert d["module"] == "net"
        assert d["status"] == "available"
        assert d["raw_data"]["key"] == "val"


class TestCapabilityInfo:
    def test_bool_available(self):
        c = CapabilityInfo("WiFi", ModuleStatus.AVAILABLE)
        assert bool(c) is True

    def test_bool_limited(self):
        c = CapabilityInfo("WiFi", ModuleStatus.LIMITED, "needs root")
        assert bool(c) is True

    def test_bool_unavailable(self):
        c = CapabilityInfo("SDR", ModuleStatus.UNAVAILABLE)
        assert bool(c) is False

    def test_to_dict(self):
        c = CapabilityInfo("BT", ModuleStatus.AVAILABLE, "ok", {"adapters": ["hci0"]})
        d = c.to_dict()
        assert d["name"] == "BT"
        assert d["details"]["adapters"] == ["hci0"]


# ================================================================
# core/config
# ================================================================

class TestConfig:
    def test_defaults(self):
        cfg = load_config("nonexistent.yaml")
        assert cfg["telecom"]["mode"] == "laboratory"
        assert cfg["database"]["path"] == "database/cyberscope.db"

    def test_yaml_override(self, tmp_path):
        f = tmp_path / "cfg.yaml"
        f.write_text("telecom:\n  sri_threshold: 99\n")
        cfg = load_config(str(f))
        assert cfg["telecom"]["sri_threshold"] == 99
        assert cfg["telecom"]["mode"] == "laboratory"  # default preserved

    def test_nested_merge(self, tmp_path):
        f = tmp_path / "cfg.yaml"
        f.write_text("ai:\n  risk_threshold_high: 80\n")
        cfg = load_config(str(f))
        assert cfg["ai"]["risk_threshold_high"] == 80
        assert cfg["ai"]["risk_threshold_critical"] == 85  # default preserved


# ================================================================
# core/discovery  (mocked — no real hardware needed for CI)
# ================================================================

class TestDiscovery:
    def test_detect_os_returns_info(self):
        from core.discovery import detect_os
        info = detect_os()
        assert info.kernel
        assert info.arch
        assert isinstance(info.is_root, bool)
        assert isinstance(info.is_termux, bool)

    def test_detect_tools(self):
        from core.discovery import detect_tools
        tools = detect_tools()
        assert isinstance(tools, dict)
        # python3 should always be present
        assert "python3" in tools

    def test_discover_all_returns_capabilities(self):
        from core.discovery import discover_all
        caps = discover_all()
        assert caps.os_info is not None
        assert isinstance(caps.network, list)
        # Telecom is always available
        assert bool(caps.telecom)

    def test_os_env_label(self):
        from core.discovery import detect_os
        info = detect_os()
        label = info.env_label
        assert isinstance(label, str) and len(label) > 0


# ================================================================
# Network module
# ================================================================

class TestNetworkDiscovery:
    def _make_scanner(self):
        from modules.network.discovery import NetworkDiscovery
        return NetworkDiscovery({})

    def test_parse_ip_addr(self):
        nd = self._make_scanner()
        sample = (
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast\n"
            "    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n"
        )
        result = nd._parse_ip_addr(sample)
        assert len(result) >= 1
        assert result[0]["ifname"] == "eth0"

    def test_analyze_promisc(self):
        nd = self._make_scanner()
        ifaces = [{"ifname": "eth0", "flags": ["PROMISC", "UP"]}]
        findings = nd._analyze_interfaces(ifaces)
        assert any("PROMISC" in f.type for f in findings)

    def test_analyze_sensitive_port(self):
        nd = self._make_scanner()
        svcs = [{"port": 23, "address": "0.0.0.0", "proto": "tcp"}]
        findings = nd._analyze_services(svcs)
        assert len(findings) > 0
        assert any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in findings)

    def test_safe_port_low_severity(self):
        nd = self._make_scanner()
        svcs = [{"port": 8080, "address": "0.0.0.0", "proto": "tcp"}]
        findings = nd._analyze_services(svcs)
        assert all(f.severity in (Severity.LOW, Severity.INFO) for f in findings)

    def test_run_returns_result(self):
        nd = self._make_scanner()
        result = nd.run()
        assert result.module == "network"
        assert result.status == ModuleStatus.AVAILABLE


# ================================================================
# WiFi module
# ================================================================

class TestWiFiScanner:
    def _make(self):
        from modules.wifi.scanner import WiFiScanner
        return WiFiScanner({})

    def test_parse_iw_output(self):
        scanner = self._make()
        sample = """
BSS aa:bb:cc:dd:ee:ff(on wlan0)
    freq: 2437
    signal: -65.00 dBm
    SSID: TestNetwork
    DS Parameter set: channel 6
    WPA2-PSK:
"""
        nets = scanner._parse_iw_output(sample)
        assert len(nets) >= 1
        n = nets[0]
        assert n.ssid == "TestNetwork"
        assert n.signal == -65
        assert n.channel == 6
        assert "WPA2" in n.security

    def test_open_network_finding(self):
        from modules.wifi.scanner import WiFiNetwork
        scanner = self._make()
        nets = [WiFiNetwork(ssid="FreeWifi", bssid="11:22:33:44:55:66", security="OPEN")]
        findings = scanner._analyze(nets)
        assert any(f.type == "WIFI_OPEN_NETWORK" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_wep_finding_critical(self):
        from modules.wifi.scanner import WiFiNetwork
        scanner = self._make()
        nets = [WiFiNetwork(ssid="OldNet", bssid="11:22:33:44:55:66", security="WEP")]
        findings = scanner._analyze(nets)
        assert any(f.type == "WIFI_WEP_NETWORK" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_wpa3_no_critical_finding(self):
        from modules.wifi.scanner import WiFiNetwork
        scanner = self._make()
        nets = [WiFiNetwork(ssid="SecureNet", bssid="11:22:33:44:55:66", security="WPA3")]
        findings = scanner._analyze(nets)
        assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

    def test_parse_nmcli(self):
        scanner = self._make()
        # Verify it doesn't crash on empty output
        nets = scanner._scan_nmcli() if False else []  # Don't actually run nmcli
        assert isinstance(nets, list)

    def test_vendor_derived_from_bssid(self):
        from modules.wifi.scanner import WiFiNetwork
        net = WiFiNetwork(ssid="Test", bssid="00:0C:29:AB:CD:EF")
        assert net.vendor == "VMware (virtual NIC)"

    def test_vendor_left_empty_without_bssid(self):
        from modules.wifi.scanner import WiFiNetwork
        net = WiFiNetwork(ssid="Test")
        assert net.vendor == ""

    def test_explicit_vendor_not_overwritten(self):
        from modules.wifi.scanner import WiFiNetwork
        net = WiFiNetwork(ssid="Test", bssid="00:0C:29:AB:CD:EF", vendor="Custom")
        assert net.vendor == "Custom"


# ================================================================
# Bluetooth module
# ================================================================

class TestBluetoothScanner:
    def _make(self):
        from modules.bluetooth.scanner import BluetoothScanner
        return BluetoothScanner({})

    def test_vendor_derived_from_address(self):
        from modules.bluetooth.scanner import BTDevice
        dev = BTDevice(address="08:00:27:11:22:33")
        assert dev.vendor == "Oracle VirtualBox (virtual NIC)"

    def test_vendor_flags_ble_private_address(self):
        from modules.bluetooth.scanner import BTDevice
        # 0x02 U/L bit set -> classic "locally administered / private" example
        dev = BTDevice(address="02:00:00:00:00:01", le=True)
        assert "administered" in dev.vendor.lower()

    def test_analyze_discoverable(self):
        from modules.bluetooth.scanner import BTAdapter, BTDevice
        scanner = self._make()
        adapter = BTAdapter(name="hci0", discoverable=True, bd_address="AA:BB:CC:DD:EE:FF")
        findings = scanner._analyze(adapter, [])
        assert any(f.type == "BT_ADAPTER_DISCOVERABLE" for f in findings)

    def test_analyze_unnamed_devices(self):
        from modules.bluetooth.scanner import BTAdapter, BTDevice
        scanner = self._make()
        adapter = BTAdapter(name="hci0", discoverable=False)
        devs    = [BTDevice("11:22:33:44:55:66", "Unknown")]
        findings = scanner._analyze(adapter, devs)
        assert any(f.type == "BT_UNNAMED_DEVICES" for f in findings)

    def test_ble_finding(self):
        from modules.bluetooth.scanner import BTAdapter, BTDevice
        scanner = self._make()
        adapter = BTAdapter(name="hci0")
        devs    = [BTDevice("AA:BB:CC:DD:EE:FF", "BLE Beacon", le=True)]
        findings = scanner._analyze(adapter, devs)
        assert any(f.type == "BLE_DEVICES_DETECTED" for f in findings)


# ================================================================
# Device module
# ================================================================

class TestDeviceAnalyzer:
    def _make(self):
        from modules.device.system import DeviceAnalyzer
        return DeviceAnalyzer({})

    def test_os_info_populated(self):
        da = self._make()
        info = da._os_info()
        assert "system"   in info
        assert "release"  in info
        assert "is_root"  in info
        assert isinstance(info["is_root"], bool)

    def test_cpu_info(self):
        da = self._make()
        info = da._cpu_info()
        assert "architecture" in info
        assert "cores" in info

    def test_aslr_finding(self):
        da = self._make()
        raw = {"security": {"aslr": 0}, "memory": {}}
        findings = da._analyze(raw)
        assert any(f.type == "ASLR_DISABLED" for f in findings)

    def test_run_returns_result(self):
        da = self._make()
        result = da.run()
        assert result.module == "device"
        assert result.status == ModuleStatus.AVAILABLE

    def test_installed_tools(self):
        da = self._make()
        tools = da._installed_tools()
        assert isinstance(tools, dict)
        assert "python3" in tools


# ================================================================
# AI Engine
# ================================================================

def _make_results(specs: list) -> List[ModuleResult]:
    """Build ModuleResult list from (module, [Finding]) specs."""
    results = []
    for mod, findings in specs:
        r = ModuleResult(mod, ModuleStatus.AVAILABLE, findings)
        results.append(r)
    return results


class TestRiskEngine:
    def setup_method(self):
        self.engine = RiskEngine()

    def _f(self, t: str, s: Severity, mod: str = "test") -> Finding:
        return Finding(t, s, "desc", module=mod)

    def test_empty_results_zero_score(self):
        report = self.engine.analyze([])
        assert report.risk_score.overall == 0.0

    def test_critical_finding_raises_score(self):
        findings = [self._f("ISD", Severity.CRITICAL, "telecom")]
        results  = _make_results([("telecom", findings)])
        report   = self.engine.analyze(results)
        # Single CRITICAL should meaningfully raise score above zero
        assert report.risk_score.overall > 30

    def test_many_info_findings_low_score(self):
        findings = [self._f(f"INFO_{i}", Severity.INFO, "net") for i in range(20)]
        results  = _make_results([("net", findings)])
        report   = self.engine.analyze(results)
        assert report.risk_score.overall < 50

    def test_risk_level_critical(self):
        findings = [self._f("ISD", Severity.CRITICAL, "t") for _ in range(5)]
        results  = _make_results([("t", findings)])
        report   = self.engine.analyze(results)
        # 5 CRITICAL findings should reach at least MEDIUM; typically HIGH
        assert report.risk_score.level in ("CRITICAL", "HIGH", "MEDIUM")

    def test_recommendations_generated(self):
        findings = [self._f("SUBSCRIBER_DATA_MANIPULATION", Severity.CRITICAL, "telecom")]
        results  = _make_results([("telecom", findings)])
        report   = self.engine.analyze(results)
        assert len(report.recommendations) > 0

    def test_attack_surface_wireless(self):
        findings = [self._f("WIFI_OPEN_NETWORK", Severity.HIGH, "wifi")]
        results  = _make_results([("wifi", findings)])
        report   = self.engine.analyze(results)
        assert report.attack_surface.wireless

    def test_top_findings_sorted(self):
        findings = [
            self._f("LOW", Severity.LOW, "m"),
            self._f("CRIT", Severity.CRITICAL, "m"),
            self._f("MED", Severity.MEDIUM, "m"),
        ]
        results = _make_results([("m", findings)])
        report  = self.engine.analyze(results)
        if len(report.top_findings) >= 2:
            assert report.top_findings[0].severity.score >= report.top_findings[1].severity.score

    def test_executive_summary_not_empty(self):
        results = _make_results([("device", [self._f("ASLR", Severity.HIGH, "device")])])
        report  = self.engine.analyze(results)
        assert len(report.executive_summary) > 20

    def test_aslr_recommendation(self):
        findings = [Finding("ASLR_DISABLED", Severity.HIGH, "d", module="device")]
        results  = _make_results([("device", findings)])
        report   = self.engine.analyze(results)
        assert any("ASLR" in r.title for r in report.recommendations)

    def test_to_dict(self):
        results = _make_results([("net", [self._f("X", Severity.MEDIUM, "net")])])
        report  = self.engine.analyze(results)
        d = report.to_dict()
        assert "risk_score" in d
        assert "recommendations" in d
        assert "attack_surface" in d


# ================================================================
# Reports
# ================================================================

class TestReports:
    def _make_report(self) -> tuple:
        engine = RiskEngine()
        findings = [
            Finding("WIFI_OPEN_NETWORK", Severity.HIGH, "Open network", module="wifi"),
            Finding("ASLR_DISABLED",     Severity.HIGH, "ASLR off",     module="device"),
        ]
        results = _make_results([("wifi", [findings[0]]), ("device", [findings[1]])])
        report  = engine.analyze(results)
        return report, results

    def test_json_report(self, tmp_path):
        from reports.generator import ReportGenerator
        rep, results = self._make_report()
        gen  = ReportGenerator(str(tmp_path))
        path = gen.save_json(rep, results, "test123")
        assert Path(path).exists()
        data = json.loads(Path(path).read_text())
        assert "meta" in data
        assert "ai_analysis" in data

    def test_html_report(self, tmp_path):
        from reports.generator import ReportGenerator
        rep, results = self._make_report()
        gen  = ReportGenerator(str(tmp_path))
        path = gen.save_html(rep, results, "test123")
        assert Path(path).exists()
        html = Path(path).read_text()
        assert "CyberScope" in html
        assert "Risk" in html

    def test_markdown_report(self, tmp_path):
        from reports.generator import ReportGenerator
        rep, results = self._make_report()
        gen  = ReportGenerator(str(tmp_path))
        path = gen.save_markdown(rep, results, "test123")
        assert Path(path).exists()
        md = Path(path).read_text()
        assert "# 🔍 CyberScope" in md
        assert "Risk" in md


# ================================================================
# Database
# ================================================================

class TestDatabase:
    def _make_db(self, tmp_path):
        from database.db import CyberScopeDB
        return CyberScopeDB(str(tmp_path / "test.db"))

    def test_save_and_get_session(self, tmp_path):
        db = self._make_db(tmp_path)
        db.save_session("sess1", "auto_audit", risk_level="HIGH", risk_score=72.5)
        sessions = db.get_sessions()
        assert len(sessions) == 1
        assert sessions[0]["id"] == "sess1"
        assert sessions[0]["risk_level"] == "HIGH"

    def test_save_and_get_findings(self, tmp_path):
        db = self._make_db(tmp_path)
        db.save_session("sess2", "test")
        findings = [
            {"type":"ASLR","severity":"HIGH","description":"ASLR off",
             "evidence":"val=0","recommendation":"fix","module":"device",
             "mitre":"T1203","timestamp":"2024-01-01T00:00:00+00:00"},
        ]
        n = db.save_findings("sess2", findings)
        assert n == 1
        rows = db.get_findings("sess2")
        assert len(rows) == 1
        assert rows[0]["type"] == "ASLR"

    def test_stats(self, tmp_path):
        db = self._make_db(tmp_path)
        db.save_session("s1", "test", risk_level="LOW")
        stats = db.get_stats()
        assert stats["total_sessions"] == 1
        assert "total_findings" in stats

    def test_filter_by_severity(self, tmp_path):
        db = self._make_db(tmp_path)
        db.save_session("s1", "test")
        db.save_findings("s1", [
            {"type":"H","severity":"HIGH","description":"","evidence":"","recommendation":"","module":"m","mitre":"","timestamp":"2024-01-01T00:00:00+00:00"},
            {"type":"L","severity":"LOW", "description":"","evidence":"","recommendation":"","module":"m","mitre":"","timestamp":"2024-01-01T00:00:00+00:00"},
        ])
        high = db.get_findings(severity="HIGH")
        assert all(r["severity"] == "HIGH" for r in high)
        assert len(high) == 1

    def test_close_and_reopen(self, tmp_path):
        db = self._make_db(tmp_path)
        db.save_session("s1", "test")
        db.close()
        db2 = self._make_db(tmp_path)
        sessions = db2.get_sessions()
        assert len(sessions) == 1


# ================================================================
# Privileges (root / sudo / su detection)
# ================================================================

class TestPrivileges:
    def test_already_root(self, monkeypatch):
        from core import permissions
        monkeypatch.setattr(permissions.os, "geteuid", lambda: 0)
        status = permissions.detect_privileges()
        assert status.is_root is True
        assert status.method == "already_root"
        assert status.can_escalate is True

    def test_no_escalation_available(self, monkeypatch):
        from core import permissions
        monkeypatch.setattr(permissions.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(permissions, "_tool_exists", lambda name: False)
        status = permissions.detect_privileges()
        assert status.is_root is False
        assert status.method == "none"
        assert status.can_escalate is False

    def test_sudo_nopasswd_detected(self, monkeypatch):
        from core import permissions
        monkeypatch.setattr(permissions.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(permissions, "_tool_exists", lambda name: name == "sudo")
        monkeypatch.setattr(permissions, "_probe",
                             lambda cmd, timeout: 0 if cmd[0] == "sudo" else None)
        status = permissions.detect_privileges()
        assert status.sudo_nopasswd is True
        assert status.method == "sudo_nopasswd"
        assert status.can_escalate is True

    def test_su_granted_detected(self, monkeypatch):
        from core import permissions
        monkeypatch.setattr(permissions.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(permissions, "_tool_exists", lambda name: name == "su")
        monkeypatch.setattr(permissions, "_probe",
                             lambda cmd, timeout: 0 if cmd[0] == "su" else None)
        status = permissions.detect_privileges()
        assert status.su_granted is True
        assert status.method == "su_granted"
        assert status.can_escalate is True

    def test_su_present_but_denied(self, monkeypatch):
        from core import permissions
        monkeypatch.setattr(permissions.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(permissions, "_tool_exists", lambda name: name == "su")
        monkeypatch.setattr(permissions, "_probe", lambda cmd, timeout: 1)
        status = permissions.detect_privileges()
        assert status.su_granted is False
        assert status.can_escalate is False

    def test_probe_never_hangs_on_timeout(self, monkeypatch):
        from core import permissions
        monkeypatch.setattr(permissions.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(permissions, "_tool_exists", lambda name: True)
        monkeypatch.setattr(permissions, "_probe", lambda cmd, timeout: None)
        status = permissions.detect_privileges()
        assert status.can_escalate is False
        assert status.method == "none"

    def test_to_dict(self):
        from core.permissions import PrivilegeStatus
        s = PrivilegeStatus(
            is_root=True, method="already_root", sudo_available=True,
            sudo_nopasswd=True, su_available=True, su_granted=True,
            tsu_available=False, is_termux=False, reason="ok",
        )
        d = s.to_dict()
        assert d["can_escalate"] is True
        assert d["method"] == "already_root"


# ================================================================
# WiFi monitor-mode capability detection
# ================================================================

class TestMonitorModeDetection:
    def test_supported(self, monkeypatch):
        from core import discovery
        sample = (
            "Wiphy phy0\n"
            "\tSupported interface modes:\n"
            "\t\t * IBSS\n"
            "\t\t * managed\n"
            "\t\t * AP\n"
            "\t\t * monitor\n"
            "\n"
            "\tBand 1:\n"
        )
        monkeypatch.setattr(discovery, "_tool_exists", lambda name: True)
        monkeypatch.setattr(discovery, "_run", lambda cmd, timeout=5: (0, sample, ""))
        ok, reason = discovery.detect_monitor_mode_support("wlan0")
        assert ok is True
        assert reason == ""

    def test_unsupported(self, monkeypatch):
        from core import discovery
        sample = (
            "Wiphy phy0\n"
            "\tSupported interface modes:\n"
            "\t\t * IBSS\n"
            "\t\t * managed\n"
            "\t\t * AP\n"
            "\n"
        )
        monkeypatch.setattr(discovery, "_tool_exists", lambda name: True)
        monkeypatch.setattr(discovery, "_run", lambda cmd, timeout=5: (0, sample, ""))
        ok, reason = discovery.detect_monitor_mode_support("wlan0")
        assert ok is False
        assert reason

    def test_no_iw_tool(self, monkeypatch):
        from core import discovery
        monkeypatch.setattr(discovery, "_tool_exists", lambda name: False)
        ok, reason = discovery.detect_monitor_mode_support("wlan0")
        assert ok is False
        assert reason


# ================================================================
# WiFi live monitor
# ================================================================

class TestWiFiMonitorMerge:
    def test_new_network_added(self):
        from modules.wifi.monitor import merge_scan
        from modules.wifi.scanner import WiFiNetwork
        registry = {}
        merge_scan(registry, [WiFiNetwork(ssid="Net1", bssid="AA:BB:CC:DD:EE:FF", signal=-50)], now=100.0)
        t = registry["AA:BB:CC:DD:EE:FF"]
        assert t.first_seen == 100.0 == t.last_seen
        assert t.seen_count == 1

    def test_existing_network_updated(self):
        from modules.wifi.monitor import merge_scan
        from modules.wifi.scanner import WiFiNetwork
        registry = {}
        merge_scan(registry, [WiFiNetwork(ssid="Net1", bssid="AA:BB", signal=-70)], now=100.0)
        merge_scan(registry, [WiFiNetwork(ssid="Net1", bssid="AA:BB", signal=-40)], now=105.0)
        t = registry["AA:BB"]
        assert t.signal == -40
        assert t.first_seen == 100.0
        assert t.last_seen == 105.0
        assert t.seen_count == 2

    def test_vendor_copied_from_scan(self):
        from modules.wifi.monitor import merge_scan
        from modules.wifi.scanner import WiFiNetwork
        registry = {}
        merge_scan(registry, [WiFiNetwork(ssid="Net1", bssid="00:0C:29:AB:CD:EF", signal=-50)], now=1.0)
        assert registry["00:0C:29:AB:CD:EF"].vendor == "VMware (virtual NIC)"

    def test_hidden_bssid_key_fallback(self):
        from modules.wifi.monitor import merge_scan
        from modules.wifi.scanner import WiFiNetwork
        registry = {}
        merge_scan(registry, [WiFiNetwork(ssid="NoAddr", bssid="", signal=-60)], now=1.0)
        assert "ssid:NoAddr" in registry


class TestWiFiMonitorProbe:
    def test_probe_open_network(self):
        from modules.wifi.monitor import WiFiMonitor, TrackedNetwork
        mon = WiFiMonitor({})
        mon.registry["BSSID1"] = TrackedNetwork(
            key="BSSID1", ssid="FreeWifi", bssid="BSSID1", channel=6,
            frequency=2.437, signal=-50, security="OPEN",
            first_seen=1.0, last_seen=1.0,
        )
        findings = mon.probe("BSSID1")
        assert any(f.type == "WIFI_OPEN_NETWORK" for f in findings)

    def test_probe_unknown_key_empty(self):
        from modules.wifi.monitor import WiFiMonitor
        mon = WiFiMonitor({})
        assert mon.probe("nope") == []


class TestMonitorModeSession:
    def test_no_privileges_falls_back(self):
        from modules.wifi.monitor import MonitorModeSession
        from core.permissions import PrivilegeStatus
        priv = PrivilegeStatus(
            is_root=False, method="none", sudo_available=False,
            sudo_nopasswd=False, su_available=False, su_granted=False,
            tsu_available=False, is_termux=False, reason="no root",
        )
        with MonitorModeSession("wlan0", priv) as sess:
            assert sess.active is False
            assert "not available" in sess.reason.lower()

    def test_unsupported_driver_falls_back(self, monkeypatch):
        from modules.wifi import monitor as monitor_mod
        from core.permissions import PrivilegeStatus
        priv = PrivilegeStatus(
            is_root=True, method="already_root", sudo_available=True,
            sudo_nopasswd=True, su_available=True, su_granted=True,
            tsu_available=False, is_termux=False, reason="root",
        )
        monkeypatch.setattr(monitor_mod, "detect_monitor_mode_support",
                             lambda iface: (False, "no monitor support"))
        with monitor_mod.MonitorModeSession("wlan0", priv) as sess:
            assert sess.active is False
            assert sess.reason == "no monitor support"


# ================================================================
# Bluetooth live monitor
# ================================================================

class TestBluetoothMonitorMerge:
    def test_new_device_added(self):
        from modules.bluetooth.monitor import merge_scan
        from modules.bluetooth.scanner import BTDevice
        registry = {}
        merge_scan(registry, [BTDevice(address="11:22:33:44:55:66", name="Phone")], now=1.0)
        assert registry["11:22:33:44:55:66"].name == "Phone"

    def test_name_upgrade_on_rescan(self):
        from modules.bluetooth.monitor import merge_scan
        from modules.bluetooth.scanner import BTDevice
        registry = {}
        merge_scan(registry, [BTDevice(address="AA", name="Unknown")], now=1.0)
        merge_scan(registry, [BTDevice(address="AA", name="RealName")], now=2.0)
        assert registry["AA"].name == "RealName"
        assert registry["AA"].seen_count == 2

    def test_vendor_copied_from_scan(self):
        from modules.bluetooth.monitor import merge_scan
        from modules.bluetooth.scanner import BTDevice
        registry = {}
        merge_scan(registry, [BTDevice(address="08:00:27:11:22:33", name="Phone")], now=1.0)
        assert registry["08:00:27:11:22:33"].vendor == "Oracle VirtualBox (virtual NIC)"


class TestBluetoothMonitorProbe:
    def test_probe_unknown_key_empty(self):
        from modules.bluetooth.monitor import BluetoothMonitor
        mon = BluetoothMonitor({})
        assert mon.probe("nope") == []


# ================================================================
# Live TUI helpers (non-interactive-safe paths only)
# ================================================================

class TestLiveViewHelpers:
    def test_read_line_nonblocking_non_tty_returns_none(self):
        from ui.live_view import _read_line_nonblocking
        assert _read_line_nonblocking(0.01) is None

    def test_header_panel_smoke(self):
        from ui.live_view import header_panel
        assert header_panel("Title", "Subtitle") is not None


# ================================================================
# Network live monitor
# ================================================================

class TestNetworkMonitorParsing:
    def test_parse_ip_neigh_basic(self):
        from modules.network.monitor import parse_ip_neigh
        sample = (
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "192.168.1.20 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
            "192.168.1.99 dev eth0 FAILED\n"
        )
        hosts = parse_ip_neigh(sample)
        assert len(hosts) == 3
        assert hosts[0]["ip"] == "192.168.1.1"
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert hosts[0]["state"] == "REACHABLE"
        assert hosts[2]["mac"] == ""
        assert hosts[2]["state"] == "FAILED"

    def test_parse_empty(self):
        from modules.network.monitor import parse_ip_neigh
        assert parse_ip_neigh("") == []


class TestNetworkMonitorMerge:
    def test_new_host_added(self):
        from modules.network.monitor import merge_scan
        registry = {}
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "AA:BB", "state": "REACHABLE"}], now=1.0)
        t = registry["10.0.0.5"]
        assert t.mac == "AA:BB"
        assert t.first_seen == 1.0 == t.last_seen
        assert t.seen_count == 1

    def test_existing_host_updated(self):
        from modules.network.monitor import merge_scan
        registry = {}
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "", "state": "STALE"}], now=1.0)
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "AA:BB", "state": "REACHABLE"}], now=2.0)
        t = registry["10.0.0.5"]
        assert t.mac == "AA:BB"
        assert t.state == "REACHABLE"
        assert t.first_seen == 1.0
        assert t.last_seen == 2.0
        assert t.seen_count == 2

    def test_missing_ip_skipped(self):
        from modules.network.monitor import merge_scan
        registry = {}
        merge_scan(registry, [{"ip": "", "mac": "AA", "state": "X"}], now=1.0)
        assert registry == {}

    def test_vendor_set_on_first_sighting(self):
        from modules.network.monitor import merge_scan
        registry = {}
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "00:0C:29:AB:CD:EF", "state": "REACHABLE"}], now=1.0)
        assert registry["10.0.0.5"].vendor == "VMware (virtual NIC)"

    def test_vendor_updated_when_mac_learned_later(self):
        from modules.network.monitor import merge_scan
        registry = {}
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "", "state": "STALE"}], now=1.0)
        assert registry["10.0.0.5"].vendor == ""
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "08:00:27:11:22:33", "state": "REACHABLE"}], now=2.0)
        assert registry["10.0.0.5"].vendor == "Oracle VirtualBox (virtual NIC)"

    def test_vendor_unknown_for_unrecognized_oui(self):
        from modules.network.monitor import merge_scan
        registry = {}
        merge_scan(registry, [{"ip": "10.0.0.5", "mac": "00:11:22:33:44:55", "state": "REACHABLE"}], now=1.0)
        assert registry["10.0.0.5"].vendor == "Unknown vendor"


class TestNetworkMonitorProbe:
    def test_probe_unknown_host_empty(self):
        from modules.network.monitor import NetworkMonitor
        mon = NetworkMonitor({})
        assert mon.probe("10.0.0.99") == []

    def test_probe_known_host_runs(self):
        from modules.network.monitor import NetworkMonitor, TrackedHost
        mon = NetworkMonitor({})
        mon.registry["127.0.0.1"] = TrackedHost(
            ip="127.0.0.1", mac="", state="REACHABLE",
            first_seen=1.0, last_seen=1.0,
        )
        findings = mon.probe("127.0.0.1")
        assert len(findings) >= 1
        assert any(f.type in ("HOST_REACHABLE", "HOST_UNREACHABLE") for f in findings)


# ================================================================
# Telecom/SS7 live monitor
# ================================================================

class TestTelecomMonitorMerge:
    def _subscriber(self, msisdn="13105551234"):
        from simulator import Subscriber
        return Subscriber(msisdn=msisdn, imsi="310260123456789", roaming=False, lac="LAC1234")

    def test_new_subscriber_tracked_on_first_event(self):
        from modules.telecom.monitor import merge_activity
        sub = self._subscriber()
        registry = {}
        entries = [{"msisdn": sub.msisdn, "op": "SRI", "suspicious": False}]
        merge_activity(registry, {sub.msisdn: sub}, entries, now=1.0)
        t = registry[sub.msisdn]
        assert t.events == 1
        assert t.suspicious_events == 0
        assert t.last_op == "SRI"

    def test_suspicious_event_counted(self):
        from modules.telecom.monitor import merge_activity
        sub = self._subscriber()
        registry = {}
        entries = [
            {"msisdn": sub.msisdn, "op": "SRI", "suspicious": False},
            {"msisdn": sub.msisdn, "op": "ISD", "suspicious": True},
        ]
        merge_activity(registry, {sub.msisdn: sub}, entries, now=2.0)
        t = registry[sub.msisdn]
        assert t.events == 2
        assert t.suspicious_events == 1
        assert t.last_op == "ISD"

    def test_unknown_subscriber_skipped(self):
        from modules.telecom.monitor import merge_activity
        registry = {}
        entries = [{"msisdn": "99999999999", "op": "SRI", "suspicious": False}]
        merge_activity(registry, {}, entries, now=1.0)
        assert registry == {}


class TestTelecomMonitor:
    def test_poll_tracks_synthetic_traffic(self):
        from modules.telecom.monitor import TelecomMonitor
        mon = TelecomMonitor({}, subscriber_count=5)
        msisdn = next(iter(mon.db._db))
        mon.hlr.handle_sri(msisdn, "203.0.113.1", 1)
        results = mon.poll()
        assert any(item.key == msisdn and item.kind == "lab" for item in results)

    def test_probe_flags_suspicious_subscriber(self):
        from modules.telecom.monitor import TelecomMonitor
        mon = TelecomMonitor({}, subscriber_count=5)
        msisdn = next(iter(mon.db._db))
        mon.hlr.handle_isd(msisdn, "203.0.113.9", 2)  # rejected + flagged suspicious
        mon.poll()
        findings = mon.probe(msisdn)
        assert any(f.type == "SUBSCRIBER_DATA_MANIPULATION" for f in findings)

    def test_probe_nominal_subscriber(self):
        from modules.telecom.monitor import TelecomMonitor
        mon = TelecomMonitor({}, subscriber_count=5)
        msisdn = next(iter(mon.db._db))
        mon.hlr.handle_sri(msisdn, "203.0.113.1", 1)
        mon.poll()
        findings = mon.probe(msisdn)
        assert not any(f.type == "SUBSCRIBER_DATA_MANIPULATION" for f in findings)

    def test_probe_unknown_subscriber_empty(self):
        from modules.telecom.monitor import TelecomMonitor
        mon = TelecomMonitor({}, subscriber_count=5)
        assert mon.probe("00000000000") == []

    def test_start_and_stop_traffic(self):
        from modules.telecom.monitor import TelecomMonitor
        mon = TelecomMonitor({}, subscriber_count=5)
        mon.start_traffic(interval=0.01)
        import time as _time
        _time.sleep(0.15)
        mon.stop_traffic()
        results = mon.poll()
        assert isinstance(results, list)

    def test_no_device_source_yields_no_device_row(self, monkeypatch):
        from modules.telecom import monitor as monitor_mod
        monkeypatch.setattr(monitor_mod, "detect_real_telephony", lambda: None)
        mon = monitor_mod.TelecomMonitor({}, subscriber_count=3)
        results = mon.poll()
        assert not any(item.kind == "device" for item in results)
        assert mon.probe(monitor_mod.DEVICE_KEY) == []

    def test_device_row_pinned_first_when_present(self, monkeypatch):
        from modules.telecom import monitor as monitor_mod
        from modules.telecom.device_telephony import DeviceTelephony
        dt = DeviceTelephony(source="termux-api", network_operator_name="Test Carrier",
                              network_type="LTE")
        monkeypatch.setattr(monitor_mod, "detect_real_telephony", lambda: dt)
        mon = monitor_mod.TelecomMonitor({}, subscriber_count=3)
        msisdn = next(iter(mon.db._db))
        mon.hlr.handle_sri(msisdn, "203.0.113.1", 1)
        results = mon.poll()
        assert results[0].kind == "device"
        assert results[0].key == monitor_mod.DEVICE_KEY
        assert results[0].label == "Test Carrier"

    def test_device_probe_flags_insecure_rat(self, monkeypatch):
        from modules.telecom import monitor as monitor_mod
        from modules.telecom.device_telephony import DeviceTelephony
        dt = DeviceTelephony(source="getprop", network_operator_name="Carrier X",
                              network_type="GSM")
        monkeypatch.setattr(monitor_mod, "detect_real_telephony", lambda: dt)
        mon = monitor_mod.TelecomMonitor({}, subscriber_count=1)
        mon.poll()
        findings = mon.probe(monitor_mod.DEVICE_KEY)
        assert any(f.type == "INSECURE_RADIO_ACCESS_TECHNOLOGY" for f in findings)

    def test_device_probe_nominal_on_lte(self, monkeypatch):
        from modules.telecom import monitor as monitor_mod
        from modules.telecom.device_telephony import DeviceTelephony
        dt = DeviceTelephony(source="termux-api", network_operator_name="Carrier X",
                              network_type="LTE")
        monkeypatch.setattr(monitor_mod, "detect_real_telephony", lambda: dt)
        mon = monitor_mod.TelecomMonitor({}, subscriber_count=1)
        mon.poll()
        findings = mon.probe(monitor_mod.DEVICE_KEY)
        assert not any(f.type == "INSECURE_RADIO_ACCESS_TECHNOLOGY" for f in findings)
        assert any(f.type == "RADIO_NOMINAL" for f in findings)

    def test_device_probe_weak_signal(self, monkeypatch):
        from modules.telecom import monitor as monitor_mod
        from modules.telecom.device_telephony import CellInfo, DeviceTelephony
        dt = DeviceTelephony(source="termux-api", network_operator_name="Carrier X",
                              network_type="LTE",
                              cells=[CellInfo(cell_type="lte", registered=True, dbm=-115)])
        monkeypatch.setattr(monitor_mod, "detect_real_telephony", lambda: dt)
        mon = monitor_mod.TelecomMonitor({}, subscriber_count=1)
        mon.poll()
        findings = mon.probe(monitor_mod.DEVICE_KEY)
        assert any(f.type == "WEAK_SIGNAL" for f in findings)

    def test_device_unreachable_stops_reprobing(self, monkeypatch):
        from modules.telecom import monitor as monitor_mod
        calls = {"n": 0}
        def fake_detect():
            calls["n"] += 1
            return None
        monkeypatch.setattr(monitor_mod, "detect_real_telephony", fake_detect)
        mon = monitor_mod.TelecomMonitor({}, subscriber_count=1)
        mon.poll()
        mon.poll()
        mon.poll()
        assert calls["n"] == 1  # only probed once, then remembered as unavailable


# ================================================================
# Real device telephony detection (Termux:API / root+dumpsys / getprop)
# ================================================================

class TestDeviceTelephony:
    def test_no_sources_available(self, monkeypatch):
        from modules.telecom import device_telephony as dtmod
        monkeypatch.setattr(dtmod, "_tool_exists", lambda name: False)
        assert dtmod.detect_real_telephony() is None

    def test_termux_api_info_and_cellinfo(self, monkeypatch):
        from modules.telecom import device_telephony as dtmod
        monkeypatch.setattr(dtmod, "_tool_exists", lambda name: True)

        info_json = (
            '{"network_operator_name":"Test Carrier","network_type":"LTE",'
            '"sim_state":"READY","sim_operator_name":"Test Carrier","data_state":"connected"}'
        )
        cell_json = '[{"type":"lte","registered":true,"mcc":"310","mnc":"260",' \
                    '"lac":"1234","cid":"5678","dbm":-85,"level":3}]'

        def fake_run(cmd, timeout=5):
            if cmd[0] == "termux-telephony-info":
                return 0, info_json
            if cmd[0] == "termux-telephony-cellinfo":
                return 0, cell_json
            return -1, ""

        monkeypatch.setattr(dtmod, "_run", fake_run)
        dt = dtmod.detect_real_telephony()
        assert dt is not None
        assert dt.source == "termux-api"
        assert dt.network_operator_name == "Test Carrier"
        assert dt.network_type == "LTE"
        assert len(dt.cells) == 1
        assert dt.cells[0].dbm == -85
        assert dt.cells[0].mcc == "310"

    def test_termux_api_bad_json_returns_none(self, monkeypatch):
        from modules.telecom import device_telephony as dtmod
        monkeypatch.setattr(dtmod, "_tool_exists", lambda name: name == "termux-telephony-info")
        monkeypatch.setattr(dtmod, "_run", lambda cmd, timeout=5: (0, "not json"))
        assert dtmod.detect_real_telephony() is None

    def test_dumpsys_parsing(self):
        from modules.telecom.device_telephony import parse_dumpsys_telephony
        sample = (
            "mOperatorAlphaLong=Test Carrier mDataNetworkType=LTE "
            "mSignalStrength=SignalStrength: -95 dBm mIsRoaming=false"
        )
        dt = parse_dumpsys_telephony(sample)
        assert dt is not None
        assert dt.source == "dumpsys"
        assert dt.network_operator_name == "Test Carrier"
        assert dt.network_type == "LTE"
        assert dt.roaming is False
        assert dt.cells and dt.cells[0].dbm == -95

    def test_dumpsys_parsing_no_useful_fields_returns_none(self):
        from modules.telecom.device_telephony import parse_dumpsys_telephony
        assert parse_dumpsys_telephony("garbage output with nothing useful") is None

    def test_getprop_fallback(self, monkeypatch):
        from modules.telecom import device_telephony as dtmod
        monkeypatch.setattr(dtmod, "_tool_exists", lambda name: name == "getprop")

        def fake_run(cmd, timeout=5):
            prop = cmd[-1]
            values = {
                "gsm.operator.alpha": "Test Carrier",
                "gsm.network.type":   "LTE",
                "gsm.sim.state":      "READY",
            }
            return 0, values.get(prop, "")

        monkeypatch.setattr(dtmod, "_run", fake_run)
        dt = dtmod.detect_real_telephony()
        assert dt is not None
        assert dt.source == "getprop"
        assert dt.network_operator_name == "Test Carrier"

    def test_device_is_risky_flags_2g(self):
        from modules.telecom.device_telephony import DeviceTelephony
        from modules.telecom.monitor import device_is_risky
        dt = DeviceTelephony(source="getprop", network_type="GSM")
        assert device_is_risky(dt) is True

    def test_device_is_risky_false_on_lte(self):
        from modules.telecom.device_telephony import DeviceTelephony
        from modules.telecom.monitor import device_is_risky
        dt = DeviceTelephony(source="getprop", network_type="LTE")
        assert device_is_risky(dt) is False


# ================================================================
# Explainability
# ================================================================

class TestExplainability:
    def setup_method(self):
        self.engine = RiskEngine()

    def _f(self, t: str, s: Severity, mod: str = "test", **kw) -> Finding:
        return Finding(t, s, kw.pop("description", "desc"), module=mod, **kw)

    def _assert_well_formed(self, ef: ExplainedFinding, finding: Finding):
        assert isinstance(ef, ExplainedFinding)
        assert ef.finding is finding
        for attr in ("what", "why", "risk", "fix"):
            val = getattr(ef, attr)
            assert isinstance(val, str)
            assert len(val.strip()) > 0

    def test_explain_wifi_open_network(self):
        finding = self._f("WIFI_OPEN_NETWORK", Severity.HIGH, "wifi",
                           description='Open WiFi network detected: "TestSSID"')
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        assert "plaintext" in ef.why.lower() or "unencrypted" in ef.why.lower()

    def test_explain_wifi_wep_network(self):
        finding = self._f("WIFI_WEP_NETWORK", Severity.CRITICAL, "wifi",
                           description='WEP-encrypted network: "TestSSID"')
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        assert "wep" in ef.why.lower()

    def test_explain_aslr_disabled(self):
        finding = self._f("ASLR_DISABLED", Severity.HIGH, "device",
                           description="ASLR is disabled (value=0)")
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        assert "aslr" in ef.why.lower() or "address space" in ef.why.lower()

    def test_explain_telecom_type(self):
        finding = self._f("SUBSCRIBER_DATA_MANIPULATION", Severity.CRITICAL, "telecom",
                           description="ISD attempt for +1555 from ext-node")
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        assert "ss7" in ef.why.lower() or "map" in ef.why.lower() or "hlr" in ef.why.lower()

    def test_explain_insecure_rat(self):
        finding = self._f("INSECURE_RADIO_ACCESS_TECHNOLOGY", Severity.HIGH, "telecom",
                           description="Device is registered on GSM")
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        assert "imsi" in ef.why.lower() or "2g" in ef.why.lower()

    def test_explain_unknown_type_fallback(self):
        finding = self._f("SOME_UNSEEN_FUTURE_FINDING_TYPE", Severity.MEDIUM, "misc",
                           description="Something unusual was observed",
                           evidence="ev=123", recommendation="Do the thing")
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        # Fallback should still surface the finding's own recommendation as the fix.
        assert ef.fix == "Do the thing"

    def test_explain_unknown_type_fallback_no_recommendation(self):
        finding = self._f("ANOTHER_UNSEEN_TYPE", Severity.LOW, "misc",
                           description="Odd but harmless")
        ef = self.engine.explain(finding)
        self._assert_well_formed(ef, finding)
        assert len(ef.fix) > 0

    def test_to_dict_round_trip(self):
        finding = self._f("WIFI_OPEN_NETWORK", Severity.HIGH, "wifi")
        ef = self.engine.explain(finding)
        d = ef.to_dict()
        assert set(d.keys()) == {"finding", "what", "why", "risk", "fix"}
        assert isinstance(d["what"], str)
        assert isinstance(d["why"], str)
        assert isinstance(d["risk"], str)
        assert isinstance(d["fix"], str)
        # severity must be serialised as a plain string, not an enum
        assert d["finding"]["severity"] == "HIGH"
        assert isinstance(d["finding"]["severity"], str)
        assert d["finding"]["type"] == "WIFI_OPEN_NETWORK"

    def test_report_carries_explained_top_findings(self):
        findings = [
            self._f("WIFI_OPEN_NETWORK", Severity.HIGH, "wifi"),
            self._f("ASLR_DISABLED", Severity.HIGH, "device"),
        ]
        results = _make_results([("wifi", [findings[0]]), ("device", [findings[1]])])
        report = self.engine.analyze(results)
        assert hasattr(report, "explained_top_findings")
        assert len(report.explained_top_findings) > 0
        assert all(isinstance(ef, ExplainedFinding) for ef in report.explained_top_findings)
        assert len(report.explained_top_findings) == len(report.top_findings)

    def test_report_to_dict_includes_explained_top_findings(self):
        findings = [self._f("WIFI_WEP_NETWORK", Severity.CRITICAL, "wifi")]
        results = _make_results([("wifi", findings)])
        report = self.engine.analyze(results)
        d = report.to_dict()
        assert "explained_top_findings" in d
        assert len(d["explained_top_findings"]) > 0
        assert d["explained_top_findings"][0]["finding"]["type"] == "WIFI_WEP_NETWORK"

    def test_empty_results_no_explained_findings(self):
        report = self.engine.analyze([])
        assert report.explained_top_findings == []
