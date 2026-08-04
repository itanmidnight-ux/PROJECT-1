"""
CyberScope — tests/test_wpa_capture.py

Tests for modules/pentest/wpa_capture.py. No WiFi hardware or the
aircrack-ng suite is required to run this suite: the parsing logic
(the only part that decides "did we get a handshake" / "was the
passphrase cracked") is pure and tested against realistic sample
output; the subprocess orchestration is tested with core.shell.run
mocked out, the same pattern already used throughout this codebase
for capabilities that can't be exercised without real hardware
(core.discovery's iw-list parsing, core.permissions' su/sudo probing,
modules.telecom.device_telephony's dumpsys parsing).
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.permissions import PrivilegeStatus
from modules.pentest.wpa_capture import (
    CaptureResult,
    CrackResult,
    capture_handshake,
    crack_handshake,
    find_default_wordlist,
    parse_crack_result,
    parse_handshake_check,
    to_findings,
    wpa_capture_available,
)


def _priv(can_escalate: bool) -> PrivilegeStatus:
    return PrivilegeStatus(
        is_root=can_escalate, method="already_root" if can_escalate else "none",
        sudo_available=False, sudo_nopasswd=False, su_available=False,
        su_granted=False, tsu_available=False, is_termux=False,
        reason="",
    )


class TestAvailability:
    def test_unavailable_without_privileges(self):
        ok, reason = wpa_capture_available(_priv(False), monitor_supported=True)
        assert ok is False
        assert "privileged" in reason.lower()

    def test_unavailable_without_monitor_mode(self):
        ok, reason = wpa_capture_available(_priv(True), monitor_supported=False)
        assert ok is False
        assert "monitor mode" in reason.lower()

    def test_unavailable_without_tools(self, monkeypatch):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: False)
        ok, reason = wpa_capture_available(_priv(True), monitor_supported=True)
        assert ok is False
        assert "installed" in reason.lower()

    def test_available_when_everything_present(self, monkeypatch):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: True)
        ok, reason = wpa_capture_available(_priv(True), monitor_supported=True)
        assert ok is True
        assert reason == ""


class TestFindDefaultWordlist:
    def test_returns_none_when_nothing_found(self, monkeypatch):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod.Path, "exists", lambda self: False)
        assert find_default_wordlist() is None

    def test_returns_first_existing_path(self, monkeypatch):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod.Path, "exists", lambda self: str(self) == mod._DEFAULT_WORDLIST_PATHS[0])
        assert find_default_wordlist() == mod._DEFAULT_WORDLIST_PATHS[0]


class TestParseHandshakeCheck:
    def test_detects_handshake(self):
        sample = (
            "   #  BSSID              ESSID          Encryption\n"
            "   1  AA:BB:CC:DD:EE:FF  MyNetwork      WPA (1 handshake)\n"
        )
        assert parse_handshake_check(sample, "AA:BB:CC:DD:EE:FF") is True

    def test_no_handshake_present(self):
        sample = (
            "   #  BSSID              ESSID          Encryption\n"
            "   1  AA:BB:CC:DD:EE:FF  MyNetwork      WPA2\n"
        )
        assert parse_handshake_check(sample, "AA:BB:CC:DD:EE:FF") is False

    def test_case_insensitive_bssid_match(self):
        sample = "1  aa:bb:cc:dd:ee:ff  Net  WPA (1 handshake)\n"
        assert parse_handshake_check(sample, "AA:BB:CC:DD:EE:FF") is True

    def test_wrong_bssid_not_matched(self):
        sample = "1  11:22:33:44:55:66  Net  WPA (1 handshake)\n"
        assert parse_handshake_check(sample, "AA:BB:CC:DD:EE:FF") is False

    def test_empty_output(self):
        assert parse_handshake_check("", "AA:BB:CC:DD:EE:FF") is False


class TestParseCrackResult:
    def test_key_found(self):
        sample = "\n   KEY FOUND! [ SuperSecret123 ]\n\n   Master Key ...\n"
        cracked, password = parse_crack_result(sample)
        assert cracked is True
        assert password == "SuperSecret123"

    def test_passphrase_not_found(self):
        sample = "Passphrase not in dictionary \nQuitting aircrack-ng...\n"
        cracked, password = parse_crack_result(sample)
        assert cracked is False
        assert password is None

    def test_empty_output(self):
        cracked, password = parse_crack_result("")
        assert cracked is False
        assert password is None


class TestCaptureHandshakeOrchestration:
    def test_missing_tool_returns_error(self, monkeypatch):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: False)
        result = capture_handshake("wlan0mon", "AA:BB:CC:DD:EE:FF", 6, timeout_s=1)
        assert result.error
        assert result.handshake_captured is False

    def test_bad_output_dir_returns_error(self, monkeypatch, tmp_path):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: True)

        def boom(self, parents=True, exist_ok=True):
            raise OSError("nope")
        monkeypatch.setattr(mod.Path, "mkdir", boom)

        result = capture_handshake("wlan0mon", "AA:BB:CC:DD:EE:FF", 6,
                                    output_dir=str(tmp_path / "x"), timeout_s=1)
        assert result.error
        assert "cannot create" in result.error

    def test_popen_failure_returns_error(self, monkeypatch, tmp_path):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: True)

        def boom(*a, **kw):
            raise OSError("no such executable")
        monkeypatch.setattr(mod.subprocess, "Popen", boom)

        result = capture_handshake("wlan0mon", "AA:BB:CC:DD:EE:FF", 6,
                                    output_dir=str(tmp_path), timeout_s=1)
        assert result.error

    def test_never_transmits_deauth(self):
        # Static guarantee: nothing in this module ever builds an
        # aireplay-ng / deauth command line.
        import inspect
        from modules.pentest import wpa_capture as mod
        src = inspect.getsource(mod)
        assert "aireplay" not in src.lower()
        assert "deauth" not in src.lower() or "never sends deauth" in src.lower() or "no deauth" in src.lower()


class TestCrackHandshake:
    def test_missing_capture_file(self, monkeypatch, tmp_path):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: True)
        result = crack_handshake(
            str(tmp_path / "nope.cap"), "AA:BB:CC:DD:EE:FF", str(tmp_path / "words.txt"),
        )
        assert result.error == "capture file not found"
        assert result.cracked is False

    def test_missing_wordlist(self, monkeypatch, tmp_path):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: True)
        cap = tmp_path / "cap.cap"
        cap.write_bytes(b"fake")
        result = crack_handshake(str(cap), "AA:BB:CC:DD:EE:FF", str(tmp_path / "nope.txt"))
        assert result.error == "wordlist not found"

    def test_missing_tool(self, monkeypatch, tmp_path):
        from modules.pentest import wpa_capture as mod
        monkeypatch.setattr(mod, "tool_exists", lambda name: False)
        result = crack_handshake(str(tmp_path), "AA:BB:CC:DD:EE:FF", str(tmp_path))
        assert "not installed" in result.error

    def test_successful_crack_via_mocked_shell(self, monkeypatch, tmp_path):
        from modules.pentest import wpa_capture as mod
        cap = tmp_path / "cap.cap"
        cap.write_bytes(b"fake")
        words = tmp_path / "words.txt"
        words.write_text("password\n")

        monkeypatch.setattr(mod, "tool_exists", lambda name: True)

        class FakeResult:
            returncode = 0
            stdout = "KEY FOUND! [ password ]\n"
            stderr = ""
            combined = "KEY FOUND! [ password ]\n"

        monkeypatch.setattr(mod, "_shell_run", lambda cmd, timeout=120.0: FakeResult())
        result = crack_handshake(str(cap), "AA:BB:CC:DD:EE:FF", str(words))
        assert result.cracked is True
        assert result.password == "password"
        assert result.error == ""


class TestToFindings:
    def test_capture_error(self):
        cap = CaptureResult(bssid="AA:BB", channel=6, error="airodump-ng not installed")
        findings = to_findings(cap)
        assert len(findings) == 1
        assert findings[0].type == "WPA_CAPTURE_ERROR"

    def test_no_handshake_captured(self):
        cap = CaptureResult(bssid="AA:BB", channel=6, handshake_captured=False, duration_s=60)
        findings = to_findings(cap)
        assert len(findings) == 1
        assert findings[0].type == "WPA_HANDSHAKE_NOT_CAPTURED"

    def test_handshake_captured_no_crack_attempt(self):
        cap = CaptureResult(bssid="AA:BB", channel=6, handshake_captured=True,
                             capture_file="/tmp/x.cap", duration_s=30)
        findings = to_findings(cap)
        assert any(f.type == "WPA_HANDSHAKE_CAPTURED" for f in findings)
        assert len(findings) == 1

    def test_handshake_captured_and_cracked(self):
        cap = CaptureResult(bssid="AA:BB", channel=6, handshake_captured=True,
                             capture_file="/tmp/x.cap", duration_s=30)
        crack = CrackResult(capture_file="/tmp/x.cap", wordlist="/tmp/words.txt",
                             cracked=True, password="hunter2", duration_s=5)
        findings = to_findings(cap, crack)
        assert any(f.type == "WPA_PASSPHRASE_WEAK" for f in findings)
        weak = [f for f in findings if f.type == "WPA_PASSPHRASE_WEAK"][0]
        assert weak.severity.value == "CRITICAL"
        # The real password must never leak into the persisted description/evidence.
        assert "hunter2" not in weak.description
        assert "hunter2" not in weak.evidence

    def test_handshake_captured_not_cracked(self):
        cap = CaptureResult(bssid="AA:BB", channel=6, handshake_captured=True,
                             capture_file="/tmp/x.cap", duration_s=30)
        crack = CrackResult(capture_file="/tmp/x.cap", wordlist="/tmp/words.txt",
                             cracked=False, duration_s=5)
        findings = to_findings(cap, crack)
        assert any(f.type == "WPA_PASSPHRASE_NOT_IN_DICTIONARY" for f in findings)

    def test_crack_error(self):
        cap = CaptureResult(bssid="AA:BB", channel=6, handshake_captured=True,
                             capture_file="/tmp/x.cap", duration_s=30)
        crack = CrackResult(capture_file="/tmp/x.cap", wordlist="/tmp/words.txt",
                             error="aircrack-ng not installed")
        findings = to_findings(cap, crack)
        assert any(f.type == "WPA_CRACK_ERROR" for f in findings)
