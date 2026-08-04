"""
CyberScope — tests/test_authorization.py

Tests for core/authorization.py, the consent gate every active-testing
feature must pass through before touching a real target.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.authorization import AuthorizationDecision, confirm_target


class TestConfirmTarget:
    def test_exact_match_grants(self):
        d = confirm_target("192.168.1.50", "credential_test", "192.168.1.50")
        assert d.granted is True
        assert d.reason == ""

    def test_case_insensitive_match_grants(self):
        d = confirm_target("AA:BB:CC:DD:EE:FF", "wpa_capture", "aa:bb:cc:dd:ee:ff")
        assert d.granted is True

    def test_whitespace_trimmed(self):
        d = confirm_target("192.168.1.50", "credential_test", "  192.168.1.50  ")
        assert d.granted is True

    def test_mismatch_denies(self):
        d = confirm_target("192.168.1.50", "credential_test", "192.168.1.51")
        assert d.granted is False
        assert "did not match" in d.reason

    def test_empty_string_denies(self):
        d = confirm_target("192.168.1.50", "credential_test", "")
        assert d.granted is False

    def test_bare_yes_denies(self):
        # A reflexive "y"/"yes" must never authorize anything.
        for typed in ("y", "yes", "Y", "YES", "confirm"):
            d = confirm_target("192.168.1.50", "credential_test", typed)
            assert d.granted is False, f"{typed!r} should not have granted authorization"

    def test_decision_carries_target_and_action(self):
        d = confirm_target("192.168.1.50", "wpa_capture", "192.168.1.50")
        assert d.target == "192.168.1.50"
        assert d.action == "wpa_capture"

    def test_to_dict(self):
        d = confirm_target("192.168.1.50", "credential_test", "192.168.1.50")
        data = d.to_dict()
        assert data["granted"] is True
        assert data["target"] == "192.168.1.50"
        assert data["action"] == "credential_test"
        assert "timestamp" in data

    def test_denied_decision_logged(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="cyberscope.authorization"):
            confirm_target("192.168.1.50", "credential_test", "wrong")
        assert any("DENIED" in r.message for r in caplog.records)

    def test_granted_decision_logged(self, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger="cyberscope.authorization"):
            confirm_target("192.168.1.50", "credential_test", "192.168.1.50")
        assert any("GRANTED" in r.message for r in caplog.records)
