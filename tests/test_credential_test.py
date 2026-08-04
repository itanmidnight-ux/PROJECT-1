"""
CyberScope — tests/test_credential_test.py

Tests for modules/pentest/credential_test.py.

The `ssh_server` fixture spins up a REAL in-process SSH server using
paramiko's own server-side API (paramiko.Transport + ServerInterface)
bound to 127.0.0.1 on an ephemeral port, in a background thread. This
lets the tests exercise the actual TCP connect + SSH handshake + auth
exchange that test_ssh_credentials() performs — nothing about paramiko
itself is mocked here, only the "remote host" is a local server we
control.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from typing import Iterator, Tuple

import paramiko
import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.types import Severity
# Alias on import: pytest collects any top-level `test_*` name in a test
# module as a test case, so importing the function under its real name
# would make pytest try (and fail) to collect it directly.
from modules.pentest.credential_test import (
    CredentialTestResult,
    test_ssh_credentials as check_ssh_credentials,
    to_findings,
)

VALID_USERNAME = "testuser"
VALID_PASSWORD = "testpass"


# ── In-process SSH server (real handshake, no mocking) ───────────────────────

class _AcceptingServer(paramiko.ServerInterface):
    """Accepts exactly one (username, password) pair, rejects everything
    else. Sets `auth_done` once a client has completed an auth attempt so
    the connection handler knows it's safe to tear the transport down."""

    def __init__(self, valid_username: str, valid_password: str) -> None:
        self._valid_username = valid_username
        self._valid_password = valid_password
        self.auth_done = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        result = (
            paramiko.AUTH_SUCCESSFUL
            if username == self._valid_username and password == self._valid_password
            else paramiko.AUTH_FAILED
        )
        self.auth_done.set()
        return result

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.OPEN_SUCCEEDED


def _handle_connection(
    client_sock: socket.socket,
    host_key: paramiko.PKey,
    valid_username: str,
    valid_password: str,
) -> None:
    transport = paramiko.Transport(client_sock)
    try:
        transport.add_server_key(host_key)
        server = _AcceptingServer(valid_username, valid_password)
        transport.start_server(server=server)
        server.auth_done.wait(timeout=5)
        # Give the client a moment to receive the auth response before
        # this end tears the transport down underneath it.
        time.sleep(0.05)
    except Exception:
        pass
    finally:
        transport.close()


@pytest.fixture
def ssh_server() -> Iterator[Tuple[str, int, str, str]]:
    """Starts a minimal real SSH server on 127.0.0.1:<ephemeral port>
    accepting only (VALID_USERNAME, VALID_PASSWORD). Yields
    (host, port, username, password) and tears the server down after."""
    host_key = paramiko.ECDSAKey.generate()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(5)
    port = listener.getsockname()[1]

    stop_event = threading.Event()

    def serve() -> None:
        listener.settimeout(0.5)
        while not stop_event.is_set():
            try:
                client_sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=_handle_connection,
                args=(client_sock, host_key, VALID_USERNAME, VALID_PASSWORD),
                daemon=True,
            ).start()

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    try:
        yield "127.0.0.1", port, VALID_USERNAME, VALID_PASSWORD
    finally:
        stop_event.set()
        listener.close()
        server_thread.join(timeout=2)


def _closed_port() -> int:
    """Returns a TCP port on 127.0.0.1 that nothing is listening on, by
    binding then immediately releasing it."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ── test_ssh_credentials: real handshake against the in-process server ──────

class TestSshCredentialsRealHandshake:
    def test_succeeds_and_stops_at_one_attempt(self, ssh_server):
        host, port, username, password = ssh_server
        result = check_ssh_credentials(
            host, port,
            credentials=[(username, password)],
            timeout=2.0, delay_seconds=0,
        )
        assert result.succeeded == [(username, password)]
        assert result.attempted == 1
        assert result.errors == []

    def test_valid_pair_found_after_wrong_ones(self, ssh_server):
        host, port, username, password = ssh_server
        creds = [("wrong1", "bad"), ("wrong2", "bad"), (username, password), ("wrong3", "bad")]
        result = check_ssh_credentials(
            host, port, credentials=creds, timeout=2.0, delay_seconds=0,
        )
        assert result.succeeded == [(username, password)]
        # Stopped as soon as it found the working pair, not after trying all four.
        assert result.attempted == 3

    def test_all_fail_when_valid_pair_excluded(self, ssh_server):
        host, port, _username, _password = ssh_server
        creds = [("wrong1", "bad"), ("wrong2", "bad"), ("wrong3", "bad")]
        result = check_ssh_credentials(
            host, port, credentials=creds, timeout=2.0, delay_seconds=0,
        )
        assert result.succeeded == []
        assert result.attempted == len(creds)
        assert result.errors == []

    def test_max_attempts_is_honestly_enforced(self, ssh_server):
        host, port, _username, _password = ssh_server
        # A long list of credentials, none of which are valid.
        creds = [(f"user{i}", f"pass{i}") for i in range(50)]
        result = check_ssh_credentials(
            host, port, credentials=creds,
            max_attempts=5, timeout=2.0, delay_seconds=0,
        )
        assert result.attempted <= 5
        assert result.attempted == 5
        assert result.succeeded == []

    def test_unreachable_port_returns_quickly_with_error(self):
        port = _closed_port()
        start = time.monotonic()
        result = check_ssh_credentials(
            "127.0.0.1", port,
            credentials=[("a", "b")],
            timeout=1.0, max_attempts=1, delay_seconds=0,
        )
        elapsed = time.monotonic() - start
        assert result.succeeded == []
        assert len(result.errors) == 1
        assert result.attempted <= 1
        # Must not hang: a refused connection should fail almost instantly,
        # well under the 1s connect timeout being multiplied out.
        assert elapsed < 5.0

    def test_never_raises_on_connection_error(self):
        port = _closed_port()
        # Should not raise, regardless of how many creds are queued.
        result = check_ssh_credentials(
            "127.0.0.1", port,
            credentials=[("a", "b"), ("c", "d"), ("e", "f")],
            timeout=1.0, delay_seconds=0,
        )
        assert result.succeeded == []
        assert result.errors


# ── to_findings ───────────────────────────────────────────────────────────────

class TestToFindings:
    def test_succeeded_case(self):
        result = CredentialTestResult(
            host="10.0.0.5", port=22, attempted=1,
            succeeded=[("root", "hunter2")], errors=[], duration_ms=12.3,
        )
        findings = to_findings(result)
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "WEAK_SSH_CREDENTIALS"
        assert f.severity == Severity.CRITICAL
        assert f.module == "pentest"
        assert "root" in f.description
        assert "10.0.0.5" in f.description
        assert "22" in f.description
        # The real password must never appear anywhere in the finding.
        assert "hunter2" not in f.description
        assert "hunter2" not in f.evidence
        assert "hunter2" not in (f.recommendation or "")

    def test_succeeded_case_multiple_pairs_one_finding_each(self):
        result = CredentialTestResult(
            host="10.0.0.5", port=22, attempted=2,
            succeeded=[("root", "toor"), ("admin", "admin")],
            errors=[], duration_ms=5.0,
        )
        findings = to_findings(result)
        assert len(findings) == 2
        assert {f.type for f in findings} == {"WEAK_SSH_CREDENTIALS"}
        assert "toor" not in " ".join(f.description + f.evidence for f in findings)
        assert "admin" in findings[1].description  # username, not password, is fine

    def test_not_weak_case(self):
        result = CredentialTestResult(
            host="10.0.0.5", port=22, attempted=13,
            succeeded=[], errors=[], duration_ms=800.0,
        )
        findings = to_findings(result)
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "SSH_CREDENTIALS_NOT_WEAK"
        assert f.severity == Severity.INFO
        assert f.module == "pentest"

    def test_unreachable_case(self):
        result = CredentialTestResult(
            host="10.0.0.5", port=22, attempted=1,
            succeeded=[], errors=["connection refused"], duration_ms=15.0,
        )
        findings = to_findings(result)
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "SSH_UNREACHABLE"
        assert f.severity == Severity.INFO
        assert "connection refused" in f.evidence

    def test_no_real_password_leaks_across_all_cases(self):
        secret = "S3cr3tSauce!"
        cases = [
            CredentialTestResult(host="h", port=22, attempted=1,
                                  succeeded=[("root", secret)], errors=[]),
            CredentialTestResult(host="h", port=22, attempted=5,
                                  succeeded=[], errors=[]),
            CredentialTestResult(host="h", port=22, attempted=1,
                                  succeeded=[], errors=["connection timed out"]),
        ]
        for result in cases:
            for f in to_findings(result):
                assert secret not in f.description
                assert secret not in f.evidence
                assert secret not in (f.recommendation or "")
                assert secret not in str(f.to_dict())
