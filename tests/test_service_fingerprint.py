"""
CyberScope — tests/test_service_fingerprint.py

Tests for modules/pentest/service_fingerprint.py:
  - parse_banner()    pure regex parsing, sample banner strings, no I/O
  - grab_banner()     real TCP sockets against a local background server
  - fingerprint_host() end-to-end over real sockets
  - to_findings()     pure Finding construction
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path
from typing import Tuple

import pytest

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.types import Severity
from modules.pentest.service_fingerprint import (
    ServiceFingerprint,
    fingerprint_host,
    grab_banner,
    parse_banner,
    to_findings,
)


# ── Test server helpers (real sockets, no mocking) ──────────────────────────

def _start_immediate_banner_server(banner: bytes) -> Tuple[str, int, socket.socket]:
    """Bind an ephemeral loopback port and, on the first connection,
    send `banner` immediately (mimicking SSH/FTP's connect-time banner)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def _serve() -> None:
        try:
            srv.settimeout(5)
            conn, _ = srv.accept()
            with conn:
                conn.sendall(banner)
        except OSError:
            pass

    threading.Thread(target=_serve, daemon=True).start()
    return host, port, srv


def _start_request_response_server(response: bytes) -> Tuple[str, int, socket.socket]:
    """Bind an ephemeral loopback port and, on the first connection, wait
    for the client to send bytes (the HTTP request) then reply with
    `response` (mimicking a web server's Server: header)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    def _serve() -> None:
        try:
            srv.settimeout(5)
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(5)
                conn.recv(4096)
                conn.sendall(response)
        except OSError:
            pass

    threading.Thread(target=_serve, daemon=True).start()
    return host, port, srv


def _free_closed_port() -> Tuple[str, int]:
    """Return (host, port) of a loopback port with nothing listening on
    it, so connecting to it fails fast (connection refused)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    host, port = s.getsockname()
    s.close()
    return host, port


# ── parse_banner() — pure, no I/O ────────────────────────────────────────────

class TestParseBanner:
    def test_openssh(self):
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        product, version = parse_banner("ssh", banner)
        assert product == "OpenSSH"
        assert version == "8.9p1"

    def test_openssh_via_unknown_protocol_guess(self):
        banner = "SSH-2.0-OpenSSH_9.6p1"
        product, version = parse_banner("unknown", banner)
        assert product == "OpenSSH"
        assert version == "9.6p1"

    def test_nginx(self):
        banner = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n"
        product, version = parse_banner("http", banner)
        assert product == "nginx"
        assert version == "1.18.0"

    def test_apache(self):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"
        product, version = parse_banner("http", banner)
        assert product == "Apache"
        assert version == "2.4.41"

    def test_vsftpd(self):
        banner = "220 (vsFTPd 3.0.3)"
        product, version = parse_banner("ftp", banner)
        assert product == "vsftpd"
        assert version == "3.0.3"

    def test_unrecognized_banner_returns_empty(self):
        product, version = parse_banner("unknown", "some random junk\r\n")
        assert product == ""
        assert version == ""

    def test_empty_banner_returns_empty(self):
        assert parse_banner("ssh", "") == ("", "")

    def test_does_not_cross_match_wrong_protocol(self):
        # An nginx Server header shouldn't be mined for an SSH product
        # when protocol_guess is explicitly "ssh" (not "unknown").
        banner = "Server: nginx/1.18.0"
        product, version = parse_banner("ssh", banner)
        assert product == ""
        assert version == ""


# ── grab_banner() — real sockets ─────────────────────────────────────────────

class TestGrabBanner:
    def test_immediate_banner_like_ssh(self):
        host, port, srv = _start_immediate_banner_server(
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
        )
        try:
            banner = grab_banner(host, port, timeout=2.0)
        finally:
            srv.close()
        assert banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

    def test_http_server_header_extraction(self, monkeypatch):
        import modules.pentest.service_fingerprint as sf
        monkeypatch.setattr(sf, "_protocol_guess", lambda port: "http")

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.18.0\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        host, port, srv = _start_request_response_server(response)
        try:
            banner = grab_banner(host, port, timeout=2.0)
        finally:
            srv.close()
        assert "Server: nginx/1.18.0" in banner
        product, version = parse_banner("http", banner)
        assert product == "nginx"
        assert version == "1.18.0"

    def test_https_port_skips_handshake(self, monkeypatch):
        import modules.pentest.service_fingerprint as sf
        monkeypatch.setattr(sf, "_protocol_guess", lambda port: "https")
        # No server needed at all — grab_banner must not attempt a
        # connection for an https guess.
        assert grab_banner("127.0.0.1", 443, timeout=1.0) == "HTTPS (TLS)"

    def test_closed_port_returns_empty_quickly(self):
        host, port = _free_closed_port()
        timeout = 0.5
        start = time.monotonic()
        banner = grab_banner(host, port, timeout=timeout)
        elapsed = time.monotonic() - start
        assert banner == ""
        assert elapsed <= timeout * 2 + 1.0

    def test_unreachable_port_never_raises(self):
        # A closed port on loopback: connect() fails fast with
        # ECONNREFUSED rather than hanging — exercise the "never raises"
        # contract end to end.
        host, port = _free_closed_port()
        try:
            result = grab_banner(host, port, timeout=0.5)
        except Exception as e:  # pragma: no cover - must never happen
            pytest.fail(f"grab_banner raised {e!r} instead of returning \"\"")
        assert result == ""


# ── fingerprint_host() — real sockets end to end ─────────────────────────────

class TestFingerprintHost:
    def test_mixed_ports(self):
        host_a, port_a, srv_a = _start_immediate_banner_server(
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
        )
        closed_host, closed_port = _free_closed_port()
        try:
            results = fingerprint_host(host_a, [port_a, closed_port], timeout=1.0)
        finally:
            srv_a.close()

        assert len(results) == 2
        by_port = {r.port: r for r in results}

        banner_fp = by_port[port_a]
        assert isinstance(banner_fp, ServiceFingerprint)
        assert banner_fp.product == "OpenSSH"
        assert banner_fp.version == "8.9p1"
        assert banner_fp.banner != ""

        closed_fp = by_port[closed_port]
        # Still present in the results (port was checked) even though
        # nothing could be learned.
        assert closed_fp.banner == ""
        assert closed_fp.product == ""
        assert closed_fp.version == ""

    def test_every_port_gets_a_fingerprint_even_when_empty(self):
        closed_host, closed_port = _free_closed_port()
        results = fingerprint_host(closed_host, [closed_port], timeout=0.5)
        assert len(results) == 1
        assert results[0].port == closed_port


# ── to_findings() ────────────────────────────────────────────────────────────

class TestToFindings:
    def test_identified_service_emits_info_finding(self):
        fps = [
            ServiceFingerprint(
                port=22, protocol_guess="ssh",
                banner="SSH-2.0-OpenSSH_8.9p1", product="OpenSSH", version="8.9p1",
            ),
        ]
        findings = to_findings(fps, "192.168.1.10")
        assert len(findings) == 1
        f = findings[0]
        assert f.type == "SERVICE_FINGERPRINTED"
        assert f.severity == Severity.INFO
        assert f.module == "pentest"
        assert "192.168.1.10" in f.description
        assert "22" in f.description
        assert "OpenSSH" in f.description
        assert "8.9p1" in f.description
        assert f.evidence == "banner=SSH-2.0-OpenSSH_8.9p1"

    def test_unidentified_service_emits_no_finding(self):
        fps = [
            ServiceFingerprint(port=21, protocol_guess="ftp", banner="", product="", version=""),
            ServiceFingerprint(port=9999, protocol_guess="unknown", banner="garbage", product="", version=""),
        ]
        assert to_findings(fps, "192.168.1.10") == []

    def test_mixed_list_only_identified_ones_reported(self):
        fps = [
            ServiceFingerprint(port=80, protocol_guess="http", banner="Server: nginx/1.18.0",
                                product="nginx", version="1.18.0"),
            ServiceFingerprint(port=23, protocol_guess="telnet", banner="", product="", version=""),
        ]
        findings = to_findings(fps, "10.0.0.5")
        assert len(findings) == 1
        assert findings[0].description.startswith("10.0.0.5:80")
