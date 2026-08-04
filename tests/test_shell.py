"""
CyberScope — tests/test_shell.py

Tests for core/shell.py, the consolidated subprocess/tool-detection
layer that replaced 14 near-identical copies scattered across
core/discovery.py, core/permissions.py, and every scan/monitor module.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.shell import RunResult, run, safe_iterdir, tool_exists


class TestRun:
    def test_success_captures_stdout_and_stderr(self):
        r = run(["python3", "-c", "import sys; print('out'); print('err', file=sys.stderr)"])
        assert r.returncode == 0
        assert r.stdout.strip() == "out"
        assert r.stderr.strip() == "err"
        assert r.ok is True

    def test_combined_property(self):
        r = run(["python3", "-c", "print('a')"])
        assert "a" in r.combined

    def test_nonzero_exit_is_not_ok(self):
        r = run(["python3", "-c", "import sys; sys.exit(3)"])
        assert r.returncode == 3
        assert r.ok is False

    def test_missing_binary_returns_minus_one(self):
        r = run(["this-binary-does-not-exist-cyberscope"])
        assert r.returncode == -1
        assert r.stdout == ""
        assert r.stderr  # error message present

    def test_timeout_returns_minus_one(self):
        r = run(["python3", "-c", "import time; time.sleep(5)"], timeout=0.2)
        assert r.returncode == -1
        assert r.stdout == ""

    def test_never_raises_on_bad_command(self):
        # Should not raise even for a nonsense command list
        r = run([])
        assert isinstance(r, RunResult)
        assert r.returncode == -1


class TestToolExists:
    def test_known_tool(self):
        assert tool_exists("python3") is True

    def test_unknown_tool(self):
        assert tool_exists("definitely-not-a-real-tool-xyz") is False


class TestSafeIterdir:
    def test_lists_real_directory(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        entries = safe_iterdir(tmp_path)
        names = {p.name for p in entries}
        assert names == {"a", "b"}

    def test_nonexistent_directory_returns_empty(self, tmp_path):
        assert safe_iterdir(tmp_path / "nope") == []

    def test_permission_denied_returns_empty_not_raise(self, tmp_path, monkeypatch):
        from pathlib import Path as _Path

        def boom(self):
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(_Path, "iterdir", boom)
        assert safe_iterdir(tmp_path) == []
