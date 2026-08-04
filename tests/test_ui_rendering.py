"""
CyberScope — tests/test_ui_rendering.py

Regression tests for a real bug found while building the Asset
Database view: rich.Console defaults to emoji=True, which silently
substitutes any `:shortcode:`-shaped substring for an emoji glyph --
including hex byte pairs inside MAC addresses that happen to collide
with a real shortcode name ("00:0C:29:AB:CD:EF" rendered as
"00:0C:29🆎CD:EF" because ":ab:" is the shortcode for the AB-blood-type
emoji). For a security tool, silently mangling a MAC/BSSID in a
findings table is a correctness bug, not a cosmetic one. Every
rich.Console this platform constructs must disable that substitution.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from io import StringIO

from rich.console import Console
from rich.table import Table

# Every real hex-byte pair that collides with a known emoji shortcode.
# If any of these ever regress, a real MAC/BSSID containing that byte
# pair would render corrupted.
_COLLIDING_PAIRS = ["AB", "CD", "OK", "UP", "NG", "ID", "VS", "CL"]


def _render(text: str) -> str:
    buf = StringIO()
    console = Console(file=buf, emoji=False, width=120)
    console.print(text)
    return buf.getvalue()


def _render_table_cell(text: str) -> str:
    buf = StringIO()
    console = Console(file=buf, emoji=False, width=120)
    t = Table()
    t.add_column("Value")
    t.add_row(text)
    console.print(t)
    return buf.getvalue()


class TestEmojiSubstitutionDisabled:
    def test_mac_with_ab_byte_survives_print(self):
        mac = "00:0C:29:AB:CD:EF"
        out = _render(mac)
        assert mac in out
        assert "🆎" not in out

    def test_mac_with_ab_byte_survives_table_cell(self):
        mac = "00:0C:29:AB:CD:EF"
        out = _render_table_cell(mac)
        assert "AB" in out
        assert "🆎" not in out

    def test_every_known_colliding_hex_pair(self):
        for pair in _COLLIDING_PAIRS:
            mac = f"AA:BB:{pair}:11:22:33"
            out = _render(mac)
            assert pair in out, f"byte pair {pair} was altered: {out!r}"

    def test_emoji_true_would_have_reproduced_the_bug(self):
        # Sanity check that this is a real, demonstrable Rich behavior
        # (not a test artifact) -- emoji=True on the exact same input
        # must still corrupt it, proving emoji=False is the actual fix.
        buf = StringIO()
        console = Console(file=buf, emoji=True, width=120)
        console.print("00:0C:29:AB:CD:EF")
        assert "🆎" in buf.getvalue()


class TestAppConsolesDisableEmoji:
    """Exercise the actual Console instances the app constructs (not a
    freshly-built stand-in) so a future `Console()` call that forgets
    emoji=False is caught here."""

    def test_main_module_console_renders_mac_unmangled(self):
        import main
        assert main._CON is not None, "rich must be installed for this test to be meaningful"
        buf = StringIO()
        original_file = main._CON.file
        main._CON.file = buf
        try:
            main._CON.print("00:0C:29:AB:CD:EF")
        finally:
            main._CON.file = original_file
        out = buf.getvalue()
        assert "AB" in out
        assert "🆎" not in out

    def test_live_view_console_renders_mac_unmangled(self):
        from ui.live_view import console as live_console
        buf = StringIO()
        original_file = live_console.file
        live_console.file = buf
        try:
            live_console.print("00:0C:29:AB:CD:EF")
        finally:
            live_console.file = original_file
        out = buf.getvalue()
        assert "AB" in out
        assert "🆎" not in out
