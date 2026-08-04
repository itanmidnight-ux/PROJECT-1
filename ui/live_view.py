"""
CyberScope — ui/live_view.py

Reusable live TUI primitives for the interactive monitor menu:

  - activation_progress()  professional spinner/progress bar while a
                            monitor session is starting up
  - run_live_list()        static header + auto-refreshing enumerated
                            table the user can pick a row from
  - run_live_detail()      "locked" live view for one selected item,
                            refreshed on an interval, with a background
                            non-destructive security probe

Built on rich.live.Live. Input is read without blocking rendering via
select() on stdin — a real POSIX tty, true for both Linux and Termux.
If stdin isn't a tty (piped input, CI), list/detail views degrade to
"press Enter to exit" instead of hanging.
"""
from __future__ import annotations

import select
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

console = Console()


def _read_line_nonblocking(timeout: float) -> Optional[str]:
    """Return a full line typed by the user within `timeout` seconds, or
    None if nothing arrived. Never blocks longer than timeout."""
    if not sys.stdin.isatty():
        return None
    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
    except (OSError, ValueError):
        return None
    if not ready:
        return None
    line = sys.stdin.readline()
    return line.strip() if line else None


def header_panel(title: str, subtitle: str = "") -> Panel:
    text = f"[bold cyan]{title}[/bold cyan]"
    if subtitle:
        text += f"\n[dim]{subtitle}[/dim]"
    return Panel(text, style="cyan", padding=(0, 2))


def _format_value(v: Any) -> str:
    """Stable, consistent rendering for a detail-view value so the same
    field never prints differently between refreshes (e.g. a float
    that gains/loses trailing zeros, or None showing up as the literal
    string 'None')."""
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "Sí" if v else "No"
    if isinstance(v, float):
        return f"{v:.3f}"
    return str(v)


def activation_progress(
    title: str,
    steps: Sequence[Tuple[str, Callable[[], Any]]],
) -> Dict[str, Any]:
    """Run `steps` (label, fn) sequentially under a spinner/progress bar,
    returning {label: fn() result}. Used for the 'Activating monitor
    mode…' / 'Starting detection engine…' sequence before a live view
    opens."""
    results: Dict[str, Any] = {}
    with Progress(
        SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
        BarColumn(), TimeElapsedColumn(), console=console, transient=True,
    ) as progress:
        task = progress.add_task(title, total=len(steps))
        for label, fn in steps:
            progress.update(task, description=f"[cyan]{label}…[/cyan]")
            try:
                results[label] = fn()
            except Exception as exc:
                results[label] = None
                console.print(f"[yellow]  ! {label} failed: {exc}[/yellow]")
            progress.advance(task)
        progress.update(task, description="[green]Ready[/green]")
    return results


@dataclass
class ListColumn:
    header: str
    getter: Callable[[Any], str]


def run_live_list(
    title: str,
    subtitle_fn: Callable[[], str],
    poll_fn: Callable[[], List[Any]],
    columns: Sequence[ListColumn],
    refresh_interval: float = 3.0,
) -> Optional[Any]:
    """
    Enumerated, auto-refreshing live list. Returns the selected item, or
    None if the user backed out without selecting.

    Controls (type then Enter — never blocks the refresh loop):
      <number>   select that row
      r          refresh immediately
      q          back
    """
    items: List[Any] = []
    last_poll = 0.0
    status = "Scanning…"

    if not sys.stdin.isatty():
        items = poll_fn()
        console.print(f"[yellow]Non-interactive session — showing one scan pass "
                       f"({len(items)} found).[/yellow]")
        return None

    with Live(console=console, refresh_per_second=4, screen=False) as live:
        while True:
            now = time.monotonic()
            if now - last_poll >= refresh_interval or not items:
                try:
                    items = poll_fn()
                    status = f"{len(items)} found — live, refreshes every {refresh_interval:.0f}s"
                except Exception as exc:
                    status = f"[red]Scan error: {exc}[/red]"
                last_poll = now

            table = Table(title=title, expand=True)
            table.add_column("#", justify="right", style="bold yellow", width=4)
            for col in columns:
                table.add_column(col.header)
            for i, item in enumerate(items, start=1):
                table.add_row(str(i), *[col.getter(item) for col in columns])
            if not items:
                table.add_row("–", *(["—"] * len(columns)))

            body = Group(
                header_panel(title, subtitle_fn()),
                table,
                Text(f"{status}   ·   [#] select   ·   [r] refresh now   ·   [q] back",
                     style="dim"),
            )
            live.update(body)

            line = _read_line_nonblocking(0.25)
            if line is None:
                continue
            low = line.lower()
            if low in ("q", "quit", "exit", "b", "back"):
                return None
            if low in ("r", "refresh"):
                last_poll = 0.0
                continue
            if line.isdigit():
                idx = int(line)
                if 1 <= idx <= len(items):
                    return items[idx - 1]


def run_live_detail(
    title: str,
    item: Any,
    detail_fn: Callable[[Any], Dict[str, Any]],
    probe_fn: Optional[Callable[[Any], List[Any]]] = None,
    refresh_interval: float = 2.0,
) -> None:
    """
    "Locked" live view for a single selected item: every known field,
    refreshed on an interval, plus background non-destructive security
    probe results appended once they're ready. Press 'q' to go back.
    """
    probe_results: List[Any] = []
    probe_done  = threading.Event()
    probe_error: Optional[str] = None

    def _run_probe() -> None:
        nonlocal probe_error
        if probe_fn is None:
            probe_done.set()
            return
        try:
            probe_results.extend(probe_fn(item))
        except Exception as exc:
            probe_error = str(exc)
        probe_done.set()

    threading.Thread(target=_run_probe, daemon=True).start()

    if not sys.stdin.isatty():
        fields = detail_fn(item)
        console.print(Panel(str(fields), title=title))
        return

    last_poll = 0.0
    fields: Dict[str, Any] = {}

    with Live(console=console, refresh_per_second=4, screen=False) as live:
        while True:
            now = time.monotonic()
            if now - last_poll >= refresh_interval or not fields:
                try:
                    fields = detail_fn(item)
                except Exception as exc:
                    fields = {"error": str(exc)}
                last_poll = now

            # Field labels never wrap (no_wrap + auto-fit to content) so a
            # row is always exactly one line — a fixed ratio here would
            # let a slightly-too-long label wrap and visibly deform the
            # panel between refreshes.
            detail_table = Table(show_header=False, expand=True, box=None, padding=(0, 1))
            detail_table.add_column("Field", style="bold cyan", no_wrap=True)
            detail_table.add_column("Value", ratio=1, overflow="fold")
            for k, v in fields.items():
                detail_table.add_row(str(k), _format_value(v))

            sec_lines: List[str] = []
            if probe_fn is not None:
                if not probe_done.is_set():
                    sec_lines.append("[dim]Running non-destructive security probe…[/dim]")
                elif probe_error:
                    sec_lines.append(f"[red]Probe error: {probe_error}[/red]")
                elif not probe_results:
                    sec_lines.append("[green]No issues found by automated probe.[/green]")
                else:
                    for f in probe_results:
                        sev = getattr(f, "severity", None)
                        sev_val = getattr(sev, "value", str(sev))
                        desc = getattr(f, "description", str(f))
                        sec_lines.append(f"[bold]{sev_val}[/bold] — {desc}")

            body = Group(
                header_panel(title),
                Panel(detail_table, title="Live Detail", border_style="cyan"),
                Panel("\n".join(sec_lines) or "—", title="Security Probe", border_style="yellow"),
                Text(f"Refreshing every {refresh_interval:.0f}s   ·   [q] back", style="dim"),
            )
            live.update(body)

            line = _read_line_nonblocking(0.25)
            if line and line.lower() in ("q", "quit", "exit", "b", "back"):
                return
