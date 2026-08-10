"""
CyberScope — ui/live_view.py

Reusable live TUI primitives for the interactive monitor menu:

  - activation_progress()  professional spinner/progress bar while a
                            monitor session is starting up
  - run_live_list()        static header + auto-refreshing enumerated
                            table the user can pick a row from
  - run_live_detail()      Multi-panel dashboard for a single selected item:
                            - Info panel (static network details)
                            - Live attack progress panel (auto-starts attack)
                            - Live clients panel (real-time enumeration)
                            - Attack control panel (auto-starts attacks)
                            - Action menu panel (shows when 'a' pressed with vertical options)
                            - Connected device monitoring

Built on rich.live.Live. Input is read without blocking rendering via
select() on stdin — a real POSIX tty, true for both Linux and Termux.
If stdin isn't a tty (piped input, CI), list/detail views degrade to
"press Enter to exit" instead of hanging.
"""
from __future__ import annotations

import json
import select
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.box import ROUNDED

# emoji=False: Rich's default `:shortcode:` emoji substitution would
# otherwise silently corrupt any MAC/BSSID/identifier containing a hex
# byte pair that collides with a real emoji shortcode (":ab:" -> "🆎",
# ":cd:", ":ok:", ":up:", etc. all exist) -- these live views render
# security-relevant identifiers that must appear byte-for-byte.
console = Console(emoji=False)


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
    if not line:
        return None
    return line.strip()


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


def _severity_color(severity: str) -> str:
    """Return Rich color for severity level."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "bold blue",
    }
    return colors.get(severity.upper(), "white")


def _execute_action(action_num: int, item: Any, fields: Dict[str, Any], 
                    extra_actions: Optional[Callable[[], None]],
                    attack_callback: Optional[Callable[[], None]],
                    client_enum_callback: Optional[Callable[[], List[Any]]],
                    attack_log_lock: threading.Lock,
                    attack_log_lines: List[str]) -> None:
    """Execute the selected action in background thread."""
    def _run_action():
        try:
            with attack_log_lock:
                attack_log_lines.append(f"[cyan]▶ Ejecutando acción {action_num}...[/cyan]")
            
            if action_num == 1:
                # Full audit
                if attack_callback:
                    attack_callback()
            elif action_num == 2:
                # PMKID
                with attack_log_lock:
                    attack_log_lines.append("[yellow]PMKID attack not yet implemented in quick actions[/yellow]")
            elif action_num == 3:
                # Deauth handshake
                with attack_log_lock:
                    attack_log_lines.append("[yellow]Deauth handshake not yet implemented in quick actions[/yellow]")
            elif action_num == 4:
                # WPS
                with attack_log_lock:
                    attack_log_lines.append("[yellow]WPS attack not yet implemented in quick actions[/yellow]")
            elif action_num == 5:
                # Crack handshake
                with attack_log_lock:
                    attack_log_lines.append("[yellow]Handshake crack not yet implemented in quick actions[/yellow]")
            elif action_num == 6:
                # Enum clients
                if client_enum_callback:
                    clients = client_enum_callback()
                    with attack_log_lock:
                        attack_log_lines.append(f"[green]✓ Enumerados {len(clients)} clientes[/green]")
            elif action_num == 7:
                # Connect
                with attack_log_lock:
                    attack_log_lines.append("[yellow]Connect not yet implemented in quick actions[/yellow]")
            
            with attack_log_lock:
                attack_log_lines.append("[green]✓ Acción completada[/green]")
        except Exception as e:
            with attack_log_lock:
                attack_log_lines.append(f"[red]❌ Error: {e}[/red]")
    threading.Thread(target=_run_action, daemon=True).start()


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
    sort_key: Optional[Callable] = None
    sort_reverse = True
    filter_text = ""

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

            # Apply filter if set
            display_items = items
            if filter_text:
                display_items = [item for item in items 
                    if filter_text.lower() in str(item).lower()]

            # Apply sorting if set
            if sort_key:
                try:
                    display_items = sorted(display_items, key=sort_key, reverse=sort_reverse)
                except Exception:
                    pass

            table = Table(title=title, expand=True, box=ROUNDED)
            table.add_column("#", justify="right", style="bold yellow", width=4)
            for col in columns:
                table.add_column(col.header)
            for i, item in enumerate(display_items, start=1):
                row_data = [str(i)]
                for col in columns:
                    try:
                        val = col.getter(item)
                        row_data.append(val)
                    except Exception:
                        row_data.append("[red]Error[/red]")
                table.add_row(*row_data)
            if not display_items:
                table.add_row("–", *(["—"] * len(columns)))

            # Status bar with controls
            controls = Text()
            controls.append("  [#] select  ", style="bold yellow")
            controls.append("  [r] refresh  ", style="bold cyan")
            controls.append("  [f] filter  ", style="bold magenta")
            controls.append("  [s] sort  ", style="bold blue")
            controls.append("  [q] back  ", style="bold red")

            body = Group(
                header_panel(title, subtitle_fn()),
                table,
                Text(status, style="dim"),
                controls,
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
            if low in ("f", "filter"):
                # Prompt for filter text
                console.print("\n[bold]Enter filter text (empty to clear):[/bold] ", end="")
                filter_text = sys.stdin.readline().strip()
                continue
            if low in ("s", "sort"):
                # Toggle sort
                if sort_key is None:
                    # Default to first column
                    if columns:
                        sort_key = lambda x: str(columns[0].getter(x))
                        sort_reverse = True
                else:
                    sort_reverse = not sort_reverse
                continue
            if line.isdigit():
                idx = int(line)
                if 1 <= idx <= len(display_items):
                    return display_items[idx - 1]


def run_live_detail(
    title: str,
    item: Any,
    detail_fn: Callable[[Any], Dict[str, Any]],
    probe_fn: Optional[Callable[[Any], List[Any]]] = None,
    refresh_interval: float = 2.0,
    extra_actions: Optional[Callable[[], None]] = None,
    layout_mode: str = "dashboard",
    auto_attack: bool = True,
    attack_callback: Optional[Callable[[], None]] = None,
    client_enum_callback: Optional[Callable[[], List[Any]]] = None,
) -> None:
    """
    Multi-panel dashboard for a single selected item:
    - Info panel (static network details)
    - Live attack progress panel (auto-starts attack)
    - Live clients panel (real-time enumeration)
    - Attack control panel (auto-starts attacks)
    - Action menu panel (shows when 'a' pressed with vertical options)
    - Connected device monitoring
    """
    probe_results: List[Any] = []
    probe_done = threading.Event()
    probe_error: Optional[str] = None
    attack_started = False
    attack_completed = False
    attack_result: Optional[Any] = None
    attack_thread: Optional[threading.Thread] = None
    clients: List[Any] = []
    client_lock = threading.Lock()
    client_thread: Optional[threading.Thread] = None
    client_running = True
    last_client_update = 0
    attack_running = True
    show_raw = False
    attack_launched = False
    show_action_menu = False
    action_menu_selection = 0
    attack_log_lines: List[str] = ["[bold]Attack Progress Log (Live):[/bold]"]
    attack_log_lock = threading.Lock()

    def _run_probe() -> None:
        nonlocal probe_error, probe_results
        if probe_fn is None:
            probe_done.set()
            return
        try:
            probe_results.extend(probe_fn(item))
        except Exception as exc:
            probe_error = str(exc)
        probe_done.set()

    # Start probe in background
    threading.Thread(target=_run_probe, daemon=True).start()

    # Client enumeration thread
    def _background_client_enum():
        nonlocal clients
        while client_running:
            try:
                if client_enum_callback:
                    with client_lock:
                        clients = client_enum_callback()
                time.sleep(5)
            except Exception:
                pass

    threading.Thread(target=_background_client_enum, daemon=True).start()

    # Auto-attack thread with logging
    def _auto_attack():
        nonlocal attack_started, attack_completed, attack_result, attack_launched
        if not auto_attack or attack_callback is None:
            return
        # Wait a moment for UI to initialize
        time.sleep(1)
        attack_launched = True
        attack_started = True
        try:
            with attack_log_lock:
                attack_log_lines.append("[yellow]🔄 Iniciando auditoría automática completa...[/yellow]")
            attack_callback()
            attack_completed = True
        except Exception as e:
            with attack_log_lock:
                attack_log_lines.append(f"[red]❌ Error en ataque: {e}[/red]")

    if auto_attack and attack_callback:
        threading.Thread(target=_auto_attack, daemon=True).start()

    if not sys.stdin.isatty():
        fields = detail_fn(item)
        console.print(Panel(str(fields), title=title))
        return

    last_poll = 0.0
    fields: Dict[str, Any] = {}
    show_raw = False

    with Live(console=console, refresh_per_second=4, screen=True) as live:
        while True:
            now = time.monotonic()
            if now - last_poll >= refresh_interval or not fields:
                try:
                    fields = detail_fn(item)
                except Exception as exc:
                    fields = {"error": str(exc)}
                last_poll = now

            # Extract key info for dashboard
            bssid = fields.get("BSSID", "unknown")
            ssid = fields.get("SSID", "unknown")
            channel = fields.get("Channel", "unknown")
            freq = fields.get("Frequency (GHz)", "unknown")
            signal = fields.get("Signal (dBm)", "unknown")
            security = fields.get("Security", "unknown")
            vendor = fields.get("Vendor", "unknown")
            first_seen = fields.get("First seen", "unknown")
            last_seen = fields.get("Last seen", "unknown")
            times_seen = fields.get("Times seen", "unknown")

            # Build info panel
            info_table = Table(show_header=False, box=ROUNDED, padding=(0, 1))
            info_table.add_column("Field", style="bold cyan", no_wrap=True, width=22)
            info_table.add_column("Value", style="white", ratio=1)
            info_table.add_row("SSID", ssid)
            info_table.add_row("BSSID", bssid)
            info_table.add_row("Vendor", vendor)
            info_table.add_row("Channel", str(channel))
            info_table.add_row("Frequency", f"{freq} GHz" if freq != "unknown" else "unknown")
            info_table.add_row("Signal", f"{signal} dBm" if signal != "unknown" else "unknown")
            info_table.add_row("Security", security)
            info_table.add_row("First seen", first_seen)
            info_table.add_row("Last seen", last_seen)
            info_table.add_row("Times seen", str(times_seen))

            # Build probe/attack status panel
            probe_lines = []
            if probe_fn is not None:
                if not probe_done.is_set():
                    probe_lines.append("[yellow]🔄 Running security probe...[/yellow]")
                elif probe_error:
                    probe_lines.append(f"[red]❌ Probe error: {probe_error}[/red]")
                elif not probe_results:
                    probe_lines.append("[green]✅ No issues found by automated probe.[/green]")
                else:
                    for f in probe_results:
                        sev = getattr(f, "severity", None)
                        sev_val = getattr(sev, "value", str(sev))
                        desc = getattr(f, "description", str(f))
                        color = _severity_color(sev_val)
                        probe_lines.append(f"[{color}]{sev_val}[/{color}] {desc}")

            # Build client list panel
            client_lines = ["[bold]Connected Clients (Live):[/bold]"]
            with client_lock:
                if clients:
                    for c in clients:
                        mac = getattr(c, 'mac', getattr(c, 'address', str(c)))
                        vendor_str = getattr(c, 'vendor', '') or 'Unknown'
                        signal_str = getattr(c, 'signal', '') or '0'
                        client_lines.append(f"  {mac} | {vendor_str} | {signal_str} dBm")
                else:
                    client_lines.append("[dim]Enumerating clients...[/dim]")

            # Build attack log panel (vertical updates)
            with attack_log_lock:
                attack_display = attack_log_lines[-15:] if len(attack_log_lines) > 15 else attack_log_lines
            
            attack_log_panel_lines = ["[bold]Attack Progress Log (Live):[/bold]"] + attack_display

            # If attack completed, show credential
            if attack_completed and attack_result and hasattr(attack_result, 'credentials') and attack_result.credentials:
                with attack_log_lock:
                    attack_log_lines.append(f"[bold green]🔑 CREDENTIAL FOUND: {attack_result.credentials}[/bold green]")

            # Build action menu panel
            if show_action_menu:
                action_lines = ["[bold yellow]⚡ MENÚ DE ACCIONES[/bold yellow]", ""]
                actions = [
                    ("1", "🔴 ATAQUE COMPLETO (PMKID + Deauth + WPS + Crack + Enum)"),
                    ("2", "PMKID Attack (sin cliente necesario)"),
                    ("3", "Deauth + Handshake Capture (forzar reautenticación)"),
                    ("4", "WPS Attack (Pixie-Dust + Brute Force)"),
                    ("5", "Crack Handshake (Aircrack-ng / Hashcat GPU)"),
                    ("6", "Enumerar clientes conectados"),
                    ("7", "Conectar a la red (si hay credenciales)"),
                    ("q", "Volver al monitor"),
                ]
                for key, desc in actions:
                    if key == str(action_menu_selection) or (action_menu_selection == 0 and key == "1"):
                        action_lines.append(f"[bold black on yellow]  {key}  {desc}  [/bold black on yellow]")
                    else:
                        action_lines.append(f"  {key}  {desc}")
                action_lines.append("")
                action_lines.append("[dim]Use ↑/↓ or number keys, Enter to select, 'q' to close[/dim]")
            else:
                action_lines = ["[dim]Press 'a' to open action menu[/dim]"]

            # Controls
            controls_text = Text()
            controls_text.append("  [r] Refresh  ", style="bold cyan")
            controls_text.append("  [a] Actions  ", style="bold yellow")
            controls_text.append("  [c] Connect  ", style="bold green")
            controls_text.append("  [q] Quit  ", style="bold red")

            # Build multi-panel layout
            info_panel = Panel(info_table, title="[bold]Network Info[/bold]", border_style="cyan")
            probe_panel = Panel("\n".join(probe_lines) or "—", title="[bold]Security Probe[/bold]", border_style="yellow")
            client_panel = Panel("\n".join(client_lines) or "—", title="[bold]Connected Clients[/bold]", border_style="green")
            
            # Attack log panel with vertical updates
            attack_panel = Panel(
                "\n".join(attack_log_panel_lines) or "—", 
                title="[bold]Attack Progress (Vertical Log)[/bold]", 
                border_style="magenta"
            )
            
            # Action menu panel
            action_panel = Panel(
                "\n".join(action_lines) or "—", 
                title="[bold]Action Menu[/bold]", 
                border_style="yellow" if show_action_menu else "blue"
            )
            
            controls_panel = Panel(Text("  [r] Refresh  ·  [a] Actions  ·  [c] Connect  ·  [q] Quit", style="dim"), border_style="blue")

            # Layout: 3x2 grid
            top_row = Columns([info_panel, probe_panel], equal=True)
            mid_row = Columns([client_panel, attack_panel], equal=True)
            bottom_row = Columns([action_panel, controls_panel], equal=True)
            body = Group(
                header_panel(title),
                top_row,
                mid_row,
                bottom_row,
            )
            live.update(body)

            line = _read_line_nonblocking(0.25)
            if line and line.lower() in ("q", "quit", "exit", "b", "back"):
                if show_action_menu:
                    show_action_menu = False
                    action_menu_selection = 0
                else:
                    return
            if line and line.lower() in ("r", "raw"):
                pass  # show_raw = not show_raw (would need state management)
            if line and line.lower() in ("a", "action", "actions"):
                show_action_menu = not show_action_menu
                action_menu_selection = 0
            if line and line.lower() in ("c", "connect") and attack_completed and attack_result and hasattr(attack_result, 'credentials'):
                # Auto-connect logic would go here
                pass
            
            # Handle action menu navigation
            if show_action_menu:
                if line and line.isdigit() and 1 <= int(line) <= 7:
                    action_menu_selection = int(line)
                elif line and line.lower() == 'q':
                    show_action_menu = False
                    action_menu_selection = 0
                elif line == '\x1b[A':  # Up arrow (ESC[A)
                    action_menu_selection = max(1, action_menu_selection - 1)
                elif line == '\x1b[B':  # Down arrow (ESC[B)
                    action_menu_selection = min(7, action_menu_selection + 1)
                elif line == '\n' or line == '\r':  # Enter
                    # Execute selected action
                    _execute_action(action_menu_selection, item, fields, extra_actions, attack_callback, client_enum_callback, attack_log_lock, attack_log_lines)
                    show_action_menu = False
                    action_menu_selection = 0


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


def _severity_color(severity: str) -> str:
    """Return Rich color for severity level."""
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold orange3",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "bold blue",
    }
    return colors.get(severity.upper(), "white")


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


def header_panel(title: str, subtitle: str = "") -> Panel:
    text = f"[bold cyan]{title}[/bold cyan]"
    if subtitle:
        text += f"\n[dim]{subtitle}[/dim]"
    return Panel(text, style="cyan", padding=(0, 2))