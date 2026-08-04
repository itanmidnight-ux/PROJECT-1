"""
CyberScope AI Security Platform — main.py

Interactive security assessment platform.
Detects available capabilities and shows only relevant options.

Usage:
    python3 main.py                  # interactive mode
    python3 main.py --auto           # auto-audit all modules
    python3 main.py --module wifi    # single module
    python3 main.py --report json    # generate report from last session
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import os
import time
from pathlib import Path
from typing import List, Optional

# Ensure project root is in path (critical for Termux / non-CWD execution)
_ROOT = Path(__file__).parent.resolve()
for _p in [str(_ROOT), str(_ROOT / "modules" / "telecom")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from rich.console  import Console
    from rich.panel    import Panel
    from rich.table    import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt   import Prompt, Confirm
    from rich.text     import Text
    _CON = Console()
    _RICH = True
except ImportError:
    _CON = None  # type: ignore
    _RICH = False

BANNER = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
"""


def _print(msg: str) -> None:
    if _CON:
        _CON.print(msg)
    else:
        import re
        print(re.sub(r'\[/?[^\]]+\]', '', msg))


def _input(prompt: str) -> str:
    if _RICH:
        return Prompt.ask(prompt)
    return input(prompt + " ")


def _confirm(prompt: str) -> bool:
    if _RICH:
        return Confirm.ask(prompt)
    return input(prompt + " [y/N] ").strip().lower() == "y"


def _banner() -> None:
    if _CON:
        _CON.print(f"[bold cyan]{BANNER}[/bold cyan]")
        _CON.print(Panel(
            "[cyan]AI Security Platform v1.0.0[/cyan]  |  "
            "[yellow]Authorized use only[/yellow]",
            style="bold",
        ))
    else:
        print(BANNER)
        print("  CyberScope AI Security Platform v1.0.0")
        print("  Authorized use only\n")


# ── Discovery display ─────────────────────────────────────────────────────────

def _show_capabilities(caps) -> None:
    from core.discovery import ModuleStatus
    priv = caps.privileges
    priv_detail = f"{priv.method.replace('_',' ')}" + ("" if priv.can_escalate else f" — {priv.reason}")
    mm = caps.wifi.details.get("monitor_mode") if caps.wifi.details else False
    mm_reason = caps.wifi.details.get("monitor_mode_reason", "") if caps.wifi.details else ""
    items = [
        ("OS",          f"{caps.os_info.env_label} / {caps.os_info.arch}",  True),
        ("Privileges",  priv_detail,                                        priv.can_escalate),
        ("Network",     f"{len(caps.network)} interface(s)",                bool(caps.network)),
        ("WiFi",        caps.wifi.reason or caps.wifi.status.value,         bool(caps.wifi)),
        ("WiFi Monitor Mode", "Supported" if mm else (mm_reason or "Unsupported"), bool(mm)),
        ("Bluetooth",   caps.bluetooth.reason or caps.bluetooth.status.value, bool(caps.bluetooth)),
        ("SDR",         caps.sdr.reason or caps.sdr.status.value,           bool(caps.sdr)),
        ("Telecom/SS7", "Always available (simulator + PCAP)",              True),
    ]
    if _CON:
        t = Table(title="System Capabilities", style="cyan", show_header=True)
        t.add_column("Component"); t.add_column("Status"); t.add_column("Detail")
        for name, detail, ok in items:
            icon = "[green]✓[/green]" if ok else "[red]✗[/red]"
            t.add_row(icon, name, detail)
        _CON.print(t)
    else:
        print("\n  System Capabilities")
        print("  " + "─" * 40)
        for name, detail, ok in items:
            mark = "✓" if ok else "✗"
            print(f"  {mark} {name:<15} {detail}")
        print()


# ── Menu ──────────────────────────────────────────────────────────────────────

_MENU_ITEMS = [
    ("1",  "auto",             "Auditoría automática completa",             None),
    ("2",  "network",          "Análisis de red local",                     "network"),
    ("3",  "wifi",             "Análisis WiFi",                             "wifi"),
    ("4",  "wifi_monitor",     "Monitoreo WiFi en vivo (lista → detalle)",  "wifi"),
    ("5",  "bluetooth",        "Análisis Bluetooth",                        "bluetooth"),
    ("6",  "bluetooth_monitor","Monitoreo Bluetooth en vivo (lista → detalle)", "bluetooth"),
    ("7",  "device",           "Información del dispositivo",               "device"),
    ("8",  "telecom",          "Análisis Telecom / SS7",                    "telecom"),
    ("9",  "report",           "Generar reporte (JSON / HTML / Markdown)",  None),
    ("10", "history",          "Historial de auditorías",                   None),
    ("11", "quit",             "Salir",                                     None),
]


def _show_menu(caps) -> None:
    available_mods = caps.available_modules() if caps else []

    if _CON:
        t = Table(title="Menú Principal", style="cyan", show_header=False)
        t.add_column("Key", justify="right", style="bold yellow")
        t.add_column("Action")
        for key, action, label, mod_req in _MENU_ITEMS:
            if mod_req and mod_req not in available_mods:
                t.add_row(key, f"[dim]{label} (no disponible)[/dim]")
            else:
                t.add_row(key, label)
        _CON.print(t)
    else:
        print("\n  Seleccione una operación:\n")
        for key, action, label, mod_req in _MENU_ITEMS:
            avail = "" if (not mod_req or mod_req in available_mods) else " [no disponible]"
            print(f"  {key}. {label}{avail}")
        print()


# ── Actions ───────────────────────────────────────────────────────────────────

def _run_module_with_progress(engine, module: str) -> None:
    if _RICH:
        with Progress(
            SpinnerColumn(), TextColumn("{task.description}"),
            BarColumn(), console=_CON,
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {module}…", total=None)
            result = engine.run_module(module)
            progress.update(task, completed=True)
    else:
        print(f"  Scanning {module}…")
        result = engine.run_module(module)

    _show_result(result)


def _show_result(result) -> None:
    sev_colors = {
        "CRITICAL": "red", "HIGH": "orange3",
        "MEDIUM": "yellow", "LOW": "green", "INFO": "dim",
    }
    if _CON:
        t = Table(title=f"{result.module.upper()} — {result.finding_count} findings",
                  style="cyan")
        t.add_column("Severity"); t.add_column("Type"); t.add_column("Description", max_width=70)
        for f in result.findings:
            c = sev_colors.get(f.severity.value, "white")
            t.add_row(
                f"[{c}]{f.severity.value}[/{c}]",
                f.type,
                f.description[:100],
            )
        _CON.print(t)
    else:
        print(f"\n  {result.module.upper()}: {result.finding_count} finding(s)")
        for f in result.findings:
            print(f"  [{f.severity.value}] {f.type}: {f.description[:80]}")
        print()


def _run_wifi_monitor(engine, caps) -> None:
    from modules.wifi.monitor import WiFiMonitor
    from ui.live_view import ListColumn, activation_progress, run_live_detail, run_live_list

    mon = WiFiMonitor(engine.cfg)
    if not mon.available:
        _print("[red]No WiFi interface available for monitoring.[/red]")
        return

    activation_progress("WiFi Monitor", [
        ("Verificando privilegios",          lambda: caps.privileges.to_dict()),
        ("Verificando soporte de modo monitor", lambda: caps.wifi.details.get("monitor_mode")),
        ("Iniciando motor de detección",     mon.poll),
    ])

    def subtitle() -> str:
        mm = "monitor-mode capable" if caps.wifi.details.get("monitor_mode") else "active-scan mode"
        return f"Interface: {mon.interface}  ·  {mm}  ·  {len(mon.registry)} tracked"

    columns = [
        ListColumn("SSID",     lambda n: n.ssid),
        ListColumn("BSSID",    lambda n: n.bssid or "—"),
        ListColumn("Signal",   lambda n: f"{n.signal} dBm"),
        ListColumn("Channel",  lambda n: str(n.channel) if n.channel else "—"),
        ListColumn("Security", lambda n: n.security),
    ]

    selected = run_live_list("WiFi Monitor — Live Networks", subtitle, mon.poll, columns)
    if selected is None:
        return

    def detail(net) -> dict:
        mon.poll()
        t = mon.registry.get(net.key, net)
        return {
            "SSID":            t.ssid,
            "BSSID":           t.bssid or "unknown",
            "Channel":         t.channel or "unknown",
            "Frequency (GHz)": t.frequency or "unknown",
            "Signal (dBm)":    t.signal,
            "Security":        t.security,
            "First seen":      time.strftime("%H:%M:%S", time.localtime(t.first_seen)),
            "Last seen":       time.strftime("%H:%M:%S", time.localtime(t.last_seen)),
            "Times seen":      t.seen_count,
        }

    run_live_detail(
        f"WiFi Network — {selected.ssid}", selected, detail,
        probe_fn=lambda n: mon.probe(n.key),
    )


def _run_bluetooth_monitor(engine, caps) -> None:
    from modules.bluetooth.monitor import BluetoothMonitor
    from ui.live_view import ListColumn, activation_progress, run_live_detail, run_live_list

    mon = BluetoothMonitor(engine.cfg)
    if not mon.available:
        _print("[red]No Bluetooth adapter available for monitoring.[/red]")
        return

    activation_progress("Bluetooth Monitor", [
        ("Verificando privilegios",      lambda: caps.privileges.to_dict()),
        ("Verificando adaptador",        lambda: mon.scanner.adapters[0].name),
        ("Iniciando motor de detección", mon.poll),
    ])

    def subtitle() -> str:
        adapter = mon.scanner.adapters[0].name if mon.scanner.adapters else "?"
        return f"Adapter: {adapter}  ·  {len(mon.registry)} tracked"

    columns = [
        ListColumn("Name",    lambda d: d.name),
        ListColumn("Address", lambda d: d.address),
        ListColumn("Type",    lambda d: "BLE" if d.le else "Classic"),
        ListColumn("Seen",    lambda d: str(d.seen_count)),
    ]

    selected = run_live_list("Bluetooth Monitor — Live Devices", subtitle, mon.poll, columns)
    if selected is None:
        return

    def detail(dev) -> dict:
        mon.poll()
        t = mon.registry.get(dev.address, dev)
        return {
            "Name":       t.name,
            "Address":    t.address,
            "Type":       "BLE" if t.le else "Classic",
            "First seen": time.strftime("%H:%M:%S", time.localtime(t.first_seen)),
            "Last seen":  time.strftime("%H:%M:%S", time.localtime(t.last_seen)),
            "Times seen": t.seen_count,
        }

    run_live_detail(
        f"Bluetooth Device — {selected.name}", selected, detail,
        probe_fn=lambda d: mon.probe(d.address),
    )


def _run_auto_audit(engine) -> None:
    _print("[cyan]Starting full auto-audit…[/cyan]")
    engine.run_auto_audit()
    _print("[cyan]Running AI risk analysis…[/cyan]")
    ai_report = engine.analyze()

    # Display AI summary
    rs = ai_report.risk_score
    color = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"green"}.get(rs.level,"dim")
    if _CON:
        _CON.print(Panel(
            f"[bold {color}]Risk: {rs.level} ({rs.overall:.0f}/100)[/bold {color}]\n\n"
            + ai_report.executive_summary,
            title="AI Security Assessment",
        ))
        # Recommendations
        rec_tbl = Table(title="Recommendations", style="yellow")
        rec_tbl.add_column("#"); rec_tbl.add_column("Title"); rec_tbl.add_column("Effort")
        for r in ai_report.recommendations[:5]:
            rec_tbl.add_row(str(r.priority), r.title, r.effort)
        _CON.print(rec_tbl)
    else:
        print(f"\n  Risk: {rs.level} ({rs.overall:.0f}/100)")
        print(f"  {ai_report.executive_summary}\n")
        for r in ai_report.recommendations[:5]:
            print(f"  [{r.priority}] {r.title}")

    _generate_reports(engine, ai_report)


def _generate_reports(engine, ai_report) -> None:
    paths = engine.save_reports(ai_report)
    _print("\n[green]Reports saved:[/green]")
    for fmt, path in paths.items():
        _print(f"  [cyan]{fmt.upper()}[/cyan]: {path}")


def _show_history(engine) -> None:
    sessions = engine.db.get_sessions(limit=10)
    if not sessions:
        _print("[dim]No audit history found.[/dim]")
        return
    if _CON:
        t = Table(title="Audit History", style="cyan")
        t.add_column("Session"); t.add_column("Date"); t.add_column("Risk"); t.add_column("Score")
        for s in sessions:
            t.add_row(s["id"], s["started_at"][:16],
                      s.get("risk_level","?"), str(s.get("risk_score","?")))
        _CON.print(t)
    else:
        print("\n  Audit History")
        for s in sessions:
            print(f"  {s['id']} | {s['started_at'][:16]} | {s.get('risk_level','?')}")
    stats = engine.db.get_stats()
    _print(f"\n  Total sessions: {stats['total_sessions']} | "
           f"Total findings: {stats['total_findings']}")


# ── Main loop ─────────────────────────────────────────────────────────────────

def interactive_mode() -> None:
    _banner()

    from core.engine import CyberScopeEngine
    engine = CyberScopeEngine()

    _print("[cyan]Detecting system capabilities…[/cyan]\n")
    caps = engine.discover()
    _show_capabilities(caps)

    available_mods = caps.available_modules()

    while True:
        _show_menu(caps)
        choice = _input("Seleccione").strip()

        if choice == "1":
            _run_auto_audit(engine)

        elif choice in ("2","3","5","7","8"):
            mod_map = {"2":"network","3":"wifi","5":"bluetooth","7":"device","8":"telecom"}
            mod = mod_map[choice]
            if mod not in available_mods:
                _print(f"[red]{mod} not available on this system.[/red]")
            else:
                _run_module_with_progress(engine, mod)

        elif choice == "4":
            if "wifi" not in available_mods:
                _print("[red]wifi not available on this system.[/red]")
            else:
                _run_wifi_monitor(engine, caps)

        elif choice == "6":
            if "bluetooth" not in available_mods:
                _print("[red]bluetooth not available on this system.[/red]")
            else:
                _run_bluetooth_monitor(engine, caps)

        elif choice == "9":
            if not engine.results:
                _print("[yellow]No scan results yet. Run a module first.[/yellow]")
            else:
                ai_report = engine.analyze()
                _generate_reports(engine, ai_report)

        elif choice == "10":
            _show_history(engine)

        elif choice in ("11","q","quit","exit"):
            _print("[cyan]Goodbye.[/cyan]")
            sys.exit(0)

        else:
            _print("[red]Invalid option.[/red]")


# ── CLI mode ──────────────────────────────────────────────────────────────────

def cli_mode(args: argparse.Namespace) -> None:
    _banner()
    from core.engine import CyberScopeEngine
    engine = CyberScopeEngine(args.config)
    caps = engine.discover()

    if args.monitor:
        available = caps.live_monitor_modules()
        if args.monitor not in available:
            _print(f"[red]{args.monitor} monitor not available on this system.[/red]")
            return
        if args.monitor == "wifi":
            _run_wifi_monitor(engine, caps)
        else:
            _run_bluetooth_monitor(engine, caps)
    elif args.auto:
        _run_auto_audit(engine)
    elif args.module:
        result = engine.run_module(args.module)
        _show_result(result)
        if args.report:
            ai_report = engine.analyze()
            _generate_reports(engine, ai_report)
    elif args.report:
        if not engine.results:
            # Load from DB? For now, run all
            engine.run_auto_audit()
        ai_report = engine.analyze()
        _generate_reports(engine, ai_report)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cyberscope",
        description="CyberScope AI Security Platform",
    )
    parser.add_argument("--config",  "-c", default=str(_ROOT / "config.yaml"))
    parser.add_argument("--auto",    "-a", action="store_true",
                        help="Run full auto-audit")
    parser.add_argument("--module",  "-m",
                        choices=["network","wifi","bluetooth","device","telecom"],
                        help="Run specific module")
    parser.add_argument("--report",  "-r",
                        choices=["json","html","markdown","all"],
                        help="Generate report")
    parser.add_argument("--monitor",
                        choices=["wifi","bluetooth"],
                        help="Open the live list→detail monitor for a module")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    # Interactive mode if no args given
    if not (args.auto or args.module or args.report or args.monitor):
        interactive_mode()
    else:
        cli_mode(args)


if __name__ == "__main__":
    main()
