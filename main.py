"""
CyberScope WiFi — main.py

Comprehensive WiFi Security Auditing Platform.
Terminal-first interface with beautiful Rich-based UI.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# Ensure project root is in path
_ROOT = Path(__file__).parent.resolve()
for _p in [str(_ROOT), str(_ROOT / "modules" / "telecom")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.auto_config import run_auto_config, ConfigAction
from core.engine import CyberScopeEngine

try:
    from rich.console  import Console
    from rich.panel    import Panel
    from rich.table    import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.tree     import Tree
    from rich.columns  import Columns
    from rich.align    import Align
    from rich.text     import Text
    from rich.live     import Live
    from rich.layout   import Layout
    from rich.rule     import Rule
    _CON = Console(emoji=False)
    _RICH = True
except ImportError:
    _CON = None
    _RICH = False

BANNER = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║     ██║   ██║██████╔╝█████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚██████╗╚██████╔╝██║     ███████╗
 ╚═════╝   ╚══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝
"""

SEV_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "orange3",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim cyan",
}

SEV_ICONS = {
    "CRITICAL": "●",
    "HIGH": "▲",
    "MEDIUM": "■",
    "LOW": "◆",
    "INFO": "○",
}

SECURITY_ICONS = {
    "OPEN": "🔓",
    "BROKEN": "💀",
    "WEAK": "⚠️",
    "GOOD": "🔒",
    "STRONG": "🛡️",
    "UNKNOWN": "❓",
}

ATTACK_ICONS = {
    "PMKID": "🎯",
    "DEAUTH_HANDSHAKE": "📡",
    "WPS_PIXIE": "🔑",
    "WPS_BRUTE": "🔨",
    "HANDSHAKE_CRACK": "💻",
    "HANDSHAKE_CRACK_HASHCAT": "🚀",
}

def _print(msg: str) -> None:
    if _CON:
        _CON.print(msg)
    else:
        import re
        print(re.sub(r'\[/?[^\]]+\]', '', msg))

def _banner() -> None:
    if _CON:
        _CON.print(f"[bold cyan]{BANNER}[/bold cyan]")
        _CON.print(Panel(
            "[bold cyan]CyberScope WiFi v2.0.0[/bold cyan]  |  "
            "[yellow]Comprehensive WiFi Security Auditing[/yellow]  |  "
            "[red]Authorized Use Only[/red]",
            style="bold",
            border_style="cyan",
        ))
    else:
        print(BANNER)
        print("  CyberScope WiFi v2.0.0")
        print("  Comprehensive WiFi Security Auditing")
        print("  Authorized Use Only\n")

def _show_capabilities(caps) -> None:
    if _CON:
        t = Table(title="System Capabilities", style="cyan", show_header=True, border_style="cyan")
        t.add_column("Component", style="bold")
        t.add_column("Status", justify="center")
        t.add_column("Detail")
        
        os_info = caps.os_info
        net_ifaces = caps.network
        wifi_cap = caps.wifi
        privs = caps.privileges
        
        wifi_details = wifi_cap.details or {}
        monitor_mode = "supported" if wifi_details.get("monitor_mode") else "unsupported"
        can_scan = wifi_details.get("can_scan", False)
        
        for comp, status, detail in [
            ("OS", "✓", f"{os_info.distro or os_info.env_label} / {os_info.arch}"),
            ("Kernel", "✓", os_info.kernel),
            ("Privileges", "✓" if privs.can_escalate else "✗", privs.method),
            ("Network", "✓", f"{len(net_ifaces)} interface(s)" if net_ifaces else "none"),
            ("WiFi", "✓" if wifi_cap.status.value == "available" else "✗", 
             f"Interfaces: {', '.join(wifi_details.get('interfaces', [])) or 'none'} | Scan: {'Yes' if can_scan else 'No'}"),
            ("Monitor Mode", "✓" if monitor_mode == "supported" else "✗", monitor_mode),
            ("Tools", "✓" if caps.tools else "✗", 
             ", ".join([k for k, v in caps.tools.items() if v and k in ["aircrack-ng", "aireplay-ng", "airodump-ng", "iw", "nmcli", "hashcat", "reaver"]]) or "missing"),
        ]:
            status_style = "green" if status == "✓" else "red"
            t.add_row(comp, f"[{status_style}]{status}[/{status_style}]", detail)
        _CON.print(t)
    else:
        print("\n  System Capabilities:")
        os_info = caps.os_info
        net_ifaces = caps.network
        wifi_cap = caps.wifi
        privs = caps.privileges
        wifi_details = wifi_cap.details or {}
        for comp, status, detail in [
            ("OS", "✓", f"{os_info.distro or os_info.env_label} / {os_info.arch}"),
            ("Privileges", "✓" if privs.can_escalate else "✗", privs.method),
            ("Network", "✓", f"{len(net_ifaces)} interface(s)" if net_ifaces else "none"),
            ("WiFi", "✓" if wifi_cap.status.value == "available" else "✗", 
             f"Interfaces: {', '.join(wifi_details.get('interfaces', [])) or 'none'}"),
        ]:
            print(f"  {comp}: {status} {detail}")
        print()

def _show_networks_table(networks) -> None:
    """Display discovered networks in a beautiful table."""
    if not networks:
        _print("[yellow]No networks found[/yellow]")
        return
    
    # Convert dict to WiFiNetwork if needed
    from modules.wifi.scanner import WiFiNetwork
    net_objects = []
    for n in networks:
        if isinstance(n, dict):
            # Filter out fields not in WiFiNetwork (like 'key' from TrackedNetwork)
            filtered = {k: v for k, v in n.items() if k in WiFiNetwork.__dataclass_fields__}
            net_objects.append(WiFiNetwork(**filtered))
        else:
            net_objects.append(n)
    
    if _CON:
        t = Table(
            title=f"Discovered Networks ({len(net_objects)} found)",
            style="cyan",
            show_header=True,
            border_style="cyan",
            header_style="bold cyan",
        )
        t.add_column("#", style="dim", width=4)
        t.add_column("SSID", style="bold", max_width=30)
        t.add_column("BSSID", style="dim", width=18)
        t.add_column("CH", justify="center", width=4)
        t.add_column("Freq", justify="center", width=6)
        t.add_column("Signal", justify="right", width=8)
        t.add_column("Security", width=18)
        t.add_column("Risk", justify="center", width=8)
        t.add_column("Vendor", style="dim", max_width=20)
        
        for i, net in enumerate(net_objects, 1):
            sec = net.security.upper()
            sec_icon = SECURITY_ICONS.get(net.security_level, "❓")
            risk_color = SEV_COLORS.get(net.risk_level, "white")
            signal_color = "green" if net.signal > -50 else "yellow" if net.signal > -70 else "red"
            
            t.add_row(
                str(i),
                net.ssid or "<hidden>",
                net.bssid,
                str(net.channel) if net.channel else "-",
                f"{net.frequency:.1f}GHz" if net.frequency else "-",
                f"[{signal_color}]{net.signal} dBm[/{signal_color}]",
                f"{sec_icon} {sec}",
                f"[{risk_color}]{SEV_ICONS.get(net.risk_level, '?')} {net.risk_level}[/{risk_color}]",
                net.vendor[:18] if net.vendor else "-",
            )
        _CON.print(t)
    else:
        print(f"\n  Discovered Networks ({len(net_objects)} found):")
        for i, net in enumerate(net_objects, 1):
            print(f"  {i}. {net.ssid} ({net.bssid}) Ch:{net.channel} {net.signal}dBm {net.security}")

def _show_findings(findings, module_name: str) -> None:
    """Display findings in a beautiful table."""
    if not findings:
        _print(f"[green]No findings from {module_name}[/green]")
        return
    
    if _CON:
        t = Table(
            title=f"{module_name.upper()} — {len(findings)} Finding(s)",
            style="cyan",
            show_header=True,
            border_style="cyan",
            header_style="bold cyan",
        )
        t.add_column("Sev", justify="center", width=4)
        t.add_column("Type", style="bold", max_width=25)
        t.add_column("Description", max_width=70)
        t.add_column("Evidence", style="dim", max_width=40)
        
        for f in findings:
            color = SEV_COLORS.get(f.severity.value, "white")
            icon = SEV_ICONS.get(f.severity.value, "?")
            t.add_row(
                f"[{color}]{icon}[/{color}]",
                f.type,
                f.description[:90] + ("..." if len(f.description) > 90 else ""),
                f.evidence[:35] + ("..." if len(f.evidence) > 35 else ""),
            )
        _CON.print(t)
    else:
        print(f"\n  {module_name.upper()}: {len(findings)} finding(s)")
        for f in findings:
            print(f"  [{f.severity.value}] {f.type}: {f.description[:80]}")

def _show_attack_results(report) -> None:
    """Display attack results beautifully."""
    if not report.attacks_performed:
        _print("[yellow]No attacks performed[/yellow]")
        return
    
    if _CON:
        t = Table(
            title="Attack Results",
            style="red",
            show_header=True,
            border_style="red",
            header_style="bold red",
        )
        t.add_column("Attack", style="bold", width=25)
        t.add_column("Target", width=18)
        t.add_column("Status", justify="center", width=10)
        t.add_column("Duration", justify="right", width=10)
        t.add_column("Credentials", style="green", max_width=40)
        t.add_column("Details", style="dim", max_width=40)
        
        for attack in report.attacks_performed:
            icon = ATTACK_ICONS.get(attack.attack_type, "⚔️")
            status = "[green]✓ SUCCESS[/green]" if attack.success else "[red]✗ FAILED[/red]"
            creds = attack.credentials or "-"
            if creds and len(creds) > 38:
                creds = creds[:38] + "..."
            
            t.add_row(
                f"{icon} {attack.attack_type}",
                attack.target_bssid,
                status,
                f"{attack.duration_s:.1f}s",
                creds,
                attack.error[:35] if attack.error else ("OK" if attack.success else "-"),
            )
        _CON.print(t)
        
        # Show vulnerabilities
        if report.vulnerabilities:
            _print("")
            vt = Table(
                title="Vulnerabilities Found",
                style="red",
                show_header=True,
                border_style="red",
                header_style="bold red",
            )
            vt.add_column("Sev", justify="center", width=4)
            vt.add_column("Type", style="bold", max_width=25)
            vt.add_column("Description", max_width=80)
            for v in report.vulnerabilities:
                color = SEV_COLORS.get(v.severity.value, "white")
                icon = SEV_ICONS.get(v.severity.value, "?")
                vt.add_row(
                    f"[{color}]{icon}[/{color}]",
                    v.type,
                    v.description[:90] + ("..." if len(v.description) > 90 else ""),
                )
            _CON.print(vt)
        
        # Show connected clients
        if report.connected_clients:
            _print("")
            ct = Table(
                title=f"Connected Clients ({len(report.connected_clients)})",
                style="yellow",
                show_header=True,
                border_style="yellow",
                header_style="bold yellow",
            )
            ct.add_column("MAC", style="bold", width=18)
            ct.add_column("Vendor", max_width=20)
            ct.add_column("IP", width=16)
            ct.add_column("Hostname", max_width=20)
            ct.add_column("Signal", justify="right", width=8)
            ct.add_column("Rate", width=10)
            for c in report.connected_clients:
                ct.add_row(c.mac, c.vendor or "-", c.ip or "-", c.hostname or "-", 
                          f"{c.signal} dBm" if c.signal else "-", c.data_rate or "-")
            _CON.print(ct)

def _show_phased_results(report) -> None:
    """Display phased audit results."""
    p1 = report.phase1
    p2 = report.phase2
    p3 = report.phase3
    attempts = p1.all_attempts or []
    
    if _CON:
        color = "green" if p1.success else "red"
        status = "✅ SUCCESS" if p1.success else "❌ FAILED"
        
        _CON.print(Panel(
            f"[bold {color}]{status}[/bold {color}]\n"
            f"Method: [cyan]{p1.attack_method or 'N/A'}[/cyan]\n"
            f"Credentials: [green]{p1.credentials or 'N/A'}[/green]\n"
            f"BSSID: {p1.bssid} | Channel: {p1.channel}",
            title="📡 Phase 1: Attack & Access",
            border_style=color,
        ))
        
        if attempts:
            t = Table(title="Attack Attempts", style="cyan", border_style="cyan", header_style="bold cyan")
            t.add_column("Attack", style="bold", width=20)
            t.add_column("Status", justify="center", width=10)
            t.add_column("Duration", justify="right", width=10)
            t.add_column("Details", style="dim", max_width=50)
            
            for attempt in attempts:
                icon = ATTACK_ICONS.get(attempt.attack_type, "⚔️")
                a_status = "[green]✓ SUCCESS[/green]" if attempt.success else "[red]✗ FAILED[/red]"
                detail = (attempt.error or "")[:45] or ("OK" if attempt.success else "-")
                t.add_row(
                    f"{icon} {attempt.attack_type}",
                    a_status,
                    f"{attempt.duration_s:.1f}s",
                    detail,
                )
            _CON.print(t)
        
        color2 = "green" if p2.success else "yellow"
        status2 = "✅ SUCCESS" if p2.success else "⚠️ SKIPPED/FAILED"
        
        _CON.print(Panel(
            f"[bold {color2}]{status2}[/bold {color2}]\n"
            f"Gateway: {p2.gateway or 'N/A'}\n"
            f"Local IP: {p2.local_ip or 'N/A'}\n"
            f"Devices: {len(p2.devices)} | Vulns: {len(p2.vulnerabilities)}",
            title="🔍 Phase 2: Internal Recon",
            border_style=color2,
        ))
        
        if p2.devices:
            dt = Table(title="Discovered Devices", style="cyan", border_style="cyan", header_style="bold cyan")
            dt.add_column("IP", width=16)
            dt.add_column("OS", max_width=30)
            dt.add_column("Open Ports", max_width=40)
            for dev in p2.devices[:15]:
                ports = ", ".join([p["port"] for p in (dev.get("ports") or [])[:5]])
                dt.add_row(dev["ip"], (dev.get("os") or "Unknown")[:28], ports)
            _CON.print(dt)
        
        if p2.vulnerabilities:
            vt = Table(title="Vulnerabilities", style="red", border_style="red", header_style="bold red")
            vt.add_column("IP", width=16)
            vt.add_column("Port", width=8)
            vt.add_column("Vulnerability", max_width=60)
            for vuln in p2.vulnerabilities[:20]:
                vt.add_row(vuln["ip"], str(vuln["port"]), vuln["vulnerability"][:70])
            _CON.print(vt)
        
        _CON.print(Panel(
            f"Report: {p3.report_path or 'N/A'}\n"
            f"Total Duration: {report.duration_total:.1f}s",
            title="📄 Phase 3: Report",
            border_style="blue",
        ))
    else:
        print("\n=== PHASE 1: ATTACK & ACCESS ===")
        print(f"Status: {'SUCCESS' if p1.success else 'FAILED'}")
        print(f"Method: {p1.attack_method or 'N/A'}")
        print(f"Credentials: {p1.credentials or 'N/A'}")
        print(f"BSSID: {p1.bssid} Channel: {p1.channel}")
        print("\nAttempts:")
        for a in attempts:
            print(f"  {a.attack_type}: {'OK' if a.success else 'FAIL'} ({a.duration_s:.1f}s) {a.error or ''}")
        
        print("\n=== PHASE 2: INTERNAL RECON ===")
        print(f"Status: {'SUCCESS' if p2.success else 'FAILED/SKIPPED'}")
        print(f"Gateway: {p2.gateway} IP: {p2.local_ip}")
        print(f"Devices: {len(p2.devices)} Vulns: {len(p2.vulnerabilities)}")
        for dev in p2.devices[:10]:
            ports = ", ".join([p["port"] for p in (dev.get("ports") or [])[:3]])
            print(f"  {dev['ip']} - {dev.get('os','Unknown')} - {ports}")
        
        print("\n=== PHASE 3: REPORT ===")
        print(f"Report: {p3.report_path or 'N/A'}")
        print(f"Total: {report.duration_total:.1f}s")

def _show_ai_report(ai_report) -> None:
    if _CON:
        rs = ai_report.risk_score
        color = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"green"}.get(rs.level,"dim")
        
        _CON.print(Panel(
            f"[bold {color}]Risk: {rs.level} ({rs.overall:.0f}/100)[/bold {color}]\n\n"
            + ai_report.executive_summary,
            title="🤖 AI Security Assessment",
            border_style=color,
        ))
        
        rec_tbl = Table(title="Recommendations", style="yellow", border_style="yellow")
        rec_tbl.add_column("#", justify="center", width=4)
        rec_tbl.add_column("Title", style="bold", max_width=50)
        rec_tbl.add_column("Effort", justify="center", width=10)
        rec_tbl.add_column("Impact", justify="center", width=10)
        for r in ai_report.recommendations[:10]:
            rec_tbl.add_row(str(r.priority), r.title, r.effort, r.impact)
        _CON.print(rec_tbl)
    else:
        rs = ai_report.risk_score
        print(f"\n  Risk: {rs.level} ({rs.overall:.0f}/100)")
        print(f"  {ai_report.executive_summary}\n")
        for r in ai_report.recommendations[:10]:
            print(f"  [{r.priority}] {r.title} (Effort: {r.effort}, Impact: {r.impact})")

def _generate_reports(engine, ai_report) -> None:
    paths = engine.save_reports(ai_report)
    _print("\n[green]Reports saved:[/green]")
    for fmt, path in paths.items():
        _print(f"  [cyan]{fmt.upper()}[/cyan]: {path}")

def _run_auto_config(engine) -> None:
    _print("[cyan]Running intelligent auto-configuration…[/cyan]")
    actions = run_auto_config(engine.cfg)
    if _CON:
        t = Table(title="Auto-Configuration", style="green", show_header=True, border_style="green")
        t.add_column("Action", style="bold cyan")
        t.add_column("Status", justify="center")
        t.add_column("Description")
        t.add_column("Root", justify="center", width=6)
        t.add_column("Reboot", justify="center", width=6)
        for action in actions:
            status = "[green]✓ Success[/green]" if action.success else "[red]✗ Failed[/red]"
            req_root = "[yellow]Yes[/yellow]" if action.requires_root else "[dim]No[/dim]"
            req_reboot = "[yellow]Yes[/yellow]" if action.requires_reboot else "[dim]No[/dim]"
            t.add_row(action.name, status, action.message, req_root, req_reboot)
        _CON.print(t)
    else:
        print("\n  Auto-Configuration:")
        for action in actions:
            status = "✓" if action.success else "✗"
            print(f"  {status} {action.name}: {action.message}")
        print()
    success_count = sum(1 for a in actions if a.success)
    total_count = len(actions)
    _print(f"\n[cyan]Auto-configuration completed: {success_count}/{total_count} actions successful[/cyan]")

def _run_wifi_scan(engine, iface: Optional[str] = None) -> None:
    _print("[cyan]Starting WiFi scan…[/cyan]")
    result = engine.run_module("wifi")
    _show_networks_table(result.raw_data.get("networks", []))
    _show_findings(result.findings, "wifi")

def _run_wifi_monitor(engine, iface: Optional[str] = None, duration: int = 30) -> None:
    _print(f"[cyan]Starting WiFi monitor for {duration}s…[/cyan]")
    result = engine.run_module("wifi_monitor")
    _show_networks_table(result.raw_data.get("networks", []))

def _run_full_audit(engine) -> None:
    _print("[cyan]Starting full WiFi auto-audit…[/cyan]")
    engine.run_auto_audit()
    _print("[cyan]Running AI risk analysis…[/cyan]")
    ai_report = engine.analyze()
    _show_ai_report(ai_report)
    _generate_reports(engine, ai_report)

def _run_targeted_attack(
    engine,
    bssid: str,
    channel: int,
    ssid: str,
    attack_types: List[str],
    wordlist: Optional[str] = None,
) -> None:
    from modules.pentest.phased_attack import run_phased_audit
    from core.permissions import detect_privileges
    from core.shell import tool_exists
    
    # Use the engine's already discovered capabilities
    caps = engine.capabilities or engine.discover()
    privs = detect_privileges()
    
    if not caps.wifi.details:
        _print("[red]No WiFi interface available[/red]")
        return
    
    iface = caps.wifi.details.get("interfaces", [""])[0]
    
    # Check tools
    missing = []
    for tool in ["airodump-ng", "aireplay-ng", "aircrack-ng", "airmon-ng", "hcxdumptool", "hcxpcapngtool", "reaver", "wash", "hashcat", "nmap"]:
        if not tool_exists(tool):
            missing.append(tool)
    if missing:
        _print(f"[yellow]Missing optional tools: {', '.join(missing)}[/yellow]")
        _print("[cyan]Attempting to continue with available tools...[/cyan]")
    
    if not iface:
        _print("[red]No WiFi interface found[/red]")
        return
    
    _print(f"[cyan]Starting PHASED WiFi audit on {ssid or bssid} ({bssid}) channel {channel}[/cyan]")
    _print(f"[cyan]Interface: {iface}[/cyan]")
    _print(f"[cyan]Mode: 3-Phase (Attack→Recon→Report)[/cyan]\n")
    
    # Warn and ask about monitor mode (it disconnects the current network)
    allow_monitor = False
    if _CON:
        _CON.print(Panel(
            "[bold yellow]⚠️ IMPORTANTE[/bold yellow]\n\n"
            "Los ataques activos (PMKID, DEAUTH, WPS) requieren [bold]modo monitor[/bold], "
            "lo que [red]DESCONECTA la interfaz WiFi actual[/red].\n\n"
            "Si solo tienes [bold]1 adaptador WiFi[/bold], perderás la conexión. "
            "Se recomienda un [bold]segundo adaptador USB WiFi[/bold] con soporte "
            "monitor + inyección.\n\n"
            "[cyan]¿Deseas activar modo monitor y ejecutar ataques activos?[/cyan]\n"
            "[bold]s[/bold] = Sí (desconecta la red actual) | [bold]N[/bold] = No (solo pasivo/offline)",
            title="⚠️ Modo Monitor",
            border_style="yellow",
        ))
        try:
            resp = _CON.input("[bold yellow]¿Activar modo monitor? [s/N]: [/bold yellow]").strip().lower()
            allow_monitor = resp == "s"
        except (KeyboardInterrupt, EOFError):
            allow_monitor = False
    else:
        try:
            resp = input("\n¿Activar modo monitor? (desconecta la red actual) [s/N]: ").strip().lower()
            allow_monitor = resp == "s"
        except (KeyboardInterrupt, EOFError):
            allow_monitor = False
    
    # Run phased audit
    report = run_phased_audit(
        iface=iface,
        target_bssid=bssid,
        target_channel=channel,
        target_ssid=ssid,
        wordlist=wordlist,
        auto_connect=False,
        allow_monitor=allow_monitor,
    )
    
    # Display results
    _show_phased_results(report)

def _interactive_target_selection(engine) -> Optional[tuple]:
    """Interactive network selection for attack."""
    result = engine.run_module("wifi")
    networks = result.raw_data.get("networks", [])
    
    if not networks:
        _print("[red]No networks found[/red]")
        return None
    
    _show_networks_table(networks)
    
    # Convert dicts to WiFiNetwork objects for attribute access
    from modules.wifi.scanner import WiFiNetwork
    net_objects = []
    for n in networks:
        if isinstance(n, dict):
            net_objects.append(WiFiNetwork(**n))
        else:
            net_objects.append(n)
    
    if _CON:
        _CON.print()
        try:
            choice = _CON.input("[bold cyan]Select network number (or 'q' to quit): [/bold cyan]")
            if choice.lower() == 'q':
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(net_objects):
                net = net_objects[idx]
                return (net.bssid, net.channel, net.ssid)
        except (ValueError, KeyboardInterrupt):
            return None
    else:
        try:
            choice = input("\nSelect network number (or 'q' to quit): ")
            if choice.lower() == 'q':
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(net_objects):
                net = net_objects[idx]
                return (net.bssid, net.channel, net.ssid)
        except (ValueError, KeyboardInterrupt):
            return None
    return None

def _interactive_attack_menu() -> List[str]:
    """Interactive attack type selection with detailed explanations."""
    attacks = [
        ("1", "pmkid", 
         "PMKID Attack",
         "Attacks the AP directly to capture PMKID hash — no client needed",
         "Requires: monitor mode + injection. Best for: WPA2/WPA3 networks with PMKID enabled",
         "Output: Hashcat-compatible hash (mode 16800) for offline cracking"),
        ("2", "deauth",
         "Deauth Handshake Capture",
         "Forces 4-way handshake by deauthenticating connected clients",
         "Requires: monitor mode + injection + active client. Best for: Networks with connected clients",
         "Output: .cap file with WPA handshake (hashcat mode 2500 / aircrack-ng)"),
        ("3", "wps",
         "WPS Attack (Pixie-Dust + Brute Force)",
         "Exploits WPS protocol to recover PIN and PSK",
         "Requires: monitor mode + WPS enabled on AP. Best for: Older routers with WPS on",
         "Output: WPS PIN + WPA PSK. Pixie-Dust is fast (seconds), brute force takes hours"),
        ("4", "crack",
         "Handshake Crack (Dictionary/Brute Force)",
         "Offline cracks captured handshake/PMKID using wordlist",
         "Requires: captured .cap/.hccapx + wordlist. Best for: After PMKID or deauth capture",
         "Output: WPA PSK if password in wordlist. Supports aircrack-ng (CPU) or hashcat (GPU)"),
        ("5", "enum",
         "Client Enumeration",
         "Lists all devices connected to target AP",
         "Requires: monitor mode. Best for: Reconnaissance before deauth attack",
         "Output: Client MACs, vendors, IPs, signal strength, data rates"),
    ]
    
    if _CON:
        _CON.print()
        
        # Build detailed table
        t = Table(title="Attack Types — Select one or more (comma-separated)", 
                  style="cyan", border_style="cyan", header_style="bold cyan",
                  show_lines=True)
        t.add_column("#", justify="center", width=3)
        t.add_column("Attack", style="bold", width=18)
        t.add_column("Description", max_width=50)
        t.add_column("Requirements / Best For", style="yellow", max_width=50)
        t.add_column("Output", style="green", max_width=45)
        
        for k, aid, name, desc, req, out in attacks:
            t.add_row(f"[bold]{k}[/bold]", 
                     f"[cyan]{aid.upper()}[/cyan]\n{name}",
                     desc, req, out)
        _CON.print(t)
        
        _CON.print(Panel(
            "[bold]Usage:[/bold] Enter numbers separated by commas (e.g., [cyan]1,2,3[/cyan])\n"
            "[bold]All:[/bold] Type [cyan]a[/cyan] for all attacks\n"
            "[bold]Recommended combos:[/bold]\n"
            "  [cyan]1,3[/cyan] — PMKID + WPS (fast, no client needed)\n"
            "  [cyan]2,4[/cyan] — Deauth + Crack (needs client, gets PSK)\n"
            "  [cyan]1,2,4[/cyan] — Full attack chain (PMKID → Deauth → Crack)\n"
            "  [cyan]5[/cyan] — Recon only (list clients first)",
            title="💡 Tips",
            border_style="yellow",
        ))
        choices = _CON.input("[bold cyan]Select attacks: [/bold cyan]")
    else:
        print("\nAttack Types:")
        for k, aid, name, desc, req, out in attacks:
            print(f"  {k}  {aid.upper()} — {name}")
            print(f"     {desc}")
            print(f"     Requirements: {req}")
            print(f"     Output: {out}\n")
        choices = input("\nSelect attacks (comma-separated, e.g. 1,2,3) or 'a' for all: ")
    
    if choices.lower() == 'a':
        return [aid for _, aid, _, _, _, _ in attacks]
    
    selected = []
    for c in choices.split(','):
        c = c.strip()
        for k, aid, _, _, _, _ in attacks:
            if c == k:
                selected.append(aid)
                break
    return selected

def cli_mode(args: argparse.Namespace) -> None:
    _banner()
    engine = CyberScopeEngine(args.config)
    caps = engine.discover()
    _show_capabilities(caps)
    
    if args.autoconfig:
        _run_auto_config(engine)
    elif args.auto:
        _run_full_audit(engine)
    elif args.scan:
        _run_wifi_scan(engine, args.interface)
    elif args.monitor:
        _run_wifi_monitor(engine, args.interface, args.duration)
    elif args.attack:
        if args.target:
            # Parse target: bssid,channel,ssid (comma-separated, BSSID may contain colons)
            parts = args.target.split(',')
            bssid = parts[0] if parts else ""
            channel = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
            ssid = parts[2] if len(parts) > 2 else ""
            attack_types = args.attacks.split(',') if args.attacks else ["pmkid", "deauth", "wps", "crack", "enum"]
            _run_targeted_attack(engine, bssid, channel, ssid, attack_types, args.wordlist)
        else:
            # Interactive mode
            target = _interactive_target_selection(engine)
            if target:
                bssid, channel, ssid = target
                attack_types = _interactive_attack_menu()
                if attack_types:
                    _run_targeted_attack(engine, bssid, channel, ssid, attack_types, args.wordlist)
    elif args.report:
        if not engine.results:
            engine.run_auto_audit()
        ai_report = engine.analyze()
        _generate_reports(engine, ai_report)
    else:
        # Interactive main menu
        _interactive_main_menu(engine)

def _interactive_main_menu(engine) -> None:
    """Main interactive menu."""
    while True:
        if _CON:
            _CON.print()
            _CON.print(Panel(
                "[bold]1[/bold]  Scan Networks\n"
                "[bold]2[/bold]  Monitor Networks (live)\n"
                "[bold]3[/bold]  Full Auto-Audit\n"
                "[bold]4[/bold]  Targeted Attack\n"
                "[bold]5[/bold]  Auto-Configuration\n"
                "[bold]6[/bold]  Generate Report\n"
                "[bold]q[/bold]  Quit",
                title="CyberScope WiFi — Main Menu",
                border_style="cyan",
            ))
            choice = _CON.input("[bold cyan]Select option: [/bold cyan]")
        else:
            print("\n  1  Scan Networks")
            print("  2  Monitor Networks (live)")
            print("  3  Full Auto-Audit")
            print("  4  Targeted Attack")
            print("  5  Auto-Configuration")
            print("  6  Generate Report")
            print("  q  Quit")
            choice = input("\nSelect option: ")
        
        if choice == '1':
            _run_wifi_scan(engine)
        elif choice == '2':
            try:
                dur = int(_CON.input("[cyan]Duration (seconds, default 30): [/cyan]") or "30")
            except:
                dur = 30
            _run_wifi_monitor(engine, duration=dur)
        elif choice == '3':
            _run_full_audit(engine)
        elif choice == '4':
            target = _interactive_target_selection(engine)
            if target:
                bssid, channel, ssid = target
                attack_types = _interactive_attack_menu()
                if attack_types:
                    _run_targeted_attack(engine, bssid, channel, ssid, attack_types)
        elif choice == '5':
            _run_auto_config(engine)
        elif choice == '6':
            if not engine.results:
                _print("[yellow]No scan data — running auto-audit first[/yellow]")
                engine.run_auto_audit()
            ai_report = engine.analyze()
            _generate_reports(engine, ai_report)
        elif choice.lower() == 'q':
            _print("[cyan]Goodbye![/cyan]")
            break
        else:
            _print("[red]Invalid option[/red]")

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cyberscope-wifi",
        description="CyberScope WiFi v2.0.0 — Comprehensive WiFi Security Auditing Platform",
    )
    parser.add_argument("--config", "-c", default=str(_ROOT / "config.yaml"))
    parser.add_argument("--auto", "-a", action="store_true", help="Run full auto-audit")
    parser.add_argument("--scan", "-s", action="store_true", help="Scan WiFi networks")
    parser.add_argument("--monitor", "-m", action="store_true", help="Live monitor WiFi networks")
    parser.add_argument("--duration", "-d", type=int, default=30, help="Monitor duration (seconds)")
    parser.add_argument("--attack", action="store_true", help="Launch targeted attack")
    parser.add_argument("--target", "-t", help="Target: BSSID,CHANNEL,SSID (comma-separated)")
    parser.add_argument("--attacks", help="Attack types (comma-separated): pmkid,deauth,wps,crack,enum")
    parser.add_argument("--wordlist", "-w", help="Custom wordlist path")
    parser.add_argument("--autoconfig", action="store_true", help="Run intelligent auto-configuration")
    parser.add_argument("--report", "-r", choices=["json", "markdown", "all"], help="Generate report")
    parser.add_argument("--interface", "-i", help="WiFi interface to use")
    parser.add_argument("--verbose", "-v", action="store_true")
    
    args = parser.parse_args()
    
    if args.verbose:
        import logging
        logging.basicConfig(level=logging.DEBUG)
    
    # If no CLI flags provided, start interactive mode
    if not (args.auto or args.scan or args.monitor or args.attack or args.autoconfig or args.report):
        cli_mode(args)  # Will enter interactive menu
    else:
        cli_mode(args)

if __name__ == "__main__":
    main()