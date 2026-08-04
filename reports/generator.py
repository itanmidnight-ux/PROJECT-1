"""
CyberScope — reports/generator.py

Produces professional audit reports (JSON / HTML / Markdown) from an
AIReport (ai/engine.py) plus the raw ModuleResult list collected during
a scan session.

Each format shares the same underlying payload so JSON stays the
canonical machine-readable record while HTML/Markdown are human-facing
renderings of it.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, TYPE_CHECKING

from core.types import ModuleResult, Severity

if TYPE_CHECKING:
    from ai.engine import AIReport

_SEVERITY_COLOR = {
    "CRITICAL": "#d32f2f",
    "HIGH":     "#f57c00",
    "MEDIUM":   "#fbc02d",
    "LOW":      "#388e3c",
    "INFO":     "#757575",
}

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class ReportGenerator:
    """Renders audit results as JSON, HTML, and Markdown reports."""

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Shared payload ────────────────────────────────────────────────────

    def _build_payload(
        self,
        ai_report: "AIReport",
        results: List[ModuleResult],
        session_id: str,
    ) -> Dict[str, Any]:
        return {
            "meta": {
                "platform":      "CyberScope AI Security Platform",
                "report_type":   "security_audit",
                "session_id":    session_id,
                "generated_at":  datetime.now(timezone.utc).isoformat(),
                "modules_run":   [r.module for r in results],
                "target":        "Local Environment",
            },
            "ai_analysis":    ai_report.to_dict(),
            "module_results": [r.to_dict() for r in results],
        }

    def _findings_sorted(self, results: List[ModuleResult]):
        findings = [f for r in results for f in r.findings]
        return sorted(findings, key=lambda f: f.severity.score, reverse=True)

    def _path(self, session_id: str, ext: str) -> Path:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return self.output_dir / f"cyberscope_report_{session_id}_{ts}.{ext}"

    # ── JSON ──────────────────────────────────────────────────────────────

    def save_json(
        self,
        ai_report: "AIReport",
        results: List[ModuleResult],
        session_id: str,
    ) -> str:
        payload = self._build_payload(ai_report, results, session_id)
        path = self._path(session_id, "json")
        path.write_text(json.dumps(payload, indent=2, default=str))
        return str(path)

    # ── Markdown ──────────────────────────────────────────────────────────

    def save_markdown(
        self,
        ai_report: "AIReport",
        results: List[ModuleResult],
        session_id: str,
    ) -> str:
        rs = ai_report.risk_score
        lines: List[str] = []

        lines.append("# 🔍 CyberScope Security Report")
        lines.append("")
        lines.append(f"**Target:** Local Environment  ")
        lines.append(f"**Session:** `{session_id}`  ")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}  ")
        lines.append(f"**Modules run:** {', '.join(r.module for r in results) or 'none'}")
        lines.append("")
        lines.append("## Risk Summary")
        lines.append("")
        lines.append(f"- **Risk Level:** {rs.level}")
        lines.append(f"- **Overall Score:** {rs.overall}/100")
        lines.append(f"- **Confidence:** {rs.confidence}")
        lines.append("")
        lines.append(ai_report.executive_summary.replace("\n", "  \n"))
        lines.append("")

        if ai_report.recommendations:
            lines.append("## Recommendations")
            lines.append("")
            for r in ai_report.recommendations:
                lines.append(f"### {r.priority}. {r.title}")
                lines.append(f"*Effort: {r.effort} · Impact: {r.impact}*")
                lines.append("")
                lines.append(r.description)
                lines.append("")

        findings = self._findings_sorted(results)
        lines.append("## Findings")
        lines.append("")
        if not findings:
            lines.append("No findings recorded.")
        else:
            lines.append("| Severity | Module | Type | Description |")
            lines.append("|---|---|---|---|")
            for f in findings:
                desc = f.description.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {f.severity.value} | {f.module} | {f.type} | {desc} |")
        lines.append("")

        lines.append("## Evidence & Detail")
        lines.append("")
        for f in findings:
            lines.append(f"### [{f.severity.value}] {f.type} ({f.module})")
            lines.append(f"**Description:** {f.description}")
            if f.evidence:
                lines.append(f"**Evidence:** `{f.evidence}`")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}")
            if f.mitre:
                lines.append(f"**MITRE ATT&CK:** {f.mitre}")
            lines.append("")

        content = "\n".join(lines)
        path = self._path(session_id, "md")
        path.write_text(content)
        return str(path)

    # ── HTML ──────────────────────────────────────────────────────────────

    def save_html(
        self,
        ai_report: "AIReport",
        results: List[ModuleResult],
        session_id: str,
    ) -> str:
        rs = ai_report.risk_score
        risk_color = _SEVERITY_COLOR.get(rs.level, "#757575")
        findings = self._findings_sorted(results)

        rows = []
        for f in findings:
            color = _SEVERITY_COLOR.get(f.severity.value, "#757575")
            rows.append(
                "<tr>"
                f'<td><span class="badge" style="background:{color}">{html.escape(f.severity.value)}</span></td>'
                f"<td>{html.escape(f.module)}</td>"
                f"<td>{html.escape(f.type)}</td>"
                f"<td>{html.escape(f.description)}</td>"
                f"<td>{html.escape(f.recommendation)}</td>"
                "</tr>"
            )
        findings_table = "\n".join(rows) or '<tr><td colspan="5">No findings recorded.</td></tr>'

        rec_items = "\n".join(
            f"<li><strong>{html.escape(r.title)}</strong> "
            f"<em>(effort: {html.escape(r.effort)}, impact: {html.escape(r.impact)})</em>"
            f"<p>{html.escape(r.description)}</p></li>"
            for r in ai_report.recommendations
        ) or "<li>No immediate actions required.</li>"

        modules_run = ", ".join(r.module for r in results) or "none"

        content = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CyberScope Security Report — {html.escape(session_id)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0;
         background: #0f1115; color: #e6e6e6; }}
  header {{ padding: 32px; background: linear-gradient(135deg,#0f1115,#161a22);
            border-bottom: 2px solid {risk_color}; }}
  h1 {{ margin: 0 0 4px; font-size: 1.6rem; }}
  .risk-badge {{ display:inline-block; padding: 4px 14px; border-radius: 20px;
                 background: {risk_color}; color:#111; font-weight:700; }}
  main {{ padding: 24px 32px 64px; max-width: 1100px; margin: 0 auto; }}
  section {{ margin-bottom: 36px; }}
  h2 {{ border-bottom: 1px solid #2a2f3a; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2f3a;
            vertical-align: top; font-size: 0.9rem; }}
  th {{ color: #9aa4b2; text-transform: uppercase; font-size: 0.75rem; }}
  .badge {{ padding: 2px 8px; border-radius: 10px; color:#111; font-weight:700;
            font-size: 0.75rem; white-space: nowrap; }}
  .meta {{ color: #9aa4b2; font-size: 0.9rem; }}
  ul.recs li {{ margin-bottom: 14px; }}
  .summary {{ white-space: pre-wrap; background:#161a22; padding:16px; border-radius:8px; }}
</style>
</head>
<body>
<header>
  <h1>CyberScope Security Report</h1>
  <div class="meta">Target: Local Environment &middot; Session: {html.escape(session_id)}
    &middot; Generated: {datetime.now(timezone.utc).isoformat()}</div>
  <div class="meta">Modules run: {html.escape(modules_run)}</div>
  <p><span class="risk-badge">Risk: {html.escape(rs.level)} ({rs.overall}/100)</span></p>
</header>
<main>
  <section>
    <h2>Executive Summary</h2>
    <div class="summary">{html.escape(ai_report.executive_summary)}</div>
  </section>
  <section>
    <h2>Recommendations</h2>
    <ul class="recs">{rec_items}</ul>
  </section>
  <section>
    <h2>Findings ({len(findings)})</h2>
    <table>
      <thead><tr><th>Severity</th><th>Module</th><th>Type</th><th>Description</th><th>Recommendation</th></tr></thead>
      <tbody>
      {findings_table}
      </tbody>
    </table>
  </section>
</main>
</body>
</html>
"""
        path = self._path(session_id, "html")
        path.write_text(content)
        return str(path)
