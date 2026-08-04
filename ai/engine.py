"""
CyberScope — ai/engine.py

Intelligent risk aggregation and recommendation engine.

Takes findings from all modules and produces:
  - Overall risk score (0–100)
  - Risk level (CRITICAL/HIGH/MEDIUM/LOW/INFO)
  - Prioritised finding list
  - Attack surface analysis
  - Specific, actionable recommendations
  - Executive summary
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.types import Finding, ModuleResult, Severity


# ── Risk models ───────────────────────────────────────────────────────────────

@dataclass
class RiskScore:
    overall:    float       # 0–100
    level:      str         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    confidence: str         # HIGH / MEDIUM / LOW
    by_module:  Dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_score(cls, score: float, by_module: Dict[str, float]) -> "RiskScore":
        if   score >= 85: level = "CRITICAL"
        elif score >= 65: level = "HIGH"
        elif score >= 40: level = "MEDIUM"
        elif score >= 15: level = "LOW"
        else:             level = "INFO"
        n      = sum(1 for v in by_module.values() if v > 0)
        conf   = "HIGH" if n >= 3 else ("MEDIUM" if n >= 2 else "LOW")
        return cls(round(score, 1), level, conf, by_module)


@dataclass
class Recommendation:
    priority:    int         # 1 = most urgent
    title:       str
    description: str
    effort:      str         # LOW / MEDIUM / HIGH
    impact:      str         # LOW / MEDIUM / HIGH
    findings:    List[str]   = field(default_factory=list)  # finding types


@dataclass
class AttackSurface:
    wireless:    bool = False
    bluetooth:   bool = False
    network:     bool = False
    telecom:     bool = False
    physical:    bool = False
    web:         bool = False
    open_services: int = 0
    open_ports:    int = 0

    def to_dict(self) -> dict:
        return vars(self)


@dataclass
class AIReport:
    risk_score:     RiskScore
    attack_surface: AttackSurface
    recommendations:List[Recommendation]
    finding_summary:Dict[str, int]          # severity → count
    top_findings:   List[Finding]
    executive_summary: str
    timestamp:      datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "risk_score": {
                "overall":    self.risk_score.overall,
                "level":      self.risk_score.level,
                "confidence": self.risk_score.confidence,
                "by_module":  self.risk_score.by_module,
            },
            "attack_surface": self.attack_surface.to_dict(),
            "executive_summary": self.executive_summary,
            "finding_summary": self.finding_summary,
            "top_findings": [f.to_dict() for f in self.top_findings],
            "recommendations": [
                {
                    "priority":    r.priority,
                    "title":       r.title,
                    "description": r.description,
                    "effort":      r.effort,
                    "impact":      r.impact,
                }
                for r in self.recommendations
            ],
        }


# ── Risk engine ───────────────────────────────────────────────────────────────

class RiskEngine:
    """
    Rule-based risk aggregation engine.

    Scoring formula:
      score = Σ(severity_weight × count × decay) / normaliser
    where decay reduces the impact of many low-severity findings
    relative to few critical ones.
    """

    _WEIGHT = {
        Severity.CRITICAL: 40,
        Severity.HIGH:     20,
        Severity.MEDIUM:    9,
        Severity.LOW:       3,
        Severity.INFO:      1,
    }

    def analyze(self, results: List[ModuleResult]) -> AIReport:
        all_findings = [f for r in results for f in r.findings]

        risk_score  = self._calculate_risk(all_findings, results)
        surface     = self._map_attack_surface(results, all_findings)
        recs        = self._generate_recommendations(all_findings, surface)
        summary     = Counter(f.severity.value for f in all_findings)
        top         = self._top_findings(all_findings, n=10)
        exec_sum    = self._executive_summary(risk_score, summary, surface, recs)

        return AIReport(
            risk_score=risk_score,
            attack_surface=surface,
            recommendations=recs,
            finding_summary=dict(summary),
            top_findings=top,
            executive_summary=exec_sum,
        )

    # ── Risk scoring ───────────────────────────────────────────────────────

    def _calculate_risk(
        self,
        findings: List[Finding],
        results:  List[ModuleResult],
    ) -> RiskScore:
        by_module: Dict[str, float] = {}
        total_score = 0.0

        # Per-module score
        module_groups: Dict[str, List[Finding]] = defaultdict(list)
        for f in findings:
            module_groups[f.module or "unknown"].append(f)

        for mod, flist in module_groups.items():
            ms = self._module_score(flist)
            by_module[mod] = ms
            total_score += ms

        # Combine with diminishing returns across modules
        # Using logarithmic decay so many small modules don't inflate score
        n = max(len(module_groups), 1)
        combined = (total_score / n) * (1 + math.log1p(n) * 0.2)
        combined = min(combined, 100.0)

        return RiskScore.from_score(combined, by_module)

    def _module_score(self, findings: List[Finding]) -> float:
        if not findings: return 0.0
        score = 0.0
        counts: Counter = Counter(f.severity for f in findings)
        for sev, cnt in counts.items():
            w = self._WEIGHT[sev]
            # Diminishing returns: first finding at full weight, then log decay
            score += w * (1 + 0.5 * math.log1p(cnt - 1))
        return min(score, 100.0)

    # ── Attack surface ─────────────────────────────────────────────────────

    def _map_attack_surface(
        self,
        results: List[ModuleResult],
        findings: List[Finding],
    ) -> AttackSurface:
        mods = {r.module for r in results}
        ftypes = {f.type for f in findings}
        return AttackSurface(
            wireless   = "wifi"      in mods,
            bluetooth  = "bluetooth" in mods,
            network    = "network"   in mods,
            telecom    = "telecom"   in mods,
            open_services = sum(1 for f in findings if "EXPOSED_SERVICE" in f.type),
            open_ports    = sum(1 for f in findings if "PORT" in f.type),
        )

    # ── Recommendations ────────────────────────────────────────────────────

    def _generate_recommendations(
        self,
        findings: List[Finding],
        surface:  AttackSurface,
    ) -> List[Recommendation]:
        recs: List[Recommendation] = []
        ftypes = Counter(f.type for f in findings)
        sevs   = Counter(f.severity for f in findings)

        priority = 1

        # Critical: WEP networks
        if "WIFI_WEP_NETWORK" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="MEDIUM", impact="HIGH",
                title="Replace WEP with WPA3 immediately",
                description=(
                    "WEP encryption is cryptographically broken and can be defeated in minutes. "
                    "Upgrade all WEP-protected access points to WPA2-AES or preferably WPA3. "
                    "On the router: Security → WPA3-Personal → Apply."
                ),
                findings=["WIFI_WEP_NETWORK"],
            ))
            priority += 1

        # High: ISD MAP manipulation
        if "SUBSCRIBER_DATA_MANIPULATION" in ftypes or "RESTRICTED_OPERATION" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="HIGH", impact="HIGH",
                title="Deploy SS7 Firewall at network boundary",
                description=(
                    "Critical MAP operations (ISD, CancelLocation) detected from potentially "
                    "untrusted sources. Deploy an SS7 firewall (Category 1–3 filtering per GSMA FS.11). "
                    "Block or challenge SRI, ISD, and auth vector requests from inter-PLMN links."
                ),
                findings=["SUBSCRIBER_DATA_MANIPULATION","RESTRICTED_OPERATION","AUTH_VECTOR_REQUEST"],
            ))
            priority += 1

        # ASLR
        if "ASLR_DISABLED" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="LOW", impact="HIGH",
                title="Enable kernel ASLR",
                description=(
                    "Address Space Layout Randomization is disabled or partial. "
                    "Run: sysctl -w kernel.randomize_va_space=2\n"
                    "Persist: echo 'kernel.randomize_va_space=2' >> /etc/sysctl.conf"
                ),
                findings=["ASLR_DISABLED"],
            ))
            priority += 1

        # No firewall
        if "NO_FIREWALL" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="LOW", impact="MEDIUM",
                title="Install and configure a host firewall",
                description=(
                    "No firewall was detected. Install ufw or iptables:\n"
                    "Debian/Ubuntu: apt install ufw && ufw default deny incoming && ufw enable\n"
                    "Arch: pacman -S ufw && systemctl enable ufw\n"
                    "Termux: pkg install iptables (requires root)"
                ),
                findings=["NO_FIREWALL"],
            ))
            priority += 1

        # Exposed services
        if surface.open_services > 0:
            recs.append(Recommendation(
                priority=priority, effort="LOW", impact="MEDIUM",
                title=f"Restrict {surface.open_services} service(s) listening on all interfaces",
                description=(
                    "Services bound to 0.0.0.0 accept connections from any network interface. "
                    "Restrict sensitive services to localhost (127.0.0.1) or specific interfaces. "
                    "Use firewall rules to limit access by IP address."
                ),
                findings=["EXPOSED_SERVICE"],
            ))
            priority += 1

        # Open WiFi
        if "WIFI_OPEN_NETWORK" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="LOW", impact="MEDIUM",
                title="Avoid open WiFi networks for sensitive operations",
                description=(
                    "Open WiFi networks transmit all traffic unencrypted. "
                    "Use a VPN on any open network. "
                    "For networks you operate: enable WPA2-AES or WPA3."
                ),
                findings=["WIFI_OPEN_NETWORK"],
            ))
            priority += 1

        # Bluetooth discoverable
        if "BT_ADAPTER_DISCOVERABLE" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="LOW", impact="LOW",
                title="Disable Bluetooth discoverability",
                description=(
                    "The Bluetooth adapter is in discoverable mode, making it visible to all nearby devices. "
                    "Disable when not actively pairing:\n"
                    "bluetoothctl → discoverable off\n"
                    "or via system Bluetooth settings."
                ),
                findings=["BT_ADAPTER_DISCOVERABLE"],
            ))
            priority += 1

        # SRI tracking
        if "SRI_RATE_BURST" in ftypes or "SUBSCRIBER_TRACKING" in ftypes:
            recs.append(Recommendation(
                priority=priority, effort="MEDIUM", impact="HIGH",
                title="Implement SRI rate limiting and subscriber tracking prevention",
                description=(
                    "High-rate SRI queries detected — possible location harvesting. "
                    "Configure SS7 firewall to:\n"
                    "• Limit SRI from external sources to < 5/min per subscriber\n"
                    "• Alert on > 10 SRI from same source in 60 seconds\n"
                    "• Log all SRI with subscriber MSISDN for audit trail"
                ),
                findings=["SRI_RATE_BURST","SUBSCRIBER_TRACKING"],
            ))
            priority += 1

        return sorted(recs, key=lambda r: r.priority)

    # ── Helpers ────────────────────────────────────────────────────────────

    def _top_findings(self, findings: List[Finding], n: int = 10) -> List[Finding]:
        return sorted(findings, key=lambda f: f.severity.score, reverse=True)[:n]

    def _executive_summary(
        self,
        risk:    RiskScore,
        counts:  Counter,
        surface: AttackSurface,
        recs:    List[Recommendation],
    ) -> str:
        total = sum(counts.values())
        crit  = counts.get("CRITICAL", 0)
        high  = counts.get("HIGH", 0)

        surfaces = []
        if surface.wireless:   surfaces.append("wireless")
        if surface.bluetooth:  surfaces.append("Bluetooth")
        if surface.network:    surfaces.append("network")
        if surface.telecom:    surfaces.append("telecom/SS7")
        if surface.open_services: surfaces.append(f"{surface.open_services} exposed services")

        return (
            f"CyberScope Security Assessment — Risk Level: {risk.level} "
            f"(Score: {risk.overall}/100)\n\n"
            f"Total findings: {total} "
            f"({crit} CRITICAL, {high} HIGH).\n"
            f"Attack surface: {', '.join(surfaces) or 'minimal'}.\n"
            f"Confidence: {risk.confidence} ({len(risk.by_module)} module(s) scanned).\n\n"
            f"Priority action: {recs[0].title if recs else 'No immediate actions required.'}"
        )
