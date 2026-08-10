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
class ExplainedFinding:
    """A single finding, expanded into a structured, plain-language
    explanation: what was observed, why it matters, the concrete risk
    if left unaddressed, and how to fix it."""
    finding: Finding
    what:    str   # plain-language restatement of what was observed
    why:     str   # why this matters / the underlying mechanism or attack it enables
    risk:    str   # concrete consequence if left unaddressed
    fix:     str   # concrete remediation step

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding": self.finding.to_dict(),
            "what":    self.what,
            "why":     self.why,
            "risk":    self.risk,
            "fix":     self.fix,
        }


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
    explained_top_findings: List["ExplainedFinding"] = field(default_factory=list)
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
            "explained_top_findings": [
                ef.to_dict() for ef in self.explained_top_findings
            ],
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

    # MITRE ATT&CK technique mapping for findings
    _MITRE_MAP = {
        # Network findings
        "EXPOSED_SERVICE": "T1046",  # Network Service Scanning
        "HOST_OPEN_PORTS": "T1046",
        "INTERFACE_PROMISC": "T1040",  # Network Sniffing
        "NEIGHBORS_FOUND": "T1016",  # System Network Configuration Discovery
        "DUPLICATE_MAC": "T1557",  # Adversary-in-the-Middle
        "MULTIPLE_DEFAULT_ROUTES": "T1599",  # Network Boundary Bridging
        "SERVICE_VERSION_DISCLOSURE": "T1592",  # Gather Victim Host Information
        "SERVICE_DEFAULT_CREDENTIALS": "T1589",  # Gather Victim Identity Information
        
        # WiFi findings
        "WIFI_OPEN_NETWORK": "T1040",
        "WIFI_WEP_NETWORK": "T1040",
        "WIFI_WPA_TKIP": "T1040",
        "WIFI_WPA2_NETWORK": "T1040",
        "WIFI_WPA3_NETWORK": "T1040",
        "WIFI_STRONG_SIGNAL": "T1040",
        "WIFI_WEAK_SIGNAL": "T1040",
        "WIFI_HIGH_OPEN_COUNT": "T1040",
        "WIFI_NO_WPA3": "T1040",
        "WIFI_HANDSHAKE_CAPTURED": "T1557",
        "WPA_PASSPHRASE_WEAK": "T1110",  # Brute Force
        
        # Bluetooth findings
        "BT_ADAPTER_DISCOVERABLE": "T1119",  # Automated Collection
        "BT_DEVICES_FOUND": "T1016",
        "BT_UNNAMED_DEVICES": "T1016",
        "BLE_DEVICES_DETECTED": "T1016",
        
        # Device findings
        "ASLR_DISABLED": "T1203",  # Exploitation for Client Execution
        "NO_FIREWALL": "T1562",  # Impair Defenses
        "WEAK_PASSWORD_POLICY": "T1110",  # Brute Force
        "CORE_DUMP_PIPE": "T1005",  # Data from Local System
        "HIGH_MEMORY_USAGE": "T1499",  # Endpoint Denial of Service
        "KERNEL_DMESG_UNRESTRICTED": "T1592",
        "KERNEL_KPTR_UNRESTRICTED": "T1592",
        "KERNEL_BPF_UNRESTRICTED": "T1592",
        "KERNEL_PTRACE_UNRESTRICTED": "T1055",  # Process Injection
        "NET_NET_IPV4_CONF_ALL_SEND_REDIRECTS": "T1557",
        "NET_NET_IPV4_CONF_ALL_ACCEPT_REDIRECTS": "T1557",
        "NET_NET_IPV4_CONF_ALL_LOG_MARTIANS": "T1592",
        "NET_NET_IPV4_CONF_ALL_RP_FILTER": "T1557",
        "KERNEL_CMDLINE_SLAB_NOMERGE": "T1592",
        "KERNEL_CMDLINE_PAGE_POISON": "T1592",
        "KERNEL_CMDLINE_VSYSCALL": "T1592",
        "KERNEL_CMDLINE_MODULE_SIG_ENFORCE": "T1592",
        "KERNEL_CMDLINE_LOCKDOWN": "T1592",
        "KERNEL_CMDLINE_INIT_ON_ALLOC": "T1592",
        "KERNEL_CMDLINE_INIT_ON_FREE": "T1592",
        "SECURE_BOOT_DISABLED": "T1542",  # Pre-OS Boot
        "GRUB_NO_PASSWORD": "T1542",
        "NO_INTEGRITY_CHECKER": "T1599",
        "IMA_DISABLED": "T1592",
        "CONTAINER_DETECTED": "T1592",
        "CONTAINER_PID_NS_SHARED": "T1592",
        "CONTAINER_USER_NS_DISABLED": "T1592",
        
        # Telecom findings
        "SS7_MODULE_ACTIVE": "T1600",  # Wireless Communication Interception
        "INSECURE_RADIO_ACCESS_TECHNOLOGY": "T1449",  # Fake Cell Tower
        "DEVICE_ROAMING": "T1591",  # Location Tracking
        "WEAK_SIGNAL": "T1449",
        "RADIO_NOMINAL": "T1600",
        "RESTRICTED_OPERATION": "T1600",
        "SUBSCRIBER_DATA_MANIPULATION": "T1557",
        "AUTH_VECTOR_REQUEST": "T1557",
        "SRI_RATE_BURST": "T1590",  # Active Scanning
        "SUBSCRIBER_TRACKING": "T1591",
        "EXTERNAL_MAP_SCCP": "T1600",
        "SUBSCRIBER_ROAMING": "T1591",
        "SUBSCRIBER_NOMINAL": "T1600",
        
        # Pentest findings
        "SERVICE_FINGERPRINTED": "T1592",
        "WEAK_SSH_CREDENTIALS": "T1110",
        "SSH_UNREACHABLE": "T1046",
        "SSH_CREDENTIALS_NOT_WEAK": "T1046",
        "WPA_CAPTURE_ERROR": "T1557",
        "WPA_HANDSHAKE_NOT_CAPTURED": "T1557",
        "WPA_HANDSHAKE_CAPTURED": "T1557",
        "WPA_CRACK_ERROR": "T1557",
        "WPA_PASSPHRASE_NOT_IN_DICTIONARY": "T1110",
    }

    def analyze(self, results: List[ModuleResult]) -> AIReport:
        all_findings = [f for r in results for f in r.findings]

        risk_score  = self._calculate_risk(all_findings, results)
        surface     = self._map_attack_surface(results, all_findings)
        recs        = self._generate_recommendations(all_findings, surface)
        summary     = Counter(f.severity.value for f in all_findings)
        top         = self._top_findings(all_findings, n=10)
        exec_sum    = self._executive_summary(risk_score, summary, surface, recs)
        explained   = [self.explain(f) for f in top]

        return AIReport(
            risk_score=risk_score,
            attack_surface=surface,
            recommendations=recs,
            finding_summary=dict(summary),
            top_findings=top,
            executive_summary=exec_sum,
            explained_top_findings=explained,
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

    # ── Explainability ──────────────────────────────────────────────────────

    def explain(self, finding: Finding) -> ExplainedFinding:
        """
        Turn a single Finding into a structured, plain-language explanation:
        what was observed, why it matters, the concrete risk if left
        unaddressed, and how to fix it.

        Mirrors the per-finding.type dispatch style of
        `_generate_recommendations()` above, and reuses the same domain
        knowledge (and, where one already exists, the same remediation text)
        rather than inventing a parallel system.
        """
        t  = finding.type
        d  = finding.description

        if t == "WIFI_OPEN_NETWORK":
            what = f"An access point advertising no encryption at all was seen in range. {d}"
            why = (
                "Open networks send every packet — HTTP requests, DNS lookups, chat messages, "
                "session cookies — as plaintext over the air. Anyone within radio range with a "
                "packet sniffer (e.g. Wireshark/airodump-ng) can passively capture and read it, "
                "and an attacker can stand up an identically-named evil-twin AP to intercept "
                "clients that auto-reconnect."
            )
            risk = (
                "Credentials, session tokens and private messages sent over this network while "
                "unprotected can be captured and replayed; an attacker on the same AP can also "
                "perform ARP spoofing to intercept traffic to/from other clients."
            )
            fix = (
                "Open networks transmit data unencrypted. Do not connect to open networks for "
                "sensitive operations — use a VPN on any open network. If you operate this AP, "
                "switch it to WPA2-AES or preferably WPA3 (Security → WPA3-Personal → Apply)."
            )

        elif t == "WIFI_WEP_NETWORK":
            what = f"A WiFi network still using WEP encryption was detected. {d}"
            why = (
                "WEP's RC4-based key scheduling and 24-bit IV are cryptographically broken — "
                "tools like aircrack-ng recover the WEP key from a few minutes of captured "
                "traffic using IV-collision (FMS/Korek/PTW) attacks, regardless of key length."
            )
            risk = (
                "An attacker within radio range can recover the network key in minutes, join the "
                "network as a trusted device, and decrypt all traffic previously captured from it."
            )
            fix = (
                "WEP encryption is cryptographically broken and can be defeated in minutes. "
                "Upgrade all WEP-protected access points to WPA2-AES or preferably WPA3. "
                "On the router: Security → WPA3-Personal → Apply."
            )

        elif t == "WIFI_WPA_TKIP":
            what = f"A WiFi network using the older WPA/TKIP cipher was detected. {d}"
            why = (
                "TKIP was a stop-gap fix for WEP, not a modern cipher — it inherits WEP's RC4 "
                "stream cipher and is vulnerable to packet-forgery/decryption attacks "
                "(Beck-Tews, Ohigashi-Morii), letting an attacker inject or decrypt small packets "
                "such as ARP requests without recovering the full key."
            )
            risk = (
                "Attackers can forge or decrypt individual packets (e.g. ARP/DNS) on this "
                "network, enabling traffic injection and partial eavesdropping."
            )
            fix = "Upgrade to WPA2-AES or WPA3."

        elif t == "WIFI_STRONG_SIGNAL":
            what = f"A very strong WiFi signal was measured, meaning the access point is physically close. {d}"
            why = (
                "Signal strength is a rough proxy for distance — a signal this strong usually "
                "means the AP (or an attacker's rogue AP mimicking it) is within a room or two, "
                "which matters when correlating findings with physical security."
            )
            risk = (
                "On its own this is informational, but combined with an insecure security mode "
                "it confirms an attacker could realistically be close enough to actively attack "
                "(not just passively sniff) this network."
            )
            fix = "Strong signal suggests the AP is nearby; note it during a physical security walkthrough."

        elif t == "WIFI_HIGH_OPEN_COUNT":
            what = f"Several insecure (open or WEP) wireless networks were seen in range at once. {d}"
            why = (
                "A dense cluster of insecure networks increases the odds that a device will "
                "auto-associate with the wrong one, and gives an attacker more cover to run a "
                "rogue AP or evil-twin among legitimate-looking weak networks."
            )
            risk = (
                "Increases the likelihood of a device accidentally joining — or being tricked "
                "into joining — an insecure or malicious network in this environment."
            )
            fix = "Be aware of your wireless environment; disable WiFi auto-connect for open/unknown networks and prefer known WPA2/WPA3 networks."

        elif t == "BT_ADAPTER_DISCOVERABLE":
            what = f"This device's own Bluetooth adapter is broadcasting itself to nearby devices. {d}"
            why = (
                "Discoverable mode answers inquiry scans from any nearby Bluetooth radio, "
                "exposing the device name, class and address — information used to fingerprint "
                "the device and target it with pairing-based or BlueBorne-style attacks."
            )
            risk = (
                "Any nearby attacker can see this device, attempt to pair with it, or use the "
                "advertised information to build a profile of the device and its owner's habits."
            )
            fix = (
                "Disable discoverable mode when not actively pairing. Discoverable devices are "
                "visible to all nearby attackers. Use `bluetoothctl` → `discoverable off`."
            )

        elif t == "BT_DEVICES_FOUND":
            what = f"Other Bluetooth devices were detected nearby. {d}"
            why = (
                "Every classic Bluetooth device that responds to inquiry scans is broadcasting "
                "its presence and often its device class/name, which can be used for passive "
                "reconnaissance of who and what is in the area."
            )
            risk = (
                "An attacker performing reconnaissance can map nearby devices and target "
                "specific ones (e.g. by vendor/class) for pairing or exploitation attempts."
            )
            fix = "Review detected devices. Unknown devices in corporate environments may warrant investigation."

        elif t == "BT_UNNAMED_DEVICES":
            what = f"Bluetooth devices with no readable/advertised name were detected. {d}"
            why = (
                "Legitimate consumer devices almost always advertise a friendly name; devices "
                "that deliberately withhold one are more consistent with covert trackers, "
                "skimmers, or purpose-built surveillance hardware than everyday peripherals."
            )
            risk = (
                "Unnamed devices may be tracking beacons, Bluetooth skimmers, or rogue devices "
                "placed to monitor a location or a specific person."
            )
            fix = "Unknown devices may be tracking beacons or rogue devices — physically locate and identify them if they persist across scans."

        elif t == "BLE_DEVICES_DETECTED":
            what = f"Bluetooth Low Energy devices were detected advertising nearby. {d}"
            why = (
                "BLE beacons (iBeacon, Eddystone, proprietary tracker tags) broadcast persistent "
                "or semi-persistent identifiers that can be used to detect device proximity or, "
                "in aggregate across multiple reader locations, to track a person's movement."
            )
            risk = (
                "If one of these beacons is not yours, it may be being used to track this "
                "device's location or the movements of the person carrying it."
            )
            fix = (
                "BLE devices may include tracking beacons (iBeacon, Eddystone). Review in "
                "environments with strict privacy requirements, and use a tracker-detection app "
                "if an unfamiliar beacon persists across locations."
            )

        elif t == "INTERFACE_PROMISC":
            what = f"A network interface on this device is running in promiscuous mode. {d}"
            why = (
                "Promiscuous mode disables the NIC's normal filter so it accepts and hands the "
                "OS every frame on the segment, not just those addressed to it — the mode "
                "packet sniffers (tcpdump, Wireshark) and, more concerningly, unauthorized "
                "eavesdropping malware require to capture other hosts' traffic."
            )
            risk = (
                "If this was not enabled intentionally for legitimate diagnostics, it likely "
                "means something on this host is capturing — and potentially exfiltrating — "
                "traffic belonging to other devices on the same network segment."
            )
            fix = (
                "Investigate why the interface is in promiscuous mode. This may indicate packet "
                "sniffing activity — check for unexpected capture processes and disable it "
                "(`ip link set <iface> promisc off`) if not intentional."
            )

        elif t == "EXPOSED_SERVICE":
            what = f"A network service on this device is listening on all interfaces, not just localhost. {d}"
            why = (
                "Binding to 0.0.0.0/:: means the service accepts connections from any network "
                "the host is attached to — including untrusted WiFi or the public internet if "
                "there's no NAT/firewall in front of it — rather than only from processes on the "
                "same machine."
            )
            risk = (
                "Anyone who can route traffic to this host can reach the service directly, "
                "potentially exploiting unpatched vulnerabilities, weak/default credentials, or "
                "unauthenticated management interfaces in that service."
            )
            fix = (
                "Bind the service to specific interfaces only. Use a firewall to restrict access "
                "by source IP."
            )

        elif t == "MULTIPLE_DEFAULT_ROUTES":
            what = f"More than one default route was found in the routing table. {d}"
            why = (
                "A host should normally have a single default gateway; multiple default routes "
                "usually indicate misconfiguration (e.g. two active network managers, a leftover "
                "VPN route) but can also result from an attacker injecting a rogue route to "
                "redirect traffic through a machine they control."
            )
            risk = (
                "Traffic can be unpredictably or maliciously routed through an unintended "
                "gateway, which could enable man-in-the-middle interception of otherwise-trusted "
                "traffic."
            )
            fix = "Review routing configuration for potential misrouting and remove any unexpected default route."

        elif t == "HOST_REACHABLE":
            what = f"A neighboring host responded to an ICMP ping probe. {d}"
            why = (
                "This simply confirms the host is up and reachable on the local network — a "
                "baseline fact used to scope which devices seen in ARP/neighbor tables are "
                "actually live right now."
            )
            risk = "Informational only; reachability itself is not a vulnerability."
            fix = "No action required; use this to decide which live hosts warrant a closer look (e.g. a port probe)."

        elif t == "HOST_UNREACHABLE":
            what = f"A previously-seen neighboring host did not respond to an ICMP ping probe. {d}"
            why = (
                "The host may be offline, asleep, or simply blocking ICMP echo requests with a "
                "host firewall — all common and not inherently suspicious."
            )
            risk = "Informational only; no risk implied by a single missed ping."
            fix = "No action required unless the host is expected to always be reachable, in which case investigate why it stopped responding."

        elif t == "HOST_OPEN_PORT":
            what = f"A TCP port was found open and accepting connections on a neighboring host. {d}"
            why = (
                "An open port means a service is actively listening and will complete a TCP "
                "handshake with anyone who can reach it on the LAN — the same reconnaissance "
                "step an attacker performs before attempting exploitation, credential stuffing, "
                "or banner-grabbing against that service."
            )
            risk = (
                "If the service is unpatched, uses default/weak credentials, or wasn't meant to "
                "be reachable from this network segment, it becomes a direct foothold for "
                "lateral movement from this host."
            )
            fix = "Confirm this service is intentionally exposed to the LAN; restrict it with a firewall if not."

        elif t == "HOST_NO_COMMON_PORTS_OPEN":
            what = f"None of the commonly-probed ports were found open on this host. {d}"
            why = "A clean result on a well-known-port sweep is a good sign, though it doesn't rule out services on uncommon or high ports."
            risk = "No risk identified by this probe."
            fix = "No action required."

        elif t == "ASLR_DISABLED":
            what = f"Kernel Address Space Layout Randomization is disabled or only partially enabled. {d}"
            why = (
                "ASLR randomizes where the stack, heap, libraries and executable are loaded in "
                "memory on each run. Without it, memory addresses are predictable across runs, "
                "which is exactly what an attacker needs to reliably weaponize a memory-"
                "corruption bug (buffer overflow, use-after-free) into working code execution — "
                "with ASLR off, return-oriented-programming (ROP) gadget addresses can simply be "
                "hard-coded into an exploit."
            )
            risk = (
                "Any memory-corruption vulnerability in a running process on this device becomes "
                "dramatically easier to turn into reliable remote or local code execution, since "
                "the attacker doesn't have to guess or leak memory addresses first."
            )
            fix = (
                "Enable full ASLR: `sysctl -w kernel.randomize_va_space=2`. Add to "
                "/etc/sysctl.conf for persistence."
            )

        elif t == "NO_FIREWALL":
            what = f"No host-based firewall tool was detected on this device. {d}"
            why = (
                "With no firewall, every service that binds to a network interface is directly "
                "reachable by anything that can route packets to the host — there is no "
                "additional layer filtering unwanted connections before they hit a listening "
                "service."
            )
            risk = (
                "Any currently or future exposed service (see EXPOSED_SERVICE/HOST_OPEN_PORT "
                "findings) is reachable from the entire network with nothing standing in "
                "between."
            )
            fix = "Install and configure a firewall. For Debian: `apt install ufw && ufw enable`."

        elif t == "WEAK_PASSWORD_POLICY":
            what = f"The system's minimum password length policy is set too low. {d}"
            why = (
                "A short minimum length dramatically shrinks the password search space — an "
                "8-character policy can be exhausted by offline brute-force/GPU cracking rigs in "
                "hours to days for typical hash algorithms, whereas 12+ characters pushes that "
                "into impractical territory."
            )
            risk = (
                "Local or service accounts on this system are more susceptible to brute-force "
                "and credential-stuffing attacks if their password hashes are ever exposed."
            )
            fix = "Set PASS_MIN_LEN to at least 12 in /etc/login.defs."

        elif t == "CORE_DUMP_PIPE":
            what = f"Core dumps on this system are being piped to an external handler process. {d}"
            why = (
                "A crashing process's core dump contains a full memory snapshot — potentially "
                "including passwords, private keys, or session tokens that were in memory at "
                "crash time. Piping dumps to a custom handler (rather than disk with tight "
                "permissions) means that handler process controls where that sensitive memory "
                "ends up."
            )
            risk = (
                "Sensitive data resident in a crashed process's memory could be captured, "
                "logged, or exfiltrated by whatever the pipe target does with it."
            )
            fix = "Review core dump handling. Piped dumps may expose sensitive memory."

        elif t == "HIGH_MEMORY_USAGE":
            what = f"System memory utilization is very high. {d}"
            why = (
                "Memory pressure this high increases the chance of OOM-killer intervention on "
                "security-relevant processes (firewall daemons, monitoring agents), and can be a "
                "symptom of a runaway or malicious process consuming resources."
            )
            risk = (
                "Security tooling could be killed or become unresponsive under memory pressure, "
                "creating a window where protections are not actively running."
            )
            fix = "Identify the top memory consumers (`ps aux --sort=-%mem`) and investigate any unexpected process before it triggers OOM kills of critical services."

        elif t == "RESTRICTED_OPERATION":
            what = f"A restricted SS7 MAP operation was received that should never originate outside the home network. {d}"
            why = (
                "Certain MAP operations (e.g. InsertSubscriberData, CancelLocation, PurgeMS) are "
                "only legitimate when issued by the subscriber's own HLR/HSS. SS7's original "
                "trust model assumes all interconnected operators are honest, so nothing at the "
                "protocol level stops a compromised or malicious foreign network element from "
                "sending these — only a firewall filtering by category can."
            )
            risk = (
                "If this reaches the HLR unfiltered, it can be used to redirect a subscriber's "
                "calls/SMS, deregister them from the network, or manipulate their service "
                "profile without their knowledge."
            )
            fix = (
                "Verify SS7 firewall rules. Block or challenge this operation at the network "
                "boundary (GSMA FS.11 category 2/3)."
            )

        elif t == "SUBSCRIBER_DATA_MANIPULATION":
            what = f"An InsertSubscriberData (ISD) attempt or other subscriber-data-manipulation event was observed. {d}"
            why = (
                "ISD is meant to let a subscriber's home HLR push profile updates to a serving "
                "VLR. Accepted from an external or untrusted source, it can silently rewrite the "
                "subscriber's call-forwarding, barring, or service profile — the technique "
                "behind real-world SMS/call interception and one-time-passcode theft attacks "
                "against SS7 networks."
            )
            risk = (
                "An attacker can redirect a subscriber's SMS (including OTP/2FA codes) or voice "
                "calls to a number they control, or silently modify their service profile — "
                "enabling account takeover of anything protected by SMS-based verification."
            )
            fix = (
                "Deploy an SS7 firewall (Category 1–3 filtering per GSMA FS.11). Block ISD from "
                "inter-PLMN links, require mutual authentication, and alert the NOC immediately."
            )

        elif t == "AUTH_VECTOR_REQUEST":
            what = f"A SendAuthenticationInfo (SAI) request was observed from a network element. {d}"
            why = (
                "SAI returns authentication vectors (ciphering and integrity keys, RAND/SRES) "
                "used to authenticate the subscriber and encrypt their radio traffic. If a "
                "malicious node can request these for a target MSISDN, it obtains the material "
                "needed to decrypt that subscriber's traffic or assist a man-in-the-middle "
                "attack."
            )
            risk = (
                "Authentication vectors obtained this way can be used to decrypt intercepted "
                "radio traffic or assist in SIM-cloning / man-in-the-middle attacks against the "
                "target subscriber."
            )
            fix = "Block SAI from untrusted network elements. Enable SAI filtering."

        elif t == "SRI_RATE_BURST":
            what = f"An unusually high rate of SendRoutingInfo (SRI) queries was observed from a single source. {d}"
            why = (
                "SRI is the operation used to look up which cell/VLR a subscriber is currently "
                "registered on — legitimate for call routing, but a high-rate burst of SRI "
                "queries against many subscribers from one source is the classic signature of "
                "automated bulk location-harvesting tools."
            )
            risk = (
                "An attacker can build a real-time map of where large numbers of subscribers "
                "are currently located, enabling mass surveillance or targeted physical "
                "tracking."
            )
            fix = "Implement SRI rate limiting. Throttle > 5 SRI/min per source."

        elif t == "SUBSCRIBER_TRACKING":
            what = f"Repeated SendRoutingInfo (SRI) queries for the same subscriber were observed over time. {d}"
            why = (
                "A single SRI query is normal call-setup behavior; many SRI queries for the "
                "exact same subscriber in a short window is not — it matches the pattern of an "
                "attacker or stalkerware-style service repeatedly polling to track that one "
                "person's real-time location."
            )
            risk = (
                "The targeted subscriber's physical location can be tracked in near-real-time "
                "by whoever is issuing these repeated queries, without their knowledge or "
                "consent."
            )
            fix = "Enable per-subscriber SRI throttling. Alert on repetitive location queries."

        elif t == "EXTERNAL_MAP_SCCP":
            what = f"SCCP traffic addressed to the MAP subsystem (SSN=147) was received from an external source. {d}"
            why = (
                "MAP is the SS7 application layer that carries all the sensitive subscriber "
                "operations (ISD, SAI, SRI, CancelLocation). Traffic reaching this subsystem "
                "directly from outside the home PLMN means the inter-PLMN firewall either isn't "
                "filtering MAP SSN traffic or has a gap allowing it through."
            )
            risk = (
                "Without SCCP/MAP-layer filtering at the network boundary, all of the more "
                "specific MAP-based attacks (ISD spoofing, SAI theft, SRI tracking) become "
                "directly reachable from outside the operator's own network."
            )
            fix = (
                "Deploy SS7 firewall (IPX/GPRS-backbone level). Filter MAP operations at "
                "category 1 minimum."
            )

        elif t == "INSECURE_RADIO_ACCESS_TECHNOLOGY":
            what = f"The device is currently registered on a legacy radio access technology. {d}"
            why = (
                "2G/GSM has no mutual authentication between the network and the handset — the "
                "handset trusts any base station broadcasting the right identifiers, and A5/1 "
                "ciphering is breakable in near-real-time with commodity hardware. This is "
                "exactly what fake base stations / IMSI-catchers (Stingrays) exploit: they "
                "impersonate a legitimate cell tower and the phone connects without any way to "
                "verify it."
            )
            risk = (
                "An IMSI-catcher in range can silently force this device onto a rogue 2G cell, "
                "intercept calls and SMS (including OTP codes), and harvest the device's "
                "IMSI/IMEI for tracking — all without any indication on the handset."
            )
            fix = (
                "Disable 2G fallback if supported (Android 12+: Settings > Network & Internet > "
                "SIMs > Allow 2G), or use a carrier/device that enforces LTE/5G-only "
                "registration."
            )

        elif t == "DEVICE_ROAMING":
            what = f"The device is currently roaming on a network other than its home operator. {d}"
            why = (
                "While roaming, the device's traffic and signaling pass through a foreign "
                "operator's infrastructure and inter-operator roaming agreements — a trust "
                "boundary the subscriber has less visibility into and less ability to audit "
                "than their home network."
            )
            risk = (
                "Roaming networks vary widely in their SS7/Diameter firewall maturity, so the "
                "device may be more exposed to interception or tracking attacks than on its "
                "home network."
            )
            fix = "Informational — no action required unless roaming is unexpected, in which case verify the SIM/account hasn't been cloned or misused."

        elif t == "WEAK_SIGNAL":
            what = f"The device is seeing a weak cellular signal from a nearby cell. {d}"
            why = (
                "Weak coverage increases the odds the handset's baseband will hand over to, or "
                "fall back onto, a lower-generation (less secure) radio technology in order to "
                "maintain a connection — the same fallback behavior IMSI-catchers deliberately "
                "induce by jamming stronger legitimate signals."
            )
            risk = (
                "A device in a weak-signal area is more likely to fall back to an insecure "
                "radio technology, making it easier for a nearby rogue base station to capture "
                "it."
            )
            fix = "No direct fix for signal strength; be aware that weak-coverage areas are higher-risk for fake base station attacks."

        elif t == "RADIO_NOMINAL":
            what = f"No radio access technology or signal issues were detected for this device. {d}"
            why = "The device is registered on a modern, mutually-authenticated radio technology with adequate signal — the expected, healthy baseline."
            risk = "No risk identified."
            fix = "No action required."

        elif t == "SUBSCRIBER_ROAMING":
            what = f"This subscriber is currently marked as roaming. {d}"
            why = (
                "Roaming status by itself is normal subscriber behavior, but it's tracked here "
                "because it changes which network's SS7/Diameter security posture applies to "
                "the subscriber's traffic."
            )
            risk = "No risk identified by roaming status alone."
            fix = "Informational — no action required."

        elif t == "SUBSCRIBER_NOMINAL":
            what = f"No suspicious activity was observed for this subscriber. {d}"
            why = "This is the expected, healthy baseline — no restricted operations, tracking bursts, or manipulation attempts observed."
            risk = "No risk identified."
            fix = "No action required."

        else:
            # Fallback for any finding type not enumerated above: build a
            # specific-as-possible explanation from the finding's own fields
            # rather than a blank placeholder.
            what = d or f"A {t} finding was reported by the {finding.module or 'scanner'} module."
            why = (
                f"This was classified as {finding.severity.value} severity by the "
                f"{finding.module or 'scanner'} module because it represents a deviation from "
                f"a secure baseline or an indicator worth reviewing."
            )
            risk = (
                f"Left unaddressed, this {finding.severity.value.lower()}-severity condition "
                f"may be combined with other findings to increase overall exposure, or may "
                f"itself be directly exploitable depending on context"
                + (f": {finding.evidence}" if finding.evidence else ".")
            )
            fix = finding.recommendation or (
                "Review this finding manually against vendor and security best practices for "
                "the affected component, and re-scan after remediation to confirm it clears."
            )

        return ExplainedFinding(finding=finding, what=what, why=why, risk=risk, fix=fix)

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
