"""
CyberScope — core/asset_manager.py

Turns every identifiable thing a scan/monitor observes (a WiFi AP's
BSSID, a Bluetooth device's address, a LAN host's IP) into a persisted
Asset: what it is, its vendor, what's been observed about it, and how
risky it currently looks -- surviving across sessions in the same
`assets` table the rest of the platform's history already lives in.

Feeds via core/event_bus.py: publish an ASSET_OBSERVED event and
whatever's subscribed (normally the single AssetManager instance
core/engine.py owns) records it. Nothing here re-scans anything --
this layer only aggregates what modules already found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from core.event_bus import ASSET_OBSERVED, Event, EventBus
from core.types import Severity

_RISK_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _risk_rank(risk: str) -> int:
    try:
        return _RISK_ORDER.index(risk.upper())
    except (ValueError, AttributeError):
        return 0


def _higher_risk(a: str, b: str) -> str:
    return a if _risk_rank(a) >= _risk_rank(b) else b


@dataclass
class Asset:
    """One persisted entity CyberScope has observed on the network."""
    type:               str                 # "wifi_ap" / "bluetooth_device" / "network_host"
    identifier:         str                 # BSSID / BD address / IP (whatever uniquely names it)
    vendor:             str = ""
    interfaces:         List[str] = field(default_factory=list)
    observed_services:  List[str] = field(default_factory=list)
    risk:               str = "INFO"
    first_seen:         str = ""
    last_seen:          str = ""
    seen_count:         int = 1
    sessions:           List[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.type}:{self.identifier}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":                self.id,
            "type":              self.type,
            "identifier":        self.identifier,
            "vendor":            self.vendor,
            "interfaces":        self.interfaces,
            "observed_services": self.observed_services,
            "risk":              self.risk,
            "first_seen":        self.first_seen,
            "last_seen":         self.last_seen,
            "seen_count":        self.seen_count,
            "sessions":          self.sessions,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Asset":
        return cls(
            type=d["type"], identifier=d["identifier"],
            vendor=d.get("vendor", ""),
            interfaces=list(d.get("interfaces", [])),
            observed_services=list(d.get("observed_services", [])),
            risk=d.get("risk", "INFO"),
            first_seen=d.get("first_seen", ""),
            last_seen=d.get("last_seen", ""),
            seen_count=d.get("seen_count", 1),
            sessions=list(d.get("sessions", [])),
        )


class AssetManager:
    """
    Owns the asset knowledge base. Can be driven directly via observe(),
    or wired to an EventBus so any publisher of ASSET_OBSERVED events
    feeds it without importing it directly.
    """

    def __init__(self, db: Any, events: Optional[EventBus] = None) -> None:
        self.db = db
        if events is not None:
            events.subscribe(ASSET_OBSERVED, self._on_event)

    # ── Event bus hook ────────────────────────────────────────────────

    def _on_event(self, event: Event) -> None:
        self.observe(**event.payload)

    # ── Core operation ────────────────────────────────────────────────

    def observe(
        self,
        asset_type:  str,
        identifier:  str,
        vendor:      str = "",
        interfaces:  Optional[List[str]] = None,
        services:    Optional[List[str]] = None,
        risk:        str = "INFO",
        session_id:  str = "",
    ) -> Asset:
        """Record one observation of an asset, merging it with any prior
        record of the same (type, identifier). Risk only ever escalates
        within a merge (the highest severity ever observed wins) --
        history isn't erased by a quieter follow-up scan."""
        now = datetime.now(timezone.utc).isoformat()
        asset_id = f"{asset_type}:{identifier}"
        existing = self.db.get_asset(asset_id)

        if existing:
            asset = Asset.from_dict(existing)
            asset.vendor = vendor or asset.vendor
            asset.interfaces = sorted(set(asset.interfaces) | set(interfaces or []))
            asset.observed_services = sorted(set(asset.observed_services) | set(services or []))
            asset.risk = _higher_risk(asset.risk, risk)
            asset.last_seen = now
            asset.seen_count += 1
            if session_id and session_id not in asset.sessions:
                asset.sessions.append(session_id)
        else:
            asset = Asset(
                type=asset_type, identifier=identifier, vendor=vendor,
                interfaces=sorted(set(interfaces or [])),
                observed_services=sorted(set(services or [])),
                risk=risk, first_seen=now, last_seen=now,
                sessions=[session_id] if session_id else [],
            )

        self.db.upsert_asset(asset.to_dict())
        return asset

    # ── Queries ───────────────────────────────────────────────────────

    def get_assets(self, asset_type: Optional[str] = None, limit: int = 200) -> List[Asset]:
        return [Asset.from_dict(d) for d in self.db.get_assets(asset_type, limit)]

    def get_asset(self, asset_type: str, identifier: str) -> Optional[Asset]:
        d = self.db.get_asset(f"{asset_type}:{identifier}")
        return Asset.from_dict(d) if d else None
