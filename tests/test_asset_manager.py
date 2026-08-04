"""
CyberScope — tests/test_asset_manager.py

Tests for core/asset_manager.py and the assets table it drives in
database/db.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.asset_manager import Asset, AssetManager
from core.event_bus import ASSET_OBSERVED, Event, EventBus
from database.db import CyberScopeDB


def _make_manager(tmp_path) -> AssetManager:
    db = CyberScopeDB(str(tmp_path / "assets_test.db"))
    return AssetManager(db)


class TestAssetDataclass:
    def test_id_property(self):
        a = Asset(type="wifi_ap", identifier="AA:BB:CC:DD:EE:FF")
        assert a.id == "wifi_ap:AA:BB:CC:DD:EE:FF"

    def test_to_dict_from_dict_roundtrip(self):
        a = Asset(
            type="network_host", identifier="10.0.0.5", vendor="VMware",
            interfaces=["ethernet"], observed_services=["ssh"], risk="MEDIUM",
            first_seen="t1", last_seen="t2", seen_count=3, sessions=["s1"],
        )
        d = a.to_dict()
        b = Asset.from_dict(d)
        assert b.type == a.type
        assert b.identifier == a.identifier
        assert b.vendor == a.vendor
        assert b.interfaces == a.interfaces
        assert b.observed_services == a.observed_services
        assert b.risk == a.risk
        assert b.seen_count == a.seen_count
        assert b.sessions == a.sessions


class TestAssetManagerObserve:
    def test_new_asset_created(self, tmp_path):
        mgr = _make_manager(tmp_path)
        asset = mgr.observe("wifi_ap", "AA:BB:CC:DD:EE:FF", vendor="TP-Link",
                             interfaces=["wifi"], services=["http"], risk="HIGH",
                             session_id="sess1")
        assert asset.id == "wifi_ap:AA:BB:CC:DD:EE:FF"
        assert asset.vendor == "TP-Link"
        assert asset.risk == "HIGH"
        assert asset.seen_count == 1
        assert asset.sessions == ["sess1"]

    def test_repeated_observation_merges(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.observe("wifi_ap", "AA:BB", vendor="TP-Link", services=["http"],
                    risk="LOW", session_id="s1")
        asset = mgr.observe("wifi_ap", "AA:BB", services=["dns"], risk="LOW",
                             session_id="s2")
        assert asset.seen_count == 2
        assert set(asset.observed_services) == {"http", "dns"}
        assert set(asset.sessions) == {"s1", "s2"}
        # vendor persists even when a later observation doesn't supply one
        assert asset.vendor == "TP-Link"

    def test_risk_only_escalates(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.observe("wifi_ap", "AA:BB", risk="HIGH")
        asset = mgr.observe("wifi_ap", "AA:BB", risk="LOW")
        assert asset.risk == "HIGH"  # doesn't get downgraded by a quieter pass

    def test_risk_upgrades_when_worse(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.observe("wifi_ap", "AA:BB", risk="LOW")
        asset = mgr.observe("wifi_ap", "AA:BB", risk="CRITICAL")
        assert asset.risk == "CRITICAL"

    def test_persisted_across_manager_instances(self, tmp_path):
        db_path = tmp_path / "shared.db"
        db1 = CyberScopeDB(str(db_path))
        AssetManager(db1).observe("bluetooth_device", "11:22:33", vendor="Acme")
        db1.close()

        db2 = CyberScopeDB(str(db_path))
        mgr2 = AssetManager(db2)
        found = mgr2.get_asset("bluetooth_device", "11:22:33")
        assert found is not None
        assert found.vendor == "Acme"

    def test_interfaces_and_services_deduplicated(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.observe("network_host", "10.0.0.5", interfaces=["ethernet"], services=["ssh"])
        asset = mgr.observe("network_host", "10.0.0.5", interfaces=["ethernet"], services=["ssh"])
        assert asset.interfaces == ["ethernet"]
        assert asset.observed_services == ["ssh"]


class TestAssetManagerQueries:
    def test_get_assets_filters_by_type(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.observe("wifi_ap", "AA:BB")
        mgr.observe("bluetooth_device", "11:22")
        wifi_only = mgr.get_assets("wifi_ap")
        assert len(wifi_only) == 1
        assert wifi_only[0].type == "wifi_ap"

    def test_get_assets_no_filter_returns_all(self, tmp_path):
        mgr = _make_manager(tmp_path)
        mgr.observe("wifi_ap", "AA:BB")
        mgr.observe("bluetooth_device", "11:22")
        assert len(mgr.get_assets()) == 2

    def test_get_asset_missing_returns_none(self, tmp_path):
        mgr = _make_manager(tmp_path)
        assert mgr.get_asset("wifi_ap", "nope") is None


class TestAssetManagerEventBus:
    def test_subscribes_and_records_on_publish(self, tmp_path):
        db = CyberScopeDB(str(tmp_path / "eventbus_test.db"))
        bus = EventBus()
        mgr = AssetManager(db, events=bus)

        bus.publish(Event(
            type=ASSET_OBSERVED,
            payload={
                "asset_type": "network_host", "identifier": "10.0.0.9",
                "vendor": "Acme", "risk": "MEDIUM",
            },
            source="test",
        ))

        found = mgr.get_asset("network_host", "10.0.0.9")
        assert found is not None
        assert found.vendor == "Acme"
        assert found.risk == "MEDIUM"

    def test_bad_payload_does_not_crash_bus(self, tmp_path):
        db = CyberScopeDB(str(tmp_path / "eventbus_bad.db"))
        bus = EventBus()
        AssetManager(db, events=bus)

        # Missing required kwargs -- observe() will raise TypeError, but
        # the event bus must catch it and not propagate to the publisher.
        bus.publish(Event(type=ASSET_OBSERVED, payload={"nonsense": True}, source="test"))
        # If we get here without an exception, the bus contained it correctly.
        assert True
