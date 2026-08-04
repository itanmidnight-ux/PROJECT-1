"""
CyberScope AI Security Platform — tests/test_event_bus.py

Tests cover:
  - core/event_bus.py (Event, EventBus)
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

# Insert project root into sys.path
_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.event_bus import (
    ASSET_OBSERVED, EventBus, Event, FINDING_RAISED, WILDCARD,
)


class TestEvent:
    def test_defaults(self):
        e = Event(type=ASSET_OBSERVED)
        assert e.type == ASSET_OBSERVED
        assert e.payload == {}
        assert e.source == ""
        assert e.timestamp is not None

    def test_to_dict(self):
        e = Event(type=FINDING_RAISED, payload={"id": 1}, source="wifi_monitor")
        d = e.to_dict()
        assert d["type"] == FINDING_RAISED
        assert d["payload"] == {"id": 1}
        assert d["source"] == "wifi_monitor"
        assert "timestamp" in d


class TestEventBusBasic:
    def test_publish_subscribe_delivery(self):
        bus = EventBus()
        received = []
        bus.subscribe(ASSET_OBSERVED, received.append)

        event = Event(type=ASSET_OBSERVED, payload={"mac": "aa:bb"})
        bus.publish(event)

        assert received == [event]

    def test_no_subscribers_is_safe(self):
        bus = EventBus()
        # Should not raise even though nobody is subscribed.
        bus.publish(Event(type=ASSET_OBSERVED))

    def test_only_matching_type_delivered(self):
        bus = EventBus()
        asset_events = []
        finding_events = []
        bus.subscribe(ASSET_OBSERVED, asset_events.append)
        bus.subscribe(FINDING_RAISED, finding_events.append)

        bus.publish(Event(type=ASSET_OBSERVED))

        assert len(asset_events) == 1
        assert len(finding_events) == 0


class TestMultipleSubscribers:
    def test_multiple_subscribers_same_type(self):
        bus = EventBus()
        calls_a: list = []
        calls_b: list = []
        bus.subscribe(ASSET_OBSERVED, calls_a.append)
        bus.subscribe(ASSET_OBSERVED, calls_b.append)

        event = Event(type=ASSET_OBSERVED)
        bus.publish(event)

        assert calls_a == [event]
        assert calls_b == [event]


class TestWildcard:
    def test_wildcard_receives_everything(self):
        bus = EventBus()
        seen = []
        bus.subscribe(WILDCARD, seen.append)

        e1 = Event(type=ASSET_OBSERVED)
        e2 = Event(type=FINDING_RAISED)
        bus.publish(e1)
        bus.publish(e2)

        assert seen == [e1, e2]

    def test_wildcard_plus_specific_both_fire(self):
        bus = EventBus()
        wildcard_calls = []
        specific_calls = []
        bus.subscribe(WILDCARD, wildcard_calls.append)
        bus.subscribe(ASSET_OBSERVED, specific_calls.append)

        bus.publish(Event(type=ASSET_OBSERVED))

        assert len(wildcard_calls) == 1
        assert len(specific_calls) == 1


class TestFailingHandler:
    def test_raising_handler_does_not_stop_others(self):
        bus = EventBus()
        calls = []

        def bad_handler(event):
            raise RuntimeError("boom")

        def good_handler(event):
            calls.append(event)

        bus.subscribe(ASSET_OBSERVED, bad_handler)
        bus.subscribe(ASSET_OBSERVED, good_handler)

        # Must not raise out to the publisher.
        bus.publish(Event(type=ASSET_OBSERVED))

        assert len(calls) == 1

    def test_raising_handler_logged(self, caplog):
        bus = EventBus()

        def bad_handler(event):
            raise ValueError("nope")

        bus.subscribe(ASSET_OBSERVED, bad_handler)

        with caplog.at_level("ERROR", logger="cyberscope.event_bus"):
            bus.publish(Event(type=ASSET_OBSERVED))

        assert any("bad_handler" in r.message or "handler" in r.message
                    for r in caplog.records)


class TestUnsubscribe:
    def test_unsubscribe_stops_delivery(self):
        bus = EventBus()
        calls = []

        def handler(event):
            calls.append(event)

        bus.subscribe(ASSET_OBSERVED, handler)
        bus.publish(Event(type=ASSET_OBSERVED))
        assert len(calls) == 1

        bus.unsubscribe(ASSET_OBSERVED, handler)
        bus.publish(Event(type=ASSET_OBSERVED))
        assert len(calls) == 1  # unchanged

    def test_unsubscribe_unknown_handler_is_noop(self):
        bus = EventBus()

        def handler(event):
            pass

        # Never subscribed — should not raise.
        bus.unsubscribe(ASSET_OBSERVED, handler)

    def test_unsubscribe_during_dispatch_does_not_crash(self):
        bus = EventBus()
        calls = []

        def self_removing(event):
            calls.append(event)
            bus.unsubscribe(ASSET_OBSERVED, self_removing)

        def other(event):
            calls.append(event)

        bus.subscribe(ASSET_OBSERVED, self_removing)
        bus.subscribe(ASSET_OBSERVED, other)

        bus.publish(Event(type=ASSET_OBSERVED))
        assert len(calls) == 2

        calls.clear()
        bus.publish(Event(type=ASSET_OBSERVED))
        assert len(calls) == 1  # only "other" remains


class TestThreadSafety:
    def test_concurrent_publish_from_multiple_threads(self):
        bus = EventBus()
        received: list = []
        lock = threading.Lock()

        def handler(event):
            with lock:
                received.append(event)

        bus.subscribe(WILDCARD, handler)

        def worker(n: int):
            for i in range(50):
                bus.publish(Event(type=ASSET_OBSERVED, payload={"worker": n, "i": i}))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 5 * 50

    def test_concurrent_subscribe_and_publish(self):
        bus = EventBus()
        errors: list = []

        def subscriber_worker():
            for _ in range(50):
                bus.subscribe(ASSET_OBSERVED, lambda event: None)

        def publisher_worker():
            for _ in range(50):
                try:
                    bus.publish(Event(type=ASSET_OBSERVED))
                except Exception as exc:  # pragma: no cover - failure path
                    errors.append(exc)

        threads = [
            threading.Thread(target=subscriber_worker),
            threading.Thread(target=publisher_worker),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
