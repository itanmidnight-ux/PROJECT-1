"""
CyberScope — core/event_bus.py

Lightweight in-process publish/subscribe event bus. Lets modules (asset
manager, monitors, reporters, ...) react to activity without importing
each other directly. Thread-safe: monitor loops (WiFi/Bluetooth/Telecom)
may publish or subscribe from background threads while the main thread
does the same.
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List

log = logging.getLogger("cyberscope.event_bus")

# ── Well-known event types ──────────────────────────────────────────────
ASSET_OBSERVED = "asset.observed"
FINDING_RAISED = "finding.raised"
SCAN_COMPLETED = "scan.completed"

# Subscribing with this type receives every published event.
WILDCARD = "*"

Handler = Callable[["Event"], None]


@dataclass
class Event:
    type:      str
    payload:   Dict[str, Any] = field(default_factory=dict)
    source:    str            = ""
    timestamp: datetime       = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":      self.type,
            "payload":   self.payload,
            "source":    self.source,
            "timestamp": self.timestamp.isoformat(),
        }


class EventBus:
    """Synchronous pub/sub registry. One bad subscriber never blocks or
    breaks delivery to the others, and never propagates back to the
    publisher."""

    def __init__(self) -> None:
        self._handlers: Dict[str, List[Handler]] = {}
        self._lock = threading.Lock()

    # ── Registration ──────────────────────────────────────────────────
    def subscribe(self, event_type: str, handler: Handler) -> None:
        """Register handler for event_type, or WILDCARD ("*") for all events."""
        with self._lock:
            self._handlers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, event_type: str, handler: Handler) -> None:
        """Remove a previously-registered handler. No-op if not present."""
        with self._lock:
            handlers = self._handlers.get(event_type)
            if handlers and handler in handlers:
                handlers.remove(handler)

    # ── Publishing ────────────────────────────────────────────────────
    def publish(self, event: Event) -> None:
        """Notify every handler subscribed to event.type plus wildcard
        handlers. Handler exceptions are caught and logged, never raised
        to the caller."""
        with self._lock:
            handlers = list(self._handlers.get(event.type, []))
            handlers += list(self._handlers.get(WILDCARD, []))

        for handler in handlers:
            try:
                handler(event)
            except Exception:
                log.exception(
                    "event_bus: handler %r raised while handling %r",
                    handler, event.type,
                )
