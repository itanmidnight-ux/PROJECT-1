"""
CyberScope — core/types.py

Common types shared across all modules:
  Finding, ModuleResult, Severity, ModuleStatus, CapabilityInfo
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def score(self) -> int:
        return {"CRITICAL":10,"HIGH":8,"MEDIUM":5,"LOW":2,"INFO":1}[self.value]

    def __lt__(self, other: "Severity") -> bool:
        order = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
        return order.index(self.value) < order.index(other.value)


class ModuleStatus(Enum):
    AVAILABLE   = "available"
    LIMITED     = "limited"    # present but restricted (e.g. no root)
    UNAVAILABLE = "unavailable"
    ERROR       = "error"


@dataclass
class CapabilityInfo:
    name:    str
    status:  ModuleStatus
    reason:  str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.status in (ModuleStatus.AVAILABLE, ModuleStatus.LIMITED)

    def to_dict(self) -> dict:
        return {
            "name":    self.name,
            "status":  self.status.value,
            "reason":  self.reason,
            "details": self.details,
        }


@dataclass
class Finding:
    """Standardised security finding produced by any module."""
    type:           str
    severity:       Severity
    description:    str
    evidence:       str            = ""
    recommendation: str            = ""
    module:         str            = ""
    mitre:          Optional[str]  = None
    source:         Optional[str]  = None
    timestamp:      datetime       = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type":           self.type,
            "severity":       self.severity.value,
            "description":    self.description,
            "evidence":       self.evidence,
            "recommendation": self.recommendation,
            "module":         self.module,
            "mitre":          self.mitre,
            "source":         self.source,
            "timestamp":      self.timestamp.isoformat(),
        }


@dataclass
class ModuleResult:
    """Output from a single module scan."""
    module:      str
    status:      ModuleStatus
    findings:    List[Finding]      = field(default_factory=list)
    raw_data:    Dict[str, Any]     = field(default_factory=dict)
    duration_ms: float              = 0.0
    timestamp:   datetime           = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def highest_severity(self) -> Optional[Severity]:
        return max(self.findings, key=lambda f: f.severity.score).severity \
               if self.findings else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module":      self.module,
            "status":      self.status.value,
            "duration_ms": self.duration_ms,
            "timestamp":   self.timestamp.isoformat(),
            "findings":    [f.to_dict() for f in self.findings],
            "raw_data":    self.raw_data,
        }
