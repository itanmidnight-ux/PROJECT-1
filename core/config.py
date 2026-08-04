"""CyberScope — core/config.py"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_ROOT = Path(__file__).parent.parent

_DEFAULTS: Dict[str, Any] = {
    "platform": {"name": "CyberScope AI Security Platform", "version": "1.0.0"},
    "logging":  {"level": "INFO", "file": "logs/cyberscope.log"},
    "database": {"path": "database/cyberscope.db"},
    "reports":  {"output_dir": "reports", "formats": ["json", "html", "markdown"]},
    "wifi":     {"scan_timeout": 10, "passive_only": True},
    "bluetooth":{"scan_timeout": 10, "max_devices": 50},
    "network":  {"port_scan": False, "interface": "auto"},
    "telecom":  {"mode": "laboratory", "sri_threshold": 10},
    "ai":       {"risk_threshold_high": 70, "risk_threshold_critical": 85},
}


def _merge(base: dict, override: dict) -> None:
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            _merge(base[k], v)
        else:
            base[k] = v


def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    cfg = json.loads(json.dumps(_DEFAULTS))
    p = Path(path) if path else _ROOT / "config.yaml"
    if p.exists():
        with p.open() as f:
            user = yaml.safe_load(f)
        if user:
            _merge(cfg, user)
    return cfg
