"""SNIFF Web GUI — FastAPI backend.

Single pane of glass for the realtime-packet-sniff IDS pipeline:
controls the in-process capture engine, manages systemd services,
queries Kafka and ClickHouse, manages rotated PCAP files.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict

import yaml

DEFAULTS: Dict[str, Any] = {
    "bind": "0.0.0.0",
    "port": 8000,
    "username": "admin",
    "password_hash": "",
    "jwt_secret": "",
    "jwt_expiry_seconds": 86400,
    "auto_restore": True,
    "persistence_dir": "/var/lib/sniff-web",
}


def load_web_config(path: str) -> Dict[str, Any]:
    """Load the `web:` section from config.yaml. Returns DEFAULTS merged with file values."""
    p = Path(path)
    if not p.exists():
        return dict(DEFAULTS)
    with p.open("r", encoding="utf-8") as f:
        full = yaml.safe_load(f) or {}
    web = full.get("web", {}) or {}
    merged = dict(DEFAULTS)
    merged.update(web)
    return merged


if __name__ == "__main__":  # pragma: no cover
    import sys
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    print(load_web_config(cfg_path))
