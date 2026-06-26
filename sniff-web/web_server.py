"""SNIFF Web GUI — FastAPI backend.

Single pane of glass for the realtime-packet-sniff IDS pipeline:
controls the in-process capture engine, manages systemd services,
queries Kafka and ClickHouse, manages rotated PCAP files.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

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


# ---------------------------------------------------------------------------
# Persistence layer (Task 3): last_capture.json
# ---------------------------------------------------------------------------

logger = logging.getLogger("sniff_web")

_LAST_CAPTURE_FILENAME = "last_capture.json"
_REQUIRED_KEYS = {"interface", "auto_restore"}


def read_last_capture(persistence_dir: str) -> Optional[dict]:
    """Read last capture config. Returns None if file missing or malformed."""
    path = Path(persistence_dir) / _LAST_CAPTURE_FILENAME
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Last capture config at %s is malformed: %s", path, exc)
        return None
    if not isinstance(data, dict):
        logger.warning("Last capture config at %s is not a dict", path)
        return None
    return data


def write_last_capture(persistence_dir: str, cfg: dict) -> None:
    """Persist capture config atomically. Validates required keys."""
    missing = _REQUIRED_KEYS - set(cfg.keys())
    if missing:
        raise ValueError(f"Missing required keys: {missing}")
    p = Path(persistence_dir)
    p.mkdir(parents=True, exist_ok=True)
    target = p / _LAST_CAPTURE_FILENAME
    tmp = target.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    tmp.replace(target)


if __name__ == "__main__":  # pragma: no cover
    import sys
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    print(load_web_config(cfg_path))


# ---------------------------------------------------------------------------
# Auth layer (Task 2): JWT + bcrypt
# ---------------------------------------------------------------------------

import secrets
import time
import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException, status

_USERNAME = "admin"
_PASSWORD_HASH = ""
_JWT_SECRET = ""
_JWT_EXPIRY = 86400


def configure_auth(username: str, password_hash: str, jwt_secret: str, jwt_expiry: int) -> None:
    global _USERNAME, _PASSWORD_HASH, _JWT_SECRET, _JWT_EXPIRY
    _USERNAME = username
    _PASSWORD_HASH = password_hash
    _JWT_SECRET = jwt_secret or secrets.token_urlsafe(32)
    _JWT_EXPIRY = jwt_expiry


def make_token(payload: dict, secret=None, expiry_s=None) -> str:
    sec = secret or _JWT_SECRET
    exp = expiry_s if expiry_s is not None else _JWT_EXPIRY
    now = int(time.time())
    full = {**payload, "iat": now, "exp": now + exp, "sub": payload.get("sub", _USERNAME)}
    return jwt.encode(full, sec, algorithm="HS256")


def decode_token(token: str, secret=None) -> dict:
    sec = secret or _JWT_SECRET
    return jwt.decode(token, sec, algorithms=["HS256"])


def require_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token")
    return {"username": payload["sub"]}


def login(username: str, password: str) -> dict:
    if username != _USERNAME:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    if not _PASSWORD_HASH:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Auth not configured")
    if not bcrypt.checkpw(password.encode("utf-8"), _PASSWORD_HASH.encode("utf-8")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")
    token = make_token({"sub": username})
    return {"token": token, "expires_in": _JWT_EXPIRY}


def change_password(username: str, new_password: str) -> dict:
    if username != _USERNAME:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid user")
    global _PASSWORD_HASH
    _PASSWORD_HASH = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode()
    return {"ok": True}
