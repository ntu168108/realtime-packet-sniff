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


# ---------------------------------------------------------------------------
# Capture layer (Task 4): FastAPI app + lifecycle endpoints
# ---------------------------------------------------------------------------

import sys
from fastapi import FastAPI
from pydantic import BaseModel, Field

try:
    sys.path.insert(0, str(Path(__file__).parent))
    from core.capture import CaptureEngine, get_interfaces, validate_interface, get_interface_info
    from core.decoder import decode_packet
except ImportError as e:
    logger.warning("Could not import core.capture: %s", e)
    CaptureEngine = None
    get_interfaces = None
    validate_interface = None
    get_interface_info = None
    decode_packet = None

PERSISTENCE_DIR_OVERRIDE = None
_test_engine_factory = None


def _make_engine(**kwargs):
    if _test_engine_factory is not None:
        return _test_engine_factory(**kwargs)
    if CaptureEngine is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Capture engine unavailable")
    return CaptureEngine(**kwargs)


class StartBody(BaseModel):
    interface: str
    bpf_filter: str = ""
    snaplen: int = Field(default=65535, ge=64, le=65535)
    promisc: bool = True
    auto_restore: bool = True


app = FastAPI(title="SNIFF Web GUI", version="0.3.0")


@app.post("/api/auth/login")
def api_login(body: dict):
    return login(body.get("username"), body.get("password"))


@app.on_event("startup")
async def _on_startup():
    cfg = load_web_config("config.yaml")
    persistence = PERSISTENCE_DIR_OVERRIDE or cfg["persistence_dir"]
    configure_auth(username=cfg["username"], password_hash=cfg["password_hash"],
                   jwt_secret=cfg["jwt_secret"], jwt_expiry=cfg["jwt_expiry_seconds"])
    app.state.persistence_dir = persistence
    if cfg["auto_restore"]:
        last = read_last_capture(persistence)
        if last and last.get("auto_restore") and last.get("interface"):
            if validate_interface(last["interface"]):
                logger.info("Auto-restoring capture on %s", last["interface"])
                app.state.engine = _make_engine(
                    interface=last["interface"], bpf_filter=last.get("bpf_filter", ""),
                    snaplen=last.get("snaplen", 65535), promisc=last.get("promisc", True))
                app.state.engine.setup()
                app.state.engine.start()
            else:
                logger.warning("Auto-restore skipped: interface %s not found", last.get("interface"))


@app.on_event("shutdown")
async def _on_shutdown():
    eng = getattr(app.state, "engine", None)
    if eng and getattr(eng, "is_running", False):
        eng.stop()


@app.get("/api/interfaces")
def api_interfaces(user=Depends(require_user)):
    if get_interfaces is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "core.capture unavailable")
    return [get_interface_info(i) for i in get_interfaces()]


@app.post("/api/capture/start")
def api_start(body: StartBody, user=Depends(require_user)):
    if not validate_interface(body.interface):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Interface '{body.interface}' not found")
    eng = getattr(app.state, "engine", None)
    if eng and getattr(eng, "is_running", False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Capture already running")
    new_engine = _make_engine(interface=body.interface, bpf_filter=body.bpf_filter,
                              snaplen=body.snaplen, promisc=body.promisc)
    new_engine.setup()
    new_engine.start()
    app.state.engine = new_engine
    write_last_capture(app.state.persistence_dir, {
        "interface": body.interface, "bpf_filter": body.bpf_filter, "snaplen": body.snaplen,
        "promisc": body.promisc, "auto_restore": body.auto_restore,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    return {"ok": True}


@app.post("/api/capture/stop")
def api_stop(user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng or not getattr(eng, "is_running", False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No capture running")
    eng.stop()
    return {"ok": True}


@app.post("/api/capture/toggle-pause")
def api_toggle_pause(user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng or not getattr(eng, "is_running", False):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No capture running")
    paused = eng.toggle_pause()
    return {"paused": paused}


@app.get("/api/capture/status")
def api_status(user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng:
        return {"running": False, "paused": False, "interface": None,
                "packets": 0, "bytes": 0, "dropped": 0, "pps": 0, "bps": 0,
                "protocols": {}, "uptime": 0}
    return eng.get_status()


@app.get("/api/capture/last-config")
def api_last_config(user=Depends(require_user)):
    cfg = read_last_capture(app.state.persistence_dir)
    if cfg is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No last config")
    return cfg


@app.get("/api/capture/conversations")
def api_conversations(n: int = 20, user=Depends(require_user)):
    eng = getattr(app.state, "engine", None)
    if not eng or not getattr(eng, "is_running", False):
        return []
    return eng.get_top_conversations(n)


# ---------------------------------------------------------------------------
# Systemd service control (Task 5)
# ---------------------------------------------------------------------------

import subprocess

SERVICE_ALLOWLIST = {"kafka", "sniff-producer", "ec-consumer", "clickhouse-server", "grafana-server", "sniff-web"}
SERVICE_ACTIONS = {"start", "stop", "restart", "enable", "disable"}


def run_systemctl(name: str, action: str) -> dict:
    if name not in SERVICE_ALLOWLIST or action not in SERVICE_ACTIONS:
        raise ValueError(f"Disallowed: {action} {name}")
    try:
        proc = subprocess.run(["sudo", "-n", "systemctl", action, name],
                              capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "systemctl timeout", "exit_code": 124}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": "sudo not found", "exit_code": 127}
    return {"ok": proc.returncode == 0, "stdout": proc.stdout,
            "stderr": proc.stderr, "exit_code": proc.returncode}


def list_services_status() -> list:
    out = []
    for name in sorted(SERVICE_ALLOWLIST):
        try:
            proc = subprocess.run(["systemctl", "is-active", name],
                                  capture_output=True, text=True, timeout=5)
            active = proc.stdout.strip() == "active"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            active = False
        out.append({"name": name, "active": active})
    return out


@app.get("/api/services/list")
def api_services_list(user=Depends(require_user)):
    return list_services_status()


@app.post("/api/services/{name}/{action}")
def api_services_action(name: str, action: str, user=Depends(require_user)):
    if name not in SERVICE_ALLOWLIST:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Service '{name}' not in allowlist")
    if action not in SERVICE_ACTIONS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Action '{action}' not allowed")
    result = run_systemctl(name, action)
    if not result["ok"]:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            result["stderr"] or f"systemctl {action} {name} failed")
    return {"ok": True, "exit_code": result["exit_code"]}


CH_ALLOWLIST_PREFIXES = ("SELECT ", "SHOW ", "DESCRIBE ", "DESC ", "EXISTS ", "SELECT 1")
CH_MAX_ROWS_HARD_LIMIT = 1000


def query_clickhouse(sql: str, max_rows: int = 1000) -> dict:
    from clickhouse_driver import Client
    import time as _t
    client = Client(host="localhost", port=9000, database="network_ids")
    start = _t.time()
    rows = client.execute(sql, with_column_types=True)
    elapsed = (_t.time() - start) * 1000
    if not rows:
        return {"columns": [], "rows": [], "elapsed_ms": elapsed}
    data, types = rows
    columns = [t[0] for t in types]
    truncated = data[:max_rows]
    return {"columns": columns, "rows": [list(r) for r in truncated], "elapsed_ms": elapsed}


@app.post("/api/clickhouse/query")
def api_clickhouse_query(body: dict, user=Depends(require_user)):
    sql = (body.get("sql") or "").strip()
    if not sql:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty SQL")
    upper = sql.upper().lstrip()
    if not any(upper.startswith(p) for p in CH_ALLOWLIST_PREFIXES):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Only SELECT/SHOW/DESCRIBE/EXISTS allowed")
    max_rows = min(int(body.get("max_rows", 1000)), CH_MAX_ROWS_HARD_LIMIT)
    try:
        return query_clickhouse(sql, max_rows)
    except Exception as exc:
        logger.warning("ClickHouse query failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"ClickHouse error: {exc}")


@app.get("/api/clickhouse/counts")
def api_clickhouse_counts(user=Depends(require_user)):
    families = ["dos", "exploits", "fuzzers", "generic", "analysis", "reconnaissance", "shellcode"]
    out = {}
    try:
        result = query_clickhouse("SELECT count() FROM network_ids.flows_all", 1)
        out["flows_all"] = result["rows"][0][0] if result["rows"] else 0
        for fam in families:
            r = query_clickhouse(f"SELECT count() FROM network_ids.flows_{fam}", 1)
            out[f"flows_{fam}"] = r["rows"][0][0] if r["rows"] else 0
        r = query_clickhouse("SELECT count() FROM network_ids.pipeline_runs", 1)
        out["pipeline_runs"] = r["rows"][0][0] if r["rows"] else 0
        return out
    except Exception as exc:
        logger.warning("ClickHouse counts failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "ClickHouse unavailable")
