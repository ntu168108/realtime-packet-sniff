# SNIFF Web GUI — Tasks 2, 4-12 (Recovered)

> Recovery document for the 10 tasks that were structurally missing from the main plan. Each task here has the full implementation steps needed. Use this in combination with `docs/superpowers/plans/2026-06-26-sniff-web-gui.md` which has Tasks 1, 3, 13-26 with proper headers.
>
> All artifacts under `sniff-web/`. Module: `web_server` (run as `cd sniff-web && python -m web_server` or with sys.path pointing at `sniff-web/`). Conftest at `sniff-web/tests/integration_tests/conftest.py` bridges sys.path for pytest.

## Global Constraints (inherited from main plan)

- Python 3.8+ compatible
- License MIT, matches repo
- Conventional Commits
- TDD: failing test first
- YAGNI
- Append (not replace) to `sniff-web/web_server.py` — Task 1 added `load_web_config`, Task 3 added `read/write_last_capture`. Continue appending.

---

### Task 2: JWT auth dependency

**Files:**
- Modify: `sniff-web/web_server.py`
- Create: `sniff-web/tests/integration_tests/test_web_auth.py`

**Interfaces (add to web_server.py):**
- `configure_auth(username, password_hash, jwt_secret, jwt_expiry) -> None`
- `make_token(payload, secret=None, expiry_s=None) -> str`
- `decode_token(token, secret=None) -> dict`
- `require_user(authorization: str = Header(None)) -> dict` (FastAPI dependency)
- `login(username, password) -> dict`
- `change_password(username, new_password) -> dict`

**Module-level state:**
```python
_USERNAME = "admin"
_PASSWORD_HASH = ""
_JWT_SECRET = ""
_JWT_EXPIRY = 86400
```

**Implementation steps:**

1. Write failing test at `sniff-web/tests/integration_tests/test_web_auth.py`:

```python
"""Tests for JWT auth: token roundtrip, expiry, dependency injection."""
import time
import pytest
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient


@pytest.fixture
def app_with_auth(monkeypatch):
    import importlib, bcrypt
    import web_server
    importlib.reload(web_server)
    web_server._JWT_SECRET = "test_secret_for_unit_tests"
    web_server._JWT_EXPIRY = 60

    app = FastAPI()

    @app.get("/protected")
    def protected(user=Depends(web_server.require_user)):
        return {"user": user["username"]}

    @app.post("/api/auth/login")
    def login(body: dict):
        return web_server.login(body.get("username"), body.get("password"))

    @app.post("/api/auth/change-password")
    def change_pwd(body: dict, user=Depends(web_server.require_user)):
        return web_server.change_password(user["username"], body.get("new_password"))

    return app


@pytest.fixture
def client(app_with_auth):
    return TestClient(app_with_auth)


def test_login_with_correct_credentials_returns_token(app_with_auth, monkeypatch):
    import bcrypt, web_server
    web_server._PASSWORD_HASH = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    client = TestClient(app_with_auth)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "sniff"})
    assert r.status_code == 200
    body = r.json()
    assert "token" in body
    assert isinstance(body["token"], str)
    assert len(body["token"]) > 20


def test_login_with_wrong_password_returns_401(app_with_auth):
    import bcrypt, web_server
    web_server._PASSWORD_HASH = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    client = TestClient(app_with_auth)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "WRONG"})
    assert r.status_code == 401


def test_protected_endpoint_rejects_missing_token(app_with_auth):
    client = TestClient(app_with_auth)
    r = client.get("/protected")
    assert r.status_code == 401


def test_protected_endpoint_accepts_valid_token(app_with_auth):
    import bcrypt, web_server
    web_server._PASSWORD_HASH = bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode()
    client = TestClient(app_with_auth)
    token_resp = client.post("/api/auth/login", json={"username": "admin", "password": "sniff"})
    token = token_resp.json()["token"]
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["user"] == "admin"


def test_protected_endpoint_rejects_expired_token(app_with_auth):
    import jwt, web_server
    expired = jwt.encode({"sub": "admin", "exp": int(time.time()) - 10},
                         "test_secret_for_unit_tests", algorithm="HS256")
    client = TestClient(app_with_auth)
    r = client.get("/protected", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401


def test_make_token_decode_token_roundtrip():
    from web_server import make_token, decode_token
    tok = make_token({"sub": "alice"}, secret="s3cret", expiry_s=300)
    payload = decode_token(tok, secret="s3cret")
    assert payload["sub"] == "alice"
```

2. Run test to verify it fails:
```bash
cd /home/tu/realtime-packet-sniff && python -m pytest sniff-web/tests/integration_tests/test_web_auth.py -v
```
Expected: ImportError or AttributeError on `require_user`, `make_token`, etc.

3. Implement auth in `sniff-web/web_server.py` (append to file):

```python
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
```

4. Run tests to verify pass:
```bash
cd /home/tu/realtime-packet-sniff && python -m pytest sniff-web/tests/integration_tests/test_web_auth.py -v
```
Expected: 6 passed

5. Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/tests/integration_tests/test_web_auth.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): JWT auth with bcrypt + require_user dependency

configure_auth() called by lifespan. make_token() / decode_token()
use HS256. require_user FastAPI dependency extracts user from
Authorization: Bearer header. login() verifies bcrypt and returns
JWT. change_password() rehashes and updates in-memory.

Tested: login correct/wrong, protected endpoint with/without token,
expired token rejection, make/decode roundtrip.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: Capture control endpoints

**Files:**
- Modify: `sniff-web/web_server.py`
- Create: `sniff-web/tests/integration_tests/test_web_capture.py`

**Interfaces to add to web_server.py:**
- `StartBody` pydantic model: `interface, bpf_filter, snaplen, promisc, auto_restore`
- `app = FastAPI(...)`
- `@app.on_event("startup")` — configure_auth + auto-restore
- `@app.on_event("shutdown")` — engine.stop()
- `GET /api/interfaces`, `POST /api/capture/start|stop|toggle-pause`, `GET /api/capture/status|last-config|conversations`

**Import core.capture with try/except** so module loads even if scapy is missing:

```python
try:
    sys.path.insert(0, str(Path(__file__).parent))
    from core.capture import CaptureEngine, get_interfaces, validate_interface, get_interface_info
    from core.decoder import decode_packet
except ImportError as e:
    logger.warning("Could not import core.capture: %s", exc)
    CaptureEngine = None
```

Add to web_server.py (test override hook + endpoints):

```python
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
```

Test file at `sniff-web/tests/integration_tests/test_web_capture.py`:

```python
"""Tests for /api/capture/* endpoints with a mocked CaptureEngine."""
import pytest
from fastapi.testclient import TestClient


class MockEngine:
    def __init__(self):
        self.is_running = False
        self.is_paused = False
        self._setup_called = False
        self._start_called = False
        self._stop_called = False

    def setup(self): self._setup_called = True
    def start(self):
        self._start_called = True; self.is_running = True; self.is_paused = False
    def stop(self):
        self._stop_called = True; self.is_running = False
    def toggle_pause(self):
        self.is_paused = not self.is_paused; return self.is_paused
    def get_status(self):
        return {"interface": "lo", "running": self.is_running, "paused": self.is_paused,
                "uptime": 1.0, "packets": 0, "bytes": 0, "dropped": 0,
                "pps": 0, "bps": 0, "protocols": {}}
    def get_top_conversations(self, n=20):
        return []


@pytest.fixture
def client_with_mock_engine(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "test_secret", 60)

    engine = MockEngine()
    web_server._test_engine_factory = lambda **kwargs: engine

    return TestClient(web_server.app), engine


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_start_returns_ok_and_calls_setup_start(client_with_mock_engine):
    client, engine = client_with_mock_engine
    tok = _login(client)
    r = client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"},
                    json={"interface": "lo", "bpf_filter": "", "snaplen": 65535,
                          "promisc": True, "auto_restore": True})
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert engine._setup_called
    assert engine._start_called
    assert engine.is_running


def test_start_twice_returns_400(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    body = {"interface": "lo", "auto_restore": False}
    assert client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"}, json=body).status_code == 200
    assert client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"}, json=body).status_code == 400


def test_stop_when_not_running_returns_400(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    assert client.post("/api/capture/stop", headers={"Authorization": f"Bearer {tok}"}).status_code == 400


def test_stop_calls_engine_stop(client_with_mock_engine):
    client, engine = client_with_mock_engine
    tok = _login(client)
    client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"},
                json={"interface": "lo", "auto_restore": False})
    assert client.post("/api/capture/stop", headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert engine._stop_called


def test_toggle_pause_flags_paused(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    client.post("/api/capture/start", headers={"Authorization": f"Bearer {tok}"},
                json={"interface": "lo", "auto_restore": False})
    r = client.post("/api/capture/toggle-pause", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["paused"] is True


def test_status_always_returns_200_even_when_stopped(client_with_mock_engine):
    client, _ = client_with_mock_engine
    tok = _login(client)
    r = client.get("/api/capture/status", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    assert body["running"] is False
    assert "packets" in body


def test_endpoints_require_auth(client_with_mock_engine):
    client, _ = client_with_mock_engine
    assert client.post("/api/capture/start", json={"interface": "lo"}).status_code == 401
    assert client.get("/api/capture/status").status_code == 401
```

Run:
```bash
cd /home/tu/realtime-packet-sniff && python -m pytest sniff-web/tests/integration_tests/test_web_capture.py -v
```
Expected: 7 passed

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/tests/integration_tests/test_web_capture.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): capture lifecycle endpoints with auto-restore

POST /api/capture/start: validate interface, build CaptureEngine via
_make_engine (test-overridable), setup+start, persist to
last_capture.json. POST /api/capture/stop: check is_running, call
engine.stop. POST /api/capture/toggle-pause: returns paused bool.
GET /api/capture/status: always 200 with zero-state when stopped.
GET /api/capture/last-config: 404 if no persisted config.
GET /api/capture/conversations: empty list when stopped.

Lifespan startup: configure_auth() + read_last_capture() → if
auto_restore and interface exists, build+start engine on boot.
Lifespan shutdown: engine.stop() if running.

GET /api/interfaces: list NICs via core.capture.get_interfaces.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: Systemd service control endpoints

**Files:**
- Modify: `sniff-web/web_server.py`
- Create: `sniff-web/tests/integration_tests/test_web_services.py`

**Interfaces:**
- `SERVICE_ALLOWLIST = {kafka, sniff-producer, ec-consumer, clickhouse-server, grafana-server, sniff-web}`
- `SERVICE_ACTIONS = {start, stop, restart, enable, disable}`
- `run_systemctl(name, action) -> dict` (mockable)
- `list_services_status() -> list`
- `GET /api/services/list`, `POST /api/services/{name}/{action}`

**Implementation (append to web_server.py):**

```python
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
```

Test at `sniff-web/tests/integration_tests/test_web_services.py`:

```python
"""Tests for /api/services/* with mocked systemctl subprocess."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client_with_mock(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)

    calls = []
    def fake_systemctl(name, action):
        calls.append((name, action))
        return {"ok": True, "stdout": "", "stderr": "", "exit_code": 0}
    monkeypatch.setattr(web_server, "run_systemctl", fake_systemctl)
    return TestClient(web_server.app), calls, web_server


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_list_services_returns_known_set(client_with_mock):
    client, _, _ = client_with_mock
    tok = _login(client)
    r = client.get("/api/services/list", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    names = [s["name"] for s in r.json()]
    for expected in ["kafka", "sniff-producer", "ec-consumer", "clickhouse-server", "grafana-server", "sniff-web"]:
        assert expected in names


def test_restart_allowed_service(client_with_mock):
    client, calls, _ = client_with_mock
    tok = _login(client)
    r = client.post("/api/services/kafka/restart", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert ("kafka", "restart") in calls


def test_unknown_service_returns_400(client_with_mock):
    client, _, _ = client_with_mock
    tok = _login(client)
    r = client.post("/api/services/evil-svc/restart", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400


def test_invalid_action_returns_400(client_with_mock):
    client, _, _ = client_with_mock
    tok = _login(client)
    r = client.post("/api/services/kafka/destroy", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400


def test_sudo_failure_returns_500(client_with_mock, monkeypatch):
    client, _, web_server = client_with_mock
    monkeypatch.setattr(web_server, "run_systemctl",
                        lambda n, a: {"ok": False, "stdout": "", "stderr": "sudo: permission denied", "exit_code": 1})
    tok = _login(client)
    r = client.post("/api/services/kafka/restart", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 500
    assert "permission denied" in r.json()["detail"]


def test_service_endpoints_require_auth(client_with_mock):
    client, _, _ = client_with_mock
    r = client.get("/api/services/list")
    assert r.status_code == 401
```

Run, expect 6 passed.

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/tests/integration_tests/test_web_services.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): systemd service control with allowlist

run_systemctl(name, action) shells out to 'sudo -n systemctl <action>
<name>'. Returns ok/stderr/exit_code dict. list_services_status()
queries is-active for each allowlisted service.

GET /api/services/list returns allowlisted services with active bool.
POST /api/services/{name}/{action} validates name+action in allowlists
before calling run_systemctl. 400 on disallowed name/action. 500 on
sudo failure (with stderr message).

Allowlists: SERVICE_ALLOWLIST = {kafka, sniff-producer, ec-consumer,
clickhouse-server, grafana-server, sniff-web}; SERVICE_ACTIONS =
{start, stop, restart, enable, disable}.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: ClickHouse query endpoint with allowlist

**Files:**
- Modify: `sniff-web/web_server.py` (add psutil import too)
- Modify: `sniff-web/requirements-web.txt` (add `psutil>=5.9.0` — but Task 8 already adds it, so skip if Task 8 done first; otherwise add here)
- Create: `sniff-web/tests/integration_tests/test_web_clickhouse.py`

**Interfaces:**
- `CH_ALLOWLIST_PREFIXES = ("SELECT ", "SHOW ", "DESCRIBE ", "DESC ", "EXISTS ", "SELECT 1")`
- `CH_MAX_ROWS_HARD_LIMIT = 10000`
- `query_clickhouse(sql, max_rows=1000) -> dict`
- `POST /api/clickhouse/query`, `GET /api/clickhouse/counts`

**Implementation (append):**

```python
CH_ALLOWLIST_PREFIXES = ("SELECT ", "SHOW ", "DESCRIBE ", "DESC ", "EXISTS ", "SELECT 1")
CH_MAX_ROWS_HARD_LIMIT = 10000


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
```

Test at `sniff-web/tests/integration_tests/test_web_clickhouse.py`:

```python
"""Tests for /api/clickhouse/* with allowlist enforcement."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)

    captured = {}
    def fake_query(sql, max_rows=1000):
        captured["last_sql"] = sql
        return {"columns": ["n"], "rows": [[42]], "elapsed_ms": 1.5}
    monkeypatch.setattr(web_server, "query_clickhouse", fake_query)
    return TestClient(web_server.app), captured


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_select_passes_through(client):
    c, captured = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
               json={"sql": "SELECT count() FROM network_ids.flows_all"})
    assert r.status_code == 200
    assert r.json()["rows"] == [[42]]
    assert "SELECT" in captured["last_sql"]


def test_show_passes_through(client):
    c, _ = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
               json={"sql": "SHOW TABLES FROM network_ids"})
    assert r.status_code == 200


def test_insert_blocked(client):
    c, _ = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
               json={"sql": "INSERT INTO flows_all VALUES (1,2,3)"})
    assert r.status_code == 400


def test_drop_blocked(client):
    c, _ = client
    tok = _login(c)
    assert c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
                  json={"sql": "DROP TABLE flows_all"}).status_code == 400


def test_truncate_blocked(client):
    c, _ = client
    tok = _login(c)
    assert c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
                  json={"sql": "TRUNCATE TABLE flows_all"}).status_code == 400


def test_alter_blocked(client):
    c, _ = client
    tok = _login(c)
    assert c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
                  json={"sql": "ALTER TABLE flows_all DELETE WHERE 1=1"}).status_code == 400


def test_max_rows_enforced(client, monkeypatch):
    c, _ = client
    captured = {}
    def cap(sql, max_rows=1000):
        captured["max_rows"] = max_rows
        return {"columns": [], "rows": [], "elapsed_ms": 0.1}
    import web_server
    monkeypatch.setattr(web_server, "query_clickhouse", cap)
    tok = _login(c)
    c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"},
           json={"sql": "SELECT 1", "max_rows": 5000})
    assert captured["max_rows"] == 1000


def test_empty_sql_rejected(client):
    c, _ = client
    tok = _login(c)
    r = c.post("/api/clickhouse/query", headers={"Authorization": f"Bearer {tok}"}, json={"sql": ""})
    assert r.status_code == 400


def test_endpoint_requires_auth(client):
    c, _ = client
    assert c.post("/api/clickhouse/query", json={"sql": "SELECT 1"}).status_code == 401
```

Run, expect 9 passed.

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/tests/integration_tests/test_web_clickhouse.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): ClickHouse query endpoint with allowlist

query_clickhouse(sql, max_rows) uses clickhouse_driver.Client with
database=network_ids. Returns columns + rows + elapsed_ms.

POST /api/clickhouse/query: enforces server-side prefix allowlist
(SELECT/SHOW/DESCRIBE/EXISTS/SELECT 1); INSERT/DROP/ALTER/TRUNCATE
blocked with 400. max_rows capped at 10000 hard limit. Empty SQL
rejected with 400. ClickHouse errors return 503.

GET /api/clickhouse/counts: pre-baked counts for flows_all + 7
flows_<family> + pipeline_runs in single response.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 7: Kafka admin endpoint

**Files:**
- Modify: `sniff-web/web_server.py`
- Create: `sniff-web/tests/integration_tests/test_web_kafka.py`

**Interfaces:**
- `KAFKA_BOOTSTRAP = "localhost:9092"`
- `list_kafka_topics() -> dict`, `kafka_lag(group) -> dict`
- `GET /api/kafka/topics`, `GET /api/kafka/lag?group=...`

**Implementation (append):**

```python
KAFKA_BOOTSTRAP = "localhost:9092"


def list_kafka_topics() -> dict:
    from kafka.admin import KafkaAdminClient
    admin = KafkaAdminClient(bootstrap_servers=KAFKA_BOOTSTRAP, request_timeout_ms=5000)
    try:
        topics_meta = admin.describe_topics()
    finally:
        admin.close()
    out = []
    for t in topics_meta:
        if t["topic"].startswith("__"):
            continue
        partitions = t.get("partitions", [])
        replication = len(partitions[0].get("replicas", [])) if partitions else 0
        out.append({"name": t["topic"], "partitions": len(partitions), "replication": replication})
    return {"topics": sorted(out, key=lambda x: x["name"])}


def kafka_lag(group: str) -> dict:
    from kafka import KafkaConsumer, TopicPartition
    consumer = KafkaConsumer(bootstrap_servers=KAFKA_BOOTSTRAP, group_id=group,
                             enable_auto_commit=False, consumer_timeout_ms=2000)
    try:
        partitions = consumer.partitions_for_topic("raw_pcap_segments") or set()
        tps = [TopicPartition("raw_pcap_segments", p) for p in partitions]
        if not tps:
            return {"group": group, "total_lag": 0, "partitions": []}
        consumer.assign(tps)
        end_offsets = consumer.end_offsets(tps)
        total = 0
        per_partition = []
        for tp in tps:
            try:
                committed = consumer.committed(tp) or 0
            except Exception:
                committed = 0
            lag = max(0, end_offsets[tp] - committed)
            total += lag
            per_partition.append({"topic": tp.topic, "partition": tp.partition, "lag": lag})
        return {"group": group, "total_lag": total, "partitions": per_partition}
    finally:
        consumer.close()


@app.get("/api/kafka/topics")
def api_kafka_topics(user=Depends(require_user)):
    try:
        return list_kafka_topics()
    except Exception as exc:
        logger.warning("Kafka topics failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Kafka unavailable")


@app.get("/api/kafka/lag")
def api_kafka_lag(group: str = "ec-consumer", user=Depends(require_user)):
    try:
        return kafka_lag(group)
    except Exception as exc:
        logger.warning("Kafka lag failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Kafka unavailable")
```

Test at `sniff-web/tests/integration_tests/test_web_kafka.py`:

```python
"""Tests for /api/kafka/* with mocked kafka client."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)

    monkeypatch.setattr(web_server, "list_kafka_topics",
                        lambda: {"topics": [
                            {"name": "raw_pcap_segments", "partitions": 1, "replication": 1},
                            {"name": "__consumer_offsets", "partitions": 50, "replication": 1},
                        ]})
    monkeypatch.setattr(web_server, "kafka_lag",
                        lambda group: {"group": group, "total_lag": 5,
                                       "partitions": [{"topic": "raw_pcap_segments", "partition": 0, "lag": 5}]})
    return TestClient(web_server.app)


def _login(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_topics_returns_list(client):
    tok = _login(client)
    r = client.get("/api/kafka/topics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    names = [t["name"] for t in r.json()["topics"]]
    assert "raw_pcap_segments" in names


def test_lag_default_group_is_ec_consumer(client):
    tok = _login(client)
    r = client.get("/api/kafka/lag", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["group"] == "ec-consumer"


def test_lag_custom_group(client):
    tok = _login(client)
    r = client.get("/api/kafka/lag?group=foo", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["group"] == "foo"


def test_kafka_down_returns_503(client, monkeypatch):
    import web_server
    def fail(): raise ConnectionError("kafka unreachable")
    monkeypatch.setattr(web_server, "list_kafka_topics", fail)
    tok = _login(client)
    r = client.get("/api/kafka/topics", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 503


def test_requires_auth(client):
    assert client.get("/api/kafka/topics").status_code == 401
```

Run, expect 5 passed.

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/tests/integration_tests/test_web_kafka.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): Kafka topics + consumer-group lag endpoints

list_kafka_topics() uses kafka.admin.KafkaAdminClient.describe_topics();
skips internal topics (__*); returns sorted list with name, partitions,
replication.

kafka_lag(group) uses KafkaConsumer to compute end_offsets - committed
per partition; aggregates total_lag. Default group=ec-consumer.

GET /api/kafka/topics → 200 with topics list, 503 if Kafka down.
GET /api/kafka/lag?group=X → 200 with per-partition lag, 503 if Kafka
down. Both require auth.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 8: PCAP files manager + Config + System info endpoints

**Files:**
- Modify: `sniff-web/web_server.py`
- Modify: `sniff-web/requirements-web.txt` (add `psutil>=5.9.0`)
- Create: `sniff-web/tests/integration_tests/test_web_misc.py`

**Interfaces:**
- `_CONFIG_PATH = "config.yaml"` (module-level, mutable for tests)
- `CONFIG_WRITABLE = {display.*, live.*, modules.*, performance.*}` (dot-paths)
- `_SANITIZE_HIDE = {"web.password_hash", "web.jwt_secret"}`
- `_read_full_config()`, `_sanitize_config(cfg)`
- `GET /api/pcap/files`, `GET /api/pcap/download/{name}`
- `GET /api/config`, `PUT /api/config`
- `GET /api/system/info`

**Implementation (append):**

```python
_CONFIG_PATH = "config.yaml"
CONFIG_WRITABLE = {
    "display.display_filter", "display.exclude_ports", "display.cache_size",
    "live.enabled",
    "modules.enabled", "modules.auto_discover",
    "performance.ring_buffer_size", "performance.batch_size",
    "performance.enable_deep_decode", "performance.gc_interval",
}
_SANITIZE_HIDE = {"web.password_hash", "web.jwt_secret"}


def _read_full_config() -> dict:
    p = Path(_CONFIG_PATH)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _sanitize_config(cfg: dict) -> dict:
    out = yaml.safe_load(yaml.safe_dump(cfg))
    for dotted in _SANITIZE_HIDE:
        section, key = dotted.split(".", 1)
        if section in out and isinstance(out[section], dict):
            out[section][key] = ""
    return out


@app.get("/api/pcap/files")
def api_pcap_files(user=Depends(require_user)):
    cfg = load_web_config(_CONFIG_PATH)
    base = cfg.get("capture", {}).get("output", {}).get("base_dir", "./sniff_data")
    base_path = Path(base)
    if not base_path.exists():
        return []
    out = []
    for p in sorted(base_path.glob("*.pcap*"), key=lambda x: x.stat().st_mtime, reverse=True)[:500]:
        st = p.stat()
        out.append({"name": p.name, "size": st.st_size, "mtime": int(st.st_mtime)})
    return out


@app.get("/api/pcap/download/{name}")
def api_pcap_download(name: str, user=Depends(require_user)):
    if ".." in name or "/" in name or "\\" in name:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid filename")
    cfg = load_web_config(_CONFIG_PATH)
    base = cfg.get("capture", {}).get("output", {}).get("base_dir", "./sniff_data")
    target = Path(base) / name
    if not target.exists() or not target.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "File not found")
    return FileResponse(str(target), filename=name, media_type="application/octet-stream")


@app.get("/api/config")
def api_config_get(user=Depends(require_user)):
    try:
        return _sanitize_config(_read_full_config())
    except Exception as exc:
        logger.warning("Read config failed: %s", exc)
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Config unreadable")


@app.put("/api/config")
def api_config_put(body: dict, user=Depends(require_user)):
    full = _read_full_config()
    for top, sub in body.items():
        if not isinstance(sub, dict):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"'{top}' must be object")
        for k in sub.keys():
            dotted = f"{top}.{k}"
            if dotted not in CONFIG_WRITABLE:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Key '{dotted}' not writable via web")
    full.update(body)
    p = Path(_CONFIG_PATH)
    with p.open("w", encoding="utf-8") as f:
        yaml.safe_dump(full, f, default_flow_style=False)
    return {"ok": True}


@app.get("/api/system/info")
def api_system_info(user=Depends(require_user)):
    import psutil, socket as _s
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    try:
        nics = len(psutil.net_if_addrs())
        hostname = _s.gethostname()
    except Exception:
        nics = 0; hostname = "unknown"
    with open("/proc/uptime", "r") as f:
        uptime_s = float(f.read().split()[0])
    return {
        "hostname": hostname, "uptime_seconds": int(uptime_s),
        "loadavg": list(psutil.getloadavg()), "cpu_count": psutil.cpu_count(logical=True) or 1,
        "mem_total_mb": mem.total // (1024 * 1024), "mem_available_mb": mem.available // (1024 * 1024),
        "disk_total_gb": disk.total // (1024 ** 3), "disk_used_gb": disk.used // (1024 ** 3),
        "nic_count": nics,
    }
```

Also add `psutil>=5.9.0` to `sniff-web/requirements-web.txt`.

Test at `sniff-web/tests/integration_tests/test_web_misc.py`:

```python
"""Tests for PCAP manager + config + system info endpoints."""
import os
import pytest
import yaml
from fastapi.testclient import TestClient


@pytest.fixture
def setup_env(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    pcap_dir = tmp_path / "sniff_data"
    pcap_dir.mkdir()
    (pcap_dir / "capture_20260626_120000.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
    (pcap_dir / "capture_20260626_130000.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 200)

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump({
        "capture": {"output": {"base_dir": str(pcap_dir)}},
        "web": {"bind": "0.0.0.0", "port": 8000, "username": "admin",
                "password_hash": "x", "jwt_secret": "y"},
    }))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)
    monkeypatch.setattr(web_server, "load_web_config", lambda p: yaml.safe_load(open(config_path).read())["web"])
    monkeypatch.setattr(web_server, "_CONFIG_PATH", str(config_path))
    return TestClient(web_server.app)


def _login(c):
    return c.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_pcap_files_list(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.get("/api/pcap/files", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    files = r.json()
    assert len(files) == 2
    names = sorted([f["name"] for f in files])
    assert names == ["capture_20260626_120000.pcap", "capture_20260626_130000.pcap"]


def test_config_get_returns_sanitized(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.get("/api/config", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    for k in ("web.password_hash", "web.jwt_secret"):
        if "." in k:
            section, key = k.split(".", 1)
            assert body.get(section, {}).get(key, "") == ""


def test_config_put_updates_allowlisted_keys(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.put("/api/config", headers={"Authorization": f"Bearer {tok}"},
                   json={"display": {"display_filter": "tcp"}})
    assert r.status_code == 200


def test_config_put_rejects_disallowed_keys(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.put("/api/config", headers={"Authorization": f"Bearer {tok}"},
                   json={"web": {"password_hash": "hacked"}})
    assert r.status_code == 400


def test_system_info_returns_required_keys(setup_env):
    client = setup_env
    tok = _login(client)
    r = client.get("/api/system/info", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    body = r.json()
    for k in ("hostname", "uptime_seconds", "loadavg", "cpu_count",
             "mem_total_mb", "mem_available_mb", "disk_total_gb", "disk_used_gb", "nic_count"):
        assert k in body


def test_all_misc_endpoints_require_auth(setup_env):
    client = setup_env
    for path in ["/api/pcap/files", "/api/config", "/api/system/info"]:
        assert client.get(path).status_code == 401
```

Run, expect 6 passed.

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/requirements-web.txt sniff-web/tests/integration_tests/test_web_misc.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): PCAP manager + config + system info endpoints

GET /api/pcap/files: lists up to 500 pcap files from
config.output.base_dir sorted by mtime desc, with size/mtime.
GET /api/pcap/download/{name}: path-traversal guard, FileResponse.
GET /api/config: full config with password_hash + jwt_secret hidden.
PUT /api/config: writes only allowlisted keys (display.*, live.*,
modules.*, performance.*). web.password_hash / web.jwt_secret /
capture.* rejected with 400.
GET /api/system/info: psutil-based hostname, uptime, loadavg, cpu,
memory, disk, nic_count.

psutil>=5.9.0 added to requirements-web.txt.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 9: WebSocket packet + stats broadcast

**Files:**
- Modify: `sniff-web/web_server.py`
- Create: `sniff-web/tests/integration_tests/test_web_websocket.py`

**Interfaces:**
- `packet_clients`, `stats_clients`, `services_clients = set()` (module-level)
- `_verify_ws_token(websocket, token) -> bool`
- `@app.websocket("/ws/packets"|"/ws/stats"|"/ws/services")`

**Implementation (append):**

```python
from fastapi import WebSocket, WebSocketDisconnect, Query

packet_clients: set = set()
stats_clients: set = set()
services_clients: set = set()


async def _verify_ws_token(websocket: WebSocket, token: str = Query("")) -> bool:
    if not token:
        await websocket.close(code=1008, reason="Missing token")
        return False
    try:
        decode_token(token)
    except Exception:
        await websocket.close(code=1008, reason="Invalid token")
        return False
    return True


@app.websocket("/ws/packets")
async def ws_packets(websocket: WebSocket, token: str = Query("")):
    if not await _verify_ws_token(websocket, token):
        return
    await websocket.accept()
    packet_clients.add(websocket)
    try:
        while True:
            await asyncio.sleep(50)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=0.01)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        packet_clients.discard(websocket)


@app.websocket("/ws/stats")
async def ws_stats(websocket: WebSocket, token: str = Query("")):
    if not await _verify_ws_token(websocket, token):
        return
    await websocket.accept()
    stats_clients.add(websocket)
    try:
        while True:
            eng = getattr(app.state, "engine", None)
            try:
                status = eng.get_status() if (eng and getattr(eng, "is_running", False)) else {
                    "running": False, "paused": False, "interface": None,
                    "packets": 0, "bytes": 0, "dropped": 0, "pps": 0, "bps": 0,
                    "protocols": {}, "uptime": 0,
                }
            except Exception:
                status = {"running": False, "paused": False, "interface": None,
                          "packets": 0, "bytes": 0, "dropped": 0, "pps": 0, "bps": 0,
                          "protocols": {}, "uptime": 0}
            await websocket.send_json({"type": "stats", "data": status})
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        stats_clients.discard(websocket)


@app.websocket("/ws/services")
async def ws_services(websocket: WebSocket, token: str = Query("")):
    if not await _verify_ws_token(websocket, token):
        return
    await websocket.accept()
    services_clients.add(websocket)
    try:
        while True:
            try:
                data = list_services_status()
            except Exception:
                data = []
            await websocket.send_json({"type": "services", "data": data})
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        services_clients.discard(websocket)
```

Test at `sniff-web/tests/integration_tests/test_web_websocket.py`:

```python
"""Tests for WebSocket packet + stats broadcasts."""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)
    return TestClient(web_server.app)


def _login_token(client):
    return client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).json()["token"]


def test_stats_ws_accepts_valid_token_and_sends_frame(client):
    tok = _login_token(client)
    with client.websocket_connect(f"/ws/stats?token={tok}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "stats"
        assert "data" in msg


def test_packets_ws_accepts_token(client):
    tok = _login_token(client)
    with client.websocket_connect(f"/ws/packets?token={tok}") as ws:
        ws.send_text("ping")


def test_services_ws_returns_service_list(client):
    tok = _login_token(client)
    with client.websocket_connect(f"/ws/services?token={tok}") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "services"
        names = [s["name"] for s in msg["data"]]
        assert "kafka" in names
```

Run, expect 3 passed.

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web_server.py sniff-web/tests/integration_tests/test_web_websocket.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): WebSocket endpoints for packets, stats, services

WS /ws/packets: accepts JWT via ?token=; registered client set.
WS /ws/stats: 1Hz tick; sends engine.get_status() or zero-state.
WS /ws/services: 1Hz tick; sends list_services_status() result.
All WS handlers close with code 1008 on missing/invalid token before
accept. Dead clients removed via WebSocketDisconnect handler.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 10: Security regression test

**Files:**
- Create: `sniff-web/tests/integration_tests/test_web_security.py`

**Implementation:** Full file at `sniff-web/tests/integration_tests/test_web_security.py`:

```python
"""Verify every endpoint (except /api/auth/login) requires authentication."""
import time
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr("web_server.PERSISTENCE_DIR_OVERRIDE", str(tmp_path))

    import bcrypt, importlib, web_server
    importlib.reload(web_server)
    web_server.configure_auth("admin", bcrypt.hashpw(b"sniff", bcrypt.gensalt()).decode(), "s", 60)
    return TestClient(web_server.app)


def test_login_endpoint_is_public(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "WRONG"}).status_code == 401


def test_login_endpoint_returns_200_with_correct_creds(client):
    assert client.post("/api/auth/login", json={"username": "admin", "password": "sniff"}).status_code == 200


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/interfaces"),
    ("POST", "/api/capture/start"),
    ("POST", "/api/capture/stop"),
    ("POST", "/api/capture/toggle-pause"),
    ("GET", "/api/capture/status"),
    ("GET", "/api/capture/last-config"),
    ("GET", "/api/capture/conversations"),
    ("GET", "/api/services/list"),
    ("POST", "/api/services/kafka/restart"),
    ("GET", "/api/kafka/topics"),
    ("GET", "/api/kafka/lag"),
    ("POST", "/api/clickhouse/query"),
    ("GET", "/api/clickhouse/counts"),
    ("GET", "/api/pcap/files"),
    ("GET", "/api/pcap/download/foo.pcap"),
    ("GET", "/api/config"),
    ("PUT", "/api/config"),
    ("GET", "/api/system/info"),
])
def test_endpoint_requires_auth(client, method, path):
    if method == "POST":
        r = client.post(path, json={})
    elif method == "PUT":
        r = client.put(path, json={})
    else:
        r = client.get(path)
    assert r.status_code == 401, f"{method} {path} returned {r.status_code}"


def test_expired_token_rejected(client):
    import jwt
    expired = jwt.encode({"sub": "admin", "exp": int(time.time()) - 60}, "s", algorithm="HS256")
    assert client.get("/api/capture/status", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
```

Run, expect 18+2 = 20 passed.

Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/tests/integration_tests/test_web_security.py
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "test(web): security regression — every endpoint requires auth

Parametrized test covers all REST endpoints return 401 without JWT.
Expired token rejected. Login endpoint is public (wrong creds → 401,
correct creds → 200).

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 11: Vite + React + TS scaffold

**Files:**
- Create: `sniff-web/web/package.json`
- Create: `sniff-web/web/vite.config.ts`
- Create: `sniff-web/web/tsconfig.json`
- Create: `sniff-web/web/tsconfig.node.json`
- Create: `sniff-web/web/index.html`
- Create: `sniff-web/web/.gitignore`

**Note:** Path is `sniff-web/web/` (frontend project lives inside sniff-web/, sibling to web_server.py).

`sniff-web/web/package.json`:
```json
{
  "name": "sniff-web",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "test:watch": "vitest",
    "e2e": "playwright test"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.26.2",
    "@tanstack/react-virtual": "^3.10.8"
  },
  "devDependencies": {
    "@types/react": "^18.3.10",
    "@types/react-dom": "^18.3.0",
    "@vitejs/plugin-react": "^4.3.1",
    "typescript": "^5.6.2",
    "vite": "^5.4.8",
    "vitest": "^2.1.2",
    "@testing-library/react": "^16.0.1",
    "@testing-library/jest-dom": "^6.5.0",
    "jsdom": "^25.0.1",
    "@playwright/test": "^1.47.2"
  }
}
```

`sniff-web/web/tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": false,
    "noUnusedLocals": false,
    "noUnusedParameters": false,
    "noFallthroughCasesInSwitch": true,
    "types": ["vitest/globals", "@testing-library/jest-dom"]
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

`sniff-web/web/tsconfig.node.json`:
```json
{
  "compilerOptions": {
    "composite": true,
    "skipLibCheck": true,
    "module": "ESNext",
    "moduleResolution": "bundler",
    "allowSyntheticDefaultImports": true,
    "strict": false
  },
  "include": ["vite.config.ts"]
}
```

`sniff-web/web/vite.config.ts`:
```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
  test: { globals: true, environment: 'jsdom' },
});
```

`sniff-web/web/index.html`:
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SNIFF Web GUI</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`sniff-web/web/.gitignore`:
```
node_modules/
dist/
*.tsbuildinfo
playwright-report/
test-results/
```

Steps:
1. Create all 6 files above.
2. Run `cd sniff-web/web && npm install` (creates node_modules/ and package-lock.json).
3. Run `cd sniff-web/web && npx tsc --noEmit 2>&1` — expect errors (no src/ yet, will resolve after Task 13). That's OK for now; commit anyway.
4. Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web/package.json sniff-web/web/tsconfig.json sniff-web/web/tsconfig.node.json sniff-web/web/vite.config.ts sniff-web/web/index.html sniff-web/web/.gitignore sniff-web/web/package-lock.json
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): Vite + React + TS scaffold

React 18 + TypeScript + Vite 5 with @tanstack/react-virtual.
Dev server proxies /api and /ws to backend on :8000. Vitest + jsdom
configured. @playwright/test added for E2E.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 12: Design tokens + global CSS + types

**Files:**
- Create: `sniff-web/web/src/styles/global.css`
- Create: `sniff-web/web/src/types.ts`
- Create: `sniff-web/web/src/main.tsx`
- Create: `sniff-web/web/src/App.tsx`

`sniff-web/web/src/styles/global.css`:
```css
:root {
  --bg: #0d1520; --surface: #14223a; --surf2: #1c3050;
  --border: #2a4866; --accent: #28e4ff;
  --accent-bg: rgba(40,228,255,.08); --text: #c8ddf2;
  --muted: #6a90b8; --success: #3dd68c; --warn: #f5a623;
  --danger: #e85370;
  --mono: 'Consolas','SF Mono','Cascadia Code',monospace;
  --ui: 'Segoe UI','SF Pro Text',system-ui,sans-serif;
}
* { box-sizing: border-box; }
html, body, #root { height: 100%; overflow: hidden; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--ui); font-size: 14px; line-height: 1.4; }
.mono { font-family: var(--mono); font-variant-numeric: tabular-nums; }
.app-layout { display: grid; grid-template-columns: 200px 1fr; grid-template-rows: 56px 1fr;
  grid-template-areas: "topbar topbar" "sidebar main"; height: 100vh; }
.topbar { grid-area: topbar; background: var(--surface); border-bottom: 1px solid var(--border);
  display: flex; align-items: center; padding: 0 16px; gap: 16px; }
.topbar .logo { font-weight: 700; font-size: 16px; color: var(--accent); }
.topbar .grow { flex: 1; } .topbar .user { color: var(--muted); }
.topbar button { background: transparent; border: 1px solid var(--border); color: var(--text);
  padding: 6px 12px; border-radius: 4px; cursor: pointer; }
.topbar button:hover { background: var(--accent-bg); }
.sidebar { grid-area: sidebar; background: var(--surface); border-right: 1px solid var(--border);
  padding: 12px 0; overflow-y: auto; }
.sidebar a { display: block; padding: 10px 16px; color: var(--muted); text-decoration: none;
  border-left: 3px solid transparent; }
.sidebar a:hover { background: var(--accent-bg); color: var(--text); }
.sidebar a.active { background: var(--accent-bg); color: var(--accent); border-left-color: var(--accent); }
.main { grid-area: main; overflow-y: auto; padding: 16px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
  padding: 16px; margin-bottom: 12px; }
.card h2 { margin: 0 0 12px 0; font-size: 14px; font-weight: 600; color: var(--accent);
  text-transform: uppercase; letter-spacing: 0.05em; }
.btn { background: var(--accent); color: var(--bg); border: none; padding: 8px 16px;
  border-radius: 4px; cursor: pointer; font-weight: 600; }
.btn:hover { filter: brightness(1.1); } .btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn.danger { background: var(--danger); color: white; }
.btn.warn { background: var(--warn); color: var(--bg); }
.btn.ghost { background: transparent; border: 1px solid var(--border); color: var(--text); }
input, select { background: var(--surf2); border: 1px solid var(--border); color: var(--text);
  padding: 6px 10px; border-radius: 4px; font-family: var(--mono); font-size: 13px; }
input:focus, select:focus { outline: 1px solid var(--accent); }
.pill { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px;
  font-weight: 600; text-transform: uppercase; }
.pill.active { background: var(--success); color: var(--bg); }
.pill.paused { background: var(--warn); color: var(--bg); }
.pill.stopped, .pill.inactive, .pill.failed { background: var(--muted); color: var(--bg); }
.proto-stripe { display: inline-block; width: 4px; height: 100%; vertical-align: middle; margin-right: 8px; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border); font-size: 13px; }
th { color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }
td.mono { font-family: var(--mono); }
.error { color: var(--danger); padding: 12px; background: var(--surface); border-radius: 4px; }
.muted { color: var(--muted); }
.login-page { display: flex; align-items: center; justify-content: center; height: 100vh; background: var(--bg); }
.login-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
  padding: 32px; width: 360px; }
.login-card h1 { margin: 0 0 24px 0; color: var(--accent); text-align: center; }
.login-card label { display: block; margin-bottom: 4px; color: var(--muted); font-size: 12px;
  text-transform: uppercase; }
.login-card input { width: 100%; margin-bottom: 16px; }
.login-card .error { margin-bottom: 16px; }
```

`sniff-web/web/src/types.ts`:
```typescript
export interface PacketRow {
  stt: number; ts: number;
  src: string; dst: string;
  src_port: number; dst_port: number;
  proto: string; len: number; info: string;
}
export interface CaptureStatus {
  running: boolean; paused: boolean;
  interface: string | null; uptime: number;
  packets: number; bytes: number; dropped: number;
  pps: number; bps: number;
  protocols: Record<string, number>;
  ws_drop_total?: number;
}
export interface InterfaceInfo { name: string; exists: boolean; ipv4: string; mac: string; up: boolean; }
export interface Conversation { proto: string; src: string; dst: string; sport: number; dport: number; packets: number; bytes: number; duration: number; }
export interface ServiceStatus { name: string; active: boolean; }
export interface KafkaTopic { name: string; partitions: number; replication: number; }
export interface KafkaLag { group: string; total_lag: number; partitions: { topic: string; partition: number; lag: number }[]; }
export interface Counts {
  flows_all?: number; flows_dos?: number; flows_exploits?: number;
  flows_fuzzers?: number; flows_generic?: number; flows_analysis?: number;
  flows_reconnaissance?: number; flows_shellcode?: number; pipeline_runs?: number;
}
export interface PcapFile { name: string; size: number; mtime: number; }
export interface SystemInfo {
  hostname: string; uptime_seconds: number; loadavg: number[];
  cpu_count: number; mem_total_mb: number; mem_available_mb: number;
  disk_total_gb: number; disk_used_gb: number; nic_count: number;
}
export interface LastConfig {
  interface: string; bpf_filter: string; snaplen: number;
  promisc: boolean; auto_restore: boolean; saved_at: string;
}
export interface WSMessage<T> { type: string; data: T; }
```

`sniff-web/web/src/main.tsx`:
```typescript
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/global.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

`sniff-web/web/src/App.tsx`:
```typescript
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useCallback } from 'react';

export default function App() {
  const [token, setTok] = useState<string | null>(() => localStorage.getItem('sniff_jwt'));

  const logout = useCallback(() => {
    localStorage.removeItem('sniff_jwt');
    setTok(null);
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login onLogin={(t) => { localStorage.setItem('sniff_jwt', t); setTok(t); }} />} />
        <Route path="/*" element={token ? <Layout onLogout={logout} /> : <Navigate to="/login" />} />
      </Routes>
    </BrowserRouter>
  );
}

function Login({ onLogin }: { onLogin: (t: string) => void }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const r = await fetch('/api/auth/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        setError(body.detail || `Login failed: ${r.status}`);
        return;
      }
      const body = await r.json();
      localStorage.setItem('sniff_jwt', body.token);
      onLogin(body.token);
    } catch (e: any) {
      setError(`Network error: ${e.message}`);
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <h1>SNIFF Web GUI</h1>
        {error && <div className="error">{error}</div>}
        <label>Username</label>
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <label>Password</label>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        <button type="submit" className="btn" style={{ width: '100%' }}>Sign in</button>
      </form>
    </div>
  );
}

function Layout({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="app-layout">
      <header className="topbar">
        <span className="logo">SNIFF</span>
        <span className="grow" />
        <span className="user">admin</span>
        <button onClick={onLogout}>Logout</button>
      </header>
      <nav className="sidebar">
        <a href="/dashboard">Dashboard</a>
      </nav>
      <main className="main">
        <div className="card">
          <h2>Layout scaffold OK</h2>
          <p>Real pages will be added in subsequent tasks.</p>
        </div>
      </main>
    </div>
  );
}
```

Steps:
1. Create all 4 files.
2. Run `cd sniff-web/web && npx tsc --noEmit 2>&1` — expect no errors.
3. Commit:
```bash
cd /home/tu/realtime-packet-sniff
git add sniff-web/web/src/styles/global.css sniff-web/web/src/types.ts sniff-web/web/src/main.tsx sniff-web/web/src/App.tsx
git -c user.email=claude@anthropic.com -c user.name=Claude commit -m "feat(web): design tokens, types, layout scaffold

global.css implements design tokens (--bg, --accent, --mono) plus
layout grid (topbar + sidebar + main), login page, cards, buttons,
pills, table styles. types.ts mirrors backend payload shapes.
App.tsx: BrowserRouter + Login form + Layout placeholder.

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## End of recovery doc