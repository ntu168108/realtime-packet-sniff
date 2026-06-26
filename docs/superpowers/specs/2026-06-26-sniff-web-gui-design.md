# SNIFF Web GUI — Design Spec

**Date:** 2026-06-26
**Status:** Approved (brainstorming complete)
**Target repo:** `ntu168108/realtime-packet-sniff`
**Source spec:** `/home/tu/SNIFF_WEB_GUI_SPEC.md`

## Goal

Replace the TUI (`cli/app.py`) with a web-based control panel that:

1. Runs 24/7 as a systemd service, auto-starts on boot.
2. Lets the user pick a network interface + BPF filter, then start/stop/pause capture from the browser.
3. Streams live packets and stats to the browser over WebSocket.
4. Acts as a **single pane of glass**: control `kafka`, `sniff-producer`, `ec-consumer`, `clickhouse-server`, `grafana-server` services; query ClickHouse + Kafka admin from one place; manage rotated PCAP files; edit a curated subset of `config.yaml`.
5. Is GitHub-PR-ready: matches repo conventions, passes existing 36 tests + new test suite, includes CI workflow + smoke script + docs.

Out of scope (per `SNIFF_WEB_GUI_SPEC.md` § Out of Scope):
- Deep packet decode in web (keep `deep=False`).
- Authentication beyond single-admin password.
- Mobile-responsive UI (desktop-first).
- Replacing `sniff-producer.service` (it stays; web GUI runs alongside).

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│  /etc/systemd/system/sniff-web.service                          │
│  User=tu, WorkingDirectory=/home/tu/realtime-packet-sniff       │
│  ExecStart=/usr/bin/python3 -m uvicorn web_server:app --host 0.0.0.0 --port 8000│
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
        ┌─────────────────────────────────────────────┐
        │  FastAPI process (port 8000, host=0.0.0.0) │
        │  ┌──────────────────────────────────────┐  │
        │  │  HTTPBasic + JWT cookie auth         │  │
        │  └──────────────────────────────────────┘  │
        │  ┌──────────────────────────────────────┐  │
        │  │  REST endpoints /api/*                │  │
        │  └──────────────────────────────────────┘  │
        │  ┌──────────────────────────────────────┐  │
        │  │  WebSocket /ws/{packets,stats,svc}   │  │
        │  └──────────────────────────────────────┘  │
        │  ┌──────────────────────────────────────┐  │
        │  │  CaptureEngine (in-process)           │  │
        │  │  ← core.capture.CaptureEngine        │  │
        │  │  uses setcap for raw socket          │  │
        │  └──────────────────────────────────────┘  │
        │  ┌──────────────────────────────────────┐  │
        │  │  systemd wrapper (subprocess)         │  │
        │  │  ← sudoers NOPASSWD restricted       │  │
        │  └──────────────────────────────────────┘  │
        │  ┌──────────────────────────────────────┐  │
        │  │  Static mount: web/dist → /           │  │
        │  └──────────────────────────────────────┘  │
        └─────────────────────────────────────────────┘
                  │                 │              │
                  ▼                 ▼              ▼
        ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
        │  Kafka       │   │  ClickHouse  │   │  systemd     │
        │  :9092       │   │  :9000       │   │  systemctl   │
        └──────────────┘   └──────────────┘   └──────────────┘
```

**Why monolith:** Single process = single systemd unit = single port. Simplest path to 24/7. Spec `SNIFF_WEB_GUI_SPEC.md` already designed for this topology. Refactoring to multi-process later is straightforward (capture API is a black box).

## Components

### Backend (`web_server.py`)

| Element | Purpose |
|---|---|
| `auth_config: AuthConfig` | Loaded from `config.yaml:web.username` + `web.password_hash` (bcrypt) + `web.jwt_secret` (random 32 bytes on first boot if absent) |
| `engine: Optional[CaptureEngine]` | Module-level singleton; `None` until `/api/capture/start` |
| `last_config_path: Path` | `/var/lib/sniff-web/last_capture.json` |
| `_loop`, `_pkt_queue`, `_drop_queue` | Asyncio plumbing (spec § 105-119) |
| `packet_clients`, `stats_clients`, `services_clients` | `set[WebSocket]` |

### API Endpoints

REST (all require JWT except `/api/auth/login`):

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/auth/login` | POST | Verify password, set JWT cookie |
| `/api/auth/me` | GET | Echo current user |
| `/api/interfaces` | GET | List NICs + IP/MAC/up |
| `/api/capture/start` | POST | Build + start CaptureEngine; persist to `last_capture.json` |
| `/api/capture/stop` | POST | `engine.stop()` |
| `/api/capture/toggle-pause` | POST | `engine.toggle_pause()` |
| `/api/capture/status` | GET | `engine.get_status()` or zero-state |
| `/api/capture/last-config` | GET | Return persisted config for auto-restore UI |
| `/api/capture/conversations` | GET | `engine.get_top_conversations(n)` |
| `/api/services/list` | GET | systemctl status for all known services |
| `/api/services/{name}/{action}` | POST | action ∈ start/stop/restart/enable/disable (allowlisted) |
| `/api/kafka/topics` | GET | topic list + partitions + replication |
| `/api/kafka/lag` | GET | consumer-group lag for `ec-consumer` |
| `/api/clickhouse/query` | POST | read-only SQL (allowlisted prefixes) |
| `/api/clickhouse/counts` | GET | pre-baked counts of flows_all + 7 flows_<family> + pipeline_runs |
| `/api/pcap/files` | GET | list rotated PCAP files |
| `/api/pcap/download/{name}` | GET | stream file as attachment |
| `/api/config` | GET | read sanitized `config.yaml` |
| `/api/config` | PUT | write allowlisted keys |
| `/api/system/info` | GET | uname, uptime, disk, mem |

WebSocket (JWT in `?token=...` or first message):

| Endpoint | Cadence | Payload |
|---|---|---|
| `/ws/packets` | 50 ms batch (≤32 items) | `{type:"packets", data:[{stt,ts,src,dst,src_port,dst_port,proto,len,info}]}` |
| `/ws/stats` | 1 Hz | `{type:"stats", data:CaptureStatus + ws_drop_total}` |
| `/ws/services` | 1 Hz | `{type:"services", data:{name:{active,sub,exitcode,uptime_ms}}}` |

### Allowlists

**ClickHouse SQL prefixes (server-enforced):**
```python
CH_ALLOWLIST = ("SELECT ", "SHOW ", "DESCRIBE ", "EXISTS ", "SELECT 1")
```

**Service allowlist:**
```python
SERVICE_ALLOWLIST = {
    "kafka", "sniff-producer", "ec-consumer",
    "clickhouse-server", "grafana-server", "sniff-web",
}
SERVICE_ACTIONS = {"start", "stop", "restart", "enable", "disable"}
```

**Config writable keys:**
```python
CONFIG_WRITABLE = {
    "display.display_filter", "display.exclude_ports", "display.cache_size",
    "live.enabled",
    "modules.enabled", "modules.auto_discover",
    "performance.ring_buffer_size", "performance.batch_size",
    "performance.enable_deep_decode", "performance.gc_interval",
}
```

### Persistence

`/var/lib/sniff-web/last_capture.json`:
```json
{
  "interface": "ens18",
  "bpf_filter": "not port 22",
  "snaplen": 65535,
  "promisc": true,
  "auto_restore": true,
  "saved_at": "2026-06-26T12:34:56Z"
}
```

Auto-restore on lifespan startup if `auto_restore=true` AND interface exists.

### Frontend (`web/`)

React 18 + TypeScript + Vite + `@tanstack/react-virtual`.

```
web/src/
├── main.tsx
├── App.tsx
├── types.ts
├── pages/
│   ├── Login.tsx
│   ├── Dashboard.tsx
│   ├── Capture.tsx
│   ├── Services.tsx
│   ├── PcapFiles.tsx
│   ├── ClickHouse.tsx
│   ├── Kafka.tsx
│   ├── Config.tsx
│   └── System.tsx
├── components/
│   ├── PacketTable.tsx
│   ├── ServiceCard.tsx
│   ├── CountCard.tsx
│   ├── JWTGuard.tsx
│   ├── Sidebar.tsx
│   └── TopBar.tsx
├── hooks/
│   ├── useWebSocket.ts
│   ├── useApi.ts
│   └── useAuth.ts
├── styles/global.css
└── __tests__/*.test.ts
```

Layout: Sidebar (left) + TopBar (top) + routed main content.

## Data Flow

### Boot sequence
1. systemd `multi-user.target` → network.target online
2. kafka.service, clickhouse-server.service, grafana-server.service, sniff-producer.service, ec-consumer.service start (already enabled)
3. sniff-web.service starts
4. FastAPI lifespan startup: load `last_capture.json` → if `auto_restore`, build + start CaptureEngine → spawn broadcast tasks → uvicorn listen 0.0.0.0:8000

### Login
POST /api/auth/login → bcrypt.checkpw → JWT (HS256, 24h exp) → Set-Cookie → redirect /dashboard

### Capture start
POST /api/capture/start → validate interface → if engine.running 400 → write `last_capture.json` → CaptureEngine(...) → setup() → start() → 200 {ok}

### Service control
POST /api/services/{name}/{action} → check name+action in allowlist → subprocess `["sudo", "-n", "systemctl", action, name]` → return exit code

### Auto-restore (key feature)
lifespan startup → load JSON → if valid + interface exists + auto_restore → build CaptureEngine → engine.setup() → engine.start() → log "Auto-restored"

## Error Handling

| Failure | Handling |
|---|---|
| Web server crash | systemd Restart=always, RestartSec=5 |
| Capture error in hot path | try/except in `_on_packet`, fire drop event |
| WebSocket disconnects | dead client detection in `_fan_out`, auto-remove |
| ClickHouse/Kafka down | 503 service unavailable, exponential backoff 1s→30s cap |
| Interface gone | OSError at engine.start() → 400 to UI |
| Invalid BPF | kernel rejects at sniff time, no crash, drop event |
| JWT expired (24h) | 401 from any endpoint → frontend redirect /login |
| sudoers NOPASSWD missing | exit 1 → 500 with "Permission denied — check sudoers rule" |
| Persistence file malformed | log warning, skip auto-restore |
| Disk full | Rotator raises → `_fire_drop("rotator")` → UI drop badge |

## Testing Strategy (TDD)

| Layer | Tool | Files |
|---|---|---|
| Backend unit | pytest | `tests/integration_tests/test_web_auth.py`, `test_web_capture.py`, `test_web_services.py`, `test_web_clickhouse.py`, `test_web_kafka.py`, `test_web_persistence.py`, `test_web_security.py` |
| Backend integration | pytest + FastAPI TestClient + httpx | same files |
| Frontend unit | vitest | `web/src/__tests__/{auth,useApi,useWebSocket,statusPill}.test.ts` |
| Frontend E2E | @playwright/test | `web/e2e/{login,capture,services}.spec.ts` |
| Smoke (full stack) | bash | `scripts/smoke_web.sh` |
| CI | GitHub Actions | `.github/workflows/web-gui.yml` |

Coverage targets:
- All new endpoints have ≥1 happy-path test + ≥1 error-path test
- All allowlists have ≥1 negative test (block forbidden input)
- JWT roundtrip + expiry covered
- Persistence write/read + malformed-file recovery covered
- Frontend components: snapshot for visual regression

## Deployment

### Files

```
NEW:
  web_server.py
  web/                            # React project (Vite scaffolded)
  requirements-web.txt
  deploy/systemd/sniff-web.service
  deploy/sudoers/sniff-web
  scripts/install_web.sh
  scripts/smoke_web.sh
  tests/integration_tests/test_web_*.py
  web/src/__tests__/*.test.ts
  web/e2e/*.spec.ts
  docs/WEB_GUI.md
  .github/workflows/web-gui.yml

UPDATED:
  config.yaml.example             # add web section
  docs/ARCHITECTURE.md            # add web section
  HUONG_DAN_TRIEN_KHAI.md         # add Bước 11
  README.md, README_VI.md         # add Web GUI section
  tests/integration_tests/conftest.py  # add fixtures
  .gitignore                      # add web/dist, /var/lib/sniff-web/, jwt_secret
```

### Install flow (`scripts/install_web.sh`)

1. `pip install --break-system-packages -r requirements-web.txt`
2. `cd web && npm install && npm run build && cd ..`
3. `sudo setcap cap_net_admin,cap_net_raw+ep /usr/bin/python3.12`
4. Validate + install sudoers: `sudo visudo -c -f deploy/sudoers/sniff-web && sudo cp deploy/sudoers/sniff-web /etc/sudoers.d/`
5. Install systemd unit: `sudo cp deploy/systemd/sniff-web.service /etc/systemd/system/`, replace `/home/tu/realtime-packet-sniff` with actual `$(pwd)`
6. `sudo systemctl daemon-reload && sudo systemctl enable sniff-web && sudo systemctl start sniff-web`
7. Print URL + default credentials (admin / sniff — warn to change)

### Sudoers (`deploy/sudoers/sniff-web`)

```
tu ALL=(root) NOPASSWD: /usr/bin/systemctl start kafka, \
    /usr/bin/systemctl stop kafka, \
    /usr/bin/systemctl restart kafka, \
    /usr/bin/systemctl enable kafka, \
    /usr/bin/systemctl disable kafka, \
    /usr/bin/systemctl start sniff-producer, \
    ... (5 commands × 6 services = 30 lines)
```

### Verification (`scripts/smoke_web.sh`)

1. `systemctl is-active sniff-web` → expect `active`
2. `ss -tln | grep :8000` → expect line
3. Login via curl → extract JWT
4. `GET /api/interfaces` → expect non-empty list
5. Start capture on `lo` with filter `tcp port 22`
6. Wait 3 s → `GET /api/capture/status` → expect `running: true`
7. WebSocket `/ws/stats` connect → expect first frame within 2 s
8. Generate traffic (failed SSH to localhost) → expect `packets > 0`
9. Stop capture → expect `running: false`
10. Restart sniff-web via `/api/services/sniff-web/restart` → expect service still active after 5 s

Exits 0 only if all 10 checks pass.

## Versioning & Migration

- Add `web:` section to `config.yaml` is **optional** — if absent, web service refuses to start with clear error message pointing to `config.yaml.example`.
- Default credentials (`admin` / `sniff`) printed on first install. Forced to change on first login (UI shows "change password" form posting to `/api/auth/change-password`).
- Backward compatible: existing services (kafka, sniff-producer, ec-consumer, clickhouse, grafana) untouched. snif-web is purely additive.

## Risks

| Risk | Mitigation |
|---|---|
| setcap on system python may break on distro update | `install_web.sh` idempotent — re-run on python upgrade |
| JWT secret leaked via config.yaml in git | `.gitignore` excludes `web/instance/`; secret auto-generated on first boot if absent |
| sudoers NOPASSWD misuse | restricted to specific command+service combos, validated by `visudo -c` |
| WS flooding if many clients | per-client send queue with backpressure (already in spec `_fan_out`) |
| ClickHouse SQL injection | server-side prefix allowlist, never raw pass-through |
| Concurrent capture start requests | `is_running` check before creating new engine (already in spec) |
