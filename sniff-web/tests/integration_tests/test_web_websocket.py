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