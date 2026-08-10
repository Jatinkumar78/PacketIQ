"""Offline web app + in-UI API-key management.

These verify the two user-friendliness features:
  1. Front-end libraries (Chart.js, marked) are served locally — no CDN, so the
     web app works with no internet.
  2. API keys can be entered in the web UI and apply immediately (no restart),
     with optional persistence to .env.

Every test runs in an isolated temp cwd with a clean env, so the developer's
real .env / environment is never read or modified.
"""

import pytest
from fastapi.testclient import TestClient

from packetiq.webapp import create_app

_KEY_VARS = ("GEMINI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY")
_TG_VARS = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import os

    from packetiq.webapp import app as webapp

    monkeypatch.chdir(tmp_path)                      # isolate .env reads/writes
    for v in _KEY_VARS + _TG_VARS:
        monkeypatch.delenv(v, raising=False)         # no cloud keys / no telegram to start
    monkeypatch.setenv("PACKETIQ_ENABLE_OLLAMA", "0")  # deterministic: no local probe
    forced_before = webapp._AI_FORCED.get("provider")
    with TestClient(create_app()) as c:
        yield c
    webapp._AI_FORCED["provider"] = forced_before    # don't leak forced-provider state
    for v in _TG_VARS:
        os.environ.pop(v, None)                      # endpoints set real os.environ; clean up


# ── Offline: vendored front-end libraries ───────────────────────────────────
def test_no_cdn_and_vendored_assets_served(client):
    idx = client.get("/").text
    assert "cdn.jsdelivr.net" not in idx and "cdnjs" not in idx, "web app must not use a CDN"
    for name in ("chart.umd.min.js", "marked.min.js"):
        r = client.get(f"/static/vendor/{name}")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
        assert len(r.content) > 10_000


def test_vendor_route_is_allowlisted(client):
    assert client.get("/static/vendor/app.py").status_code == 404
    assert client.get("/static/vendor/does-not-exist.js").status_code == 404


# ── In-UI API-key entry ─────────────────────────────────────────────────────
def test_set_key_applies_immediately_without_persist(client):
    import os

    st = client.get("/api/ai/status").json()
    assert not any(p["configured"] for p in st["providers"] if p["needs_key"])
    assert "ollama" in st  # offline local-LLM status is surfaced

    r = client.post("/api/ai/key", json={"provider": "groq", "key": "gsk_TESTkey5678", "persist": False})
    assert r.status_code == 200, r.text
    groq = next(p for p in r.json()["providers"] if p["name"] == "groq")
    assert groq["configured"] and groq["key_hint"] == "…5678"
    assert os.environ.get("GROQ_API_KEY") == "gsk_TESTkey5678"  # live this session


def test_persist_writes_and_delete_removes_from_dotenv(tmp_path, client):
    r = client.post("/api/ai/key", json={"provider": "gemini", "key": "AIzaKEY", "persist": True})
    assert r.status_code == 200
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "GEMINI_API_KEY=AIzaKEY" in env

    r = client.delete("/api/ai/key/gemini")
    assert r.status_code == 200
    assert not any(p["name"] == "gemini" and p["configured"] for p in r.json()["providers"])
    assert "GEMINI_API_KEY" not in (tmp_path / ".env").read_text(encoding="utf-8")


def test_persist_preserves_other_env_lines(tmp_path, client):
    (tmp_path / ".env").write_text("# my config\nOLLAMA_HOST=http://x:11434\n",
                                   encoding="utf-8")
    client.post("/api/ai/key", json={"provider": "anthropic", "key": "sk-ant-KEY", "persist": True})
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "# my config" in env and "OLLAMA_HOST=http://x:11434" in env
    assert "ANTHROPIC_API_KEY=sk-ant-KEY" in env


def test_key_validation(client):
    assert client.post("/api/ai/key", json={"provider": "ollama", "key": "x"}).status_code == 400
    assert client.post("/api/ai/key", json={"provider": "gemini", "key": ""}).status_code == 400
    assert client.post("/api/ai/key", json={"provider": "gemini", "key": "a\nb"}).status_code == 400
    assert client.post("/api/ai/key", json={"provider": "bogus", "key": "x"}).status_code == 400


# ── In-UI Telegram setup (no manual .env editing) ───────────────────────────
_TG_TOKEN = "123456789:AAExampleToken0123456789abcdefghij"


def test_telegram_status_starts_unconfigured(client):
    j = client.get("/api/notify/telegram").json()
    assert j["configured"] is False and j["chat_id"] == ""


def test_telegram_save_applies_and_persists(tmp_path, client):
    import os

    # test=False keeps it offline (no call to api.telegram.org).
    r = client.post("/api/notify/telegram",
                    json={"token": _TG_TOKEN, "chat_id": "987654321", "persist": True, "test": False})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] and body["chat_id"] == "987654321" and body["token_hint"].startswith("…")
    assert os.environ["TELEGRAM_BOT_TOKEN"] == _TG_TOKEN      # live this session
    assert os.environ["TELEGRAM_CHAT_ID"] == "987654321"
    env = (tmp_path / ".env").read_text(encoding="utf-8")
    assert f"TELEGRAM_BOT_TOKEN={_TG_TOKEN}" in env and "TELEGRAM_CHAT_ID=987654321" in env

    assert client.get("/api/notify/telegram").json()["configured"] is True

    # Delete removes it from the process and .env.
    assert client.delete("/api/notify/telegram").status_code == 200
    assert "TELEGRAM_BOT_TOKEN" not in (tmp_path / ".env").read_text(encoding="utf-8")
    assert client.get("/api/notify/telegram").json()["configured"] is False


def test_telegram_validation(client):
    # bad token format
    assert client.post("/api/notify/telegram",
                       json={"token": "not-a-token", "chat_id": "123456789", "test": False}).status_code == 400
    # bad chat id
    assert client.post("/api/notify/telegram",
                       json={"token": _TG_TOKEN, "chat_id": "nope", "test": False}).status_code == 400
    # detect with no/invalid token
    assert client.post("/api/notify/telegram/detect", json={"token": ""}).status_code == 400


def test_telegram_save_session_only(tmp_path, client):
    import os

    r = client.post("/api/notify/telegram",
                    json={"token": _TG_TOKEN, "chat_id": "555", "persist": False, "test": False})
    assert r.status_code == 200
    assert os.environ["TELEGRAM_CHAT_ID"] == "555"           # live
    assert not (tmp_path / ".env").exists()                  # not persisted
