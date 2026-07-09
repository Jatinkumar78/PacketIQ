"""Smart auto-switch (sticky cooldown) + manual provider override."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app


@pytest.fixture(autouse=True)
def _clean_ai_state():
    """Each test starts from a known AI state and restores it after."""
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    yield
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()


def _two_providers(monkeypatch):
    monkeypatch.setattr(webapp, "_configured_providers", lambda: ["gemini", "groq"])
    monkeypatch.setattr(webapp, "_provider_key", lambda n: "key-" + n)


# ── cooldown / sticky switching ──────────────────────────────────────────────

def test_retry_after_parsing():
    assert webapp._retry_after_seconds("Please retry in 54.37s") == 54.37
    assert webapp._retry_after_seconds("'retryDelay': '54s'") == 54.0
    assert webapp._retry_after_seconds("no hint here", default=30) == 30


def test_cooldown_makes_switch_sticky(monkeypatch):
    _two_providers(monkeypatch)
    assert webapp._detect_provider()["provider"] == "gemini"
    webapp._mark_cooldown("gemini", 120)
    # auto now skips the cooled-down gemini
    assert webapp._detect_provider()["provider"] == "groq"
    assert webapp._cooldown_left("gemini") > 0


def test_cooldown_ignored_when_all_cold(monkeypatch):
    _two_providers(monkeypatch)
    webapp._mark_cooldown("gemini", 120)
    webapp._mark_cooldown("groq", 120)
    # both cold → still returns something (best effort) rather than None
    assert webapp._detect_provider()["provider"] in {"gemini", "groq"}


def test_forced_provider_wins(monkeypatch):
    _two_providers(monkeypatch)
    webapp._AI_FORCED["provider"] = "groq"
    assert webapp._detect_provider()["provider"] == "groq"
    # even if groq is on cooldown, an explicit manual choice is honoured
    webapp._mark_cooldown("groq", 120)
    assert webapp._detect_provider()["provider"] == "groq"


def test_forced_still_falls_back_when_skipped(monkeypatch):
    _two_providers(monkeypatch)
    webapp._AI_FORCED["provider"] = "gemini"
    # the fallback loop adds the failed provider to `skip`
    assert webapp._detect_provider(skip={"gemini"})["provider"] == "groq"


def test_collect_marks_cooldown_on_rate_limit(monkeypatch):
    _two_providers(monkeypatch)

    async def _stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError("429 RESOURCE_EXHAUSTED retry in 42s")
        yield "ok from groq"

    monkeypatch.setattr(webapp, "_stream_ai", _stream)
    text = asyncio.run(webapp._collect_ai_with_fallback("s", "c", [{"role": "user", "content": "x"}]))
    assert text == "ok from groq"
    # gemini should now be on cooldown so the NEXT request skips it immediately
    assert webapp._cooldown_left("gemini") > 0
    assert webapp._detect_provider()["provider"] == "groq"


# ── endpoints ────────────────────────────────────────────────────────────────

def test_ai_status_and_set_endpoints(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "ai.db"))
    monkeypatch.setattr(webapp, "_configured_providers", lambda: ["gemini", "groq"])
    monkeypatch.setattr(webapp, "_provider_key", lambda n: "key-" + n)
    with TestClient(create_app()) as c:
        st = c.get("/api/ai/status").json()
        assert st["available"] is True
        assert st["mode"] == "auto"
        assert st["active"] == "gemini"

        # switch to groq
        r = c.post("/api/ai/provider", json={"provider": "groq"})
        assert r.status_code == 200, r.text
        assert r.json()["forced"] == "groq" and r.json()["mode"] == "manual"

        # back to auto
        assert c.post("/api/ai/provider", json={"provider": "auto"}).json()["forced"] is None

        # unconfigured provider is rejected
        assert c.post("/api/ai/provider", json={"provider": "anthropic"}).status_code == 400
        # unknown provider is rejected
        assert c.post("/api/ai/provider", json={"provider": "bogus"}).status_code == 400
