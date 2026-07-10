"""The chat copilot must survive a failing provider.

Regression: the streaming chat endpoint used to fall back only on rate limits, so
a rejected API key (or a missing SDK, or a network blip) aborted the request even
when a healthy provider — notably the always-available local Ollama model — was
sitting right there. Now any failure means "try the next provider", exactly as the
non-streaming path already did.
"""

import json

import pytest
from fastapi.testclient import TestClient

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

_JOB = "job-under-test"
_BAD_KEY = "API key not valid. Please pass a valid API key."


def _sse_events(text: str) -> list:
    """Parse an SSE body into the decoded data payloads."""
    out = []
    for block in text.split("\n\n"):
        block = block.strip()
        if not block.startswith("data: "):
            continue
        raw = block[6:].strip()
        out.append("[DONE]" if raw == "[DONE]" else json.loads(raw))
    return out


@pytest.fixture()
def client(monkeypatch):
    # Two providers: a broken cloud key, and a healthy local model.
    monkeypatch.setattr(webapp, "_configured_providers", lambda: ["gemini", "ollama"])
    monkeypatch.setattr(webapp, "_ollama_model", lambda: "qwen2.5:7b-instruct")
    monkeypatch.setattr(webapp, "_ollama_host", lambda: "http://localhost:11434")
    monkeypatch.setenv("GEMINI_API_KEY", "broken-key")
    monkeypatch.setitem(webapp._AI_FORCED, "provider", None)
    webapp._AI_COOLDOWN.clear()

    with TestClient(create_app()) as c:
        webapp._jobs[_JOB] = {
            "status": "complete", "filename": "demo.pcap",
            "result": {"meta": {"filename": "demo.pcap", "size_mb": 1.0},
                       "risk": {"score": 20, "tier": "LOW"}, "events": [], "chains": []},
        }
        yield c
    webapp._jobs.pop(_JOB, None)
    webapp._AI_COOLDOWN.clear()


def _ask(c):
    return c.post(f"/api/chat/{_JOB}", json={"message": "who is scanning?", "history": []})


def _texts(events) -> str:
    return "".join(e.get("text", "") for e in events if isinstance(e, dict))


def _notices(events) -> list:
    return [e["notice"] for e in events if isinstance(e, dict) and e.get("notice")]


def test_chat_falls_back_to_local_model_when_the_cloud_key_is_rejected(client, monkeypatch):
    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError(_BAD_KEY)
        yield "answered by the local model"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)

    r = _ask(client)
    assert r.status_code == 200
    events = _sse_events(r.text)

    # The switch is reported as a `notice`, never mixed into the answer body.
    assert _notices(events) == ["Google Gemini key rejected — answered by Local (Ollama)"]
    assert _texts(events) == "answered by the local model"
    assert "key rejected" not in _texts(events)
    assert "[DONE]" in events
    assert not any(isinstance(e, dict) and e.get("error") for e in events)


def test_a_rejected_key_is_benched_so_the_next_message_skips_it(client, monkeypatch):
    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError(_BAD_KEY)
        yield "ok"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    assert webapp._cooldown_left("gemini") == 0
    _ask(client)
    # A bad key doesn't heal in seconds — don't re-fail on every message.
    assert webapp._cooldown_left("gemini") > 60
    assert webapp._detect_provider()["provider"] == "ollama"


def test_chat_surfaces_an_error_only_when_every_provider_fails(client, monkeypatch):
    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        raise RuntimeError(_BAD_KEY)
        yield  # pragma: no cover — makes this an async generator

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)

    events = _sse_events(_ask(client).text)
    errors = [e["error"] for e in events if isinstance(e, dict) and e.get("error")]
    assert len(errors) == 1
    assert "rejected its API key" in errors[0]
    assert "overrides `.env`" in errors[0]      # the trap that actually bit us


def test_rate_limited_provider_still_falls_back_and_cools_down(client, monkeypatch):
    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError("429 RESOURCE_EXHAUSTED, retry in 42s")
        yield "local answer"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    events = _sse_events(_ask(client).text)
    assert "quota reached" in _notices(events)[0]
    assert _texts(events) == "local answer"
    assert 0 < webapp._cooldown_left("gemini") <= 42


# Google reports "Please retry in 8.688s" even when the *daily* free-tier quota is
# gone (limit: 0). Honouring that retryDelay made us re-fail on every message.
_DAILY_QUOTA_ERR = (
    "429 RESOURCE_EXHAUSTED. Quota exceeded for metric: "
    "generativelanguage.googleapis.com/generate_content_free_tier_requests, limit: 0. "
    "Please retry in 8.688754398s. quotaId: 'GenerateRequestsPerDayPerProjectPerModel-FreeTier'"
)


def test_exhausted_daily_quota_is_benched_for_an_hour_not_eight_seconds():
    webapp._AI_COOLDOWN.clear()
    assert webapp._retry_after_seconds(_DAILY_QUOTA_ERR) < 10   # what Google claims
    assert webapp._is_exhausted_quota(_DAILY_QUOTA_ERR)
    webapp._note_provider_failure("gemini", _DAILY_QUOTA_ERR)
    assert webapp._cooldown_left("gemini") > 3000                # what we actually do
    assert webapp._failure_reason(_DAILY_QUOTA_ERR) == "daily quota used up"
    webapp._AI_COOLDOWN.clear()


def test_ordinary_per_minute_quota_still_honours_retry_delay():
    webapp._AI_COOLDOWN.clear()
    webapp._note_provider_failure("gemini", "429 RESOURCE_EXHAUSTED. Please retry in 42s.")
    assert 0 < webapp._cooldown_left("gemini") <= 42
    webapp._AI_COOLDOWN.clear()


def test_exhausted_quota_detector_is_not_trigger_happy():
    assert not webapp._is_exhausted_quota("429 rate limit, retry in 30s")
    assert not webapp._is_exhausted_quota("limit: 1000 requests")
    assert webapp._is_exhausted_quota("quota limit: 0 for this model")


def test_failure_classifiers():
    assert webapp._is_auth_error("401 Unauthorized")
    assert webapp._is_auth_error("API key not valid. Please pass a valid API key.")
    assert webapp._is_auth_error("403 permission denied")
    assert not webapp._is_auth_error("429 RESOURCE_EXHAUSTED")
    assert not webapp._is_auth_error("connection reset by peer")

    assert webapp._is_rate_limit("429 RESOURCE_EXHAUSTED")
    assert webapp._failure_reason("429 quota") == "quota reached"
    assert webapp._failure_reason("401 Unauthorized") == "key rejected"
    assert webapp._failure_reason("socket timeout") == "unavailable"


def test_unknown_errors_are_not_cooled_down(client, monkeypatch):
    # A transient network blip should not bench a provider for five minutes.
    webapp._AI_COOLDOWN.clear()
    webapp._note_provider_failure("gemini", "connection reset by peer")
    assert webapp._cooldown_left("gemini") == 0
