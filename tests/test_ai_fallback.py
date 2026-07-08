"""The AI 'Explain with AI' / report path must fall back across providers when
one is rate-limited (the real bug: Gemini 429 with no fallback)."""

import asyncio

import pytest

from packetiq.webapp import app as webapp


@pytest.fixture(autouse=True)
def _clean_ai_state():
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    yield
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()


def _make_stream(behaviour):
    """behaviour: dict provider -> ('ok', text) | ('raise', exc_msg)"""
    async def _stream(provider, key, model, system, context, messages):
        kind, payload = behaviour[provider]
        if kind == "raise":
            raise RuntimeError(payload)
        yield payload
    return _stream


def _detector(providers):
    def fake_detect(skip=None):
        skip = skip or set()
        for p in providers:
            if p["provider"] not in skip:
                return p
        return {"provider": None, "key": None, "model": ""}
    return fake_detect


def test_fallback_on_rate_limit(monkeypatch):
    # Gemini is configured first but 429s; Groq then succeeds.
    monkeypatch.setattr(webapp, "_detect_provider", _detector([
        {"provider": "gemini", "key": "g", "model": "gemini-2.0-flash"},
        {"provider": "groq", "key": "q", "model": "llama"},
    ]))
    monkeypatch.setattr(webapp, "_stream_ai", _make_stream({
        "gemini": ("raise", "429 RESOURCE_EXHAUSTED quota"),
        "groq": ("ok", "hello from groq"),
    }))
    text = asyncio.run(webapp._collect_ai_with_fallback(
        "sys", "ctx", [{"role": "user", "content": "hi"}]))
    assert text == "hello from groq"


def test_all_providers_rate_limited(monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider", _detector([
        {"provider": "gemini", "key": "g", "model": "m"},
    ]))
    monkeypatch.setattr(webapp, "_stream_ai", _make_stream({
        "gemini": ("raise", "429 quota exceeded"),
    }))
    with pytest.raises(RuntimeError, match="rate limits"):
        asyncio.run(webapp._collect_ai_with_fallback(
            "s", "c", [{"role": "user", "content": "x"}]))


def test_no_provider_configured(monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": None, "key": None, "model": ""})
    with pytest.raises(RuntimeError, match="No AI provider"):
        asyncio.run(webapp._collect_ai_with_fallback(
            "s", "c", [{"role": "user", "content": "x"}]))
