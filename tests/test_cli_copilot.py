"""The CLI copilot adapter (MultiProviderClient) must route through the shared
multi-provider layer and never crash the REPL on provider failure — all mocked,
offline."""

import pytest

from packetiq.copilot.multi_provider import MultiProviderClient
from packetiq.webapp import app as webapp


@pytest.fixture(autouse=True)
def _clean():
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    yield
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()


def _one_provider(name="gemini"):
    return lambda skip=None: (
        {"provider": None, "key": None, "model": ""}
        if skip and name in skip else
        {"provider": name, "key": "k", "model": "m"}
    )


def test_available_and_label(monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider", _one_provider("gemini"))
    c = MultiProviderClient()
    c.load_context("ctx")
    assert c.available() is True
    assert "Gemini" in c.model_label


def test_single_message_uses_fallback(monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider", _one_provider("groq"))

    async def fake_collect(system, context, messages):
        assert "ctx" in context
        return "the answer"
    monkeypatch.setattr(webapp, "_collect_ai_with_fallback", fake_collect)

    c = MultiProviderClient()
    c.load_context("ctx")
    assert c.single_message("q?") == "the answer"


def test_stream_message_streams_and_returns(monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider", _one_provider("gemini"))

    async def fake_stream(provider, key, model, system, context, messages):
        for piece in ("Hel", "lo ", "world"):
            yield piece
    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)

    c = MultiProviderClient()
    c.load_context("ctx")
    chunks = []
    full = c.stream_message([{"role": "user", "content": "hi"}], chunks.append)
    assert full == "Hello world"
    assert "".join(chunks) == "Hello world"


def test_stream_message_never_raises_on_total_failure(monkeypatch):
    # a single provider that always errors → adapter must return a message, not raise
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: ({"provider": None, "key": None, "model": ""}
                                           if skip else {"provider": "gemini", "key": "k", "model": "m"}))

    async def boom(*a, **k):
        raise RuntimeError("boom")
        yield  # pragma: no cover
    monkeypatch.setattr(webapp, "_stream_ai", boom)

    c = MultiProviderClient()
    c.load_context("ctx")
    chunks = []
    out = c.stream_message([{"role": "user", "content": "hi"}], chunks.append)
    assert "failed" in out.lower()
    assert chunks  # the failure message was delivered to the UI, not raised


def test_stream_message_falls_back_across_providers(monkeypatch):
    seq = {"gemini": ("raise", "429 quota"), "groq": ("ok", "hi from groq")}

    def detect(skip=None):
        skip = skip or set()
        for p in ("gemini", "groq"):
            if p not in skip:
                return {"provider": p, "key": "k", "model": "m"}
        return {"provider": None, "key": None, "model": ""}
    monkeypatch.setattr(webapp, "_detect_provider", detect)

    async def fake_stream(provider, key, model, system, context, messages):
        kind, payload = seq[provider]
        if kind == "raise":
            raise RuntimeError(payload)
        yield payload
    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)

    c = MultiProviderClient()
    c.load_context("ctx")
    chunks = []
    full = c.stream_message([{"role": "user", "content": "hi"}], chunks.append)
    assert "hi from groq" in full
