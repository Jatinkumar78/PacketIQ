"""Local Ollama provider: reachability probe, model resolution, provider
selection, and the native NDJSON streaming branch — all mocked so the suite runs
offline (no daemon required)."""

import asyncio
import json

import httpx
import pytest

from packetiq.webapp import app as webapp


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    webapp._OLLAMA_PROBE.update(at=0.0, up=False, models=[])
    # Make the local provider decisions independent of the host's real .env / daemon.
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    monkeypatch.delenv("PACKETIQ_ENABLE_OLLAMA", raising=False)
    yield
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    webapp._OLLAMA_PROBE.update(at=0.0, up=False, models=[])


class _FakeTags:
    status_code = 200

    def __init__(self, models):
        self._models = models

    def json(self):
        return {"models": [{"name": m} for m in self._models]}


def _fake_tags(models):
    def _get(url, timeout=None):
        return _FakeTags(models)
    return _get


# ── reachability + model resolution ──────────────────────────────────────────

def test_probe_up_lists_models(monkeypatch):
    monkeypatch.setattr(httpx, "get", _fake_tags(["qwen2.5:7b-instruct"]))
    assert webapp._ollama_available() is True
    assert webapp._ollama_model() == "qwen2.5:7b-instruct"  # only model present → auto-picked


def test_probe_down_when_daemon_unreachable(monkeypatch):
    def _boom(url, timeout=None):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(httpx, "get", _boom)
    assert webapp._ollama_available() is False


def test_disabled_via_env(monkeypatch):
    monkeypatch.setattr(httpx, "get", _fake_tags(["llama3.1:8b"]))
    monkeypatch.setenv("PACKETIQ_ENABLE_OLLAMA", "0")
    assert webapp._ollama_available() is False


def test_default_model_preferred_when_present(monkeypatch):
    default = webapp._OLLAMA_DEFAULT_MODEL
    monkeypatch.setattr(httpx, "get", _fake_tags(["mistral:7b", default]))
    assert webapp._ollama_model() == default


def test_explicit_model_override(monkeypatch):
    monkeypatch.setattr(httpx, "get", _fake_tags(["mistral:7b"]))
    monkeypatch.setenv("OLLAMA_MODEL", "phi3:mini")
    assert webapp._ollama_model() == "phi3:mini"  # honoured even if not in probe list


# ── provider selection ───────────────────────────────────────────────────────

def test_configured_and_detected(monkeypatch):
    monkeypatch.setattr(httpx, "get", _fake_tags(["llama3.1:8b"]))
    assert "ollama" in webapp._configured_providers()
    webapp._AI_FORCED["provider"] = "ollama"
    d = webapp._detect_provider()
    assert d["provider"] == "ollama"
    assert d["key"] == webapp._ollama_host()
    assert d["model"] == "llama3.1:8b"


def test_not_configured_when_down(monkeypatch):
    def _boom(url, timeout=None):
        raise httpx.ConnectError("refused")
    monkeypatch.setattr(httpx, "get", _boom)
    assert "ollama" not in webapp._configured_providers()


# ── the native /api/chat streaming branch ────────────────────────────────────

class _FakeStreamResp:
    status_code = 200

    def __init__(self, lines):
        self._lines = lines

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def aiter_lines(self):
        for ln in self._lines:
            yield ln

    async def aread(self):
        return b""


class _FakeAsyncClient:
    def __init__(self, lines, status=200):
        self._lines = lines
        self._status = status

    def _mk(self, *a, **k):
        return _FakeAsyncClient(self._lines, self._status)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, json=None):
        resp = _FakeStreamResp(self._lines)
        resp.status_code = self._status
        return resp


def _run_stream():
    async def _collect():
        out = ""
        async for chunk in webapp._stream_ai(
            "ollama", "http://localhost:11434", "llama3.1:8b",
            "system", "context", [{"role": "user", "content": "hi"}],
        ):
            out += chunk
        return out
    return asyncio.run(_collect())


def test_stream_assembles_ndjson(monkeypatch):
    lines = [
        json.dumps({"message": {"content": "Hello "}, "done": False}),
        "",  # ollama can emit blank keep-alive lines
        json.dumps({"message": {"content": "world"}, "done": True}),
    ]
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _FakeAsyncClient(lines))
    assert _run_stream() == "Hello world"


def test_stream_missing_model_raises_pull_hint(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _FakeAsyncClient([], status=404))
    with pytest.raises(RuntimeError, match="ollama pull"):
        _run_stream()


def test_stream_surfaces_error_field(monkeypatch):
    lines = [json.dumps({"error": "model runner crashed"})]
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _FakeAsyncClient(lines))
    with pytest.raises(RuntimeError, match="model runner crashed"):
        _run_stream()
