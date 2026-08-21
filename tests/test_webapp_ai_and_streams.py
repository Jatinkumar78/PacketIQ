"""The web app's AI plumbing: each provider's streaming arm and the fallback loop.

Every provider SDK is replaced with a recording stub, so no key and no network
are needed and each arm's message shaping is asserted directly — the Anthropic
cache-control block, Gemini's system_instruction, Groq's leading system message.

The fallback loop is the part that decides what a user sees when a provider is
out of quota. It must move on rather than fail, and when everything really is
exhausted it must say that in one sentence instead of a stack of SDK errors.
"""

import asyncio
import json
import sys
import types

import pytest
from fastapi.testclient import TestClient

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

MESSAGES = [{"role": "user", "content": "what happened?"}]


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


def _drain(agen):
    async def run():
        return [chunk async for chunk in agen]

    return asyncio.run(run())


def _collect(coro):
    return asyncio.run(coro)


# ── Gemini arm ───────────────────────────────────────────────────────────────

def _fake_gemini(monkeypatch, chunks=("The host ", "was scanned."), captured=None):
    captured = captured if captured is not None else {}

    class Chunk:
        def __init__(self, text):
            self.text = text

    async def generate_content_stream(**kw):
        captured.update(kw)

        async def gen():
            for c in chunks:
                yield Chunk(c)

        return gen()

    class Client:
        def __init__(self, api_key=None):
            captured["api_key"] = api_key
            self.aio = types.SimpleNamespace(
                models=types.SimpleNamespace(
                    generate_content_stream=generate_content_stream))

    genai = types.ModuleType("google.genai")
    genai.Client = Client
    gtypes = types.ModuleType("google.genai.types")
    gtypes.Content = lambda role, parts: {"role": role, "parts": parts}
    gtypes.Part = lambda text: {"text": text}
    gtypes.GenerateContentConfig = lambda **kw: kw
    genai.types = gtypes
    google = types.ModuleType("google")
    google.genai = genai

    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", gtypes)
    return captured


def test_the_gemini_arm_streams_and_sends_the_capture_as_a_system_instruction(monkeypatch):
    """The capture goes in the system instruction, not the user turn — that is
    what keeps the model's answers bound to the evidence."""
    captured = _fake_gemini(monkeypatch)

    out = "".join(_drain(webapp._stream_ai_raw(
        "gemini", "key", "gemini-2.0-flash", "SYSTEM", "CAPTURE-CONTEXT", MESSAGES)))

    assert out == "The host was scanned."
    assert captured["api_key"] == "key"
    assert captured["model"] == "gemini-2.0-flash"
    system_full = captured["config"]["system_instruction"]
    assert "SYSTEM" in system_full and "CAPTURE-CONTEXT" in system_full
    assert "<pcap_analysis>" in system_full


def test_the_gemini_arm_skips_empty_chunks(monkeypatch):
    _fake_gemini(monkeypatch, chunks=("ok", "", None))
    assert "".join(_drain(webapp._stream_ai_raw(
        "gemini", "k", "m", "s", "c", MESSAGES))) == "ok"


def test_the_gemini_arm_maps_assistant_turns_to_the_model_role(monkeypatch):
    """Gemini calls the assistant role "model"; sending "assistant" is rejected."""
    captured = _fake_gemini(monkeypatch)
    history = [{"role": "user", "content": "hi"},
               {"role": "assistant", "content": "hello"},
               {"role": "user", "content": "and now?"}]

    _drain(webapp._stream_ai_raw("gemini", "k", "m", "s", "c", history))

    assert [c["role"] for c in captured["contents"]] == ["user", "model", "user"]


# ── Groq arm ─────────────────────────────────────────────────────────────────

def _fake_groq(monkeypatch, texts=("The host ", "was scanned."), captured=None):
    captured = captured if captured is not None else {}

    class Delta:
        def __init__(self, content):
            self.content = content

    class Choice:
        def __init__(self, content):
            self.delta = Delta(content)

    class Chunk:
        def __init__(self, content):
            self.choices = [Choice(content)]

    async def create(**kw):
        captured.update(kw)

        async def gen():
            for t in texts:
                yield Chunk(t)

        return gen()

    class AsyncGroq:
        def __init__(self, api_key=None):
            captured["api_key"] = api_key
            self.chat = types.SimpleNamespace(
                completions=types.SimpleNamespace(create=create))

    groq = types.ModuleType("groq")
    groq.AsyncGroq = AsyncGroq
    monkeypatch.setitem(sys.modules, "groq", groq)
    return captured


def test_the_groq_arm_streams_and_leads_with_the_system_message(monkeypatch):
    captured = _fake_groq(monkeypatch)

    out = "".join(_drain(webapp._stream_ai_raw(
        "groq", "key", "llama-3.3", "SYSTEM", "CAPTURE-CONTEXT", MESSAGES)))

    assert out == "The host was scanned."
    first = captured["messages"][0]
    assert first["role"] == "system"
    assert "SYSTEM" in first["content"] and "CAPTURE-CONTEXT" in first["content"]
    assert captured["messages"][1:] == MESSAGES
    assert captured["stream"] is True


def test_the_groq_arm_skips_empty_deltas(monkeypatch):
    """A streaming response ends with a delta carrying no content."""
    _fake_groq(monkeypatch, texts=("ok", None, ""))
    assert "".join(_drain(webapp._stream_ai_raw(
        "groq", "k", "m", "s", "c", MESSAGES))) == "ok"


# ── Anthropic arm ────────────────────────────────────────────────────────────

def _fake_anthropic(monkeypatch, chunks=("The host ", "was scanned."), captured=None):
    captured = captured if captured is not None else {}

    class Stream:
        def __init__(self):
            self.text_stream = self._gen()

        async def _gen(self):
            for c in chunks:
                yield c

    class Ctx:
        async def __aenter__(self):
            return Stream()

        async def __aexit__(self, *exc):
            return False

    class Messages:
        def stream(self, **kw):
            captured.update(kw)
            return Ctx()

    class AsyncAnthropic:
        def __init__(self, api_key=None):
            captured["api_key"] = api_key
            self.messages = Messages()

    anthropic = types.ModuleType("anthropic")
    anthropic.AsyncAnthropic = AsyncAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", anthropic)
    return captured


def test_the_anthropic_arm_streams_and_caches_the_capture_block(monkeypatch):
    """The capture context is the large, stable half of the prompt. Losing the
    cache_control marker costs roughly 70% more tokens on every message."""
    captured = _fake_anthropic(monkeypatch)

    out = "".join(_drain(webapp._stream_ai_raw(
        "anthropic", "key", "claude-sonnet-4-6", "SYSTEM", "CAPTURE-CONTEXT", MESSAGES)))

    assert out == "The host was scanned."
    role_block, context_block = captured["system"]
    assert role_block["text"] == "SYSTEM"
    assert "cache_control" not in role_block
    assert context_block["cache_control"] == {"type": "ephemeral"}
    assert "CAPTURE-CONTEXT" in context_block["text"]


def test_every_arm_pins_the_configured_temperature(monkeypatch):
    """Grounding depends on a low temperature; a drifting default is how the
    copilot would start inventing findings.

    Anthropic is asserted separately below: its SDK stopped accepting the
    parameter at 1.0.0, so what this arm sends is decided by which major is
    installed — not something to assert against whatever happens to be here.
    """
    groq = _fake_groq(monkeypatch)
    _drain(webapp._stream_ai_raw("groq", "k", "m", "s", "c", MESSAGES))
    assert groq["temperature"] == webapp._AI_TEMPERATURE

    gem = _fake_gemini(monkeypatch)
    _drain(webapp._stream_ai_raw("gemini", "k", "m", "s", "c", MESSAGES))
    assert gem["config"]["temperature"] == webapp._AI_TEMPERATURE


@pytest.mark.parametrize("supported", [True, False])
def test_the_anthropic_arm_sends_temperature_only_where_the_sdk_takes_it(monkeypatch, supported):
    """anthropic 1.0.0 removed `temperature` from the Messages API, and the method
    signature has no `**kwargs` — so sending it does not get ignored, it raises
    TypeError and the provider stops answering entirely.

    Both arms are driven here rather than left to the installed SDK. `client` is
    annotated `Any` in that branch (one name, four SDKs), so mypy cannot see the
    call at all; and letting the environment pick the branch is how a line ends
    up covered on the developer's machine and uncovered on the runner.
    """
    from packetiq.copilot import client as copilot_client

    monkeypatch.setattr(copilot_client, "anthropic_supports_temperature", lambda: supported)
    captured = _fake_anthropic(monkeypatch)
    out = "".join(_drain(webapp._stream_ai_raw("anthropic", "k", "m", "s", "c", MESSAGES)))

    assert out == "The host was scanned."          # the answer arrives either way
    if supported:
        assert captured["temperature"] == webapp._AI_TEMPERATURE
    else:
        assert "temperature" not in captured


def test_the_reply_length_cap_is_passed_through(monkeypatch):
    """Short tasks (a one-packet explanation) must stay short — generation is the
    slow half on a local model."""
    groq = _fake_groq(monkeypatch)
    _drain(webapp._stream_ai_raw("groq", "k", "m", "s", "c", MESSAGES, max_tokens=256))
    assert groq["max_tokens"] == 256


# ── Cross-provider fallback ──────────────────────────────────────────────────

def _providers(monkeypatch, sequence):
    """Serve providers in order, honouring the caller's `skip` set."""
    def detect(skip=None):
        skip = skip or set()
        for p in sequence:
            if p["provider"] not in skip:
                return p
        return {"provider": None, "key": None, "model": None}

    monkeypatch.setattr(webapp, "_detect_provider", detect)


def test_no_provider_configured_is_reported_as_setup_guidance(monkeypatch):
    _providers(monkeypatch, [])

    with pytest.raises(RuntimeError) as excinfo:
        _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES))

    assert "GEMINI_API_KEY" in str(excinfo.value) or "Ollama" in str(excinfo.value)


def test_a_provider_that_returns_nothing_is_treated_as_failed(monkeypatch):
    """An empty answer is a failure even without an exception — otherwise the
    user gets a blank card and no explanation."""
    _providers(monkeypatch, [{"provider": "groq", "key": "k", "model": "m"},
                             {"provider": "ollama", "key": None, "model": "local"}])

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "groq":
            return
        yield "the local model answered"

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    out = _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES))
    assert out == "the local model answered"


def test_a_failing_provider_hands_off_to_the_next_one(monkeypatch):
    _providers(monkeypatch, [{"provider": "gemini", "key": "k", "model": "m"},
                             {"provider": "groq", "key": "k2", "model": "m2"}])

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError("429 RESOURCE_EXHAUSTED")
        yield "groq answered"

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    assert _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES)) == "groq answered"


def test_every_provider_being_rate_limited_yields_one_clear_sentence(monkeypatch):
    _providers(monkeypatch, [{"provider": "gemini", "key": "k", "model": "m"},
                             {"provider": "groq", "key": "k2", "model": "m2"}])

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        raise RuntimeError("429 Too Many Requests")
        yield  # pragma: no cover - unreachable, keeps this an async generator

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    with pytest.raises(RuntimeError, match="rate limits"):
        _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES))


def test_a_rejected_key_is_named_as_such_rather_than_as_a_quota_problem(monkeypatch):
    """A bad key and an exhausted quota need completely different fixes."""
    _providers(monkeypatch, [{"provider": "groq", "key": "bad", "model": "m"}])

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        raise RuntimeError("401 invalid_api_key: authentication failed")
        yield  # pragma: no cover

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    with pytest.raises(RuntimeError, match="key appears invalid"):
        _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES))


def test_any_other_failure_still_surfaces_its_reason(monkeypatch):
    _providers(monkeypatch, [{"provider": "groq", "key": "k", "model": "m"}])

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        raise RuntimeError("connection reset by peer")
        yield  # pragma: no cover

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    with pytest.raises(RuntimeError, match="connection reset by peer"):
        _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES))


def test_a_dead_model_is_retried_on_the_providers_next_model(monkeypatch):
    """"That model does not exist" means wrong model, not dead provider — giving
    up on the whole provider there would drop a working free tier."""
    _providers(monkeypatch, [{"provider": "gemini", "key": "k", "model": "gemini-old"}])
    monkeypatch.setattr(webapp, "_is_model_unusable", lambda msg: "not found" in msg)
    monkeypatch.setattr(webapp, "_mark_model_dead", lambda p, m: None)
    monkeypatch.setattr(webapp, "_next_model",
                        lambda p, m: "gemini-new" if m == "gemini-old" else None)

    async def stream(provider, key, model, system, context, messages, max_tokens=2048):
        if model == "gemini-old":
            raise RuntimeError("404 model not found")
        yield "the newer model answered"

    monkeypatch.setattr(webapp, "_stream_ai", stream)

    assert _collect(webapp._collect_ai_with_fallback("s", "c", MESSAGES)) == \
        "the newer model answered"


# ── WebSocket progress relay ─────────────────────────────────────────────────

class _ScriptedQueue:
    """A loop-agnostic stand-in for the job's asyncio.Queue.

    A real `asyncio.Queue()` binds to the loop that created it on Python 3.9, and
    the TestClient runs the app on its own loop in another thread — so a queue
    built here would be rejected as belonging to a different loop.
    """

    def __init__(self, messages):
        self._messages = list(messages)

    async def get(self):
        if self._messages:
            return self._messages.pop(0)
        await asyncio.sleep(3600)          # nothing further to send


def _scripted_job(job_id, messages):
    webapp._jobs[job_id] = {"status": "running", "result": None,
                            "queue": _ScriptedQueue(messages),
                            "filename": "x.pcap", "error": None}


def test_progress_messages_are_relayed_until_the_job_completes(client):
    """The browser's progress bar is driven entirely by this queue."""
    job_id = "queue-test-job"
    _scripted_job(job_id, [
        {"type": "progress", "step": "parsing", "pct": 10},
        {"type": "progress", "step": "detection", "pct": 60},
        {"type": "complete"},
    ])
    try:
        with client.websocket_connect(f"/ws/{job_id}") as ws:
            first = json.loads(ws.receive_text())
            second = json.loads(ws.receive_text())
            last = json.loads(ws.receive_text())

        assert first["step"] == "parsing"
        assert second["pct"] == 60
        assert last["type"] == "complete"
    finally:
        webapp._jobs.pop(job_id, None)


def test_an_error_message_also_ends_the_relay(client):
    job_id = "queue-error-job"
    _scripted_job(job_id, [{"type": "error", "message": "parser exploded"}])
    try:
        with client.websocket_connect(f"/ws/{job_id}") as ws:
            msg = json.loads(ws.receive_text())

        assert msg["type"] == "error" and "parser exploded" in msg["message"]
    finally:
        webapp._jobs.pop(job_id, None)


# ── Chat endpoints ───────────────────────────────────────────────────────────

def test_the_chat_endpoint_requires_a_message(client, monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "groq", "key": "k", "model": "m"})

    r = client.post("/api/chat/anything", json={"message": "   "})
    assert r.status_code in (400, 404)


def test_the_chat_endpoint_rejects_an_unknown_job(client, monkeypatch):
    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "groq", "key": "k", "model": "m"})

    r = client.post("/api/chat/00000000-0000-0000-0000-000000000000",
                    json={"message": "what happened?"})
    assert r.status_code in (400, 404)
