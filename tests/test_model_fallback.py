"""A model whose free tier is zero must not kill its provider.

Google grants free-tier quota *per model*, not per key: a valid key answers
`limit: 0` for one model while another replies normally on the very same
project. The copilot used to read that 429 as "Gemini is dead", bench it for an
hour and fall through to another provider. It must instead try the next model of
the same provider. The same walk covers a model retired outright — which is not
hypothetical: `gemini-2.0-flash` was the first candidate until Google began
answering "no longer available" for it.

Which is also why nothing below names a model directly. These tests take the
first and second candidates from `_MODEL_CANDIDATES`, so the list can be updated
when a model is retired without leaving a test asserting a name that no longer
exists.
"""

import json

import pytest
from fastapi.testclient import TestClient

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

_JOB = "job-model-fallback"

# The provider's own preference order — the first two are what the fallback walks.
FIRST, SECOND = webapp._MODEL_CANDIDATES["gemini"][:2]

# The real body Google returns for a project with no free-tier allowance.
_ZERO_QUOTA = (
    "429 RESOURCE_EXHAUSTED. Quota exceeded for metric: "
    f"generativelanguage.googleapis.com/generate_content_free_tier_requests, "
    f"limit: 0, model: {FIRST}. Please retry in 8.09s."
)
_PER_MINUTE = "429 RESOURCE_EXHAUSTED. Please retry in 42s."


@pytest.fixture(autouse=True)
def _clean():
    webapp._MODEL_DEAD.clear()
    webapp._AI_COOLDOWN.clear()
    yield
    webapp._MODEL_DEAD.clear()
    webapp._AI_COOLDOWN.clear()


def _sse(text: str) -> list:
    out = []
    for block in text.split("\n\n"):
        block = block.strip()
        if block.startswith("data: "):
            raw = block[6:].strip()
            out.append("[DONE]" if raw == "[DONE]" else json.loads(raw))
    return out


def _notices(events) -> list:
    return [e["notice"] for e in events if isinstance(e, dict) and e.get("notice")]


def _texts(events) -> str:
    return "".join(e.get("text", "") for e in events if isinstance(e, dict))


# ── classifier ───────────────────────────────────────────────────────────────

def test_zero_free_tier_is_a_model_problem_not_a_provider_problem():
    assert webapp._is_model_unusable(_ZERO_QUOTA)
    assert webapp._is_model_unusable("404 model gemini-x is not found for API version v1beta")
    assert webapp._is_model_unusable("NOT_FOUND")


def test_an_ordinary_rate_limit_is_not_a_model_problem():
    # Otherwise a per-minute throttle would silently swap the analyst's model.
    assert not webapp._is_model_unusable(_PER_MINUTE)
    assert not webapp._is_model_unusable("401 Unauthorized")
    assert not webapp._is_model_unusable("connection reset by peer")


# ── model resolution ─────────────────────────────────────────────────────────

def test_model_can_be_overridden_from_the_environment(monkeypatch):
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3-flash-preview")
    assert webapp._model_for("gemini") == "gemini-3-flash-preview"


def test_default_model_is_the_first_candidate(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setattr(webapp, "_read_env", dict)
    assert webapp._model_for("gemini") == FIRST


def test_a_dead_model_is_never_resolved_again(monkeypatch):
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setattr(webapp, "_read_env", dict)
    webapp._mark_model_dead("gemini", FIRST)
    assert webapp._model_for("gemini") == SECOND


def test_next_model_walks_the_candidates_then_gives_up():
    assert webapp._next_model("gemini", FIRST) == SECOND
    for m in webapp._MODEL_CANDIDATES["gemini"]:
        webapp._mark_model_dead("gemini", m)
    assert webapp._next_model("gemini", FIRST) == ""
    # A provider with no candidate list simply has no alternative.
    assert webapp._next_model("groq", "llama-3.3-70b-versatile") == ""


# ── the streaming chat path ──────────────────────────────────────────────────

@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(webapp, "_configured_providers", lambda: ["gemini", "ollama"])
    monkeypatch.setattr(webapp, "_ollama_model", lambda: "qwen2.5:7b-instruct")
    monkeypatch.setattr(webapp, "_ollama_host", lambda: "http://localhost:11434")
    monkeypatch.setattr(webapp, "_read_env", dict)
    monkeypatch.setenv("GEMINI_API_KEY", "valid-key")
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setitem(webapp._AI_FORCED, "provider", None)

    with TestClient(create_app()) as c:
        webapp._jobs[_JOB] = {
            "status": "complete", "filename": "demo.pcap",
            "result": {"meta": {"filename": "demo.pcap", "size_mb": 1.0},
                       "risk": {"score": 20, "tier": "LOW"}, "events": [], "chains": []},
        }
        yield c
    webapp._jobs.pop(_JOB, None)


def _ask(c):
    return c.post(f"/api/chat/{_JOB}", json={"message": "who is scanning?", "history": []})


def test_chat_switches_model_not_provider_when_free_tier_is_zero(client, monkeypatch):
    seen = []

    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        seen.append((provider, model))
        if model == FIRST:
            raise RuntimeError(_ZERO_QUOTA)
        yield "answered by gemini on a model that has quota"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    events = _sse(_ask(client).text)

    assert seen == [("gemini", FIRST), ("gemini", SECOND)]
    assert _texts(events) == "answered by gemini on a model that has quota"
    # Nothing the analyst cares about changed: no notice, and Gemini stays healthy.
    assert _notices(events) == []
    assert webapp._cooldown_left("gemini") == 0
    assert "[DONE]" in events


def test_the_dead_model_is_not_retried_on_the_next_message(client, monkeypatch):
    calls = []

    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        calls.append(model)
        if model == FIRST:
            raise RuntimeError(_ZERO_QUOTA)
        yield "ok"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    _ask(client)
    calls.clear()
    _ask(client)
    assert calls == [SECOND]  # straight to the model that works


def test_provider_is_benched_only_once_every_model_is_exhausted(client, monkeypatch):
    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError(_ZERO_QUOTA)
        yield "local answer"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    events = _sse(_ask(client).text)

    assert _texts(events) == "local answer"
    assert _notices(events) == ["Google Gemini daily quota used up — answered by Local (Ollama)"]
    assert webapp._cooldown_left("gemini") > 3000
    assert all(not webapp._model_alive("gemini", m) for m in webapp._MODEL_CANDIDATES["gemini"])


def test_a_per_minute_rate_limit_still_benches_the_provider(client, monkeypatch):
    # Regression guard: only a *model-scoped* failure may swap the model.
    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        if provider == "gemini":
            raise RuntimeError(_PER_MINUTE)
        yield "local answer"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    events = _sse(_ask(client).text)

    assert "quota reached" in _notices(events)[0]
    assert 0 < webapp._cooldown_left("gemini") <= 42
    assert webapp._model_alive("gemini", FIRST)   # model untouched


def test_forced_gemini_model_override_is_never_swapped(client, monkeypatch):
    """An explicit GEMINI_MODEL is the analyst's choice — honour it."""
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3-flash-preview")
    seen = []

    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        seen.append(model)
        yield "ok"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    _ask(client)
    assert seen == ["gemini-3-flash-preview"]


# ── the non-streaming path (packet explain, AI report) ───────────────────────

@pytest.mark.anyio
async def test_collect_path_also_switches_model_before_switching_provider(monkeypatch):
    monkeypatch.setattr(webapp, "_configured_providers", lambda: ["gemini", "ollama"])
    monkeypatch.setattr(webapp, "_ollama_model", lambda: "qwen2.5:7b-instruct")
    monkeypatch.setattr(webapp, "_ollama_host", lambda: "http://localhost:11434")
    monkeypatch.setattr(webapp, "_read_env", dict)
    monkeypatch.setenv("GEMINI_API_KEY", "valid-key")
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.setitem(webapp._AI_FORCED, "provider", None)

    seen = []

    async def fake_stream(provider, key, model, system, context, messages, max_tokens=2048):
        seen.append((provider, model))
        if model == FIRST:
            raise RuntimeError(_ZERO_QUOTA)
        yield "explained"

    monkeypatch.setattr(webapp, "_stream_ai", fake_stream)
    out = await webapp._collect_ai_with_fallback("sys", "ctx", [{"role": "user", "content": "hi"}])

    assert out == "explained"
    assert seen == [("gemini", FIRST), ("gemini", SECOND)]
    assert webapp._cooldown_left("gemini") == 0


@pytest.fixture
def anyio_backend():
    return "asyncio"
