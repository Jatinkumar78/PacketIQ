"""The local copilot must be reproducible.

Ollama seeds its sampler randomly unless told otherwise, so the same capture
produced differently-worded prose on every run. The copilot's text goes into a
forensic report, so re-running an analysis has to yield the same words. We pin
the seed by default and let `OLLAMA_SEED=random` opt back out.
"""

import pytest

from packetiq.webapp import app as webapp


@pytest.fixture(autouse=True)
def _no_dotenv(monkeypatch):
    # Isolate from the developer's real .env.
    monkeypatch.setattr(webapp, "_read_env", dict)
    monkeypatch.delenv("OLLAMA_SEED", raising=False)


def test_seed_is_pinned_by_default():
    assert webapp._ollama_seed() == webapp._OLLAMA_DEFAULT_SEED


def test_seed_can_be_pinned_to_a_chosen_value(monkeypatch):
    monkeypatch.setenv("OLLAMA_SEED", "1234")
    assert webapp._ollama_seed() == 1234


def test_sampling_variety_can_be_restored(monkeypatch):
    for value in ("random", "none", "off", "RANDOM"):
        monkeypatch.setenv("OLLAMA_SEED", value)
        assert webapp._ollama_seed() is None


def test_a_nonsense_seed_falls_back_to_the_default(monkeypatch):
    monkeypatch.setenv("OLLAMA_SEED", "not-a-number")
    assert webapp._ollama_seed() == webapp._OLLAMA_DEFAULT_SEED


@pytest.mark.anyio
async def test_the_seed_reaches_the_ollama_request(monkeypatch):
    """Guards the wiring, not just the helper: a seed nobody sends is useless."""
    sent: dict = {}

    class _Resp:
        status_code = 200

        async def aiter_lines(self):
            yield '{"message":{"content":"ok"},"done":true}'

        async def aread(self):
            return b""

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Client:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, json=None):
            sent.update(json or {})
            return _Resp()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    chunks = [c async for c in webapp._stream_ai_raw(
        "ollama", "http://localhost:11434", "qwen2.5:7b-instruct",
        "system", "context", [{"role": "user", "content": "hi"}], 256)]

    assert "".join(chunks) == "ok"
    assert sent["options"]["seed"] == webapp._OLLAMA_DEFAULT_SEED
    assert sent["options"]["num_predict"] == 256
    assert sent["options"]["temperature"] == webapp._AI_TEMPERATURE


@pytest.mark.anyio
async def test_random_seed_sends_no_seed_at_all(monkeypatch):
    monkeypatch.setenv("OLLAMA_SEED", "random")
    sent: dict = {}

    class _Resp:
        status_code = 200

        async def aiter_lines(self):
            yield '{"message":{"content":"ok"},"done":true}'

        async def aread(self):
            return b""

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    class _Client:
        def __init__(self, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def stream(self, method, url, json=None):
            sent.update(json or {})
            return _Resp()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    [c async for c in webapp._stream_ai_raw(
        "ollama", "http://localhost:11434", "qwen2.5:7b-instruct",
        "system", "context", [{"role": "user", "content": "hi"}], 256)]

    assert "seed" not in sent["options"]


@pytest.fixture
def anyio_backend():
    return "asyncio"
