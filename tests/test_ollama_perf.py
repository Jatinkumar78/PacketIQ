"""Local-LLM latency/accuracy knobs: the model must stay warm between requests
(keep_alive), the context window must be sized to the prompt (so grounded PCAP
context isn't silently truncated), and we only preload the model when Ollama is
actually the provider that will serve requests.
"""

import pytest

from packetiq.webapp import app as webapp


def test_keep_alive_default_and_override(monkeypatch):
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.delenv("OLLAMA_KEEP_ALIVE", raising=False)
    assert webapp._ollama_keep_alive() == "30m"          # not the 5m default that reloads
    monkeypatch.setenv("OLLAMA_KEEP_ALIVE", "-1")
    assert webapp._ollama_keep_alive() == "-1"


def test_num_ctx_grows_with_prompt_but_is_capped(monkeypatch):
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.delenv("OLLAMA_NUM_CTX", raising=False)
    # tiny prompt → smallest window
    assert webapp._ollama_num_ctx(200, 512) == 2048
    # big grounded context → larger window (not the truncating default)
    assert webapp._ollama_num_ctx(20000, 900) > 2048
    # an evidence-rich capture (e.g. donbot: ~34k chars ≈ 9.5k tokens) fits the
    # window fully rather than being truncated
    assert webapp._ollama_num_ctx(34000, 900) == 16384
    # never blows past the memory cap (16384 default; keeps a 7B model laptop-sized)
    assert webapp._ollama_num_ctx(10_000_000, 2048) == 16384


def test_num_ctx_cap_is_configurable(monkeypatch):
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setenv("OLLAMA_NUM_CTX", "4096")
    assert webapp._ollama_num_ctx(10_000_000, 2048) == 4096


def test_warm_only_when_ollama_will_be_used(monkeypatch):
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    for _, envname, _ in webapp._PROVIDER_SPECS:
        monkeypatch.delenv(envname, raising=False)
    monkeypatch.setitem(webapp._AI_FORCED, "provider", None)
    assert webapp._ollama_should_warm() is True           # no cloud key → Ollama serves

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    assert webapp._ollama_should_warm() is False           # cloud key wins → don't load 7B

    monkeypatch.setitem(webapp._AI_FORCED, "provider", "ollama")
    assert webapp._ollama_should_warm() is True            # explicit override
    monkeypatch.setitem(webapp._AI_FORCED, "provider", None)


def test_a_force_selected_cloud_provider_skips_the_local_preload(monkeypatch):
    """Picking Gemini/Groq/Anthropic by hand answers the question on its own — no
    need to read the environment, and certainly no reason to pull a 7B model into
    memory for a provider that will not serve the request.

    This early return was reached only through `/api/ai/status`, which consults
    `_ollama_should_warm` *only when the daemon answers the probe*. That made it a
    line about the developer's machine rather than about the code: covered wherever
    `ollama serve` happens to be running, missing on every runner.
    """
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    for provider in ("gemini", "groq", "anthropic"):
        monkeypatch.setitem(webapp._AI_FORCED, "provider", provider)
        assert webapp._ollama_should_warm() is False


def test_warm_runs_once_per_model(monkeypatch):
    calls = []
    monkeypatch.setattr(webapp, "_read_env", lambda: {})

    class _FakeThread:
        def __init__(self, target=None, daemon=None):
            self._t = target

        def start(self):
            calls.append(1)          # don't actually hit the network

    monkeypatch.setattr(webapp.threading, "Thread", _FakeThread)
    monkeypatch.setattr(webapp, "_OLLAMA_WARMED", set())
    webapp._ollama_warm("qwen2.5:7b-instruct", "http://localhost:11434")
    webapp._ollama_warm("qwen2.5:7b-instruct", "http://localhost:11434")
    assert len(calls) == 1           # second call is a no-op (already warmed)


def test_the_preload_request_loads_the_model_with_the_keep_alive(monkeypatch):
    """What the warm-up thread actually sends.

    `test_warm_runs_once_per_model` replaces `Thread` and never calls the target,
    so the request body was only ever executed for real — against the `ollama serve`
    listening on this developer's loopback, which the old network guard allowed
    through. Three statements therefore passed here and failed on a runner with
    nothing on 11434. Run the same target against a stubbed transport instead, and
    assert the payload rather than the fact that something happened.
    """
    import httpx

    sent = {}

    def fake_post(url, **kw):
        sent["url"] = url
        sent["json"] = kw.get("json")

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.delenv("OLLAMA_KEEP_ALIVE", raising=False)
    monkeypatch.setattr(webapp, "_OLLAMA_WARMED", set())

    captured = {}

    class _RunningThread:
        def __init__(self, target=None, daemon=None):
            captured["target"] = target

        def start(self):
            captured["target"]()

    monkeypatch.setattr(webapp.threading, "Thread", _RunningThread)

    webapp._ollama_warm("qwen2.5:7b-instruct", "http://localhost:11434/")

    # The trailing slash on the host must not survive into the URL.
    assert sent["url"] == "http://localhost:11434/api/chat"
    assert sent["json"]["model"] == "qwen2.5:7b-instruct"
    assert sent["json"]["keep_alive"] == "30m"      # the point of warming at all
    assert sent["json"]["options"]["num_predict"] == 1   # load the weights, generate nothing


def test_the_status_endpoint_preloads_the_model_that_will_answer(monkeypatch):
    """`/api/ai/status` is what the GUI polls, and it doubles as the trigger for the
    preload so the user's first question is not the one that waits for a cold 7B
    model. The call is guarded by a live probe, so it only ever ran on a machine
    with the daemon up — stub the probe and assert the wiring directly.
    """
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setattr(webapp, "_ollama_probe",
                        lambda *a, **kw: {"up": True, "models": ["qwen2.5:7b-instruct"]})
    monkeypatch.setattr(webapp, "_ollama_should_warm", lambda: True)
    warmed = []
    monkeypatch.setattr(webapp, "_ollama_warm", lambda model, host: warmed.append((model, host)))

    payload = webapp._ai_status_payload()

    assert warmed == [(webapp._ollama_model(), webapp._ollama_host())]
    assert payload["ollama"]["available"] is True
    assert payload["ollama"]["models"] == ["qwen2.5:7b-instruct"]


def test_the_status_endpoint_does_not_preload_when_the_daemon_is_down(monkeypatch):
    """The mirror case, and the one every CI runner is in: no daemon, no warm-up."""
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setattr(webapp, "_ollama_probe", lambda *a, **kw: {"up": False, "models": []})
    monkeypatch.setattr(webapp, "_ollama_warm",
                        lambda model, host: pytest.fail("nothing to warm when the daemon is down"))

    assert webapp._ai_status_payload()["ollama"]["available"] is False


def test_a_preload_failure_is_swallowed(monkeypatch):
    """A daemon that is down must not surface as an error in the status endpoint —
    the warm-up is an optimisation, not a feature."""
    import httpx

    def refuse(url, **kw):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", refuse)
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setattr(webapp, "_OLLAMA_WARMED", set())

    class _RunningThread:
        def __init__(self, target=None, daemon=None):
            self._t = target

        def start(self):
            self._t()

    monkeypatch.setattr(webapp.threading, "Thread", _RunningThread)

    webapp._ollama_warm("qwen2.5:7b-instruct", "http://localhost:11434")   # must not raise
