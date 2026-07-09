"""Local-LLM latency/accuracy knobs: the model must stay warm between requests
(keep_alive), the context window must be sized to the prompt (so grounded PCAP
context isn't silently truncated), and we only preload the model when Ollama is
actually the provider that will serve requests.
"""

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
    # never blows past the memory cap
    assert webapp._ollama_num_ctx(10_000_000, 2048) == 8192


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


def test_warm_runs_once_per_model(monkeypatch):
    calls = []
    monkeypatch.setattr(webapp, "_read_env", lambda: {})

    class _FakeThread:
        def __init__(self, target=None, daemon=None):
            self._t = target

        def start(self):
            calls.append(1)          # don't actually hit the network

    monkeypatch.setattr(webapp.threading, "Thread", _FakeThread)
    webapp._OLLAMA_WARMED.discard("qwen2.5:7b-instruct")
    webapp._ollama_warm("qwen2.5:7b-instruct", "http://localhost:11434")
    webapp._ollama_warm("qwen2.5:7b-instruct", "http://localhost:11434")
    assert len(calls) == 1           # second call is a no-op (already warmed)
