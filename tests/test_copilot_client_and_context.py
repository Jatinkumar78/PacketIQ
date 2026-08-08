"""The copilot's Anthropic client, provider adapter, and context builder.

No network call is made anywhere here: the Anthropic SDK is replaced with a
recording stub, so the request shape — prompt caching, temperature, system
blocks — is asserted directly. Getting the cache_control block wrong costs ~70%
more tokens on every message and would never show up as a failure.
"""


import pytest

from packetiq.copilot import client as copilot_client
from packetiq.copilot import context_builder as cb
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

TS = 1700000000.0


def _event(etype=EventType.PORT_SCAN, severity=Severity.HIGH, src="45.33.32.156",
           dst="192.168.1.50"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description="finding", dst_ip=dst, dst_port=445,
                          protocol="TCP", timestamp=TS, packet_count=10)


# ── Anthropic client ─────────────────────────────────────────────────────────

class _Stream:
    def __init__(self, chunks):
        self.text_stream = chunks

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Messages:
    def __init__(self, chunks=("Hello", " world"), content=None):
        self.chunks = chunks
        self.content = content
        self.calls = []

    def stream(self, **kw):
        self.calls.append(("stream", kw))
        return _Stream(self.chunks)

    def create(self, **kw):
        self.calls.append(("create", kw))
        blocks = self.content if self.content is not None else [
            type("Block", (), {"text": "A written report."})()]
        return type("Resp", (), {"content": blocks})()


class _Anthropic:
    last = None

    def __init__(self, api_key=None):
        self.api_key = api_key
        self.messages = _Messages()
        type(self).last = self


@pytest.fixture
def stub_sdk(monkeypatch):
    monkeypatch.setattr(copilot_client.anthropic, "Anthropic", _Anthropic)
    return _Anthropic


def test_a_missing_api_key_is_refused_with_actionable_guidance(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        copilot_client.CopilotClient()


def test_an_explicit_key_is_used_over_the_environment(stub_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    copilot_client.CopilotClient(api_key="explicit")

    assert _Anthropic.last.api_key == "explicit"


def test_the_environment_key_is_used_when_none_is_passed(stub_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    copilot_client.CopilotClient()

    assert _Anthropic.last.api_key == "from-env"


def test_the_capture_context_is_marked_for_prompt_caching(stub_sdk, monkeypatch):
    """Two system blocks: the role prompt uncached, the large capture context
    cached. Losing the cache_control marker is invisible except on the bill."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()
    c.load_context("=== CAPTURE STATS ===\n176,064 packets")

    assert len(c._system) == 2
    role, context = c._system
    assert "cache_control" not in role
    assert context["cache_control"] == {"type": "ephemeral"}
    assert "176,064 packets" in context["text"]


def test_streaming_without_a_context_is_refused(stub_sdk, monkeypatch):
    """Answering without the capture loaded is exactly how the copilot would
    start inventing findings."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()

    with pytest.raises(RuntimeError, match="load_context"):
        c.stream_message([{"role": "user", "content": "hi"}], lambda t: None)


def test_a_single_message_without_a_context_is_refused(stub_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()

    with pytest.raises(RuntimeError, match="load_context"):
        c.single_message("write the report")


def test_a_streamed_answer_is_delivered_chunk_by_chunk_and_returned_whole(stub_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()
    c.load_context("context")
    c._client.messages.chunks = ["The ", "host ", "was scanned."]

    seen = []
    full = c.stream_message([{"role": "user", "content": "what happened?"}], seen.append)

    assert seen == ["The ", "host ", "was scanned."]
    assert full == "The host was scanned."


def test_the_streaming_request_pins_a_low_temperature(stub_sdk, monkeypatch):
    """Grounding depends on it: a creative temperature is how an LLM starts
    describing findings the capture does not contain."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()
    c.load_context("context")
    c.stream_message([{"role": "user", "content": "hi"}], lambda t: None)

    _, kw = c._client.messages.calls[0]
    assert kw["temperature"] == copilot_client.TEMPERATURE
    assert kw["temperature"] <= 0.3
    assert kw["model"] == copilot_client.MODEL


def test_a_single_message_returns_the_first_text_block(stub_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()
    c.load_context("context")

    assert c.single_message("write the report") == "A written report."


def test_a_response_with_no_content_yields_an_empty_string(stub_sdk, monkeypatch):
    """The content union also covers thinking and tool-use blocks — indexing
    blindly would raise instead of degrading."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()
    c.load_context("context")
    c._client.messages.content = []

    assert c.single_message("write the report") == ""


def test_a_non_text_first_block_yields_an_empty_string(stub_sdk, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    c = copilot_client.CopilotClient()
    c.load_context("context")
    c._client.messages.content = [type("ToolUse", (), {"name": "search"})()]

    assert c.single_message("go") == ""


# ── API key discovery ────────────────────────────────────────────────────────

def test_the_api_key_is_read_from_the_environment_first(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-env")
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=from-file\n", encoding="utf-8")

    assert copilot_client.load_api_key() == "from-env"


def test_the_api_key_falls_back_to_a_dotenv_file(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / ".env").write_text('ANTHROPIC_API_KEY="from-file"\n', encoding="utf-8")

    assert copilot_client.load_api_key() == "from-file"


def test_a_dotenv_line_with_no_value_is_not_a_key(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY\nOTHER=x\n", encoding="utf-8")

    assert copilot_client.load_api_key() is None


def test_no_key_anywhere_is_none(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    assert copilot_client.load_api_key() is None


# ── Multi-provider adapter ───────────────────────────────────────────────────

def test_an_explicit_provider_choice_is_pinned(monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient
    from packetiq.webapp import app as webapp

    original = dict(webapp._AI_FORCED)
    try:
        MultiProviderClient(provider="ollama")
        assert webapp._AI_FORCED["provider"] == "ollama"
    finally:
        webapp._AI_FORCED.clear()
        webapp._AI_FORCED.update(original)


def test_the_model_label_says_so_when_no_provider_is_configured(monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient
    from packetiq.webapp import app as webapp

    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": None, "key": None, "model": None})
    c = MultiProviderClient()

    assert c.model_label == "no provider"
    assert c.available() is False


def test_the_model_label_names_the_provider_and_model(monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient
    from packetiq.webapp import app as webapp

    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": "ollama", "key": None,
                                           "model": "packetiq-net"})
    c = MultiProviderClient()

    assert "packetiq-net" in c.model_label
    assert c.available() is True


@pytest.mark.parametrize("method,args", [
    ("single_message", ("summarise",)),
    ("stream_message", ([{"role": "user", "content": "hi"}], lambda t: None)),
])
def test_the_adapter_refuses_to_answer_before_the_context_is_loaded(method, args):
    from packetiq.copilot.multi_provider import MultiProviderClient

    with pytest.raises(RuntimeError, match="load_context"):
        getattr(MultiProviderClient(), method)(*args)


def test_the_adapter_says_so_rather_than_failing_when_no_provider_exists(monkeypatch):
    """The interactive REPL must survive having no key at all — an exception
    here would kill the session on the user's first question."""
    from packetiq.copilot.multi_provider import MultiProviderClient
    from packetiq.webapp import app as webapp

    monkeypatch.setattr(webapp, "_detect_provider",
                        lambda skip=None: {"provider": None, "key": None, "model": None})

    c = MultiProviderClient()
    c.load_context("context")
    seen = []
    out = c.stream_message([{"role": "user", "content": "hi"}], seen.append)

    assert out == webapp._NO_PROVIDER_HINT
    assert seen == [webapp._NO_PROVIDER_HINT]


def test_an_empty_provider_response_moves_on_to_the_next_provider(monkeypatch):
    """A provider that returns nothing has failed, even without raising."""
    from packetiq.copilot.multi_provider import MultiProviderClient
    from packetiq.webapp import app as webapp

    providers = [{"provider": "gemini", "key": "k", "model": "g"},
                 {"provider": "ollama", "key": None, "model": "packetiq-net"}]

    def detect(skip=None):
        skip = skip or set()
        for p in providers:
            if p["provider"] not in skip:
                return p
        return {"provider": None, "key": None, "model": None}

    async def stream(provider, key, model, system, context, messages):
        if provider == "gemini":
            return
        for chunk in ("The host ", "was scanned."):
            yield chunk

    monkeypatch.setattr(webapp, "_detect_provider", detect)
    monkeypatch.setattr(webapp, "_stream_ai", stream)

    c = MultiProviderClient()
    c.load_context("context")
    seen = []
    out = c.stream_message([{"role": "user", "content": "hi"}], seen.append)

    assert out == "The host was scanned."
    assert any("switching to" in s for s in seen)


# ── Context builder ──────────────────────────────────────────────────────────

def _result_with_many_externals(n=60):
    r = ExtractionResult()
    r.capture_start, r.capture_end = TS, TS + 600
    r.total_packets, r.total_bytes = 5000, 4_000_000
    r.external_ips = {f"185.199.{i // 256}.{i % 256}" for i in range(n)}
    r.ip_dst_counts = {ip: 100 - i for i, ip in enumerate(sorted(r.external_ips))}
    return r


def test_a_long_external_ip_list_is_truncated_with_a_count():
    """Dumping 500 CDN addresses into the prompt buries the findings and burns
    the token budget the analysis actually needs."""
    text = cb._network_topology(_result_with_many_externals(60))

    assert "60 total, top 30 by volume" in text
    assert "… and 30 more external IPs" in text

    section = text.split("=== EXTERNAL IP CONTACTS")[1]
    listed = [ln for ln in section.splitlines() if ln.startswith("  185.199.")]
    assert len(listed) == cb._MAX_IP_LIST


def test_a_capture_with_no_findings_says_so_explicitly():
    """"None detected" is a fact the model can rely on; an empty section invites
    it to fill the gap."""
    assert "None detected" in cb._detection_events([])


def test_a_capture_with_no_chains_says_so_explicitly():
    assert "No multi-stage chains correlated" in cb._attack_chains([])


def test_the_ioc_summary_truncates_every_long_address_list():
    result = _result_with_many_externals(60)
    events = ([_event(src=f"45.33.32.{i}", dst=f"192.168.1.{i}") for i in range(40)])

    text = cb._ioc_summary(result, events, [])

    assert text.count("… and") >= 3, "attackers, targets and externals each cap"
    assert "Suspected Attacker IPs" in text
    assert "Targeted IPs" in text
