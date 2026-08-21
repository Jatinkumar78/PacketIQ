"""Our provider calls, bound to the SDK signatures actually installed.

Every provider SDK is stubbed elsewhere in the suite, which is what makes those
tests fast and offline — and is also what let this through: `anthropic` 1.0.0
removed `temperature` from the Messages API, the stubs accepted it happily
because they take `**kwargs`, and 1,802 tests stayed green while the real
Anthropic provider would have raised `TypeError` on the first question for
anyone who had installed from a clean environment.

The type gate caught it in `copilot/client.py` and nowhere else: in
`webapp/app.py` the client is annotated `Any`, because one name is rebound to
four different SDKs in that function, so mypy could not see the call. That half
would have reached users as a runtime failure.

So these bind the exact keyword set each call site sends against the installed
SDK's real signature. `Signature.bind_partial` raises `TypeError` for a keyword
the function does not accept, which is precisely the failure being guarded —
without a key, a network call, or a stub in the way. A provider SDK that drops
or renames a parameter now fails pytest on every platform, not just mypy on one.
"""

import inspect
import warnings

import pytest

from packetiq.copilot import client as copilot_client


def _accepts(func, **kwargs) -> None:
    """Fail with a readable message if `func` will not take these keywords."""
    try:
        inspect.signature(func).bind_partial(**kwargs)
    except TypeError as exc:                       # pragma: no cover - only on drift
        pytest.fail(
            f"{func.__qualname__} no longer accepts what PacketIQ sends: {exc}. "
            "The installed SDK changed under the call site — update the call, do "
            "not loosen this test."
        )


# ── Anthropic ────────────────────────────────────────────────────────────────

def test_the_sync_streaming_call_matches_the_installed_anthropic_sdk():
    """`CopilotClient.stream_message` — used by `packetiq chat` and `report`."""
    from anthropic.resources.messages import Messages

    _accepts(Messages.stream, model="m", max_tokens=1, system=[], messages=[],
             **copilot_client._sampling_kwargs())


def test_the_single_shot_call_matches_the_installed_anthropic_sdk():
    """`CopilotClient.single_message` — used by report generation."""
    from anthropic.resources.messages import Messages

    _accepts(Messages.create, model="m", max_tokens=1, system=[], messages=[],
             **copilot_client._sampling_kwargs())


def test_the_web_apps_async_streaming_call_matches_the_installed_anthropic_sdk():
    """The arm mypy cannot check, because its client is annotated `Any`."""
    from anthropic.resources.messages import AsyncMessages

    _accepts(AsyncMessages.stream, model="m", max_tokens=1, system=[], messages=[],
             **copilot_client._sampling_kwargs())


def test_the_temperature_probe_answers_for_the_sdk_that_is_installed():
    """The probe is the whole mechanism: if it disagrees with the SDK in front of
    it, one of the two calls above sends a parameter that raises."""
    from anthropic.resources.messages import Messages

    really_supported = "temperature" in inspect.signature(Messages.create).parameters
    copilot_client.anthropic_supports_temperature.cache_clear()
    assert copilot_client.anthropic_supports_temperature() is really_supported
    assert ("temperature" in copilot_client._sampling_kwargs()) is really_supported


@pytest.mark.parametrize("supported", [True, False])
def test_sampling_kwargs_follow_the_probe(monkeypatch, supported):
    """Both answers, whichever major happens to be installed on this machine."""
    monkeypatch.setattr(copilot_client, "anthropic_supports_temperature", lambda: supported)
    assert copilot_client._sampling_kwargs() == (
        {"temperature": copilot_client.TEMPERATURE} if supported else {})


# ── Groq ─────────────────────────────────────────────────────────────────────

def test_the_groq_call_matches_the_installed_sdk():
    from groq.resources.chat.completions import AsyncCompletions

    _accepts(AsyncCompletions.create, model="m", messages=[], max_tokens=1,
             temperature=0.15, stream=True)


# ── Gemini ───────────────────────────────────────────────────────────────────

def test_the_gemini_call_and_config_match_the_installed_sdk():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from google.genai import types as gtypes
        from google.genai.models import AsyncModels

    _accepts(AsyncModels.generate_content_stream, model="m", contents=[], config=None)
    fields = set(gtypes.GenerateContentConfig.model_fields)
    for name in ("system_instruction", "max_output_tokens", "temperature"):
        assert name in fields, (
            f"GenerateContentConfig no longer has {name!r}; the Gemini arm sets it")
