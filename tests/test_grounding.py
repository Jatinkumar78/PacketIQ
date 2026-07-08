"""The copilot must be grounded: evidence-only system prompts and a low
temperature so explanations stay tied to the analysis, not invented."""

from packetiq.copilot import client, prompts
from packetiq.webapp import app as webapp


def test_web_chat_system_has_grounding_rules():
    s = webapp._CHAT_SYSTEM
    assert "GROUNDING RULES" in s
    assert "not present in this capture" in s.lower()
    assert "never invent" in s.lower() or "do not invent" in s.lower()


def test_cli_role_prompt_has_grounding_rules():
    s = prompts.ROLE_PROMPT
    assert "GROUNDING RULES" in s
    assert "not present in this capture" in s.lower()


def test_low_temperature_everywhere():
    # Grounding relies on a low sampling temperature across web + CLI copilots.
    assert webapp._AI_TEMPERATURE <= 0.2
    assert client.TEMPERATURE <= 0.2


def test_packet_explain_prompt_is_grounded():
    # The single-packet explainer must not invent fields it wasn't shown.
    import inspect
    src = inspect.getsource(webapp.create_app)
    assert "do not invent" in src.lower()
