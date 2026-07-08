"""
Grounding guardrail — the deterministic post-filter that guarantees the copilot
never surfaces an ungrounded IP, MITRE technique ID or CVE, even when a small
local model tries to pad a list. These tests are fully offline (no LLM, no
network): they drive the real filter from `packetiq.webapp.app` directly.

The guarantee under test: for ANY streaming chunk boundaries, the reassembled
output (a) contains zero ungrounded entities, (b) keeps every grounded entity,
and (c) is byte-for-byte identical when the model was already faithful.
"""
from __future__ import annotations

import asyncio
import random

import pytest

from packetiq.webapp import app as A

CONTEXT = (
    "Attacker 45.33.32.156 hit victim 192.168.1.50. "
    "MITRE: T1110 Brute Force, T1046 Network Service Discovery, T1595. "
    "Exploited CVE-2021-44228."
)
QUESTION = [{"role": "user", "content": "which IPs and techniques?"}]

GROUNDED = {"45.33.32.156", "192.168.1.50", "T1110", "T1046", "T1595", "CVE-2021-44228"}
INVENTED = {"10.10.10.10", "T1505", "T1021.002", "CVE-2021-9999"}

PADDED_ANSWER = (
    "## Threat Summary\n"
    "The attacker 45.33.32.156 brute-forced 192.168.1.50; 10.10.10.10 also appeared.\n\n"
    "### MITRE ATT&CK Techniques\n"
    "- T1110 Brute Force\n"
    "- T1505 Server Software Component\n"      # invented
    "- T1046 Network Service Discovery\n"
    "- T1021.002 SMB/Windows Admin Shares\n"   # invented
    "- T1595 Active Scanning\n\n"
    "### CVEs\n"
    "This exploits CVE-2021-44228 and possibly CVE-2021-9999.\n"   # last is invented
)


def _allowed():
    return A._grounding_allowed(CONTEXT, QUESTION)


def _entities(text: str) -> set:
    return (A._gg_valid_ips(text)
            | {t.upper() for t in A._GG_TECH_RE.findall(text)}
            | {c.upper() for c in A._GG_CVE_RE.findall(text)})


def _run(text: str, splits) -> str:
    gf = A._GroundingFilter(_allowed())
    out, prev = [], 0
    for s in sorted(splits):
        out.append(gf.feed(text[prev:s]))
        prev = s
    out.append(gf.feed(text[prev:]))
    out.append(gf.flush())
    return "".join(out)


def test_allowed_set_extraction():
    a = _allowed()
    assert a["ips"] == {"45.33.32.156", "192.168.1.50"}
    assert a["techniques"] == {"T1110", "T1046", "T1595"}
    assert a["cves"] == {"CVE-2021-44228"}


def test_invented_entities_are_removed_and_grounded_kept():
    out = _run(PADDED_ANSWER, set())
    ents = _entities(out)
    assert INVENTED.isdisjoint(ents)
    assert GROUNDED <= ents


def test_faithful_across_all_chunk_boundaries():
    """Whatever the streaming split, the result is faithful and deterministic."""
    random.seed(7)
    outputs = set()
    for _ in range(200):
        k = random.randint(0, 15)
        splits = {random.randint(1, len(PADDED_ANSWER) - 1) for _ in range(k)}
        out = _run(PADDED_ANSWER, splits)
        assert INVENTED.isdisjoint(_entities(out))
        assert GROUNDED <= _entities(out)
        outputs.add(out)
    assert len(outputs) == 1  # boundary-independent


def test_char_by_char_streaming():
    out = _run(PADDED_ANSWER, set(range(1, len(PADDED_ANSWER))))
    assert INVENTED.isdisjoint(_entities(out))
    assert GROUNDED <= _entities(out)


def test_padded_list_items_dropped_whole():
    out = _run(PADDED_ANSWER, set())
    assert "T1505" not in out and "Server Software Component" not in out
    assert "T1021.002" not in out and "SMB/Windows Admin Shares" not in out
    assert "- T1110 Brute Force" in out
    assert "- T1046 Network Service Discovery" in out


def test_mixed_bullet_keeps_grounded_drops_invented():
    """A bullet mixing a grounded and an invented technique must keep the real one
    (never hide evidence) while stripping the invention."""
    text = "- T1110 Brute Force and T1505 Server Software Component were seen\n"
    out = _run(text, set())
    assert "T1110" in out          # grounded → kept
    assert "T1505" not in out      # invented → removed
    assert out.strip() != "-"      # line not left as a bare bullet


def test_faithful_answer_passes_through_byte_for_byte():
    clean = ("Attacker 45.33.32.156 targeted 192.168.1.50 via T1110 and T1046.\n"
             "See CVE-2021-44228 for the exploit.\n")
    assert _run(clean, {5, 20, 44, 61}) == clean


def test_non_ip_dotted_numbers_untouched():
    """Version-like dotted numbers aren't valid IPs and must not be redacted."""
    text = "PacketIQ v1.2.3.4 parsed 45.33.32.156 traffic.\n"
    out = _run(text, set())
    assert "v1.2.3.4" in out           # not a real IP, left alone
    assert "45.33.32.156" in out       # grounded IP kept


def test_lowercase_cve_is_matched():
    text = "Also cve-2021-9999 is referenced.\n"   # invented, lowercased
    assert "cve-2021-9999" not in _run(text, set()).lower()


def _drain(agen):
    async def go():
        return [c async for c in agen]
    return asyncio.run(go())


def test_stream_ai_applies_guard(monkeypatch):
    """End-to-end through _stream_ai: a raw provider that emits an invented
    technique has it stripped before the caller sees it."""
    async def fake_raw(provider, key, model, system, context, messages):
        for piece in ["Techniques:\n", "- T1110 Brute Force\n",
                      "- T1505 Invented Thing\n", "- T1046 Discovery\n"]:
            yield piece

    monkeypatch.setattr(A, "_stream_ai_raw", fake_raw)
    monkeypatch.setenv("PACKETIQ_GROUNDING_GUARD", "1")
    chunks = _drain(A._stream_ai("ollama", "h", "m", "sys", CONTEXT, QUESTION))
    full = "".join(chunks)
    assert "T1505" not in full
    assert "T1110" in full and "T1046" in full


def test_guard_can_be_disabled(monkeypatch):
    async def fake_raw(provider, key, model, system, context, messages):
        yield "- T1505 Invented\n"

    monkeypatch.setattr(A, "_stream_ai_raw", fake_raw)
    monkeypatch.setenv("PACKETIQ_GROUNDING_GUARD", "0")
    full = "".join(_drain(A._stream_ai("ollama", "h", "m", "sys", CONTEXT, QUESTION)))
    assert "T1505" in full   # disabled → raw passthrough


@pytest.mark.parametrize("flag,expected", [
    ("1", True), ("0", False), ("false", False), ("off", False), ("yes", True),
])
def test_gg_enabled_flag(monkeypatch, flag, expected):
    monkeypatch.setenv("PACKETIQ_GROUNDING_GUARD", flag)
    assert A._gg_enabled() is expected
