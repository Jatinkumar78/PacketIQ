"""One house style across the three report surfaces.

The PDF (packetiq.export.pdf_report), the HTML export (packetiq.export.html_report)
and the AI-written report (copilot prompt) must agree on what a PacketIQ report is
called, how its sections are numbered, and what it refuses to claim.
"""

from packetiq.copilot.prompts import SLASH_PROMPTS
from packetiq.export import report_style as st


def test_section_order_is_the_single_source_of_truth():
    assert st.SECTIONS[0] == "Executive Summary"
    assert st.SECTIONS[1] == "Scope & Methodology"
    assert st.SECTIONS[-1] == "Limitations & Assurance"
    assert len(st.SECTIONS) == 12
    assert len(set(st.SECTIONS)) == len(st.SECTIONS)      # no duplicates


def test_ai_report_prompt_uses_the_same_numbered_sections():
    prompt = SLASH_PROMPTS["report"]
    for i, title in enumerate(st.SECTIONS, 1):
        assert f"## {i}. {title}" in prompt, f"AI report is missing section {i}. {title}"


def test_ai_report_prompt_keeps_the_grounding_and_honesty_rules():
    prompt = SLASH_PROMPTS["report"]
    assert "verbatim" in prompt                            # no invented indicators
    assert "Not observed in this capture." in prompt       # no padding empty sections
    assert "detector certainty rather than proof" in prompt


def test_event_titles_preserve_acronyms():
    assert st.event_title("IOC_MATCH") == "IOC Match"
    assert st.event_title("DNS_TUNNELING") == "DNS Tunneling"
    assert st.event_title("JA3_ANOMALY") == "JA3 Anomaly"
    assert st.event_title("C2_BEACON") == "C2 Beacon"
    assert st.event_title("MALICIOUS_FILE") == "Malicious File"
    assert st.event_title("") == ""


def test_report_id_is_stable_and_derived_from_the_evidence():
    sha = "a" * 64
    first = st.report_id("capture.pcap", sha)
    assert first == st.report_id("capture.pcap", sha)       # stable within a day
    assert first.startswith("PIQ-")
    assert first.endswith("AAAAAAAA")                       # from the digest
    # A different capture yields a different reference even with no digest.
    assert st.report_id("a.pcap") != st.report_id("b.pcap")


def test_findings_are_ordered_by_severity_then_confidence():
    events = [
        {"severity": "LOW", "confidence": 99},
        {"severity": "CRITICAL", "confidence": 50},
        {"severity": "HIGH", "confidence": 60},
        {"severity": "HIGH", "confidence": 90},
    ]
    order = [(e["severity"], e["confidence"]) for e in st.sort_events(events)]
    assert order == [("CRITICAL", 50), ("HIGH", 90), ("HIGH", 60), ("LOW", 99)]


def test_protocol_mix_shares_sum_to_one_hundred():
    res = {"protocols": {"TCP": 75, "UDP": 25}}
    mix = st.protocol_mix(res)
    assert [name for name, _c, _p in mix] == ["TCP", "UDP"]
    assert round(sum(p for _n, _c, p in mix)) == 100


def test_recommendations_are_deduplicated_and_severity_ordered():
    events = [
        {"severity": "LOW", "confidence": 10, "recommendation": "Do the low thing."},
        {"severity": "CRITICAL", "confidence": 10, "recommendation": "Do the critical thing."},
        {"severity": "HIGH", "confidence": 10, "recommendation": "Do the critical thing."},  # dup
    ]
    assert st.recommendations(events) == ["Do the critical thing.", "Do the low thing."]


def test_limitations_text_refuses_to_overclaim():
    text = st.LIMITATIONS.lower()
    assert "not proof of compromise" in text
    assert "indicators, not identifications" in text
    assert "corroborate" in text
    assert "not attribution" in st.ATTRIBUTION_CAVEAT.lower()
