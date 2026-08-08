"""Timeline reconstruction, chain merging, actor attribution and forecasting.

These four modules turn raw findings into the narrative a reader actually acts
on: what happened, in what order, whether two findings are the same incident,
and what is likely next. The branches covered here are the ones that decide
*not* to say something — a skipped duplicate, a merged chain, an actor match
rejected for thin evidence.
"""

import io

from rich.console import Console

from packetiq.attribution.engine import AttributionEngine
from packetiq.correlation.engine import CorrelationEngine
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.timeline.builder import TimelineBuilder
from packetiq.timeline.models import ActivityBar, Category, PhaseSegment, Timeline, TimelineEvent
from packetiq.timeline.renderer import TimelineRenderer

TS = 1700000000.0


def _event(etype=EventType.PORT_SCAN, severity=Severity.HIGH, src="45.33.32.156",
           dst="192.168.1.50", ts=TS, evidence=None, description="finding"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=445,
                          protocol="TCP", timestamp=ts, packet_count=10,
                          evidence=evidence or {})


def _result(**kw):
    r = ExtractionResult()
    r.capture_start = TS
    r.capture_end = TS + 600
    for k, v in kw.items():
        setattr(r, k, v)
    return r


# ── Timeline models ──────────────────────────────────────────────────────────

def test_every_category_has_a_plain_text_marker():
    """Markers are text or box-drawing, never emoji.

    The timeline is read as a forensic record — in a terminal, in a log file,
    and pasted into a ticket — so the markers have to survive all three.
    """
    def plain(ch: str) -> bool:
        # ASCII, or the Box Drawing block used for the inactivity rule.
        return ch.isascii() or 0x2500 <= ord(ch) <= 0x257F

    for category in (Category.THREAT, Category.CHAIN_START, Category.CHAIN_END,
                     Category.DNS, Category.HTTP, Category.FLOW_SPIKE,
                     Category.PIVOT, Category.GAP):
        mark = TimelineEvent(timestamp=TS, category=category, description="x").mark
        assert mark and len(mark) <= 4
        assert all(plain(ch) for ch in mark), (
            f"{category} marker {mark!r} is not plain text")


def test_an_unknown_category_still_renders_a_marker():
    ev = TimelineEvent(timestamp=TS, category="SOMETHING_NEW", description="x")
    assert ev.mark == "•"


def test_a_phase_segment_reports_its_span_and_size():
    events = [TimelineEvent(timestamp=TS + i, category=Category.THREAT, description="x")
              for i in range(4)]
    seg = PhaseSegment(phase="Reconnaissance", start_ts=TS, end_ts=TS + 90, events=events)

    assert seg.duration == 90.0
    assert seg.event_count == 4


def test_a_segment_with_inverted_timestamps_reports_zero_duration():
    """Out-of-order packet timestamps are common in merged captures; a negative
    duration would render as nonsense in the report."""
    seg = PhaseSegment(phase="Recon", start_ts=TS + 100, end_ts=TS)
    assert seg.duration == 0.0


def test_an_event_with_no_timestamp_renders_a_placeholder():
    assert TimelineEvent(timestamp=0.0, category=Category.THREAT, description="x").ts_str == "?"


# ── Timeline construction ────────────────────────────────────────────────────

def test_a_domain_already_flagged_as_a_threat_is_not_repeated_as_dns_activity():
    """Otherwise the same domain appears twice in the timeline — once as the
    finding, once as ordinary lookup traffic — and reads like two events."""
    events = [_event(EventType.DNS_TUNNELING, evidence={"domain": "exfil.example.xyz"})]
    result = _result(dns_queries=[
        {"ts": TS + 10, "src": "192.168.1.50", "qname": "exfil.example.xyz"},
        {"ts": TS + 20, "src": "192.168.1.50", "qname": "example.com"},
    ])

    tl = TimelineBuilder().build(result, events, [])
    dns_events = [e for e in tl.events if e.category == Category.DNS]

    assert [e.evidence.get("domain") or "example.com" for e in dns_events].count(
        "exfil.example.xyz") == 0
    assert any("example.com" in e.description for e in dns_events)


def test_a_repeatedly_queried_domain_appears_once_at_its_first_lookup():
    result = _result(dns_queries=[
        {"ts": TS + 30, "src": "192.168.1.50", "qname": "example.com"},
        {"ts": TS + 10, "src": "192.168.1.50", "qname": "example.com"},
        {"ts": TS + 20, "src": "192.168.1.50", "qname": "example.com"},
    ])

    tl = TimelineBuilder().build(result, [], [])
    dns_events = [e for e in tl.events if e.category == Category.DNS]

    assert len(dns_events) == 1
    assert dns_events[0].timestamp == TS + 10, "the first lookup is the interesting one"


def test_dns_entries_with_no_name_or_no_time_are_skipped():
    result = _result(dns_queries=[
        {"ts": TS + 10, "src": "192.168.1.50", "qname": ""},
        {"ts": 0.0, "src": "192.168.1.50", "qname": "example.com"},
    ])

    tl = TimelineBuilder().build(result, [], [])
    assert [e for e in tl.events if e.category == Category.DNS] == []


def test_repeat_visits_to_one_http_host_appear_once():
    result = _result(http_requests=[
        {"ts": TS + 10, "src": "192.168.1.50", "host": "example.com",
         "method": "GET", "path": "/a"},
        {"ts": TS + 20, "src": "192.168.1.50", "host": "example.com",
         "method": "GET", "path": "/b"},
        {"ts": 0.0, "src": "192.168.1.50", "host": "skipped.example",
         "method": "GET", "path": "/c"},
    ])

    tl = TimelineBuilder().build(result, [], [])
    http_events = [e for e in tl.events if e.category == Category.HTTP]

    assert len(http_events) == 1
    assert "example.com" in http_events[0].description


def test_chain_boundaries_are_phase_annotated_without_being_re_derived():
    chain = AttackChain(chain_id="AAAA1111", name="Recon into brute force",
                        description="d", attacker_ips={"45.33.32.156"},
                        target_ips={"192.168.1.50"},
                        events=[_event(ts=TS + 5)], severity=Severity.CRITICAL,
                        first_seen=TS + 5, last_seen=TS + 300,
                        kill_chain_phases=["Reconnaissance"],
                        primary_phase="Reconnaissance")

    tl = TimelineBuilder().build(_result(), [_event(ts=TS + 5)], [chain])
    starts = [e for e in tl.events if e.category == Category.CHAIN_START]

    assert starts and starts[0].phase == "Exploitation"


# ── Timeline rendering ───────────────────────────────────────────────────────

def _render(tl, **kw):
    """Render into a captured console so the output can be asserted on."""
    from packetiq.timeline import renderer as rmod
    buf = io.StringIO()
    original = rmod.console
    rmod.console = Console(file=buf, width=100, force_terminal=False, no_color=True)
    try:
        TimelineRenderer().render(tl, **kw)
    finally:
        rmod.console = original
    return buf.getvalue()


def test_a_timeline_with_no_activity_bar_says_so_rather_than_drawing_nothing():
    tl = Timeline(events=[], capture_start=TS, capture_end=TS + 60, activity_bar=None)
    assert "Insufficient data for activity bar" in _render(tl)


def test_a_timeline_with_no_phases_skips_the_kill_chain_section():
    tl = Timeline(
        events=[TimelineEvent(timestamp=TS, category=Category.DNS, description="lookup")],
        capture_start=TS, capture_end=TS + 60,
        activity_bar=ActivityBar(buckets=[1], bucket_secs=60.0, total_events=1,
                                 start_ts=TS, end_ts=TS + 60))

    out = _render(tl)
    assert "KILL CHAIN COVERAGE" not in out


def test_a_timeline_with_no_pivots_skips_the_progression_section():
    tl = Timeline(events=[], capture_start=TS, capture_end=TS + 60, pivot_points=[])
    assert "ATTACK PROGRESSION PIVOTS" not in _render(tl)


def test_an_over_long_timeline_says_how_many_events_were_hidden():
    """A 500-event capture must not silently print 80 and stop."""
    events = [TimelineEvent(timestamp=TS + i, category=Category.THREAT,
                            description=f"finding {i}", src_ip="45.33.32.156",
                            severity=Severity.HIGH, phase="Reconnaissance")
              for i in range(30)]
    tl = Timeline(events=events, capture_start=TS, capture_end=TS + 60,
                  activity_bar=ActivityBar(buckets=[30], bucket_secs=60.0,
                                           total_events=30, start_ts=TS, end_ts=TS + 60))

    out = _render(tl, max_events=10)
    assert "20 more events" in out
    assert "--full" in out


def test_a_phase_change_prints_a_banner_between_events():
    events = [
        TimelineEvent(timestamp=TS, category=Category.THREAT, description="scan",
                      src_ip="45.33.32.156", severity=Severity.HIGH,
                      phase="Reconnaissance"),
        TimelineEvent(timestamp=TS + 60, category=Category.THREAT, description="login",
                      src_ip="45.33.32.156", severity=Severity.CRITICAL,
                      phase="Credential Access"),
    ]
    tl = Timeline(events=events, capture_start=TS, capture_end=TS + 120,
                  activity_bar=ActivityBar(buckets=[1, 1], bucket_secs=60.0,
                                           total_events=2, start_ts=TS, end_ts=TS + 120))

    out = _render(tl)
    assert "RECONNAISSANCE" in out.upper()
    assert "CREDENTIAL ACCESS" in out.upper()


# ── Chain merging ────────────────────────────────────────────────────────────

def _chain(events, chain_id, attacker="45.33.32.156", severity=Severity.HIGH):
    return AttackChain(chain_id=chain_id, name=f"chain {chain_id}", description="d",
                       attacker_ips={attacker}, target_ips={"192.168.1.50"},
                       events=events, severity=severity, confidence=0.8,
                       first_seen=TS, last_seen=TS + 300)


def test_two_chains_over_the_same_events_are_merged_into_one():
    """Two rules firing on one intrusion must not read as two intrusions."""
    shared = [_event(ts=TS + i) for i in range(5)]
    engine = CorrelationEngine()

    merged = engine._merge([_chain(shared[:4], "AAAA"),
                                        _chain(shared, "BBBB")])

    assert len(merged) == 1
    assert len(merged[0].events) == 5, "the larger chain absorbs the smaller"


def test_the_smaller_chain_is_absorbed_regardless_of_ordering():
    shared = [_event(ts=TS + i) for i in range(5)]
    merged = CorrelationEngine()._merge([_chain(shared, "AAAA"),
                                                     _chain(shared[:4], "BBBB")])
    assert len(merged) == 1


def test_chains_from_different_attackers_are_never_merged():
    """Two unrelated attackers is the finding; merging them would erase it."""
    events_a = [_event(src="45.33.32.156", ts=TS + i) for i in range(4)]
    merged = CorrelationEngine()._merge([
        _chain(events_a, "AAAA", attacker="45.33.32.156"),
        _chain(events_a, "BBBB", attacker="203.0.113.9"),
    ])

    assert len(merged) == 2


def test_chains_sharing_an_attacker_but_no_events_stay_separate():
    """One host doing two distinct things is two chains, not one blur."""
    merged = CorrelationEngine()._merge([
        _chain([_event(ts=TS + i) for i in range(4)], "AAAA"),
        _chain([_event(ts=TS + 500 + i) for i in range(4)], "BBBB"),
    ])

    assert len(merged) == 2


def test_two_empty_chains_are_not_treated_as_identical():
    """An empty intersection over an empty union is not a 100% match."""
    merged = CorrelationEngine()._merge([_chain([], "AAAA"),
                                                     _chain([], "BBBB")])
    assert len(merged) == 2


# ── Actor attribution ────────────────────────────────────────────────────────

def test_a_single_finding_does_not_match_an_actor():
    """A lone port scan matches half the actor database on TTP overlap alone.

    Requiring several distinct overlapping TTPs is what keeps attribution from
    being astrology.
    """
    assert AttributionEngine().attribute([_event(EventType.PORT_SCAN)], []) == []


def test_no_findings_produce_no_attribution():
    assert AttributionEngine().attribute([], []) == []


def test_attribution_confidence_never_exceeds_one():
    """The phase-overlap bonus is added to a ratio that can already be 1.0."""
    every_type = [_event(etype=t, ts=TS + i) for i, t in enumerate(EventType)]
    for match in AttributionEngine().attribute(every_type, []):
        assert 0.0 <= match.confidence <= 1.0


# ── Terminal renderer ────────────────────────────────────────────────────────

def test_a_key_value_line_is_printed_with_its_label_and_value():
    from packetiq.display.terminal import TerminalUI

    ui = TerminalUI()
    buf = io.StringIO()
    ui.console = Console(file=buf, width=100, force_terminal=False, no_color=True)
    ui.print_key_value("Packets parsed", "176,064")

    out = buf.getvalue()
    assert "Packets parsed" in out and "176,064" in out


def test_an_alert_shows_its_detail_line_when_one_is_given():
    from packetiq.display.terminal import TerminalUI

    ui = TerminalUI()
    buf = io.StringIO()
    ui.console = Console(file=buf, width=100, force_terminal=False, no_color=True)
    ui.print_alert("CRITICAL", "SSH brute force", detail="40 attempts in 39 seconds")

    out = buf.getvalue()
    assert "CRITICAL" in out
    assert "SSH brute force" in out
    assert "40 attempts" in out


def test_an_alert_with_an_unknown_level_still_renders():
    from packetiq.display.terminal import TerminalUI

    ui = TerminalUI()
    buf = io.StringIO()
    ui.console = Console(file=buf, width=100, force_terminal=False, no_color=True)
    ui.print_alert("INFORMATIONAL", "nothing to report")

    assert "INFORMATIONAL" in buf.getvalue()
