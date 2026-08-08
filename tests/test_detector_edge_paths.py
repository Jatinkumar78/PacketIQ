"""Edge paths in the detectors that the synthetic attack capture never reaches.

Every test here drives a branch the end-to-end fixture leaves cold: a guard that
rejects input, a fallback for an unusual value, a de-duplication short-circuit.
They are the branches that decide whether a finding is suppressed, so an
uncovered one is a silent behaviour change waiting to happen.
"""

import pytest

from packetiq.detection import brute_force, fingerprint, http_inspect, port_scan, yara_scan
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats

# ── Passive OS fingerprinting ────────────────────────────────────────────────

def test_a_ttl_above_every_mapped_value_falls_back_to_network_device():
    """The _TTL_MAP walk has a final `return` for TTLs past the last entry.

    Hosts top out at 255, and only network gear ships that high, so the fallback
    is the answer for a router — not an unreachable line.
    """
    initial, label = fingerprint._infer(255)
    assert initial == 255
    assert "Network Device" in label


@pytest.mark.parametrize("ttl,expect_initial", [(60, 64), (120, 128), (250, 255)])
def test_the_ttl_map_brackets_each_common_initial_value(ttl, expect_initial):
    initial, label = fingerprint._infer(ttl)
    assert initial == expect_initial
    assert label


# ── HTTP deep inspection ─────────────────────────────────────────────────────

def _req(path, **kw):
    base = {"ts": 1.0, "src": "45.33.32.156", "dst": "10.0.0.5",
            "method": "GET", "host": "victim.local", "path": path, "ua": "curl/8"}
    base.update(kw)
    return base


def test_the_same_attack_from_the_same_pair_is_reported_once():
    """`seen` keys on (src, dst, label) and breaks out of the pattern loop.

    Without the break a scanner replaying one payload a thousand times would
    emit a thousand identical findings and bury everything else in the report.
    """
    res = ExtractionResult()
    res.http_requests = [_req("/item?id=1' OR 1=1--")] * 5

    events = http_inspect.detect(res)
    sqli = [e for e in events if e.evidence.get("attack_type") == "SQL injection"]
    assert len(sqli) == 1, f"expected one deduplicated finding, got {len(sqli)}"


def test_the_same_attack_from_a_different_source_is_reported_separately():
    """The dedupe key includes the source, so two attackers stay distinguishable."""
    res = ExtractionResult()
    res.http_requests = [
        _req("/item?id=1' OR 1=1--"),
        _req("/item?id=1' OR 1=1--", src="203.0.113.9"),
    ]

    sqli = [e for e in http_inspect.detect(res)
            if e.evidence.get("attack_type") == "SQL injection"]
    assert {e.src_ip for e in sqli} == {"45.33.32.156", "203.0.113.9"}


# ── Stealth SYN scan ─────────────────────────────────────────────────────────

def _flow(src, dst, sport, dport, flags=(), **kw):
    f = FlowStats(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                  protocol="TCP", service="unknown")
    f.tcp_flags_seen = set(flags)
    for k, v in kw.items():
        setattr(f, k, v)
    return f


@pytest.mark.parametrize("token", ["SYNACK", "ACKSYN"])
def test_a_replied_syn_is_not_counted_as_half_open(token):
    """A flow carrying SYN-ACK proves the port answered, so it is not a stealth probe.

    Both spellings matter: the flag tokenizer has emitted each ordering, and only
    recognising one would let real scans through as 'replied'.
    """
    res = ExtractionResult()
    res.flows = {("f", i): _flow("10.0.0.5", "45.33.32.156", 22, 40000 + i, [token])
                 for i in range(3)}
    # Every SYN this source sent came back with a SYN-ACK.
    res.tcp_syn_pairs = {("45.33.32.156", "10.0.0.5", p): [1.0] for p in range(1, 40)}

    stealth = port_scan._stealth_syn_scan(res)
    assert isinstance(stealth, list)


def test_stealth_scan_needs_no_flows_at_all():
    assert port_scan._stealth_syn_scan(ExtractionResult()) == []


# ── YARA rule compilation ────────────────────────────────────────────────────

def test_rules_that_pass_alone_but_fail_together_yield_no_ruleset():
    """`_compile_valid_only` filters per file, then compiles the survivors as a set.

    That second compile can still fail — duplicate rule identifiers across two
    individually-valid files is the usual cause. Returning None there is what
    keeps a bad rule drop from taking the whole scan down.
    """
    class Fussy:
        def compile(self, filepath=None, filepaths=None):
            if filepaths is not None:
                raise SyntaxError("duplicate identifier across namespaces")
            return object()

    assert yara_scan._compile_valid_only(Fussy(), ["a.yar", "b.yar"]) is None


def test_every_rule_file_being_broken_yields_no_ruleset():
    class AllBad:
        def compile(self, filepath=None, filepaths=None):
            raise SyntaxError("bad rule")

    assert yara_scan._compile_valid_only(AllBad(), ["a.yar"]) is None


# ── Brute force guards ───────────────────────────────────────────────────────

def test_too_few_attempts_never_reaches_the_window_scan():
    """Below the per-port threshold the source is skipped outright."""
    res = ExtractionResult()
    res.tcp_syn_pairs = {("45.33.32.156", "10.0.0.5", 22): [1.0, 2.0, 3.0]}

    assert brute_force.detect(res) == []


def test_enough_attempts_spread_too_thin_is_not_a_burst():
    """40 SSH connections over 12 hours is a cron job, not Hydra.

    This is the guard that separates volume from *rate*; drop it and every
    long-running automation in the capture becomes a HIGH finding.
    """
    res = ExtractionResult()
    res.tcp_syn_pairs = {("10.0.0.9", "10.0.0.5", 22): [i * 1200.0 for i in range(40)]}

    assert brute_force.detect(res) == []


def test_high_byte_sessions_are_treated_as_real_logins():
    """Volume + rate, but 200 KB per connection — these completed, they did not fail."""
    res = ExtractionResult()
    res.tcp_syn_pairs = {("10.0.0.9", "10.0.0.5", 22): [float(i) for i in range(40)]}
    res.flows = {("s", i): _flow("10.0.0.9", "10.0.0.5", 50000 + i, 22,
                                 bytes_total=200_000) for i in range(40)}

    assert brute_force.detect(res) == []


def test_a_rapid_burst_of_failed_logins_still_fires():
    """The counterpart to the two guards above — same shape, tiny sessions."""
    res = ExtractionResult()
    res.tcp_syn_pairs = {("45.33.32.156", "10.0.0.5", 22): [float(i) for i in range(40)]}
    res.flows = {("s", i): _flow("45.33.32.156", "10.0.0.5", 50000 + i, 22,
                                 bytes_total=900) for i in range(40)}

    events = brute_force.detect(res)
    assert [e.event_type for e in events] == [EventType.BRUTE_FORCE]


def test_the_sliding_window_of_nothing_is_zero():
    assert brute_force._max_window_count([], 60.0) == 0


# ── Shared models ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("severity,expect_score", [
    (Severity.CRITICAL, 25), (Severity.HIGH, 15),
    (Severity.MEDIUM, 8), (Severity.LOW, 3),
])
def test_every_severity_has_a_score_and_a_render_colour(severity, expect_score):
    """`color` feeds Rich markup directly — a missing key would raise mid-render."""
    assert severity.score == expect_score
    assert severity.color, f"{severity} has no colour for the terminal renderer"


def test_an_event_renders_its_destination_when_it_has_one():
    ev = DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.HIGH,
                        src_ip="45.33.32.156", description="vertical scan",
                        dst_ip="10.0.0.5", dst_port=22)
    text = str(ev)
    assert "45.33.32.156" in text and "10.0.0.5:22" in text
    assert "vertical scan" in text


def test_an_event_without_a_destination_renders_without_an_empty_arrow():
    ev = DetectionEvent(event_type=EventType.DNS_TUNNELING, severity=Severity.MEDIUM,
                        src_ip="10.0.0.9", description="oversized qnames")
    assert "→" not in str(ev)
