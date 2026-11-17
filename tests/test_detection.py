"""
Detector tests — assert that each detector fires on the synthetic attack
capture and that benign traffic is not over-flagged.
"""

from packetiq.detection import dns_anomaly, protocol_misuse
from packetiq.detection.models import EventType


def _types(events):
    return {e.event_type for e in events}


def test_brute_force_detected(pipeline):
    bf = [e for e in pipeline["events"] if e.event_type == EventType.BRUTE_FORCE]
    assert bf, "SSH brute force should be detected"
    assert any(e.dst_port == 22 for e in bf)


def test_port_and_host_scan_detected(pipeline):
    types = _types(pipeline["events"])
    assert EventType.PORT_SCAN in types, "vertical/stealth scan should be detected"
    assert EventType.HOST_SCAN in types, "horizontal host scan should be detected"


def test_xmas_scan_detected(pipeline):
    """Regression: XMAS (FIN+PSH+URG) was missed due to a flag-order bug."""
    flags = [e for e in pipeline["events"] if e.event_type == EventType.SUSPICIOUS_FLAGS]
    assert flags, "XMAS scan should be detected"
    assert any(e.evidence.get("scan_type") == "XMAS" for e in flags)


def test_c2_beacon_detected(pipeline):
    beacons = [e for e in pipeline["events"] if e.event_type == EventType.C2_BEACON]
    assert beacons, "regular C2 beacon should be detected"
    assert beacons[0].evidence["cv"] < 0.25


def test_dns_tunneling_detected(pipeline):
    assert EventType.DNS_TUNNELING in _types(pipeline["events"])


def test_icmp_tunneling_detected(pipeline):
    assert EventType.ICMP_TUNNELING in _types(pipeline["events"])


def test_credential_exposure_detected(pipeline):
    creds = [e for e in pipeline["events"] if e.event_type == EventType.CREDENTIAL_EXPOSURE]
    assert creds, "cleartext FTP credentials should be detected"


def test_risk_is_critical(pipeline):
    risk = pipeline["risk"]
    assert risk.tier == "CRITICAL"
    assert 0 <= risk.score <= 100


def test_benign_domains_not_flagged_as_dga():
    """google.com / cloudflare.com etc must never be flagged as DGA."""
    from packetiq.extractor.data_extractor import ExtractionResult
    res = ExtractionResult()
    res.dns_queries = [
        {"ts": 1.0, "src": "10.0.0.1", "dst": "8.8.8.8", "qname": d}
        for d in ("google.com", "cloudflare.com", "www.microsoft.com", "github.com")
    ]
    events = dns_anomaly.detect(res)
    assert not [e for e in events if "DGA" in e.description.upper()]


def test_xmas_flag_parsing():
    """The flag tokenizer must split concatenated tokens regardless of order."""
    assert protocol_misuse._flag_set("FINPSHURG") == {"FIN", "PSH", "URG"}
    assert protocol_misuse._flag_set("SYN") == {"SYN"}
    assert protocol_misuse._flag_set("PSHACK") == {"PSH", "ACK"}


# ── Risk score saturation ────────────────────────────────────────────────────

def _crit(etype):
    from packetiq.detection.models import DetectionEvent, Severity
    return DetectionEvent(event_type=etype, severity=Severity.CRITICAL,
                          src_ip="45.33.32.156", description="x")


def test_the_capped_risk_score_still_carries_its_undamped_aggregate():
    """`score` is clamped to 100, so severity beyond that point was unreadable.

    Six distinct CRITICAL findings already reach 100, and a capture measuring
    1800 reported that same 100 — a 12x range of real severity flattened into
    one number, on a figure the analysis-history panel ranks past captures by.
    The clamp is the same thing that flattened the attribution score.

    `score` and `tier` are deliberately left alone: every report, tier
    threshold and stored history row depends on them. The magnitude rides
    alongside so saturated captures can still be ordered against each other.
    """
    from packetiq.detection import risk_scorer
    from packetiq.detection.models import EventType

    few = [_crit(t) for t in list(EventType)[:6]]
    many = [_crit(t) for t in list(EventType) for _ in range(10)]

    r_few, r_many = risk_scorer.score(few), risk_scorer.score(many)

    assert r_few.score == r_many.score == 100, "both genuinely pin the ceiling"
    assert r_few.tier == r_many.tier == "CRITICAL"
    assert r_many.raw_score > r_few.raw_score * 5, (
        "the aggregate must separate what the clamped score cannot"
    )


def test_a_risk_score_below_the_cap_equals_its_aggregate():
    """Below 100 the two agree, so the new field introduces no second scale."""
    from packetiq.detection import risk_scorer
    from packetiq.detection.models import EventType

    report = risk_scorer.score([_crit(t) for t in list(EventType)[:3]])

    assert report.score == 75
    assert int(report.raw_score) == report.score


def test_a_clean_capture_reports_a_zero_aggregate():
    from packetiq.detection import risk_scorer

    report = risk_scorer.score([])

    assert (report.score, report.raw_score, report.tier) == (0, 0.0, "LOW")
