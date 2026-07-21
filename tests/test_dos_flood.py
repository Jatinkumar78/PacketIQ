"""Tests for the SYN-flood / connection-exhaustion (DoS) detector."""

from packetiq.detection import dos_flood
from packetiq.detection.models import EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats


def _syn_storm(n=308, src="192.168.1.202", dst="4.207.44.64", dport=443,
              answered=False, span=30.0):
    r = ExtractionResult()
    r.tcp_syn_pairs = {(src, dst, dport): [1000.0 + i * (span / max(1, n)) for i in range(n)]}
    flags = {"SYN"} | ({"SYNACK"} if answered else set())
    r.flows = {("k",): FlowStats(src_ip=src, dst_ip=dst, src_port=50000, dst_port=dport,
                                 protocol="TCP", service="HTTPS", packets=n, bytes_total=n * 60,
                                 first_seen=1000.0, last_seen=1000.0 + span,
                                 tcp_flags_seen=flags)}
    return r


def test_syn_flood_detected_high():
    """308 unanswered SYNs at one target = a HIGH SYN flood (the Lab_test1 gap)."""
    events = dos_flood.detect(_syn_storm())
    floods = [e for e in events if e.event_type == EventType.DOS_FLOOD]
    assert len(floods) == 1
    e = floods[0]
    assert e.severity == Severity.HIGH
    assert e.src_ip == "192.168.1.202" and e.dst_ip == "4.207.44.64" and e.dst_port == 443
    assert e.evidence["unanswered_syns"] == 308
    assert e.evidence["technique"].startswith("T1499")


def test_below_threshold_is_quiet():
    assert not dos_flood.detect(_syn_storm(n=20))


def test_completed_handshake_not_flagged():
    """If the SYNs were answered (real connections), it is not a flood."""
    assert not dos_flood.detect(_syn_storm(answered=True))


def test_medium_band():
    """A moderate, slow burst is MEDIUM, not HIGH."""
    events = dos_flood.detect(_syn_storm(n=80, span=120.0))
    assert events and events[0].severity == Severity.MEDIUM
