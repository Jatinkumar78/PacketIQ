"""Tests for the ARP scan / spoofing detector and ARP parsing/extraction.

Deterministic and platform-independent: ExtractionResult is populated directly
(scan and spoof fixtures), and a tiny in-memory pcap exercises the parser +
extractor end-to-end so the ARP host-discovery sweep is caught the same way it
is on a real capture.
"""

from packetiq.detection import arp_scan
from packetiq.detection.models import EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult


def _result_with_sweep(sender="192.168.1.200", n_targets=253, first=1000.0, last=1275.0):
    r = ExtractionResult()
    targets = {f"192.168.1.{i}" for i in range(1, min(n_targets, 254) + 1)}
    # widen beyond a /24 if a big count is requested
    while len(targets) < n_targets:
        targets.add(f"10.0.{len(targets) // 254}.{len(targets) % 254}")
    r.arp_request_targets = {sender: targets}
    r.arp_request_counts = {sender: n_targets + 20}
    r.arp_sender_macs = {sender: {"00:e0:4c:36:14:02"}}
    r.arp_request_window = {sender: (first, last)}
    r.arp_total = n_targets + 20
    r.arp_replies = 1
    return r


def test_arp_sweep_detected_high():
    """A full-subnet ARP sweep (253 hosts) is a HIGH host-discovery finding."""
    events = arp_scan.detect(_result_with_sweep())
    scans = [e for e in events if e.event_type == EventType.ARP_SCAN]
    assert len(scans) == 1
    e = scans[0]
    assert e.severity == Severity.HIGH
    assert e.src_ip == "192.168.1.200"
    assert e.evidence["distinct_targets"] == 253
    assert e.evidence["technique"].startswith("T1018")
    assert e.confidence == 1.0  # capped


def test_arp_sweep_medium_band():
    """20–49 distinct targets is a MEDIUM sweep, not HIGH."""
    events = arp_scan.detect(_result_with_sweep(n_targets=25))
    scans = [e for e in events if e.event_type == EventType.ARP_SCAN]
    assert len(scans) == 1 and scans[0].severity == Severity.MEDIUM


def test_arp_below_threshold_is_quiet():
    """A handful of ARP lookups (normal client behaviour) must not fire."""
    events = arp_scan.detect(_result_with_sweep(n_targets=8))
    assert not [e for e in events if e.event_type == EventType.ARP_SCAN]


def test_arp_spoofing_detected_on_ip_mac_conflict():
    r = ExtractionResult()
    r.arp_ip_to_macs = {
        "192.168.1.1": {"aa:bb:cc:00:00:01", "de:ad:be:ef:00:99"},  # gateway claimed twice
        "192.168.1.50": {"aa:bb:cc:00:00:50"},                       # normal — one MAC
    }
    events = arp_scan.detect(r)
    spoof = [e for e in events if e.event_type == EventType.ARP_SPOOFING]
    assert len(spoof) == 1
    assert spoof[0].src_ip == "192.168.1.1"
    assert spoof[0].severity == Severity.HIGH
    assert spoof[0].evidence["mac_count"] == 2


def test_no_arp_no_events():
    assert arp_scan.detect(ExtractionResult()) == []


def test_parser_extractor_end_to_end_arp_sweep():
    """Build a real ARP-request pcap in memory; the pipeline must flag the sweep."""
    from scapy.all import ARP, Ether, wrpcap
    from scapy.utils import tempfile

    from packetiq.detection.engine import DetectionEngine
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser

    attacker_mac = "00:e0:4c:36:14:02"
    pkts = []
    t0 = 1700000000.0
    for i in range(1, 61):  # sweep 60 hosts → HIGH
        p = (Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
             / ARP(op=1, hwsrc=attacker_mac, psrc="192.168.1.200",
                   pdst=f"192.168.1.{i}"))
        p.time = t0 + i
        pkts.append(p)

    import os
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, pkts)
        ex = DataExtractor()
        for rec in PCAPParser(path).stream():
            ex.feed(rec)
        result = ex.finalize()
        # ARP is now a first-class protocol, not lumped into "Ethernet"
        assert result.protocol_counts.get("ARP") == 60
        assert len(result.arp_request_targets["192.168.1.200"]) == 60

        events, risk, _ = DetectionEngine().run(result, path)
        scans = [e for e in events if e.event_type == EventType.ARP_SCAN]
        assert scans and scans[0].severity == Severity.HIGH
        # A HIGH finding must not leave the headline tier at LOW.
        assert risk.tier in ("MEDIUM", "HIGH", "CRITICAL")
    finally:
        os.unlink(path)
