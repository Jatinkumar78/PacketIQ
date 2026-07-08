"""Tests for YARA scanning (bundled example rules)."""

import pytest

from packetiq.detection import yara_scan

pytest.importorskip("yara")

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def test_yara_available_with_bundled_rules():
    assert yara_scan.available(), "bundled YARA rules should compile"


def test_eicar_match():
    hits = yara_scan.scan_bytes(EICAR.encode())
    assert any(h["rule"] == "EICAR_Test_File" for h in hits)


def test_webshell_marker_match():
    body = b"<?php eval($_POST['x']); ?>"
    hits = yara_scan.scan_bytes(body)
    assert any("Webshell" in h["rule"] for h in hits)


def test_clean_data_no_match():
    assert yara_scan.scan_bytes(b"just some normal text content here") == []


def test_carver_emits_yara_event(tmp_path):
    """A webshell delivered over HTTP should produce a YARA-tagged finding."""
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    from packetiq.detection import file_carver
    from packetiq.detection.models import EventType

    body = b"<?php system($_REQUEST['cmd']); eval($_POST['x']); ?>" + b"A" * 200
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / \
        TCP(sport=80, dport=51000, seq=1000, flags="A") / Raw(load=resp)
    p.time = 1700000000.0
    pcap = tmp_path / "shell.pcap"
    wrpcap(str(pcap), [p])

    events = file_carver.analyze(str(pcap))
    assert any(e.event_type == EventType.MALICIOUS_FILE and e.evidence.get("yara_rule")
               for e in events), [e.description for e in events]
