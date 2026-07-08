"""Tests for Zeek ingestion, live replay, and file carving."""

import hashlib

from scapy.all import IP, TCP, Ether, Raw, wrpcap

from packetiq import live as live_mod
from packetiq.detection import file_carver
from packetiq.detection.engine import DetectionEngine
from packetiq.detection.models import EventType
from packetiq.inputs import load_conn_log


def test_zeek_conn_log_detects_scan_and_brute(tmp_path):
    lines = ["#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts"]
    t = 1700000000.0
    for i, port in enumerate(range(1, 60)):
        lines.append(f"{t+i*0.1:.3f}\t45.33.32.156\t{40000+i}\t192.168.1.50\t{port}\ttcp\t0\t40\t0\t1\t0")
    for i in range(40):
        lines.append(f"{t+100+i:.3f}\t45.33.32.156\t{50000+i}\t192.168.1.50\t22\ttcp\t0.2\t200\t100\t2\t1")
    log = tmp_path / "conn.log"
    log.write_text("\n".join(lines) + "\n")

    result = load_conn_log(str(log))
    assert len(result.flows) > 50
    events, risk, _ = DetectionEngine().run(result, str(log))
    types = {e.event_type for e in events}
    assert EventType.PORT_SCAN in types
    assert EventType.BRUTE_FORCE in types


def test_zeek_json_lines(tmp_path):
    import json
    rows = [
        {"ts": 1700000000.0, "id.orig_h": "10.0.0.1", "id.orig_p": 5000,
         "id.resp_h": "8.8.8.8", "id.resp_p": 53, "proto": "udp",
         "duration": 0.0, "orig_bytes": 40, "resp_bytes": 80, "orig_pkts": 1, "resp_pkts": 1},
    ]
    log = tmp_path / "conn.json"
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    result = load_conn_log(str(log))
    assert result.total_packets > 0
    assert "8.8.8.8" in result.external_ips


def test_live_replay_emits_alerts(tmp_path):
    # SSH brute force capture
    pkts = []
    t = 1700000000.0
    for i in range(40):
        p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = t + i
        pkts.append(p)
    pcap = tmp_path / "bf.pcap"
    wrpcap(str(pcap), pkts)

    alerts = []
    mon = live_mod.replay(str(pcap), alerts.append, window_secs=600, scan_every=20, threshold="HIGH")
    assert mon.alert_count >= 1
    assert any(e.event_type == EventType.BRUTE_FORCE for e in alerts)


def test_file_carver_reassembles_and_hashes(tmp_path):
    body = b"MZ" + b"\x90" * 2000
    sha = hashlib.sha256(body).hexdigest()
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)) + body

    pkts = []
    seq0 = 1000
    chunks = [resp[:60], resp[60:120], resp[120:]]
    offsets = [0, 60, 120]
    for j, i in enumerate([2, 0, 1]):   # out of order
        p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / \
            TCP(sport=80, dport=51000, seq=seq0 + offsets[i], flags="A") / Raw(load=chunks[i])
        p.time = 1700000000.0 + j
        pkts.append(p)
    pcap = tmp_path / "dl.pcap"
    wrpcap(str(pcap), pkts)

    events = file_carver.analyze(str(pcap))
    assert events, "carver should detect the executable transfer"
    # PE over cleartext from external => at least MEDIUM, correct hash
    assert events[0].evidence["sha256"] == sha
    assert "PE/EXE" in events[0].evidence["file_type"]
