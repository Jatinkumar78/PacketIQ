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
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

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
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
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


# ── The live monitor must survive a busy link ────────────────────────────────

def test_the_rolling_window_is_bounded_by_count_as_well_as_age(monkeypatch):
    """The window was trimmed by age only, so its size was the packet rate.

    Measured: at 1,000 pkt/s a 300s window holds 300,000 records and at
    10,000 pkt/s three million — each holding its raw payload, which is
    gigabytes on an ordinary busy link. `packetiq live` is built to run
    continuously, so the window has to be bounded by count too.
    """
    from collections import deque

    from packetiq import live as live_mod

    monkeypatch.setattr(live_mod, "_MAX_WINDOW_RECORDS", 50)
    mon = live_mod.LiveMonitor(300.0, "HIGH", lambda e: None)
    assert mon.buf.maxlen == 50, "the cap is read when the monitor is built"
    assert isinstance(mon.buf, deque)

    class _Rec:
        def __init__(self, ts):
            self.timestamp = ts

    for i in range(500):
        mon.feed(_Rec(float(i)))

    assert len(mon.buf) == 50
    assert mon.dropped == 450, "overflow is counted, not swallowed"
    assert mon.buf[-1][0] == 499.0, "the newest packets are the ones kept"
    assert mon.buf[0][0] == 450.0


def test_the_deduplication_set_does_not_grow_without_bound(monkeypatch):
    """`_key` includes the destination port, so a port scan mints a key per port.

    One 65,535-port scan added a measured 8.5 MB that was never released, and
    every further scan added more — on a monitor meant to run for days.
    """
    from packetiq import live as live_mod
    from packetiq.detection.models import DetectionEvent, EventType, Severity

    monkeypatch.setattr(live_mod, "_MAX_SEEN_KEYS", 5)
    monkeypatch.setattr(live_mod, "_detect", lambda records: [
        DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.HIGH,
                       src_ip="45.33.32.156", dst_ip="10.0.0.5", dst_port=p,
                       description="scan")
        for p in range(20)
    ])

    alerts: list = []
    mon = live_mod.LiveMonitor(300.0, "HIGH", alerts.append)
    mon.scan()

    assert len(alerts) == 20, "every distinct finding is still reported once"
    assert len(mon.seen) == 5, "the set is capped"
    assert len(mon.seen_order) == 5, "the eviction queue tracks it exactly"


def test_an_evicted_finding_may_alert_again(monkeypatch):
    """Oldest-first eviction is the trade: recurrence after that much distinct
    activity is worth surfacing again, which is better than unbounded memory."""
    from packetiq import live as live_mod
    from packetiq.detection.models import DetectionEvent, EventType, Severity

    monkeypatch.setattr(live_mod, "_MAX_SEEN_KEYS", 2)
    monkeypatch.setattr(live_mod, "_detect", lambda records: [
        DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.HIGH,
                       src_ip="45.33.32.156", dst_ip="10.0.0.5", dst_port=p,
                       description="scan")
        for p in range(5)
    ])

    alerts: list = []
    mon = live_mod.LiveMonitor(300.0, "HIGH", alerts.append)
    mon.scan()
    mon.scan()

    assert len(alerts) == 10, "the evicted keys are re-reported on the next scan"
