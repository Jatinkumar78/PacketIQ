"""Tests for the HTML report, SQLite history, and new web endpoints."""

from packetiq import storage
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.detection.risk_scorer import score
from packetiq.export import build_html
from packetiq.export.html_report import _network_svg
from packetiq.extractor.data_extractor import ExtractionResult, FlowStats


def _sample_result():
    r = ExtractionResult()
    r.total_packets = 100
    r.total_bytes = 50000
    r.capture_start, r.capture_end = 1.0, 61.0
    r.ip_src_counts = {"192.168.1.50": 60, "45.33.32.156": 40}
    r.ip_dst_counts = {"45.33.32.156": 40, "192.168.1.50": 60}
    r.external_ips = {"45.33.32.156"}
    r.flows = {("a", "b", "tcp"): FlowStats(src_ip="192.168.1.50", dst_ip="45.33.32.156",
                                            src_port=5000, dst_port=443, protocol="TCP",
                                            service="HTTPS", packets=40, bytes_total=40000,
                                            first_seen=1.0, last_seen=61.0)}
    return r


def test_html_report_contains_sections():
    res = _sample_result()
    events = [DetectionEvent(event_type=EventType.BRUTE_FORCE, severity=Severity.HIGH,
                             src_ip="45.33.32.156", dst_ip="192.168.1.50", dst_port=22,
                             description="Brute force on SSH")]
    risk = score(events)
    html = build_html({"filename": "demo.pcap"}, res, events, [], risk, [])
    for marker in ("Network Forensics &amp; Incident Report",   # house-style cover title
                   "PACKETIQ", "demo.pcap", "PIQ-",             # brand, evidence, report ref
                   "OVERALL RISK", "Network graph", "<svg",
                   "Detection events", "Brute force on SSH",
                   "Limitations &amp; assurance"):
        assert marker in html, marker


def test_network_svg_renders_nodes():
    res = _sample_result()
    svg = _network_svg(res, [])
    assert "<svg" in svg and "192.168.1.50" in svg


def test_history_record_and_recent(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "h.db"))
    assert storage.record("a.pcap", 100, 80, "CRITICAL", 5, 2, "45.33.32.156")
    assert storage.record("b.pcap", 50, 10, "LOW", 0, 0)
    rows = storage.recent(10)
    assert len(rows) == 2
    assert rows[0]["filename"] == "b.pcap"      # newest first
    assert rows[1]["risk_tier"] == "CRITICAL"


def test_web_endpoints(tmp_path, monkeypatch):
    """Upload demo via REST /api/analyze and pull report/stix/history."""
    import json

    from fastapi.testclient import TestClient
    from scapy.all import IP, TCP, Ether, wrpcap

    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "web.db"))
    pkts = []
    for i in range(40):
        p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = 1700000000.0 + i
        pkts.append(p)
    pcap = tmp_path / "bf.pcap"
    wrpcap(str(pcap), pkts)

    from packetiq.webapp import create_app
    with TestClient(create_app()) as client:
        with open(pcap, "rb") as f:
            r = client.post("/api/analyze", files={"file": ("bf.pcap", f, "application/octet-stream")})
        assert r.status_code == 200, r.text
        data = r.json()
        job = data["job_id"]
        assert "stix" in data
        # html report endpoint
        rep = client.get(f"/api/report/{job}.html")
        assert rep.status_code == 200 and "PacketIQ" in rep.text
        # stix endpoint
        stx = client.get(f"/api/stix/{job}")
        assert stx.status_code == 200 and json.loads(stx.text)["type"] == "bundle"
        # history endpoint records the run
        hist = client.get("/api/history")
        assert any(a["filename"] == "bf.pcap" for a in hist.json()["analyses"])
