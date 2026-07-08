"""Tests for ATT&CK Navigator export, the court-ready report, and the new endpoints."""

import json
import time

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, wrpcap

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.export import attack_coverage, build_html, build_navigator_layer
from packetiq.webapp import create_app


def _ev(et, sev=Severity.HIGH, conf=0.9):
    return DetectionEvent(et, sev, "10.0.0.9", "test", dst_ip="45.33.32.156", confidence=conf)


# ── ATT&CK Navigator ─────────────────────────────────────────────────────────

def test_navigator_layer_schema():
    layer = build_navigator_layer([_ev(EventType.PORT_SCAN), _ev(EventType.IOC_MATCH, Severity.CRITICAL)])
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["techniques"], "should contain detected techniques"
    t = layer["techniques"][0]
    assert t["techniqueID"].startswith("T")
    assert "color" in t and "score" in t


def test_navigator_dict_and_object_modes():
    obj = attack_coverage([_ev(EventType.PORT_SCAN)])
    dct = attack_coverage([{"severity": "HIGH",
                            "mitre": [{"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"}]}])
    assert obj and dct
    assert dct[0]["id"] == "T1046"


def test_coverage_severity_is_peak():
    cov = attack_coverage([_ev(EventType.PORT_SCAN, Severity.LOW, 0.6),
                           _ev(EventType.PORT_SCAN, Severity.CRITICAL, 0.9)])
    # same technique seen twice → count 2, peak severity CRITICAL
    t1046 = [c for c in cov if c["id"] == "T1046"]
    assert t1046 and t1046[0]["count"] == 2 and t1046[0]["severity"] == "CRITICAL"


# ── Court-ready report ───────────────────────────────────────────────────────

class _Risk:
    score = 70
    tier = "HIGH"
    summary = "elevated"
    by_severity = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0}


class _Res:
    total_packets = 100
    total_bytes = 5000
    capture_start = 1700000000.0
    capture_end = 1700000100.0
    flows = {}
    external_ips = {"45.33.32.156"}
    ip_src_counts = {"10.0.0.9": 50}
    ip_dst_counts = {"45.33.32.156": 50}


def test_report_has_court_ready_sections():
    html = build_html({"filename": "case.pcap"}, _Res(), [_ev(EventType.IOC_MATCH, Severity.CRITICAL)],
                      [], _Risk(), pcap_sha256="deadbeef" * 8)
    for marker in ("Executive summary", "Chain of custody", "deadbeef",
                   "MITRE ATT&CK coverage", "Finding analysis", "@media print",
                   "Recommended action"):
        assert marker in html, f"report missing: {marker}"


# ── Endpoints ────────────────────────────────────────────────────────────────

@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "ar.db"))
    with TestClient(create_app()) as c:
        yield c


def _scan_pcap(tmp_path):
    pkts = []
    for i in range(40):
        p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = 1700000000.0 + i
        pkts.append(p)
    path = tmp_path / "scan.pcap"
    wrpcap(str(path), pkts)
    return path


def _analyze(client, path):
    with open(path, "rb") as f:
        job = client.post("/api/upload", files={"file": ("scan.pcap", f, "application/octet-stream")}).json()["job_id"]
    for _ in range(80):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


def test_navigator_endpoint(client, tmp_path):
    job = _analyze(client, _scan_pcap(tmp_path))
    r = client.get(f"/api/navigator/{job}")
    assert r.status_code == 200, r.text
    layer = json.loads(r.content)
    assert layer["domain"] == "enterprise-attack"


def test_results_include_explainability_and_coverage(client, tmp_path):
    job = _analyze(client, _scan_pcap(tmp_path))
    res = client.get(f"/api/results/{job}").json()
    assert "attack_coverage" in res
    assert res["events"], "scan pcap should produce events"
    e = res["events"][0]
    assert "precision" in e and "why" in e and "recommendation" in e
    # chain-of-custody SHA-256 + FP-suppression transparency are wired into meta
    meta = res["meta"]
    assert len(meta.get("sha256", "")) == 64, "report needs a real PCAP SHA-256"
    assert "suppressed" in meta and isinstance(meta["suppressed"], list)


def test_engine_exposes_suppressed_attribute(tmp_path):
    """The detection engine must always expose a (default-empty) suppression list."""
    from packetiq.detection.engine import DetectionEngine
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.parser.pcap_parser import PCAPParser
    path = _scan_pcap(tmp_path)
    ex = DataExtractor()
    for rec in PCAPParser(str(path)).stream():
        ex.feed(rec)
    eng = DetectionEngine()
    eng.run(ex.finalize(), str(path))
    assert isinstance(eng.suppressed, list)   # default config suppresses nothing


def test_report_print_mode(client, tmp_path):
    job = _analyze(client, _scan_pcap(tmp_path))
    r = client.get(f"/api/report/{job}.html", params={"print": 1})
    assert r.status_code == 200
    assert "window.print()" in r.text
