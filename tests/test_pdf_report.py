"""The professional PDF SOC report (attached to Telegram alerts) must render a
valid PDF from the serialised analysis result, and degrade gracefully on sparse
input. All content is drawn from the real analysis — nothing is invented here.
"""

from packetiq.export import pdf_report, report_style

_RES = {
    "meta": {"filename": "jay2.pcapng", "total_packets": 1234, "bytes_fmt": "1.2 MB",
             "duration": "42s", "unique_flows": 88, "unique_src": 12, "unique_dst": 30,
             "external_ips": 9, "dns_queries": 41, "http_requests": 7,
             "capture_start": "2026-07-09 12:00:00", "sha256": "a" * 64},
    "risk": {"score": 13, "tier": "LOW", "summary": "Low-risk capture with DNS tunneling indicators.",
             "breakdown": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0}},
    "top_src_ips": [{"ip": "172.20.10.3", "count": 500}],
    "top_dst_ips": [{"ip": "172.20.10.1", "count": 450}],
    "dns_top": [["tunnel.evil.example.com", 30]],
    "threat_intel_matches": [{"source": "ThreatFox", "matches": [{"indicator": "tunnel.evil.example.com"}]}],
    "events": [
        {"event_type": "DNS_TUNNELING", "severity": "HIGH", "src_ip": "172.20.10.3",
         "dst_ip": "172.20.10.1", "dst_port": 53, "confidence": 82,
         "description": "High-entropy DNS queries consistent with tunnelling.",
         "recommendation": "Block the resolver path and inspect the host.", "mitre": []},
    ],
    "chains": [
        {"name": "DNS Exfiltration Channel", "severity": "HIGH", "confidence": 78,
         "attacker_ips": ["172.20.10.3"], "target_ips": ["172.20.10.1"],
         "phases": ["Command & Control"], "description": "Covert DNS channel.",
         "mitre": [{"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"}]},
    ],
}


def test_reportlab_is_available():
    # reportlab is a declared runtime dependency now — the PDF path must be live.
    assert pdf_report.available()


def test_build_pdf_produces_valid_pdf(tmp_path):
    out = str(tmp_path / "report.pdf")
    assert pdf_report.build_pdf(out, _RES) is True
    data = open(out, "rb").read()
    assert data[:5] == b"%PDF-"
    assert len(data) > 1500          # a real multi-section document, not a stub


def test_build_pdf_bytes():
    data = pdf_report.build_pdf_bytes(_RES)
    assert data and data[:5] == b"%PDF-"


def test_build_pdf_survives_minimal_result(tmp_path):
    out = str(tmp_path / "min.pdf")
    assert pdf_report.build_pdf(out, {"meta": {"filename": "x"}}) is True
    assert open(out, "rb").read()[:5] == b"%PDF-"


def test_build_pdf_survives_empty_result(tmp_path):
    out = str(tmp_path / "empty.pdf")
    assert pdf_report.build_pdf(out, {}) is True
    assert open(out, "rb").read()[:5] == b"%PDF-"


def test_report_is_multi_page_with_a_cover(tmp_path):
    # Cover + numbered body sections should never collapse to a single page.
    out = str(tmp_path / "r.pdf")
    assert pdf_report.build_pdf(out, _RES) is True
    data = open(out, "rb").read()
    assert data.count(b"/Type /Page") >= 2 or data.count(b"/Type/Page") >= 2


def test_iocs_and_recommendations_are_grounded():
    iocs = dict(report_style.iocs(_RES))
    assert "tunnel.evil.example.com" in iocs.get("Threat-intelligence matches", [])
    assert "172.20.10.1" in iocs.get("Hosts named in findings", [])
    recs = report_style.recommendations(_RES["events"])
    assert recs == ["Block the resolver path and inspect the host."]
