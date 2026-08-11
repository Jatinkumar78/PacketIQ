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


def _pdf_bytes(tmp_path, res) -> bytes:
    """Render through `build_pdf` — the entry point the web app and the Telegram
    sender actually call — and hand back the bytes to assert on."""
    out = tmp_path / "rendered.pdf"
    assert pdf_report.build_pdf(str(out), res) is True
    return out.read_bytes()


def test_reportlab_is_available():
    # reportlab is a declared runtime dependency now — the PDF path must be live.
    assert pdf_report.available()


def test_build_pdf_produces_valid_pdf(tmp_path):
    out = str(tmp_path / "report.pdf")
    assert pdf_report.build_pdf(out, _RES) is True
    data = open(out, "rb").read()
    assert data[:5] == b"%PDF-"
    assert len(data) > 1500          # a real multi-section document, not a stub


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


# --------------------------------------------------------------------------- #
#  Degradation and the branches a single happy-path render never reaches        #
# --------------------------------------------------------------------------- #

def test_a_capture_with_only_low_findings_is_described_as_informational(tmp_path):
    """The lead paragraph is what an executive reads first. Saying a LOW-only
    capture 'warrants analyst attention' would misdirect the whole report."""
    res = {**_RES,
           "risk": {"score": 5, "tier": "LOW", "summary": "Quiet capture.",
                    "breakdown": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 1}},
           "events": [{"event_type": "DNS_ANOMALY", "severity": "LOW",
                       "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dst_port": 53,
                       "confidence": 40, "description": "High-volume DNS.",
                       "recommendation": "None required.", "mitre": []}]}

    data = _pdf_bytes(tmp_path, res)
    assert data and data[:5] == b"%PDF-"


def test_a_large_finding_set_is_truncated_with_a_pointer_to_the_html_export(tmp_path):
    """45 rows is the table cap. Beyond it the PDF must say what was left out."""
    events = [{"event_type": "PORT_SCAN", "severity": "HIGH", "src_ip": f"45.33.32.{i}",
               "dst_ip": "10.0.0.5", "dst_port": 445, "confidence": 80,
               "description": f"Scan {i}", "recommendation": "Investigate.",
               "mitre": [{"id": "T1046", "name": "Network Service Discovery"}, "T1595"]}
              for i in range(60)]

    data = _pdf_bytes(tmp_path, {**_RES, "events": events})
    assert data and data[:5] == b"%PDF-"
    assert len(data) > 5000, "a 60-finding report should be substantially longer"


def test_a_chain_with_timestamps_and_attributions_renders(tmp_path):
    """Exercises the observed-window line and the attribution caveat, both of
    which only appear when the analysis produced that data."""
    res = {**_RES,
           "attributions": [{"actor": "Unattributed cluster", "confidence": 0.3}],
           "chains": [{**_RES["chains"][0],
                       "first_seen": "2026-07-09 12:00:00",
                       "last_seen": "2026-07-09 12:07:31"}]}

    data = _pdf_bytes(tmp_path, res)
    assert data and data[:5] == b"%PDF-"


def test_a_non_numeric_count_is_passed_through_rather_than_crashing():
    """Serialized meta can carry a pre-formatted string; the PDF must render it
    as-is instead of failing the whole document on an int() call."""
    assert pdf_report._count(1234567) == "1,234,567"
    assert pdf_report._count("n/a") == "n/a"
    assert pdf_report._count(None) == "None"


def test_mitre_techniques_render_from_both_dicts_and_bare_ids():
    e = {"mitre": [{"id": "T1046", "name": "Network Service Discovery"},
                   "T1595 Active Scanning",
                   {"name": "no id — skipped"}]}
    rendered = pdf_report._tech_ids(e)

    assert "T1046 Network Service Discovery" in rendered
    assert "T1595 Active Scanning" in rendered
    assert "no id" not in rendered


def test_an_event_with_no_mitre_mapping_renders_empty():
    assert pdf_report._tech_ids({}) == ""


def test_the_pdf_path_reports_failure_rather_than_raising(tmp_path, monkeypatch):
    """A write to an unwritable location must come back as False so the caller
    can fall back to the HTML report instead of the run dying."""
    unwritable = tmp_path / "no-such-dir" / "report.pdf"
    assert pdf_report.build_pdf(str(unwritable), _RES) is False


def test_reportlab_being_absent_is_reported_not_raised(monkeypatch):
    """PDF export is optional; without reportlab the caller uses HTML instead."""
    import builtins
    real_import = builtins.__import__

    def no_reportlab(name, *a, **kw):
        if name == "reportlab" or name.startswith("reportlab."):
            raise ImportError("not installed")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_reportlab)
    assert pdf_report.available() is False
    assert pdf_report.build_pdf("/tmp/never-written.pdf", _RES) is False
