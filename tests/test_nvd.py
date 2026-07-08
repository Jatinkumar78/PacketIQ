"""Tests for NVD CVE enrichment and the software-banner extraction that feeds it.

Network calls to the real NVD API are mocked — these tests never hit the network
and never fabricate CVE data; they assert the parsing/wiring is correct.
"""

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from packetiq.enrichment import nvd
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.webapp import create_app

# ── banner parsing ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("banner,expected", [
    ("Apache/2.4.49 (Unix)", ("Apache", "2.4.49")),
    ("nginx/1.18.0", ("nginx", "1.18.0")),
    ("Microsoft-IIS/10.0", ("Microsoft-IIS", "10.0")),
    ("curl/7.68.0", ("curl", "7.68.0")),
    ("", ("", "")),
    ("Mozilla/5.0 (Windows NT 10.0; Win64) AppleWebKit/537.36", ("", "")),
])
def test_parse_banner(banner, expected):
    assert nvd.parse_banner(banner) == expected


def test_keyword_for():
    assert nvd.keyword_for({"value": "Apache/2.4.49 (Unix)"}) == "Apache 2.4.49"
    assert nvd.keyword_for({"value": "Mozilla/5.0 (X11; Linux)"}) == ""


# ── NVD response parsing ─────────────────────────────────────────────────────

_FAKE_NVD = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2021-41773",
            "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49."}],
            "published": "2021-10-05T00:00:00.000",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        }},
        {"cve": {
            "id": "CVE-2000-0001",
            "descriptions": [{"lang": "en", "value": "Old low-severity issue."}],
            "published": "2000-01-01T00:00:00.000",
            "metrics": {"cvssMetricV2": [{"baseSeverity": "LOW", "cvssData": {"baseScore": 2.6}}]},
        }},
    ]
}


def test_client_search_parses_and_sorts(monkeypatch):
    class _Resp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return _FAKE_NVD

    monkeypatch.setattr(nvd.requests, "get", lambda *a, **k: _Resp())
    cves = nvd.NVDClient(api_key="x").search("Apache 2.4.49")
    assert [c["id"] for c in cves] == ["CVE-2021-41773", "CVE-2000-0001"]  # sorted by CVSS desc
    top = cves[0]
    assert top["cvss"] == 9.8 and top["severity"] == "CRITICAL"
    assert top["url"].endswith("CVE-2021-41773")


def test_lookup_banners_no_versions():
    res = nvd.lookup_banners([{"source": "http-user-agent", "value": "Mozilla/5.0 (X11)", "ips": []}])
    assert res["results"] == []
    assert "never invents" in res["note"]


def test_lookup_banners_with_results(monkeypatch):
    monkeypatch.setattr(nvd.NVDClient, "search",
                        lambda self, kw, limit=6: [{"id": "CVE-2021-41773", "cvss": 9.8,
                                                    "severity": "CRITICAL", "description": "x",
                                                    "published": "2021-10-05", "url": "u"}])
    banners = [{"source": "http-server", "value": "Apache/2.4.49 (Unix)", "ips": ["1.2.3.4"]}]
    res = nvd.lookup_banners(banners, api_key="key")
    assert res["queried"] == ["Apache 2.4.49"]
    assert res["results"][0]["cves"][0]["id"] == "CVE-2021-41773"


# ── banner extraction from a real (crafted) capture ──────────────────────────

def _http_pcap(tmp_path):
    req = (Ether() / IP(src="192.168.1.10", dst="93.184.216.34")
           / TCP(sport=51000, dport=80, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/",
                                  User_Agent=b"curl/7.68.0"))
    resp = (Ether() / IP(src="93.184.216.34", dst="192.168.1.10")
            / TCP(sport=80, dport=51000, flags="PA")
            / HTTP() / HTTPResponse(Status_Code=b"200", Server=b"Apache/2.4.49 (Unix)"))
    for i, p in enumerate((req, resp)):
        p.time = 1700000000.0 + i
    path = tmp_path / "http.pcap"
    wrpcap(str(path), [req, resp])
    return path


def test_extractor_collects_banners(tmp_path):
    path = _http_pcap(tmp_path)
    ex = DataExtractor()
    for rec in PCAPParser(str(path)).stream():
        ex.feed(rec)
    banners = ex.finalize().software_banners
    vals = {(b["source"], b["value"]) for b in banners}
    assert ("http-server", "Apache/2.4.49 (Unix)") in vals
    assert ("http-user-agent", "curl/7.68.0") in vals
    # server banners are listed first (most CVE-relevant)
    assert banners[0]["source"] == "http-server"


# ── CVE web endpoint ─────────────────────────────────────────────────────────

def test_cve_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "cve.db"))
    monkeypatch.setattr(nvd, "lookup_banners",
                        lambda banners, *a, **k: {"available": True, "queried": ["Apache 2.4.49"],
                                                  "results": [], "note": "ok", "error": None})
    path = _http_pcap(tmp_path)
    with TestClient(create_app()) as c:
        with open(path, "rb") as f:
            r = c.post("/api/upload", files={"file": ("http.pcap", f, "application/octet-stream")})
        job = r.json()["job_id"]
        import time
        for _ in range(80):
            if c.get(f"/api/results/{job}").status_code == 200:
                break
            time.sleep(0.25)
        jr = c.get(f"/api/results/{job}").json()
        assert "software_banners" in jr
        cve = c.get(f"/api/cve/{job}")
        assert cve.status_code == 200, cve.text
        j = cve.json()
        assert j["queried"] == ["Apache 2.4.49"]
        assert "banners_observed" in j


def test_cve_endpoint_404_for_unknown_job(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "cve2.db"))
    with TestClient(create_app()) as c:
        assert c.get("/api/cve/does-not-exist").status_code == 404
