"""Tests for the NVD CPE/CVSS/KEV vulnerability engine + per-PCAP threat intel.

All NVD/CISA network calls are mocked — these tests never hit the network and
never fabricate vulnerability data; they assert the mapping/wiring is correct.
"""

import time

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

from packetiq.enrichment import kev, nvd
from packetiq.webapp import create_app

# ── CVSS → severity ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("score,sev", [
    (9.8, "CRITICAL"), (9.0, "CRITICAL"), (7.5, "HIGH"), (5.0, "MEDIUM"),
    (3.9, "LOW"), (0.0, "LOW"), (None, "UNKNOWN"),
])
def test_cvss_to_severity(score, sev):
    assert nvd.cvss_to_severity(score) == sev


# ── KEV loader (mocked CISA catalog) ─────────────────────────────────────────

_FAKE_KEV = {"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell",
     "requiredAction": "patch", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2021-41773", "vulnerabilityName": "Apache traversal",
     "requiredAction": "patch", "knownRansomwareCampaignUse": "Unknown"},
]}


def test_kev_loader(monkeypatch, tmp_path):
    class _Resp:
        def raise_for_status(self): pass
        def json(self): return _FAKE_KEV
    monkeypatch.setattr(kev, "_cache_path", lambda: tmp_path / "kev.json")
    monkeypatch.setattr(kev.requests, "get", lambda *a, **k: _Resp())
    kev.load.cache_clear()
    assert kev.count() == 2
    assert kev.is_kev("cve-2021-44228")          # case-insensitive
    assert kev.kev_info("CVE-2021-44228")["ransomware"] is True
    assert kev.kev_info("CVE-2021-41773")["ransomware"] is False
    assert not kev.is_kev("CVE-2000-0001")
    kev.load.cache_clear()


# ── exploit-signature → CVE map ──────────────────────────────────────────────

def test_exploit_signature_map():
    assert "CVE-2021-44228" in nvd.EXPLOIT_SIGNATURE_CVE["Log4Shell / JNDI"]["cves"]


# ── full assessment (mocked NVD + KEV) ───────────────────────────────────────

def test_assess_vulnerabilities(monkeypatch):
    monkeypatch.setattr(nvd, "get_api_key", lambda: "test-key")
    monkeypatch.setattr(nvd, "resolve_cpe",
                        lambda product, version, **k: f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*")
    monkeypatch.setattr(nvd, "_cves_by_cpe", lambda client, cpe, **k: [
        {"id": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL",
         "published": "2021-10-05", "description": "x", "url": "u"},
        {"id": "CVE-2000-0001", "cvss": 2.6, "severity": "LOW",
         "published": "2000-01-01", "description": "y", "url": "u2"},
    ])
    monkeypatch.setattr(kev, "kev_info", lambda cid: {"ransomware": True} if cid == "CVE-2021-41773" else None)
    monkeypatch.setattr(kev, "is_kev", lambda cid: cid in {"CVE-2021-44228", "CVE-2021-41773"})
    monkeypatch.setattr(kev, "count", lambda: 1621)

    banners = [{"source": "http-server", "value": "Apache/2.4.49 (Unix)", "ips": ["192.168.1.10"]}]
    attacks = [{"attack_type": "Log4Shell / JNDI", "dst_ip": "192.168.1.10"}]
    r = nvd.assess_vulnerabilities(banners, attacks)

    p = r["products"][0]
    assert p["cpe"].endswith("2.4.49:*:*:*:*:*:*:*")
    # KEV CVE sorted first, then by CVSS
    assert p["cves"][0]["id"] == "CVE-2021-41773" and p["cves"][0]["kev"] is True
    assert p["cves"][0]["ransomware"] is True
    assert p["kev_count"] == 1 and p["max_cvss"] == 9.8
    # per-host roll-up
    assert r["hosts"][0]["ip"] == "192.168.1.10" and r["hosts"][0]["kev_count"] == 1
    # exploit correlation (attack seen + target software)
    cor = r["correlations"][0]
    assert cor["name"].startswith("Apache Log4j") and cor["kev"] is True
    assert cor["target_software"] == ["Apache 2.4.49"]
    # risk fused from CVSS + KEV
    assert r["risk"]["score"] >= 90 and r["risk"]["tier"] == "CRITICAL"
    assert r["totals"]["cves"] == 2 and r["totals"]["kev"] == 1


def test_assess_no_banners():
    r = nvd.assess_vulnerabilities([], [])
    assert r["products"] == [] and "never invents" in r["note"]


# ── /api/vulns endpoint + per-PCAP threat intel ──────────────────────────────

def _http_pcap(tmp_path):
    req = (Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=51000, dport=80, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"x", Path=b"/", User_Agent=b"curl/7.68.0"))
    resp = (Ether() / IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=51000, flags="PA")
            / HTTP() / HTTPResponse(Status_Code=b"200", Server=b"Apache/2.4.49 (Unix)"))
    for i, p in enumerate((req, resp)):
        p.time = 1700000000.0 + i
    path = tmp_path / "http.pcap"
    wrpcap(str(path), [req, resp])
    return path


def _ioc_pcap(tmp_path, feodo):
    pkts = [Ether() / IP(src="192.168.1.80", dst=feodo) / TCP(sport=36000 + i, dport=443, flags="PA") / (b"x" * 80)
            for i in range(6)]
    for i, p in enumerate(pkts):
        p.time = 1700000000.0 + i
    path = tmp_path / "ioc.pcap"
    wrpcap(str(path), pkts)
    return path


def _analyze(c, path, name):
    with open(path, "rb") as f:
        job = c.post("/api/upload", files={"file": (name, f, "application/octet-stream")}).json()["job_id"]
    for _ in range(80):
        if c.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


def test_vulns_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "v.db"))
    monkeypatch.setattr(nvd, "assess_vulnerabilities",
                        lambda banners, attacks, *a, **k: {"available": True, "products": [],
                                                           "hosts": [], "correlations": [],
                                                           "risk": {"score": 0, "tier": "NONE"},
                                                           "totals": {"cves": 0, "kev": 0, "products": 0,
                                                                      "kev_catalog": 1621},
                                                           "note": "ok", "error": None})
    with TestClient(create_app()) as c:
        job = _analyze(c, _http_pcap(tmp_path), "http.pcap")
        r = c.get(f"/api/vulns/{job}")
        assert r.status_code == 200, r.text
        j = r.json()
        assert "risk" in j and "totals" in j and "banners_observed" in j
        assert c.get("/api/vulns/unknown").status_code == 404


def test_threat_intel_matches_are_per_pcap(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "ti.db"))
    from packetiq.enrichment.feeds import load_store
    feodo = next(ip for ip, h in load_store().bad_ips.items() if h.source == "Feodo Tracker")
    with TestClient(create_app()) as c:
        # capture WITH an IOC hit
        job = _analyze(c, _ioc_pcap(tmp_path, feodo), "ioc.pcap")
        tim = c.get(f"/api/results/{job}").json().get("threat_intel_matches", [])
        assert tim and any(m["source"] == "Feodo Tracker" and m["count"] >= 1 for m in tim)
        assert tim[0]["matches"][0]["dst_ip"] == feodo
        # benign capture (no feed hits) → empty matches
        clean = _analyze(c, _http_pcap(tmp_path), "http.pcap")
        assert c.get(f"/api/results/{clean}").json().get("threat_intel_matches", []) == []
