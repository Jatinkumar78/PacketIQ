"""The last uncovered lines: worker-thread failures, live-session health hints,
persistence fallbacks, and the two NVD-backed endpoints.

Most of these only run when something outside the process misbehaves — a
read-only home directory, an unreadable capture, an interface that dies. Each is
driven here by making exactly that thing happen.
"""

import io
import json
import time

import pytest
from fastapi.testclient import TestClient
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetiq.attribution.engine import AttributionEngine
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

TS = 1700000000.0
UNKNOWN = "00000000-0000-0000-0000-000000000000"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


def _event(etype=EventType.PORT_SCAN, severity=Severity.HIGH, src="45.33.32.156",
           dst="192.168.1.50"):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description="finding", dst_ip=dst, dst_port=445,
                          protocol="TCP", timestamp=TS, packet_count=10)


def _pcap(tmp_path, name="bf.pcap", n=40):
    pkts = []
    for i in range(n):
        p = (Ether() / IP(src="45.33.32.156", dst="192.168.1.50")
             / TCP(sport=40000 + i, dport=22, flags="S"))
        p.time = TS + i
        pkts.append(p)
    path = tmp_path / name
    wrpcap(str(path), pkts)
    return path


def _analyze(client, path, name="bf.pcap"):
    with open(path, "rb") as f:
        r = client.post("/api/upload",
                        files={"file": (name, f, "application/octet-stream")})
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    for _ in range(120):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


# ── Worker-thread failures ───────────────────────────────────────────────────

def test_an_analysis_that_raises_reports_the_error_over_the_websocket(client, tmp_path,
                                                                      monkeypatch):
    """The browser is waiting on the socket; a silent worker death would leave
    the progress bar spinning forever."""
    from packetiq.extractor.data_extractor import DataExtractor

    def boom(self):
        raise RuntimeError("extractor exploded")

    monkeypatch.setattr(DataExtractor, "finalize", boom)

    pcap = _pcap(tmp_path)
    with open(pcap, "rb") as f:
        job = client.post("/api/upload",
                          files={"file": ("bf.pcap", f, "application/octet-stream")}
                          ).json()["job_id"]

    msg = None
    with client.websocket_connect(f"/ws/{job}") as ws:
        for _ in range(60):
            msg = json.loads(ws.receive_text())
            if msg["type"] in ("complete", "error"):
                break

    assert msg is not None and msg["type"] == "error"
    assert "extractor exploded" in msg["message"]

    # The same reason has to be readable over REST too — the browser may have
    # missed the socket entirely.
    r = client.get(f"/api/results/{job}")
    assert r.status_code == 500
    assert "extractor exploded" in r.json()["detail"]


def test_a_campaign_fusion_that_raises_reports_the_error(client, tmp_path, monkeypatch):
    from packetiq.correlation.engine import CorrelationEngine

    def boom(self, events):
        raise RuntimeError("correlation exploded")

    monkeypatch.setattr(CorrelationEngine, "correlate", boom)

    a, b = _pcap(tmp_path, "a.pcap"), _pcap(tmp_path, "b.pcap")
    with open(a, "rb") as fa, open(b, "rb") as fb:
        job = client.post("/api/fuse", files=[
            ("files", ("a.pcap", fa, "application/octet-stream")),
            ("files", ("b.pcap", fb, "application/octet-stream")),
        ]).json()["job_id"]

    msg = None
    with client.websocket_connect(f"/ws/{job}") as ws:
        for _ in range(60):
            msg = json.loads(ws.receive_text())
            if msg["type"] in ("complete", "error"):
                break

    assert msg is not None and msg["type"] == "error"
    assert "correlation exploded" in msg["message"]


def test_the_synchronous_analyze_endpoint_reports_a_failed_analysis(client, tmp_path,
                                                                     monkeypatch):
    from packetiq.extractor.data_extractor import DataExtractor

    def boom(self):
        raise RuntimeError("extractor exploded")

    monkeypatch.setattr(DataExtractor, "finalize", boom)

    with open(_pcap(tmp_path), "rb") as f:
        r = client.post("/api/analyze",
                        files={"file": ("bf.pcap", f, "application/octet-stream")})

    assert r.status_code == 500
    assert "Analysis failed" in r.json()["detail"]


def test_a_large_capture_emits_intermediate_parse_progress(client, tmp_path):
    """The percentage only advances every 10,000 packets, so a small fixture
    never exercises it — and a broken format string there kills the run."""
    pkts = []
    for i in range(11000):
        p = (Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
             / TCP(sport=51000 + (i % 500), dport=443))
        p.time = TS + i * 0.001
        pkts.append(p)
    path = tmp_path / "big.pcap"
    wrpcap(str(path), pkts)

    with open(path, "rb") as f:
        job = client.post("/api/upload",
                          files={"file": ("big.pcap", f, "application/octet-stream")}
                          ).json()["job_id"]

    steps = []
    with client.websocket_connect(f"/ws/{job}") as ws:
        for _ in range(200):
            msg = json.loads(ws.receive_text())
            steps.append(msg)
            if msg["type"] in ("complete", "error"):
                break

    parse_msgs = [m for m in steps if m.get("step") == "parse"]
    assert any("Parsed" in (m.get("label") or "") for m in parse_msgs), parse_msgs


# ── Small helpers ────────────────────────────────────────────────────────────

def test_a_file_that_cannot_be_opened_is_not_a_flow_export(tmp_path):
    assert webapp._looks_like_netflow(str(tmp_path / "absent.bin")) is False


def test_a_file_too_short_to_carry_a_version_word_is_not_a_flow_export(tmp_path):
    tiny = tmp_path / "tiny.bin"
    tiny.write_bytes(b"\x00")
    assert webapp._looks_like_netflow(str(tiny)) is False


def test_a_v5_export_is_recognised_by_its_version_word(tmp_path):
    flows = tmp_path / "flows.bin"
    flows.write_bytes(b"\x00\x05" + b"\x00" * 40)
    assert webapp._looks_like_netflow(str(flows)) is True


def test_capture_privilege_degrades_to_unknown_when_it_cannot_be_determined(monkeypatch):
    from packetiq import capture_setup

    def boom():
        raise RuntimeError("cannot determine privileges")

    monkeypatch.setattr(capture_setup, "status", boom)

    assert webapp._capture_privilege() == (False, "other")


def test_iterating_packets_skips_a_capture_it_cannot_read(tmp_path):
    """A batch of captures must not be abandoned because one is corrupt."""
    good = _pcap(tmp_path, "good.pcap", n=3)
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"not a pcap at all")

    seen = list(webapp._iter_packets([str(bad), str(good)]))
    assert len(seen) == 3


def test_iterating_packets_stops_at_the_scan_cap(tmp_path):
    """The packet browser reads lazily; an unbounded walk on a 10 GB capture
    would hang the request."""
    path = _pcap(tmp_path, "many.pcap", n=50)
    seen = list(webapp._iter_packets([str(path)], max_scan=10))

    assert len(seen) == 10


def test_an_attribution_serialises_for_the_ui():
    """The panel is driven entirely off this dict; a renamed field breaks it."""
    matches = AttributionEngine().attribute(
        [_event(etype=t) for t in EventType], [])
    if not matches:
        pytest.skip("no actor profile matched the synthetic TTP set")

    rec = webapp._ser_attr(matches[0])
    assert {"name", "confidence", "matched_ttps", "origin", "motivation"} <= set(rec)
    assert 0 <= rec["confidence"] <= 100


def test_the_chat_context_includes_the_attribution_section(client, tmp_path):
    job = _analyze(client, _pcap(tmp_path))
    result = dict(webapp._jobs[job]["result"])
    result["attributions"] = [{"name": "Unattributed cluster", "confidence": 42,
                               "origin": "unknown", "motivation": "unknown",
                               "matched_ttps": ["PORT_SCAN", "BRUTE_FORCE"]}]

    text = webapp._build_chat_context(result)
    assert "THREAT ACTOR ATTRIBUTION" in text
    assert "Unattributed cluster" in text
    assert "42%" in text


# ── Live-session health hints ────────────────────────────────────────────────

class _FakeSession:
    """A live session that never touches an interface."""
    interface = "en0"
    threshold = "HIGH"

    def __init__(self, alive=True, packets=0, started=None, status="running"):
        self.alerts = []
        self.packets = packets
        self.status = status
        self.started = started if started is not None else time.time()
        self.pkt_summaries = []
        self.pcap_path = "/nonexistent/live.pcap"
        self._alive = alive
        import threading
        self._lock = threading.Lock()

    def alive(self):
        return self._alive

    def maybe_scan(self):
        pass

    def flush(self):
        pass

    def stop(self):
        self.status = "stopped"


def test_a_capture_that_died_is_reported_as_a_permissions_problem(client):
    """"0 packets" tells the user nothing; the hint has to name the fix."""
    webapp._live_sessions["dead"] = _FakeSession(alive=False)
    try:
        body = client.get("/api/live/dead").json()
        assert "permissions issue" in body["hint"]
        assert "setup-capture" in body["hint"]
    finally:
        webapp._live_sessions.pop("dead", None)


def test_a_capture_that_is_alive_but_silent_is_flagged_after_a_few_seconds(client):
    webapp._live_sessions["quiet"] = _FakeSession(alive=True, packets=0,
                                                  started=time.time() - 30)
    try:
        body = client.get("/api/live/quiet").json()
        assert "No packets captured yet" in body["hint"]
    finally:
        webapp._live_sessions.pop("quiet", None)


def test_a_healthy_capture_carries_no_hint(client):
    webapp._live_sessions["ok"] = _FakeSession(alive=True, packets=500)
    try:
        assert client.get("/api/live/ok").json()["hint"] == ""
    finally:
        webapp._live_sessions.pop("ok", None)


def test_downloading_a_live_capture_before_anything_was_written_is_a_not_found(client):
    webapp._live_sessions["nofile"] = _FakeSession()
    try:
        r = client.get("/api/live/nofile/pcap")
        assert r.status_code == 404
        assert "No capture file yet" in r.json()["detail"]
    finally:
        webapp._live_sessions.pop("nofile", None)


def test_downloading_a_live_capture_from_an_unknown_session_is_a_not_found(client):
    r = client.get("/api/live/nosuchsession/pcap")
    assert r.status_code == 404
    assert "Live session not found" in r.json()["detail"]


def test_a_live_capture_that_dies_immediately_is_stopped_and_reported(client, monkeypatch):
    """Starting and dying within a second is the classic missing-privileges
    signature; leaving the session registered would hide it behind a running UI."""
    class DiesAtOnce(_FakeSession):
        def __init__(self, *a, **kw):
            super().__init__(alive=False)

        def start(self):
            pass

    monkeypatch.setattr(webapp, "_LiveSession", DiesAtOnce)

    r = client.post("/api/live/start", json={"interface": "en0"})
    assert r.status_code == 403
    assert "stopped immediately" in r.json()["detail"]


def test_a_live_capture_that_fails_for_another_reason_is_a_server_error(client,
                                                                        monkeypatch):
    class Broken:
        def __init__(self, *a, **kw):
            pass

        def start(self):
            raise RuntimeError("scapy is not installed")

    monkeypatch.setattr(webapp, "_LiveSession", Broken)

    r = client.post("/api/live/start", json={"interface": "en0"})
    assert r.status_code == 500
    assert "Could not start capture" in r.json()["detail"]


# ── Notification send ────────────────────────────────────────────────────────

def test_sending_findings_needs_a_completed_analysis(client):
    assert client.post(f"/api/notify/{UNKNOWN}/send").status_code == 404


def test_sending_findings_needs_a_configured_channel(client, tmp_path, monkeypatch):
    from packetiq.alerts import channels, telegram

    monkeypatch.setattr(channels, "configured_channels", lambda: [])
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))

    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/notify/{job}/send")

    assert r.status_code == 400
    assert "No channels configured" in r.json()["detail"]


def test_sending_findings_reports_the_per_channel_outcome(client, tmp_path, monkeypatch):
    from packetiq.alerts import channels, telegram

    monkeypatch.setattr(channels, "configured_channels", lambda: ["slack"])
    monkeypatch.setattr(channels, "broadcast", lambda subject, text, payload=None: {
        "slack": (True, "")})
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))

    job = _analyze(client, _pcap(tmp_path))
    r = client.post(f"/api/notify/{job}/send")

    assert r.status_code == 200
    assert r.json()["results"] == {"slack": True}


# ── Credential persistence fallbacks ─────────────────────────────────────────

def test_saving_telegram_credentials_survives_an_unwritable_env(client, monkeypatch,
                                                                 tmp_path):
    """A read-only working directory must not stop the session from working —
    the credentials still apply, they just do not survive a restart."""
    from packetiq.alerts import telegram

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))
    monkeypatch.setattr(webapp, "_env_upsert",
                        lambda k, v: (_ for _ in ()).throw(OSError("read-only")))

    r = client.post("/api/notify/telegram",
                    json={"token": "123456789:" + "A" * 25, "chat_id": "123456789",
                          "test": False})

    assert r.status_code == 200
    assert r.json()["configured"] is True


def test_clearing_telegram_credentials_survives_an_unwritable_env(client, monkeypatch,
                                                                   tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(webapp, "_env_remove",
                        lambda k: (_ for _ in ()).throw(OSError("read-only")))

    assert client.request("DELETE", "/api/notify/telegram").status_code == 200


def test_saving_an_api_key_survives_an_unwritable_env(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(webapp, "_env_upsert",
                        lambda k, v: (_ for _ in ()).throw(OSError("read-only")))

    r = client.post("/api/ai/key", json={"provider": "groq", "key": "abc123"})
    assert r.status_code == 200


def test_clearing_an_api_key_survives_an_unwritable_env(client, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(webapp, "_env_remove",
                        lambda k: (_ for _ in ()).throw(OSError("read-only")))

    assert client.request("DELETE", "/api/ai/key/groq").status_code == 200


def test_clearing_a_key_for_a_provider_that_has_none_is_refused(client):
    """Ollama needs no key, so there is nothing to clear."""
    for provider in ("ollama", "not-a-provider"):
        r = client.request("DELETE", f"/api/ai/key/{provider}")
        assert r.status_code == 400
        assert "Unknown provider" in r.json()["detail"]


# ── NVD-backed endpoints ─────────────────────────────────────────────────────

def _banner_pcap(tmp_path):
    from scapy.layers.http import HTTPResponse

    req = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=80, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/",
                                  User_Agent=b"curl/7.68.0"))
    resp = (Ether() / IP(src="93.184.216.34", dst="192.168.1.50")
            / TCP(sport=80, dport=51000, flags="PA")
            / HTTP() / HTTPResponse(Status_Code=b"200", Server=b"Apache/2.4.49 (Unix)"))
    for i, p in enumerate((req, resp)):
        p.time = TS + i
    path = tmp_path / "banner.pcap"
    wrpcap(str(path), [req, resp])
    return path


def test_the_cve_endpoint_returns_the_lookup_and_the_banners_it_used(client, tmp_path,
                                                                     monkeypatch):
    """Echoing the banners back is what makes the CVE list checkable — the reader
    can see exactly what was queried."""
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "lookup_banners", lambda banners, **kw: {
        "available": True, "queried": ["Apache 2.4.49"], "results": [],
        "note": "ok", "error": None})

    job = _analyze(client, _banner_pcap(tmp_path), "banner.pcap")
    body = client.get(f"/api/cve/{job}").json()

    assert body["queried"] == ["Apache 2.4.49"]
    assert any("Apache/2.4.49" in b["value"] for b in body["banners_observed"])


def test_an_nvd_failure_is_reported_as_a_bad_gateway(client, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    def boom(banners, **kw):
        raise RuntimeError("nvd.nist.gov unreachable")

    monkeypatch.setattr(nvd, "lookup_banners", boom)

    job = _analyze(client, _banner_pcap(tmp_path), "banner.pcap")
    r = client.get(f"/api/cve/{job}")

    assert r.status_code == 502
    assert "NVD lookup failed" in r.json()["detail"]


def test_the_vulnerability_endpoint_returns_the_assessment(client, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    monkeypatch.setattr(nvd, "assess_vulnerabilities", lambda banners, attacks=None, **kw: {
        "available": True, "products": [], "hosts": [], "correlations": [],
        "risk": {"score": 0, "tier": "NONE"},
        "totals": {"cves": 0, "kev": 0, "products": 0, "kev_catalog": 0},
        "note": "ok", "error": None})

    job = _analyze(client, _banner_pcap(tmp_path), "banner.pcap")
    body = client.get(f"/api/vulns/{job}").json()

    assert body["risk"]["tier"] == "NONE"
    assert body["banners_observed"]


def test_a_failed_vulnerability_assessment_is_a_bad_gateway(client, tmp_path, monkeypatch):
    from packetiq.enrichment import nvd

    def boom(banners, attacks=None, **kw):
        raise RuntimeError("nvd.nist.gov unreachable")

    monkeypatch.setattr(nvd, "assess_vulnerabilities", boom)

    job = _analyze(client, _banner_pcap(tmp_path), "banner.pcap")
    r = client.get(f"/api/vulns/{job}")

    assert r.status_code == 502
    assert "Vulnerability assessment failed" in r.json()["detail"]


@pytest.mark.parametrize("path", ["/api/cve/{job}", "/api/vulns/{job}"])
def test_the_nvd_endpoints_need_a_completed_analysis(client, path):
    assert client.get(path.format(job=UNKNOWN)).status_code == 404


# ── Fuse guard ───────────────────────────────────────────────────────────────

def test_fusing_more_than_fifty_captures_is_refused(client, tmp_path):
    """Each capture is a full analysis pass; 50 is already minutes of work."""
    pcap = _pcap(tmp_path, "one.pcap", n=2)
    data = pcap.read_bytes()
    files = [("files", (f"c{i}.pcap", io.BytesIO(data), "application/octet-stream"))
             for i in range(51)]

    r = client.post("/api/fuse", files=files)
    assert r.status_code == 400
    assert "max 50" in r.json()["detail"]
