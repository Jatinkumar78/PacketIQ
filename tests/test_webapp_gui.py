"""End-to-end tests for the GUI-backing web endpoints (feeds, evidence, MISP, Zeek, history)."""

import time

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, wrpcap

from packetiq.webapp import create_app


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


def _bf_pcap(tmp_path):
    pkts = []
    for i in range(40):
        p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000 + i, dport=22, flags="S")
        p.time = 1700000000.0 + i
        pkts.append(p)
    path = tmp_path / "bf.pcap"
    wrpcap(str(path), pkts)
    return path


def _analyze(client, path, name):
    with open(path, "rb") as f:
        r = client.post("/api/upload", files={"file": (name, f, "application/octet-stream")})
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    for _ in range(80):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


def test_feeds_endpoint(client):
    j = client.get("/api/feeds").json()
    assert j["total"] > 1000
    assert "Tor exit nodes" in j["feeds"] or "ThreatFox (IOCs)" in j["feeds"]
    # rich provenance for the upgraded GUI panel
    assert j["detailed"] and j["sources"] >= 1 and j["feed_count"] >= 1
    assert "checked_at" in j
    f0 = j["detailed"][0]
    assert {"name", "provider", "severity", "count", "updated_iso", "url"} <= set(f0)


def test_evidence_slice_endpoint(client, tmp_path):
    job = _analyze(client, _bf_pcap(tmp_path), "bf.pcap")
    r = client.get(f"/api/evidence/{job}", params={"ip": "45.33.32.156"})
    assert r.status_code == 200
    assert r.content[:4]  # got pcap bytes


def test_misp_guard_and_history(client, tmp_path):
    job = _analyze(client, _bf_pcap(tmp_path), "bf.pcap")
    # MISP without creds → 400
    assert client.post(f"/api/misp/{job}", json={"url": "", "key": ""}).status_code == 400
    # history recorded the run
    hist = client.get("/api/history").json()["analyses"]
    assert any(a["filename"] == "bf.pcap" for a in hist)


def test_fuse_campaign(client, tmp_path):
    p1 = _bf_pcap(tmp_path)
    # second capture: a port scan
    from scapy.all import IP, TCP, Ether, wrpcap
    pkts = []
    for i, port in enumerate(range(1, 60)):
        x = Ether() / IP(src="45.33.32.156", dst="10.0.0.9") / TCP(sport=50000 + i, dport=port, flags="S")
        x.time = 1700000500.0 + i * 0.1
        pkts.append(x)
    p2 = tmp_path / "scan.pcap"
    wrpcap(str(p2), pkts)

    with open(p1, "rb") as f1, open(p2, "rb") as f2:
        r = client.post("/api/fuse", files=[
            ("files", ("bf.pcap", f1, "application/octet-stream")),
            ("files", ("scan.pcap", f2, "application/octet-stream")),
        ])
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    for _ in range(80):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    res = client.get(f"/api/results/{job}").json()
    assert res["meta"]["campaign"] is True
    # campaign merges both captures' findings
    assert len(res["events"]) >= 2
    # evidence carving works across the campaign's captures
    ev = client.get(f"/api/evidence/{job}", params={"ip": "45.33.32.156"})
    assert ev.status_code == 200 and len(ev.content) > 24


def test_notify_status_and_test(client):
    j = client.get("/api/notify/status").json()
    assert "channels" in j and isinstance(j["channels"], list)
    # with no channels configured, test returns 400; if configured, 200
    assert client.post("/api/notify/test").status_code in (200, 400)


def test_history_clear(client, tmp_path):
    from packetiq import storage
    storage.record("x.pcap", 10, 50, "MEDIUM", 2, 1, "1.2.3.4")
    assert len(client.get("/api/history").json()["analyses"]) >= 1
    cleared = client.request("DELETE", "/api/history").json()
    assert cleared["cleared"] >= 1
    assert client.get("/api/history").json()["analyses"] == []


def test_live_analyze_populates_full_report(client, tmp_path):
    """A live session's recorded PCAP, when analyzed, must populate all sections."""
    import packetiq.webapp.app as app
    p = _bf_pcap(tmp_path)

    class _FakeSession:
        interface = "en0"
        packets = 40
        status = "running"
        pcap_path = str(p)
        def stop(self):
            self.status = "stopped"

    app._live_sessions["fakesid"] = _FakeSession()
    r = client.post("/api/live/fakesid/analyze")
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    for _ in range(80):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    res = client.get(f"/api/results/{job}").json()
    assert len(res["events"]) >= 1            # full pipeline ran → events present
    assert "graph" in res and res["meta"]["unique_flows"] >= 1


def test_live_analyze_guard_no_packets(client):
    import packetiq.webapp.app as app

    class _Empty:
        interface = "en0"; packets = 0; status = "running"; pcap_path = "/nonexistent.pcap"
        def stop(self): self.status = "stopped"

    app._live_sessions["empty"] = _Empty()
    assert client.post("/api/live/empty/analyze").status_code == 400


def test_packet_browser_list_search_detail(client, tmp_path):
    from scapy.all import IP, TCP, UDP, Ether, wrpcap
    from scapy.layers.dns import DNS, DNSQR
    pkts = []
    for i in range(20):
        x = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000 + i, dport=22, flags="S")
        x.time = 1700000000.0 + i
        pkts.append(x)
    d = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=33000, dport=53) / DNS(rd=1, qd=DNSQR(qname="evil.example.xyz"))
    d.time = 1700000050.0
    pkts.append(d)
    p = tmp_path / "pk.pcap"
    wrpcap(str(p), pkts)
    job = _analyze(client, p, "pk.pcap")

    lst = client.get(f"/api/packets/{job}", params={"limit": 10}).json()
    assert lst["total"] == 21 and len(lst["packets"]) == 10 and lst["has_more"]
    # search for the DNS packet
    s = client.get(f"/api/packets/{job}", params={"q": "evil.example.xyz"}).json()
    assert s["matched"] >= 1
    # packet detail with layers + hex
    det = client.get(f"/api/packets/{job}/0").json()
    assert [layer["name"] for layer in det["layers"]][:2] == ["Ethernet", "IP"]
    assert det["hex"] and "offset" in det["hex"][0]
    # nonexistent packet → 404
    assert client.get(f"/api/packets/{job}/99999").status_code == 404


def test_packet_explain_guard(client, tmp_path, monkeypatch):
    job = _analyze(client, _bf_pcap(tmp_path), "bf.pcap")
    monkeypatch.chdir(tmp_path)   # no .env here → AI treated as unconfigured
    for var in ("GEMINI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    # also disable local-LLM auto-detection so "no provider" is deterministic
    # regardless of whether an Ollama daemon happens to be running on this host
    monkeypatch.setattr("packetiq.webapp.app._ollama_available", lambda: False)
    assert client.post(f"/api/packets/{job}/0/explain").status_code == 503


def test_the_live_capture_callback_records_a_packet():
    """Drive the sniffer callback directly rather than hoping a real one fires.

    `test_live_packets_and_pcap` below starts a genuine interface capture, so whether
    this callback ever ran depended on whether traffic happened to arrive inside the
    test window. That left fourteen statements in `_LiveSession._cb` covered on some
    runs and not others — coverage swung by 0.15% between back-to-back runs of an
    unchanged tree. Feeding it a synthetic packet makes the path an assertion instead
    of a coincidence, and exercises it on machines where capture is not permitted.
    """
    from packetiq.webapp.app import _LiveSession

    session = _LiveSession("lo0", "LOW")
    assert session.sniffer is None, "constructing a session must not start capturing"

    pkt = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=1234, dport=80, flags="S")
    session._cb(pkt)

    assert session.packets == 1
    assert session._i == 1
    assert len(session.pkt_summaries) == 1, "the rolling per-packet view must get the summary"


def test_the_live_callback_writes_to_the_recording_and_handles_ipv6():
    """The two branches of `_cb` a synthetic IPv4 packet alone does not reach.

    Both were previously covered only when a real loopback capture happened to see
    traffic — the recording branch needs a writer attached, and the IPv6 address path
    in `inspect._ips` needs an IPv6 packet, which loopback chatter supplies at random.
    """
    from scapy.layers.inet6 import IPv6

    from packetiq.webapp.app import _LiveSession

    session = _LiveSession("lo0", "LOW")

    written = []
    session._writer = type("W", (), {"write": lambda _self, p: written.append(p)})()

    session._cb(Ether() / IPv6(src="::1", dst="::1") / TCP(sport=5555, dport=80, flags="S"))

    assert written, "a packet arriving while recording must reach the pcap writer"
    assert session.packets == 1
    summary = session.pkt_summaries[0]
    assert "::1" in str(summary), f"IPv6 endpoints should appear in the summary: {summary}"


def test_live_packets_and_pcap(client):
    ifs = client.get("/api/live/interfaces").json()["interfaces"]
    # Loopback only. The previous fallback to `ifs[0]` meant that on a host without a
    # loopback entry the suite would start a real capture on a physical NIC and write
    # the developer's own network traffic into an upload-directory pcap.
    iface = next((n for n in ("lo0", "lo") if n in ifs), None)
    if iface is None:
        pytest.skip("no loopback interface to capture on")
    r = client.post("/api/live/start", json={"interface": iface, "threshold": "LOW"})
    if r.status_code != 200:
        return  # capture not permitted in this environment
    sid = r.json()["session_id"]
    pk = client.get(f"/api/live/{sid}/packets").json()
    assert "packets" in pk and "total" in pk
    dl = client.get(f"/api/live/{sid}/pcap")
    assert dl.status_code == 200
    client.post(f"/api/live/{sid}/stop")


def test_live_interfaces_endpoint(client):
    j = client.get("/api/live/interfaces").json()
    assert "interfaces" in j and isinstance(j["interfaces"], list)
    assert "elevated" in j


def test_live_session_lifecycle(client):
    """Start may succeed (200) or be blocked by privileges (403); both are valid.
    If it starts, poll + stop must work."""
    ifs = client.get("/api/live/interfaces").json()["interfaces"]
    iface = "lo0" if "lo0" in ifs else ("lo" if "lo" in ifs else (ifs[0] if ifs else "lo"))
    r = client.post("/api/live/start", json={"interface": iface, "threshold": "LOW"})
    assert r.status_code in (200, 403, 500)
    if r.status_code == 200:
        sid = r.json()["session_id"]
        p = client.get(f"/api/live/{sid}").json()
        assert p["status"] == "running" and "packets" in p
        assert client.post(f"/api/live/{sid}/stop").json()["status"] == "stopped"
    # unknown session → 404
    assert client.get("/api/live/nope").status_code == 404


def test_zeek_conn_log_upload(client, tmp_path):
    lines = ["#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts"]
    for i, port in enumerate(range(1, 60)):
        lines.append(f"{1700000000 + i*0.1:.3f}\t45.33.32.156\t{40000+i}\t192.168.1.50\t{port}\ttcp\t0\t40\t0\t1\t0")
    log = tmp_path / "conn.log"
    log.write_text("\n".join(lines) + "\n")
    job = _analyze(client, log, "conn.log")
    res = client.get(f"/api/results/{job}").json()
    assert res["meta"]["unique_flows"] >= 50
    assert any(e["event_type"] == "PORT_SCAN" for e in res["events"])
