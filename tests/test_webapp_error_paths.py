"""Web-app endpoints: rejection paths, the text report, and the AI provider arms.

The happy paths are covered by the end-to-end GUI suite. What was uncovered is
everything that goes *wrong*: an unknown job id, a capture that has been evicted,
an upload of the wrong kind, a provider that fails mid-stream. Those are the
responses a user actually hits, and the status code is what the front end
branches on — a 500 where a 404 belongs shows a crash dialog instead of a
message.
"""

import asyncio
import io
import json
import time

import pytest
from fastapi.testclient import TestClient
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

TS = 1700000000.0
UNKNOWN = "00000000-0000-0000-0000-000000000000"


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


def _attack_pcap(tmp_path, name="bf.pcap"):
    pkts = []
    for i in range(40):
        p = (Ether() / IP(src="45.33.32.156", dst="192.168.1.50")
             / TCP(sport=40000 + i, dport=22, flags="S"))
        p.time = TS + i
        pkts.append(p)
    for i in range(6):
        p = (Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=33000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=f"{'f' * 60}.{i}.exfil.example.xyz")))
        p.time = TS + 100 + i
        pkts.append(p)
    req = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=80, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/",
                                  User_Agent=b"curl/7.68.0"))
    req.time = TS + 200
    resp = (Ether() / IP(src="93.184.216.34", dst="192.168.1.50")
            / TCP(sport=80, dport=51000, flags="PA")
            / HTTP() / HTTPResponse(Status_Code=b"200", Server=b"Apache/2.4.49 (Unix)"))
    resp.time = TS + 201
    pkts += [req, resp]

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


# ── Upload rejection ─────────────────────────────────────────────────────────

def test_an_upload_of_the_wrong_kind_is_refused_with_the_accepted_list(client):
    r = client.post("/api/upload",
                    files={"file": ("notes.txt", io.BytesIO(b"hello"), "text/plain")})

    assert r.status_code == 400
    body = r.json()["detail"]
    assert ".pcap" in body and "Zeek" in body and "NetFlow" in body


def test_an_upload_too_small_to_be_a_capture_is_refused_and_cleaned_up(client, tmp_path):
    """A pcap file header alone is 24 bytes; anything shorter is a truncated or
    empty upload, and the partial file must not be left on disk.

    Assert on what *this* request left behind rather than on the state of the whole
    upload directory. `UPLOAD_DIR` is a single shared path under the system temp
    dir, so the old "no small pcap exists anywhere" form was really a claim about
    every other test, and about anything left there by a previous run or by the
    user's own web app. It failed the moment a live-capture test wrote a recording
    that never received a packet — a file this test had nothing to do with.
    """
    before = set(webapp.UPLOAD_DIR.glob("*.pcap"))

    r = client.post("/api/upload",
                    files={"file": ("tiny.pcap", io.BytesIO(b"\xd4\xc3\xb2\xa1"),
                                    "application/octet-stream")})

    assert r.status_code == 400
    leftover = set(webapp.UPLOAD_DIR.glob("*.pcap")) - before
    assert not leftover, f"the refused upload left {leftover} on disk"


def test_fusing_fewer_than_two_captures_is_refused(client, tmp_path):
    pcap = _attack_pcap(tmp_path)
    with open(pcap, "rb") as f:
        r = client.post("/api/fuse",
                        files=[("files", ("a.pcap", f, "application/octet-stream"))])

    assert r.status_code == 400
    assert "at least 2" in r.json()["detail"]


def test_the_synchronous_analyze_endpoint_refuses_a_non_capture(client):
    r = client.post("/api/analyze",
                    files={"file": ("notes.txt", io.BytesIO(b"x" * 100), "text/plain")})
    assert r.status_code == 400


def test_the_synchronous_analyze_endpoint_refuses_a_truncated_file(client):
    r = client.post("/api/analyze",
                    files={"file": ("t.pcap", io.BytesIO(b"\xd4\xc3\xb2\xa1"),
                                    "application/octet-stream")})
    assert r.status_code == 400


def test_the_synchronous_analyze_endpoint_returns_the_whole_result(client, tmp_path):
    pcap = _attack_pcap(tmp_path)
    with open(pcap, "rb") as f:
        r = client.post("/api/analyze",
                        files={"file": ("bf.pcap", f, "application/octet-stream")})

    assert r.status_code == 200
    body = r.json()
    assert body["job_id"]
    assert body["events"]


# ── Unknown job ids ──────────────────────────────────────────────────────────

UNKNOWN_JOB_GET_PATHS = [
    "/api/results/{job}",
    "/api/report/{job}.html",
    "/api/packets/{job}",
    "/api/packets/{job}/0",
    "/api/evidence/{job}",
    "/api/sigma/{job}/rules.zip",
    "/api/stix/{job}",
    "/api/navigator/{job}",
]


@pytest.mark.parametrize("path", UNKNOWN_JOB_GET_PATHS)
def test_an_unknown_job_is_a_not_found_not_a_crash(client, path):
    """The front end shows a message on 4xx and a crash dialog on 5xx."""
    r = client.get(path.format(job=UNKNOWN))
    assert r.status_code in (400, 404, 410), f"{path} → {r.status_code}"


def test_those_paths_are_real_routes(client):
    """Otherwise the test above passes on FastAPI's own 404 and proves nothing.

    It did: the list carried `/api/sigma/{job}` (the route is
    `/api/sigma/{job}/rules.zip`) and `/api/timeline/{job}`, which has never
    existed — the browser timeline is served inside `/api/results/{job}`. Two of
    nine cases were asserting that a typo is not a route.
    """
    routes = {getattr(r, "path", "") for r in client.app.routes}
    for path in UNKNOWN_JOB_GET_PATHS:
        template = path.replace("{job}", "{job_id}").replace("/0", "/{index}")
        assert template in routes, f"{path} is not a route the app serves"


@pytest.mark.parametrize("path", [
    "/api/misp/{job}",
    "/api/notify/findings/{job}",
    "/api/packets/{job}/0/explain",
])
def test_an_unknown_job_is_rejected_on_the_post_endpoints_too(client, path):
    r = client.post(path.format(job=UNKNOWN), json={})
    assert r.status_code in (400, 404, 410)


def test_asking_for_a_vendor_asset_that_is_not_bundled_is_a_not_found(client):
    assert client.get("/static/vendor/nothing.js").status_code == 404


def test_a_bundled_vendor_asset_is_served_with_a_cache_header(client):
    r = client.get("/static/vendor/chart.min.js")
    if r.status_code == 200:
        assert "max-age" in r.headers.get("cache-control", "")


# ── Job lifecycle ────────────────────────────────────────────────────────────

def test_results_are_not_available_until_the_analysis_finishes(client, tmp_path):
    pcap = _attack_pcap(tmp_path)
    with open(pcap, "rb") as f:
        job = client.post("/api/upload",
                          files={"file": ("bf.pcap", f, "application/octet-stream")}
                          ).json()["job_id"]

    webapp._jobs[job]["status"] = "running"
    webapp._jobs[job]["result"] = None
    r = client.get(f"/api/results/{job}")

    assert r.status_code == 202
    assert "in progress" in r.json()["detail"].lower()


def test_a_failed_analysis_reports_its_reason(client, tmp_path):
    pcap = _attack_pcap(tmp_path)
    with open(pcap, "rb") as f:
        job = client.post("/api/upload",
                          files={"file": ("bf.pcap", f, "application/octet-stream")}
                          ).json()["job_id"]

    webapp._jobs[job]["status"] = "error"
    webapp._jobs[job]["error"] = "unreadable capture"
    r = client.get(f"/api/results/{job}")

    assert r.status_code == 500
    assert "unreadable capture" in r.json()["detail"]


def test_a_job_whose_capture_was_evicted_reports_gone_not_missing(client, tmp_path):
    """410 Gone is the honest answer once the pcap has been cleaned up — the job
    existed, the bytes did not survive."""
    job = _analyze(client, _attack_pcap(tmp_path))
    webapp._jobs[job]["pcap_path"] = str(tmp_path / "vanished.pcap")
    webapp._jobs[job]["pcap_paths"] = []

    r = client.get(f"/api/evidence/{job}", params={"ip": "45.33.32.156"})
    assert r.status_code == 410
    assert "no longer available" in r.json()["detail"]


def test_deleting_a_history_row_that_does_not_exist_is_reported_honestly(client):
    r = client.request("DELETE", "/api/history/999999")
    assert r.status_code == 200
    assert r.json()["deleted"] is False


# ── WebSocket progress ───────────────────────────────────────────────────────

def test_a_websocket_for_an_unknown_job_is_closed_immediately(client):
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/{UNKNOWN}") as ws:
            ws.receive_text()


def test_a_websocket_opened_after_completion_is_told_so_at_once(client, tmp_path):
    """The browser can connect after a fast analysis has already finished; it
    must still get a terminal message rather than hanging."""
    job = _analyze(client, _attack_pcap(tmp_path))

    with client.websocket_connect(f"/ws/{job}") as ws:
        assert json.loads(ws.receive_text())["type"] == "complete"


def test_a_websocket_opened_after_a_failure_reports_the_error(client, tmp_path):
    job = _analyze(client, _attack_pcap(tmp_path))
    webapp._jobs[job]["status"] = "error"
    webapp._jobs[job]["error"] = "parser exploded"

    with client.websocket_connect(f"/ws/{job}") as ws:
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert "parser exploded" in msg["message"]


# ── Text report ──────────────────────────────────────────────────────────────

def test_the_chat_context_carries_every_section_the_model_needs(client, tmp_path):
    """`_build_chat_context` is the entire evidence the copilot sees. A section
    that silently stops being built is a section the model will then be unable
    to answer about — or will guess at."""
    job = _analyze(client, _attack_pcap(tmp_path))
    text = webapp._build_chat_context(webapp._jobs[job]["result"])
    for section in ("SEVERITY BREAKDOWN", "PROTOCOL DISTRIBUTION", "TOP SOURCE IPs",
                    "TOP DESTINATION PORTS", "TOP DNS QUERIES", "HTTP REQUESTS"):
        assert section in text, f"missing section: {section}"
    assert "45.33.32.156" in text
    assert "exfil.example.xyz" in text
    assert "example.com" in text


def test_the_chat_context_lists_findings_with_their_endpoints(client, tmp_path):
    job = _analyze(client, _attack_pcap(tmp_path))
    text = webapp._build_chat_context(webapp._jobs[job]["result"])

    assert "BRUTE_FORCE" in text
    assert "192.168.1.50:22" in text


# ── AI streaming provider arms ───────────────────────────────────────────────

def _drain(agen):
    async def run():
        return [chunk async for chunk in agen]

    return asyncio.run(run())


def _ollama_stream(monkeypatch, lines, status=200):
    """Route the Ollama arm's httpx stream at a canned NDJSON body."""
    import httpx

    class Stream:
        status_code = status

        async def aiter_lines(self):
            for line in lines:
                yield line

        async def aread(self):
            return b"model not found"

    class Ctx:
        async def __aenter__(self):
            return Stream()

        async def __aexit__(self, *exc):
            return False

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def stream(self, *a, **kw):
            return Ctx()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)


def test_the_ollama_arm_streams_its_chunks(monkeypatch):
    """Ollama is the fully-offline provider, so its arm has to work with no keys
    and no network beyond localhost."""
    _ollama_stream(monkeypatch, [
        json.dumps({"message": {"content": "The host "}}),
        json.dumps({"message": {"content": "was scanned."}}),
        json.dumps({"done": True}),
    ])

    chunks = _drain(webapp._stream_ai("ollama", None, "packetiq-net",
                                      "system", "context",
                                      [{"role": "user", "content": "what happened?"}]))
    assert "".join(chunks) == "The host was scanned."


def test_an_ollama_http_error_is_raised_so_the_caller_can_fall_back(monkeypatch):
    _ollama_stream(monkeypatch, [], status=500)

    with pytest.raises(RuntimeError, match="Ollama HTTP 500"):
        _drain(webapp._stream_ai("ollama", None, "packetiq-net", "s", "c",
                                 [{"role": "user", "content": "x"}]))


def test_an_ollama_line_that_is_not_json_is_skipped(monkeypatch):
    """The daemon emits keep-alive and blank lines between chunks."""
    _ollama_stream(monkeypatch, ["", "not json at all",
                                 json.dumps({"message": {"content": "ok"}})])

    assert "".join(_drain(webapp._stream_ai("ollama", None, "m", "s", "c",
                                            [{"role": "user", "content": "x"}]))) == "ok"


@pytest.mark.parametrize("text,expected", [
    ("429 Too Many Requests", True),
    ("RESOURCE_EXHAUSTED: quota", True),
    ("rate limit exceeded", True),
    ("500 internal error", False),
    ("connection reset", False),
])
def test_rate_limit_detection_only_fires_on_real_quota_errors(text, expected):
    """Marking a provider as rate-limited puts it in cooldown. Doing that for an
    ordinary 500 would take a working provider out of rotation."""
    assert webapp._is_rate_limit(text) is expected


def test_a_retry_after_hint_is_read_out_of_the_error(monkeypatch):
    secs = webapp._retry_after_seconds("429: please retry in 37s")
    assert isinstance(secs, (int, float)) and secs > 0


def test_an_error_with_no_retry_hint_still_yields_a_cooldown():
    assert webapp._retry_after_seconds("429 Too Many Requests") > 0


# ── Live capture endpoints ───────────────────────────────────────────────────

def test_starting_a_live_capture_without_an_interface_is_refused(client):
    r = client.post("/api/live/start", json={})
    assert r.status_code == 400
    assert "interface" in r.json()["detail"].lower()


@pytest.mark.parametrize("path,method", [
    ("/api/live/nosuchsession/stop", "post"),
    ("/api/live/nosuchsession", "get"),
    ("/api/live/nosuchsession/packets", "get"),
    ("/api/live/nosuchsession/analyze", "post"),
])
def test_an_unknown_live_session_is_a_not_found(client, path, method):
    r = getattr(client, method)(path)
    assert r.status_code == 404


def test_a_live_capture_that_cannot_open_the_interface_explains_why(client, monkeypatch):
    """"Operation not permitted" is meaningless to a user; the response has to
    point at the setup command."""
    class Denied:
        def __init__(self, *a, **kw):
            pass

        def start(self):
            raise PermissionError(13, "Operation not permitted")

    monkeypatch.setattr(webapp, "_LiveSession", Denied)

    r = client.post("/api/live/start", json={"interface": "en0"})
    assert r.status_code == 403
    assert "capture privileges" in r.json()["detail"]
    assert "setup-capture" in r.json()["detail"]


# ── Notification endpoints ───────────────────────────────────────────────────

def test_notifying_with_no_channels_configured_is_refused(client, monkeypatch):
    from packetiq.alerts import channels, telegram

    monkeypatch.setattr(channels, "configured_channels", lambda: [])
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))

    r = client.post("/api/notify/test")
    assert r.status_code == 400
    assert "No channels configured" in r.json()["detail"]


def test_notify_reports_the_per_channel_result(client, monkeypatch):
    from packetiq.alerts import channels, telegram

    monkeypatch.setattr(channels, "configured_channels", lambda: ["slack", "webhook"])
    monkeypatch.setattr(telegram, "load_credentials", lambda: (None, None))
    monkeypatch.setattr(channels, "broadcast", lambda subject, text, payload=None: {
        "slack": (True, ""), "webhook": (False, "HTTP 500")})

    r = client.post("/api/notify/test")
    assert r.status_code == 200
    assert r.json()["results"] == {"slack": True, "webhook": False}


# ── Provider configuration ───────────────────────────────────────────────────

def test_selecting_an_unknown_ai_provider_is_refused(client):
    r = client.post("/api/ai/provider", json={"provider": "not-a-provider"})
    assert r.status_code == 400
    assert "Unknown provider" in r.json()["detail"]


def test_selecting_ollama_while_the_daemon_is_down_explains_the_fix(client, monkeypatch):
    monkeypatch.setattr(webapp, "_configured_providers", lambda: [])

    r = client.post("/api/ai/provider", json={"provider": "ollama"})
    assert r.status_code == 400
    assert "Ollama" in r.json()["detail"]


# ── Evidence slicing ─────────────────────────────────────────────────────────

def test_slicing_evidence_with_no_filter_at_all_is_refused(client, tmp_path):
    """Without a filter this would hand back the whole capture as "evidence"."""
    job = _analyze(client, _attack_pcap(tmp_path))
    r = client.get(f"/api/evidence/{job}")

    assert r.status_code == 400
    assert "ip and/or port" in r.json()["detail"]


def test_slicing_evidence_with_an_address_that_is_not_one_is_refused(client, tmp_path):
    job = _analyze(client, _attack_pcap(tmp_path))
    r = client.get(f"/api/evidence/{job}", params={"ip": "not-an-address"})

    assert r.status_code == 400
    assert "Invalid IP address" in r.json()["detail"]


def test_slicing_evidence_with_a_port_out_of_range_is_refused(client, tmp_path):
    job = _analyze(client, _attack_pcap(tmp_path))
    r = client.get(f"/api/evidence/{job}", params={"port": 99999})

    assert r.status_code == 400


def test_slicing_evidence_that_matches_nothing_is_a_not_found(client, tmp_path):
    """An empty pcap download would look like a broken button."""
    job = _analyze(client, _attack_pcap(tmp_path))
    r = client.get(f"/api/evidence/{job}", params={"ip": "203.0.113.201"})

    assert r.status_code == 404
    assert "No packets matched" in r.json()["detail"]
