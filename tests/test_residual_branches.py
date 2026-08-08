"""The final residual branches.

Each of these needs the environment to misbehave in one specific way: a malformed
retry hint, an asset that is listed but missing from disk, a browser that hangs
up mid-analysis, a Windows admin check on a non-Windows host. They are the last
lines in the package that had never executed.
"""

import time

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from packetiq import capture_setup
from packetiq.attribution import engine as attr_engine
from packetiq.cli import main
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

TS = 1700000000.0


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


def _parse(pkt):
    parser = object.__new__(PCAPParser)
    parser._http_flows = set()
    pkt.time = TS
    return parser._parse_packet(pkt, 0)


# ── Retry hint parsing ───────────────────────────────────────────────────────

def test_a_retry_hint_that_is_not_a_number_falls_back_to_the_default():
    """`[\\d.]+` also matches `1.2.3`, which float() rejects. A crash here would
    turn a recoverable rate-limit into a failed request."""
    assert webapp._retry_after_seconds("429: please retry in 1.2.3s") == 60.0


def test_a_well_formed_retry_hint_is_honoured():
    assert webapp._retry_after_seconds("429: please retry in 37s") == 37.0


# ── Grounding redaction of malformed addresses ───────────────────────────────

def test_a_dotted_quad_that_is_not_an_address_is_left_alone_by_the_redactor():
    """The redactor strips IPs the capture never contained. A build number like
    999.999.999.999 is not an address at all, so removing it would corrupt the
    model's prose without cause."""
    redactor = webapp._GroundingFilter({"ips": set(), "domains": set(), "hashes": set(),
                                        "techniques": set(), "cves": set()})
    out = redactor.feed("Firmware build 999.999.999.999 was observed.\n")

    assert "999.999.999.999" in out


# ── Vendor assets ────────────────────────────────────────────────────────────

def test_a_listed_vendor_asset_that_is_not_on_disk_is_a_not_found(client, monkeypatch,
                                                                   tmp_path):
    """The allow-list and the bundled files can drift; a missing file must be a
    404, never a traversal-shaped path error."""
    monkeypatch.setattr(webapp, "STATIC_DIR", tmp_path)
    name = next(iter(webapp._VENDOR_ASSETS))

    r = client.get(f"/static/vendor/{name}")
    assert r.status_code == 404
    assert "Asset not bundled" in r.json()["detail"]


# ── WebSocket disconnect ─────────────────────────────────────────────────────

def test_a_browser_that_hangs_up_mid_analysis_does_not_leave_an_error(client, tmp_path):
    """Closing the tab is normal. The server has to unwind quietly rather than
    logging a failure for a job that is still running fine."""
    from scapy.utils import wrpcap

    pkts = []
    for i in range(40):
        p = (Ether() / IP(src="45.33.32.156", dst="192.168.1.50")
             / TCP(sport=40000 + i, dport=22, flags="S"))
        p.time = TS + i
        pkts.append(p)
    path = tmp_path / "bf.pcap"
    wrpcap(str(path), pkts)

    with open(path, "rb") as f:
        job = client.post("/api/upload",
                          files={"file": ("bf.pcap", f, "application/octet-stream")}
                          ).json()["job_id"]

    with client.websocket_connect(f"/ws/{job}") as ws:
        ws.receive_text()          # take one progress message, then hang up

    for _ in range(120):
        if webapp._jobs[job]["status"] in ("complete", "error"):
            break
        time.sleep(0.25)

    assert webapp._jobs[job]["status"] == "complete", "the analysis must finish anyway"


# ── Interface enumeration, both helpers down ─────────────────────────────────

def test_the_interface_list_is_empty_when_even_scapy_cannot_enumerate(client,
                                                                       monkeypatch):
    """With nothing to list, the picker shows an empty state — not a 500."""
    import scapy.all as scapy_all

    from packetiq import net_interfaces

    monkeypatch.setattr(net_interfaces, "list_interfaces",
                        lambda: (_ for _ in ()).throw(RuntimeError("no helper")))
    monkeypatch.setattr(scapy_all, "get_if_list",
                        lambda: (_ for _ in ()).throw(RuntimeError("no scapy either")))

    r = client.get("/api/live/interfaces")
    assert r.status_code == 200
    assert r.json()["interfaces"] == []


# ── Parser: scapy-dissected HTTP with unusable raw bytes ─────────────────────

def test_the_scapy_layer_fills_fields_the_byte_sniffer_could_not_read():
    """The hand-rolled sniffer requires an `HTTP/1.x` version token. A request
    carrying a different version still dissects, and scapy's fields are then the
    only source for the method, host and path.
    """
    pkt = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=8888, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com",
                                  Path=b"/index.html", Http_Version=b"HTTP/2.0",
                                  User_Agent=b"curl/8"))
    rec = _parse(pkt)

    assert rec.has_http
    assert rec.http_method == "GET"
    assert rec.http_host == "example.com"
    assert rec.http_path == "/index.html"


def test_a_request_line_with_an_unsupported_version_is_not_sniffed_from_bytes():
    """Three fields but no `HTTP/1.x` — the byte sniffer must decline rather than
    accept an HTTP/2 preface as a plaintext request."""
    pkt = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=8888, flags="PA")
           / b"GET /index.html HTTP/2.0\r\nHost: victim\r\n\r\n")
    rec = _parse(pkt)

    assert rec.http_method is None


def test_a_netbios_datagram_is_named_by_its_layer():
    """Port 138 alone is not proof; the dissected NBT layer is."""
    from scapy.layers.netbios import NBTDatagram

    pkt = (Ether() / IP(src="192.168.1.50", dst="192.168.1.255")
           / UDP(sport=138, dport=138) / NBTDatagram())
    rec = _parse(pkt)

    assert rec.display_protocol == "NBT-DGM"


# ── Windows capture privileges ───────────────────────────────────────────────

def test_an_elevated_windows_session_can_capture(monkeypatch):
    """`ctypes.windll` exists only on the Windows build, so this branch can never
    run on a developer machine — it is stubbed to prove the admin path returns
    True without falling through to the Npcap probe."""
    import ctypes

    class Shell32:
        @staticmethod
        def IsUserAnAdmin():
            return 1

    monkeypatch.setattr(ctypes, "windll",
                        type("WinDLL", (), {"shell32": Shell32})(), raising=False)
    monkeypatch.setattr(capture_setup, "_npcap_installed",
                        lambda: pytest.fail("must not fall through to the Npcap probe"))

    assert capture_setup._windows_capture_ok() is True


# ── Attribution overlap floor ────────────────────────────────────────────────

def test_a_profile_matched_on_enough_ttps_but_weakly_is_still_rejected(monkeypatch):
    """Three overlapping TTPs out of a very broad profile is a low-confidence
    coincidence. Surfacing it would name a threat actor on thin evidence."""
    monkeypatch.setattr(attr_engine, "THREAT_ACTORS", [
        {"name": "Very Broad Profile", "aliases": [], "origin": "?", "motivation": "?",
         "ttp_weights": {t: 1.0 for t in EventType},
         "phases": set(), "description": "", "references": []},
    ])

    events = [DetectionEvent(event_type=t, severity=Severity.HIGH, src_ip="10.0.0.1",
                             description="x", timestamp=TS)
              for t in list(EventType)[:4]]

    assert attr_engine.AttributionEngine().attribute(events, []) == []


# ── CLI live sniff completing normally ───────────────────────────────────────

def test_the_live_command_finishes_cleanly_when_sniffing_ends(monkeypatch):
    """Ctrl-C inside `sniff_live` returns normally; the command must then print
    its closing divider and exit 0 rather than looking like a crash."""
    from packetiq import live as live_mod

    monkeypatch.setattr(live_mod, "sniff_live",
                        lambda *a, **kw: live_mod.LiveMonitor(300.0, "HIGH",
                                                              lambda e: None))

    result = CliRunner().invoke(main, ["live", "-i", "en0"])

    assert result.exit_code == 0
    assert "Sniffing en0" in result.output


def test_a_progress_socket_that_goes_quiet_is_closed_rather_than_held_open(client,
                                                                           monkeypatch):
    """The relay waits 10 minutes for the next progress message. If an analysis
    wedges, the socket must be closed instead of pinned open forever — the real
    timeout is stubbed here so the test does not wait for it.
    """
    import asyncio as _asyncio

    class _SilentQueue:
        """Loop-agnostic: a real asyncio.Queue binds to its creating loop on 3.9."""

        async def get(self):
            await _asyncio.sleep(3600)

    job_id = "stalled-job"
    webapp._jobs[job_id] = {"status": "running", "result": None,
                            "queue": _SilentQueue(), "filename": "x.pcap",
                            "error": None}

    async def immediate_timeout(awaitable, timeout=None):
        if hasattr(awaitable, "close"):
            awaitable.close()
        raise _asyncio.TimeoutError

    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setattr(webapp.asyncio, "wait_for", immediate_timeout)
    try:
        with client.websocket_connect(f"/ws/{job_id}") as ws:
            with pytest.raises(WebSocketDisconnect):
                ws.receive_text()
    finally:
        webapp._jobs.pop(job_id, None)
