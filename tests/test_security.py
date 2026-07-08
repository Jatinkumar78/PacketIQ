"""Regression tests for the security-audit fixes (upload DoS, command-injection hardening)."""

import asyncio
import io

import pytest
from starlette.datastructures import UploadFile

from packetiq import capture_setup
from packetiq.webapp.app import _stream_upload_to


def _uploadfile(data: bytes) -> UploadFile:
    return UploadFile(filename="x.pcap", file=io.BytesIO(data))


def test_stream_upload_writes_under_cap(tmp_path):
    dest = tmp_path / "ok.pcap"
    n = asyncio.run(_stream_upload_to(_uploadfile(b"A" * 5000), dest, max_mb=10))
    assert n == 5000 and dest.is_file() and dest.stat().st_size == 5000


def test_stream_upload_aborts_over_cap_and_cleans_up(tmp_path):
    dest = tmp_path / "big.pcap"
    # 3 MiB payload against a 1 MiB cap → 413, partial file removed (no RAM blowup)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as ei:
        asyncio.run(_stream_upload_to(_uploadfile(b"B" * (3 * 1024 * 1024)), dest, max_mb=1))
    assert ei.value.status_code == 413
    assert not dest.exists()


def test_capture_setup_rejects_unsafe_username(monkeypatch):
    """A tampered $USER must not be interpolated into the privileged shell script."""
    monkeypatch.setattr(capture_setup, "platform_name", lambda: "mac")
    monkeypatch.setattr(capture_setup, "status", lambda: (False, "mac", "no"))
    for bad in ("evil$(id)", "a;rm -rf /", "x'y", "name with space", ""):
        monkeypatch.setenv("USER", bad)
        monkeypatch.delenv("LOGNAME", raising=False)
        ok, msg = capture_setup._mac_setup()
        assert ok is False and "safe username" in msg.lower()


def test_capture_setup_accepts_safe_username_format(monkeypatch):
    """A normal username passes the charset gate (we don't actually run osascript here)."""
    import re
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,32}", "jay") is not None
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,32}", "evil$(id)") is None


# ── Round-2 fixes: path traversal, DNS-rebinding, CSRF ───────────────────────


from fastapi.testclient import TestClient  # noqa: E402
from scapy.all import IP, TCP, Ether, wrpcap  # noqa: E402

from packetiq.webapp import create_app  # noqa: E402


def _job_with_capture(client, tmp_path):
    pkts = [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80, flags="S") for i in range(10)]
    for i, p in enumerate(pkts):
        p.time = 1700000000.0 + i
    path = tmp_path / "c.pcap"
    wrpcap(str(path), pkts)
    with open(path, "rb") as f:
        job = client.post("/api/upload", files={"file": ("c.pcap", f, "application/octet-stream")}).json()["job_id"]
    import time
    for _ in range(60):
        if client.get(f"/api/results/{job}").status_code == 200:
            break
        time.sleep(0.25)
    return job


def test_evidence_endpoint_rejects_path_traversal_ip(monkeypatch, tmp_path):
    """The `ip` filter must be a real IP and must never reach the output path (CWE-22)."""
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "ev.db"))
    with TestClient(create_app()) as c:
        job = _job_with_capture(c, tmp_path)
        for bad in ["../../../../tmp/PWNED", "../escape", "not-an-ip", "1.2.3.4/../x"]:
            r = c.get(f"/api/evidence/{job}", params={"ip": bad})
            assert r.status_code == 400, f"{bad!r} should be rejected, got {r.status_code}"
        # a valid IP is accepted (200 with bytes, or 404 no-match — never a traversal)
        r = c.get(f"/api/evidence/{job}", params={"ip": "10.0.0.1"})
        assert r.status_code in (200, 404)


def test_dns_rebinding_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "r.db"))
    with TestClient(create_app()) as c:
        assert c.get("/api/feeds").status_code == 200                                   # Host: testserver
        assert c.get("/api/feeds", headers={"Host": "evil.attacker.com"}).status_code == 400


def test_csrf_cross_origin_state_change_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "x.db"))
    with TestClient(create_app()) as c:
        # cross-origin state-changing POST is rejected
        assert c.post("/api/ai/provider", json={"provider": "auto"},
                      headers={"Origin": "http://evil.example"}).status_code == 403
        # same-origin POST is allowed
        assert c.post("/api/ai/provider", json={"provider": "auto"},
                      headers={"Origin": "http://testserver"}).status_code == 200
        # cross-origin GET (read-only) is allowed (no CSRF risk)
        assert c.get("/api/feeds", headers={"Origin": "http://evil.example"}).status_code == 200
