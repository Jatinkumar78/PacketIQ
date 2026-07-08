"""Tests for the one-time live-capture privilege setup (safe paths only).

These never actually change OS privileges: `setup()` is short-circuited via a
mocked `status()` (returning already-enabled), and the web endpoint is exercised
with `capture_setup.setup` monkeypatched so no sudo/osascript runs.
"""

import pytest
from fastapi.testclient import TestClient

from packetiq import capture_setup
from packetiq.webapp import create_app


def test_status_shape():
    ok, plat, detail = capture_setup.status()
    assert isinstance(ok, bool)
    assert plat in {"mac", "linux", "windows", "other"}
    assert isinstance(detail, str) and detail


def test_platform_name():
    assert capture_setup.platform_name() in {"mac", "linux", "windows", "other"}


def test_setup_noop_when_already_enabled(monkeypatch):
    monkeypatch.setattr(capture_setup, "status", lambda: (True, "mac", "enabled"))
    ok, msg = capture_setup.setup()
    assert ok is True
    assert "already" in msg.lower()


@pytest.mark.parametrize("plat", ["mac", "linux", "windows", "other"])
def test_setup_branches_per_os(monkeypatch, plat):
    # Force "not yet enabled" so setup() dispatches to the per-OS branch,
    # but stub the actual privileged actions so nothing real happens.
    monkeypatch.setattr(capture_setup, "status", lambda: (False, plat, "no"))
    monkeypatch.setattr(capture_setup, "_mac_setup", lambda: (True, "mac done"))
    monkeypatch.setattr(capture_setup, "_linux_setup", lambda: (True, "linux done"))
    monkeypatch.setattr(capture_setup, "_npcap_installed", lambda: False)
    ok, msg = capture_setup.setup()
    assert isinstance(ok, bool) and isinstance(msg, str) and msg
    if plat in {"mac", "linux"}:
        assert ok is True
    else:
        assert ok is False  # windows guidance / unsupported


def test_setup_capture_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "cap.db"))
    monkeypatch.setattr(capture_setup, "setup", lambda: (True, "✓ enabled in test"))
    with TestClient(create_app()) as c:
        r = c.post("/api/live/setup-capture")
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["ok"] is True
        assert "enabled" in j["message"]
        assert j["platform"] in {"mac", "linux", "windows", "other"}
        assert "capture_ok" in j


def test_interfaces_endpoint_reports_capture(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "if.db"))
    with TestClient(create_app()) as c:
        j = c.get("/api/live/interfaces").json()
        assert "capture_ok" in j and "platform" in j
        assert isinstance(j["interfaces"], list)
