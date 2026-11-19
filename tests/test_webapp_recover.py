"""The GUI's opt-in offline recovery.

`/api/recover/{job}` is the web twin of the CLI's `--crack`: it cracks the AS-REP
roast the capture carries and decrypts the WinRM session the recovered password
unlocks, then folds the result into the job so the web copilot's context carries
the password, the commands and the flag. Without this the GUI copilot answered
the recon half of a room and then called the session "unrecoverable" — the same
context starvation the CLI path already fixed.

The real extractor for the Kerberos roast is exercised in ``test_offline``; here
the roast is pinned so the real cracker and the real WinRM decryptor run against
real pcap bytes, and the assertions are about the endpoint and the copilot wiring.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from packetiq.offline import recover as rec_mod
from packetiq.webapp import app as webapp
from packetiq.webapp import create_app
from tests.test_offline import (
    _SOAP_CMD,
    _soap_flag,
    _winrm_pcap,
    build_session,
    make_asrep_hash,
)


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "gui.db"))
    with TestClient(create_app()) as c:
        yield c


def _winrm_result() -> dict:
    """A minimal serialised result dict carrying a WinRM session, shaped as the
    GUI stores it in ``_jobs[job]["result"]``."""
    return {
        "winrm": {
            "requests": 793,
            "sessions": 1,
            "clients": ["10.0.0.9"],
            "targets": ["10.0.0.5"],
            "accounts": [{"domain": "directory.thm", "user": "larry.doe",
                          "workstation": "KALI"}],
            "user_agents": {"Python PSRP Client": 793},
            "actions_seen": {"Command": 3},
            "payload_bytes": 120000,
            "encrypted_requests": 793,
        },
    }


def _winrm_pcap_file(tmp_path):
    pcap = tmp_path / "winrm.pcap"
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    _winrm_pcap(str(pcap), c2s, s2c)
    return pcap


def _seed_job(tmp_path, pcap_path) -> str:
    job = "rec-" + uuid.uuid4().hex
    webapp._jobs[job] = {
        "status": "complete",
        "result": _winrm_result(),
        "pcap_path": str(pcap_path),
        "filename": "winrm.pcap",
    }
    return job


def test_recover_decrypts_the_session_and_feeds_the_copilot(client, tmp_path, monkeypatch):
    pcap = _winrm_pcap_file(tmp_path)
    monkeypatch.setattr(rec_mod, "_asrep_hashes",
                        lambda p: {"larry.doe": make_asrep_hash("Password1!")})
    job = _seed_job(tmp_path, pcap)
    try:
        r = client.post(f"/api/recover/{job}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["credentials"]["larry.doe"] == "Password1!"
        assert any("reg save" in c for c in body["commands"])
        assert "THM{round_trip_flag}" in body["flags"]

        # The job now carries the recovery, and the copilot context surfaces it.
        assert webapp._jobs[job]["result"]["offline"] == body
        ctx = webapp._build_chat_context(webapp._jobs[job]["result"])
        assert "OFFLINE RECOVERY" in ctx
        assert "CRACKED PASSWORD: the account larry.doe has password Password1!" in ctx
        assert "RECOVERED by offline decryption" in ctx
        assert "THM{round_trip_flag}" in ctx
    finally:
        webapp._jobs.pop(job, None)


def test_recover_is_idempotent_and_does_not_recrack(client, tmp_path, monkeypatch):
    pcap = _winrm_pcap_file(tmp_path)
    calls = {"n": 0}

    def _hashes(_path):
        calls["n"] += 1
        return {"larry.doe": make_asrep_hash("Password1!")}

    monkeypatch.setattr(rec_mod, "_asrep_hashes", _hashes)
    job = _seed_job(tmp_path, pcap)
    try:
        first = client.post(f"/api/recover/{job}").json()
        second = client.post(f"/api/recover/{job}").json()
        assert first == second
        assert calls["n"] == 1, "the second call must reuse the stored recovery, not re-crack"
    finally:
        webapp._jobs.pop(job, None)


def test_recover_for_an_unknown_job_is_404(client):
    r = client.post("/api/recover/" + uuid.uuid4().hex)
    assert r.status_code == 404


def test_recover_when_the_capture_is_gone_is_410(client, tmp_path):
    job = _seed_job(tmp_path, tmp_path / "vanished.pcap")  # path does not exist
    try:
        r = client.post(f"/api/recover/{job}")
        assert r.status_code == 410
        assert "no longer available" in r.json()["detail"]
    finally:
        webapp._jobs.pop(job, None)


def test_chat_context_offline_section_lists_every_recovered_fact():
    """The OFFLINE RECOVERY section must surface every kind of recovered fact —
    password, command, written file and flag — each on its own labelled line, and
    the WinRM note above it must flip to the RECOVERED wording."""
    result = _winrm_result()
    result["offline"] = {
        "roasts": 1,
        "sessions": 1,
        "credentials": {"larry.doe": "Password1!"},
        "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM"],
        "exfiltrated_files": ["C:\\SYSTEM"],
        "flags": ["THM{Ya_G0t_R0aSt3d!}"],
    }
    ctx = webapp._build_chat_context(result)
    assert "OFFLINE RECOVERY (AS-REP crack + WinRM decryption)" in ctx
    assert "CRACKED PASSWORD: the account larry.doe has password Password1!" in ctx
    assert "COMMAND RUN ON THE TARGET (decrypted from WinRM): reg save HKLM\\SYSTEM C:\\SYSTEM" in ctx
    assert "FILE WRITTEN / EXFILTRATED on the target: C:\\SYSTEM" in ctx
    assert "FLAG RECOVERED: THM{Ya_G0t_R0aSt3d!}" in ctx
    assert "RECOVERED by offline decryption" in ctx


def test_chat_context_points_to_recovery_before_the_crack():
    """Before recovery runs, the WinRM note must tell the model the commands are
    recoverable (and how) — not that they are gone, which is what starved it."""
    ctx = webapp._build_chat_context(_winrm_result())
    assert "REMOTE MANAGEMENT (WinRM / WS-Management)" in ctx
    assert "AUTHENTICATED AS   : directory.thm\\larry.doe" in ctx
    assert "Client software    : Python PSRP Client x793" in ctx
    assert "Actions in clear   : Command x3" in ctx
    assert "--crack" in ctx
    assert "Recover credentials" in ctx
    # Nothing has been decrypted yet, so no OFFLINE RECOVERY section is claimed.
    assert "OFFLINE RECOVERY" not in ctx
