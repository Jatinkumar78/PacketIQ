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

import time
import types
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


def test_chat_context_numbers_commands_per_session():
    """Each WinRM shell is its own session; "the Nth command" is counted within one
    session, so a brief first session (hostname) does not shift the main session's
    count — within the main session reg save SYSTEM is #2 and reg save SAM is #3."""
    result = {"offline": {
        "credentials": {"larry.doe": "Password1!"},
        "commands": ["hostname", "whoami /all", "reg save HKLM\\SYSTEM C:\\SYSTEM",
                     "reg save HKLM\\SAM C:\\SAM"],
        "command_sessions": [
            ["hostname"],
            ["whoami /all", "reg save HKLM\\SYSTEM C:\\SYSTEM", "reg save HKLM\\SAM C:\\SAM"]],
        "flags": [], "exfiltrated_files": [], "roasts": 1, "sessions": 2,
    }}
    ctx = webapp._build_chat_context(result)
    assert "session 1:" in ctx
    assert "session 2 (main):" in ctx
    assert "      1. whoami /all" in ctx
    assert "      2. reg save HKLM\\SYSTEM C:\\SYSTEM" in ctx
    assert "      3. reg save HKLM\\SAM C:\\SAM" in ctx


def test_chat_context_points_to_recovery_before_the_crack():
    """Before recovery runs, the WinRM note must tell the model the commands are
    recoverable (and how) — not that they are gone, which is what starved it."""
    ctx = webapp._build_chat_context(_winrm_result())
    assert "REMOTE MANAGEMENT (WinRM / WS-Management)" in ctx
    assert "AUTHENTICATED AS   : directory.thm\\larry.doe" in ctx
    assert "Client software    : Python PSRP Client x793" in ctx
    assert "Actions in clear   : Command x3" in ctx
    assert "--crack" in ctx
    assert "Recover action" in ctx
    # Nothing has been decrypted yet, so no OFFLINE RECOVERY section is claimed.
    assert "OFFLINE RECOVERY" not in ctx


def test_chat_context_note_when_recovery_ran_but_found_nothing():
    """When the offline step runs and recovers nothing (unroastable account, or a
    password not in the wordlist) the note must say exactly that — not that the
    analyst still needs to run a recovery that already ran."""
    result = _winrm_result()
    result["offline"] = {"roasts": 0, "credentials": {}, "commands": [],
                         "flags": [], "exfiltrated_files": [], "sessions": 0}
    ctx = webapp._build_chat_context(result)
    assert "ran the offline recovery and recovered no commands" in ctx
    assert "OFFLINE RECOVERY" not in ctx   # nothing recovered → no section


# ── Authoritative open ports ──────────────────────────────────────────────────

def test_open_ports_payload_keeps_protocol_and_only_answered_ports():
    """A port is "open" only if a service answered a handshake; a filtered port is
    not. Protocol is kept so a TCP port-scan answer excludes UDP. Sorted, JSON-friendly."""
    result = types.SimpleNamespace(service_exposure={
        ("10.0.2.75", 445, "TCP"): {"state": "open", "service": "smb"},
        ("10.0.2.75", 88, "TCP"):  {"state": "open", "service": "kerberos"},
        ("10.0.2.75", 137, "UDP"): {"state": "open", "service": "netbios-ns"},
        ("10.0.2.75", 23, "TCP"):  {"state": "filtered", "service": ""},   # not open → dropped
    })
    assert webapp._open_ports_payload(result) == {
        "10.0.2.75": [[88, "tcp", "kerberos"], [137, "udp", "netbios-ns"], [445, "tcp", "smb"]]}


def test_chat_context_names_the_scan_found_ports_dropping_winrm_and_udp():
    """The model truncated a 14-port list, so the context now states the scan answer
    on one line: the scanned host's TCP ports, excluding post-scan WinRM (5985) and
    UDP (137). The full per-host TCP/UDP inventory is still listed below it."""
    ctx = webapp._build_chat_context({
        "winrm": {"requests": 793},
        "open_ports": {
            "10.0.2.75": [[p, "tcp", ""] for p in (53, 80, 88, 135, 445, 5985)]
                         + [[137, "udp", "netbios-ns"]],
            "20.0.0.1": [[443, "tcp", "https"]]}})   # a single-service host, not the scan target
    assert "OPEN PORTS DISCOVERED (services that answered a handshake)" in ctx
    # one authoritative answer line: the scan target's TCP ports, no 5985, no UDP
    assert ("find open\" — the TCP ports the scan of 10.0.2.75 found, lowest to highest, "
            "comma-separated: 53, 80, 88, 135, 445") in ctx
    assert "Port 5985/WinRM answered too" in ctx
    # the full inventory still lists everything, TCP and UDP separately
    assert "open TCP ports: 53, 80, 88, 135, 445, 5985" in ctx
    assert "open UDP ports: 137" in ctx


def test_chat_context_gives_the_asrep_hash_and_its_last_30_chars():
    """A small model cannot take 'the last 30 characters' of a 500-char hash, so the
    context pre-computes it as a plain substring of the real hash."""
    h = "$krb5asrep$23$larry.doe@DIRECTORY.THM:" + "a" * 32 + "$" + "b" * 90 + \
        "55616532b664cd0b50cda8d4ba469f"
    ctx = webapp._build_chat_context({"kerberos": {"asrep_hashes": {"larry.doe": h}}})
    assert "AS-REP ROAST HASH (crackable, hashcat -m 18200)" in ctx
    assert f"full hash     : {h}" in ctx
    assert "last 30 chars : 55616532b664cd0b50cda8d4ba469f" in ctx
    assert f"last 16 chars : {h[-16:]}" in ctx


# ── Recovery runs automatically ───────────────────────────────────────────────

def _upload_and_wait(client, path):
    with open(path, "rb") as f:
        r = client.post("/api/upload",
                        files={"file": (path.name, f, "application/octet-stream")})
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    for _ in range(200):
        if client.get(f"/api/results/{job}").status_code == 200:
            return job
        time.sleep(0.1)
    raise AssertionError("analysis did not complete")


def test_recovery_runs_automatically_on_upload(client, tmp_path, monkeypatch):
    """The fix for the screenshot: a plain upload-then-ask already carries the
    recovered facts, with no Recover click. Analysis auto-runs the offline step."""
    monkeypatch.setattr(rec_mod, "_asrep_hashes",
                        lambda p: {"larry.doe": make_asrep_hash("Password1!")})
    pcap = _winrm_pcap_file(tmp_path)
    job = _upload_and_wait(client, pcap)
    off = (client.get(f"/api/results/{job}").json() or {}).get("offline") or {}
    assert off.get("credentials", {}).get("larry.doe") == "Password1!"
    assert any("reg save" in c for c in off.get("commands", []))
    # …and the copilot context carries it with no manual step.
    ctx = webapp._build_chat_context(webapp._jobs[job]["result"])
    assert "OFFLINE RECOVERY" in ctx and "RECOVERED by offline decryption" in ctx


def test_auto_recovery_can_be_disabled(client, tmp_path, monkeypatch):
    """A deployment that must not crack unprompted sets PACKETIQ_AUTO_RECOVER=0;
    analysis then leaves recovery to the explicit Recover action."""
    monkeypatch.setenv("PACKETIQ_AUTO_RECOVER", "0")
    monkeypatch.setattr(rec_mod, "_asrep_hashes",
                        lambda p: {"larry.doe": make_asrep_hash("Password1!")})
    pcap = _winrm_pcap_file(tmp_path)
    job = _upload_and_wait(client, pcap)
    assert not ((client.get(f"/api/results/{job}").json() or {}).get("offline")), \
        "with auto-recover off, analysis must not auto-crack"


# --------------------------------------------------------------------------- #
#  Credential Exposure panel data (web)                                         #
# --------------------------------------------------------------------------- #

def test_results_endpoint_carries_credential_exposure_panel_data(client):
    """`/api/results` feeds the web Credentials panel: a record with the cracked
    plaintext aligned to AD, plus the hive-dump technique and its exact answer."""
    job = "rec-" + uuid.uuid4().hex
    webapp._jobs[job] = {
        "status": "complete",
        "filename": "winrm.pcap",
        "result": {
            **_winrm_result(),
            "kerberos": {"asrep_hashes": {"larry.doe": make_asrep_hash("Password1!")},
                         "valid_accounts": {"larry.doe": "AS-REP issued without pre-authentication"}},
            "offline": {"credentials": {"larry.doe": "Password1!"},
                        "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM",
                                     "reg save HKLM\\SAM C:\\SAM"]},
        },
    }
    try:
        ce = (client.get(f"/api/results/{job}").json() or {}).get("credential_exposure") or {}
        rec = ce["records"][0]
        assert rec["principal"] == "larry.doe"
        assert rec["plaintext"] == "Password1!"
        assert rec["confirmed_in_ad"] is True
        assert any("KALI" in u for u in rec["used_for"])
        tech = ce["techniques"][0]
        assert tech["answer"] == "reg save HKLM\\SYSTEM C:\\SYSTEM,reg save HKLM\\SAM C:\\SAM"
    finally:
        webapp._jobs.pop(job, None)


def test_attach_credential_exposure_reads_the_result_findings():
    data = {
        "kerberos": {"asrep_hashes": {"larry.doe": make_asrep_hash("Password1!")}},
        "offline": {"credentials": {"larry.doe": "Password1!"}},
        "winrm": {}, "cleartext": {}, "http_forensics": {},
    }
    webapp._attach_credential_exposure(data)
    assert data["credential_exposure"]["records"][0]["plaintext"] == "Password1!"


def test_recover_keeps_credential_exposure_consistent(client, tmp_path, monkeypatch):
    """After a manual /api/recover, the stored result's credential_exposure reflects
    the newly cracked plaintext, so a Credentials-panel refresh shows it."""
    monkeypatch.setattr(rec_mod, "_asrep_hashes",
                        lambda p: {"larry.doe": make_asrep_hash("Password1!")})
    pcap = _winrm_pcap_file(tmp_path)
    job = _seed_job(tmp_path, pcap)
    try:
        assert client.post(f"/api/recover/{job}").status_code == 200
        ce = webapp._jobs[job]["result"].get("credential_exposure") or {}
        assert ce["records"][0]["plaintext"] == "Password1!"
    finally:
        webapp._jobs.pop(job, None)
