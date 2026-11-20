"""
Tests for the offline crack + decrypt tooling.

The crypto is checked against published MD4/RC4 vectors, and the AS-REP crack and
the WinRM decryption are round-tripped: a hash and a sealed session are built from
a known password with the same primitives a real client uses, and the tooling
recovers the password, the commands and the flag from them. Nothing here touches
a real credential; every value is generated for the test.
"""

import base64
import struct

from scapy.layers.inet import IP, TCP

from packetiq.offline import asrep, ntlm_seal, winrm
from packetiq.offline.crypto import RC4, hmac_md5, md4, nt_hash, rc4

KEY_EXCH = ntlm_seal.NTLMSSP_NEGOTIATE_KEY_EXCH
FLAGS = 0xE2898235   # unicode + extended session security + seal + key exch (a real set)


# ── fixture builders (the "encrypt" side, built from a known password) ────────

def _make_challenge(challenge: bytes, flags: int = FLAGS) -> bytes:
    return (b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 8
            + struct.pack("<I", flags) + challenge + b"\x00" * 8)


def _make_authenticate(user, domain, nt_response, enc_key, flags=FLAGS, wks="WS"):
    data = bytearray()

    def fld(b: bytes) -> bytes:
        off = 64 + len(data)
        data.extend(b)
        return struct.pack("<HHI", len(b), len(b), off)

    header = (b"NTLMSSP\x00" + struct.pack("<I", 3)
              + fld(b"\x00" * 24)                       # LM
              + fld(nt_response)                        # NT
              + fld(domain.encode("utf-16-le"))         # Domain
              + fld(user.encode("utf-16-le"))           # User
              + fld(wks.encode("utf-16-le"))            # Workstation
              + fld(enc_key)                            # EncryptedRandomSessionKey
              + struct.pack("<I", flags))
    return header + bytes(data)


def _nt_response(password, user, domain, server_challenge, blob=b"\x01\x01" + b"\x00" * 26):
    ntowfv2 = hmac_md5(nt_hash(password), (user.upper() + domain).encode("utf-16-le"))
    nt_proof = hmac_md5(ntowfv2, server_challenge + blob)
    return nt_proof + blob, ntowfv2


def _seal(seal_key: bytes, plaintexts: list[bytes]) -> bytes:
    rc = RC4(seal_key)
    body = b""
    for pt in plaintexts:
        sealed = rc.update(pt)
        enc_checksum = rc.update(b"\x00" * 8)
        signature = struct.pack("<I", 1) + enc_checksum + struct.pack("<I", 0)
        body += (b"OriginalContent: type=application/soap+xml;charset=UTF-8;Length="
                 + str(len(pt)).encode() + b"\r\napplication/octet-stream\r\n"
                 + struct.pack("<I", 16) + signature + sealed
                 + b"--Encrypted Boundary--\r\n")
    return body


def build_session(password, user="larry.doe", domain="directory.thm",
                  c2s_plain=None, s2c_plain=None):
    """Return (c2s_bytes, s2c_bytes) for one sealed WinRM connection."""
    challenge = b"\x4d\x46\x6e\xf1\x91\x79\xc6\x90"
    nt_response, ntowfv2 = _nt_response(password, user, domain, challenge)
    exported = b"EXPORTEDKEY16byt"
    session_base = hmac_md5(ntowfv2, nt_response[:16])
    enc_key = rc4(session_base, exported)
    t2 = base64.b64encode(_make_challenge(challenge)).decode()
    t3 = base64.b64encode(_make_authenticate(user, domain, nt_response, enc_key)).decode()
    client_seal = ntlm_seal.sealing_key(exported, outbound_from_client=True)
    server_seal = ntlm_seal.sealing_key(exported, outbound_from_client=False)
    c2s = (b"POST /wsman HTTP/1.1\r\nAuthorization: Negotiate " + t3.encode() + b"\r\n\r\n"
           + _seal(client_seal, c2s_plain or []))
    s2c = (b"HTTP/1.1 401\r\nWWW-Authenticate: Negotiate " + t2.encode() + b"\r\n\r\n"
           + _seal(server_seal, s2c_plain or []))
    return c2s, s2c


def make_asrep_hash(password, principal="larry.doe@DIRECTORY.THM", plaintext=b"\x00" * 40):
    k1 = hmac_md5(nt_hash(password), (8).to_bytes(4, "little"))
    checksum = hmac_md5(k1, plaintext)
    edata = rc4(hmac_md5(k1, checksum), plaintext)
    return f"$krb5asrep$23${principal}:{checksum.hex()}${edata.hex()}"


_SOAP_CMD = (b'<s:Envelope><rsp:CommandLine><rsp:Command>reg save HKLM\\SYSTEM C:\\SYSTEM'
             b'\r\nif (!$?) { exit 1 }</rsp:Command></rsp:CommandLine></s:Envelope>')


def _soap_flag(flag="THM{round_trip_flag}"):
    payload = base64.b64encode(b"PSRP binary output " + flag.encode()).decode()
    return (b'<s:Envelope><rsp:Stream>' + payload.encode() + b'</rsp:Stream></s:Envelope>')


# ── crypto primitives ─────────────────────────────────────────────────────────

def test_md4_matches_published_vectors():
    assert md4(b"").hex() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert md4(b"a").hex() == "bde52cb31de33e46245e05fbdbd6fb24"
    assert md4(b"abc").hex() == "a448017aaf21d8525fc10ae87aa6729d"
    # 80 bytes forces a second block
    assert md4(b"1234567890" * 8).hex() == "e33b4ddc9c38f2199c3e7b164fcc0536"


def test_nt_hash_and_rc4_vectors():
    assert nt_hash("password").hex() == "8846f7eaee8fb117ad06bdd830b7586c"
    assert rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3"
    # RC4 is symmetric
    assert rc4(b"k", rc4(b"k", b"roundtrip")) == b"roundtrip"


# ── AS-REP cracking ───────────────────────────────────────────────────────────

def test_crack_recovers_the_password_from_a_roast():
    h = make_asrep_hash("Password1!")
    assert asrep.crack(h, ["wrong", "Password1!", "other"]) == "Password1!"


def test_crack_returns_none_when_the_password_is_not_in_the_list():
    assert asrep.crack(make_asrep_hash("Secret99"), ["a", "b", "c"]) is None


def test_parse_asrep_hash_rejects_non_rc4_and_malformed():
    assert asrep.parse_asrep_hash("$krb5asrep$17$user@R$x$y") is None   # not etype 23
    assert asrep.parse_asrep_hash("not a hash") is None
    assert asrep.parse_asrep_hash("$krb5asrep$23$user@R$onlyedata") is None  # no checksum
    assert asrep.parse_asrep_hash("$krb5asrep$23$user@R:zz$ff") is None  # bad hex


def test_verify_password_rejects_the_wrong_password():
    _p, checksum, edata = asrep.parse_asrep_hash(make_asrep_hash("right"))
    assert asrep.verify_password(checksum, edata, "right") is not None
    assert asrep.verify_password(checksum, edata, "wrong") is None


def test_crack_on_a_non_rc4_hash_is_none():
    assert asrep.crack("$krb5asrep$18$user@R$edata", ["x"]) is None


def test_wordlists_stream_from_file_and_bundle(tmp_path, monkeypatch):
    wl = tmp_path / "wl.txt"
    wl.write_text("one\n\ntwo\n", encoding="utf-8")
    assert list(asrep.iter_wordlist(wl)) == ["one", "two"]
    assert "Password1!" in set(asrep.bundled_wordlist())
    monkeypatch.setattr(asrep, "_BUNDLED", tmp_path / "missing.txt")
    assert list(asrep.bundled_wordlist()) == []


# ── NTLM key derivation and unsealing ─────────────────────────────────────────

def test_parse_challenge_and_authenticate():
    chal = ntlm_seal.parse_challenge(_make_challenge(b"CHALLENG"))
    assert chal is not None and chal[0] == b"CHALLENG"
    nt, _ = _nt_response("pw", "u", "d", b"CHALLENG")
    auth = ntlm_seal.parse_authenticate(_make_authenticate("u", "d", nt, b"\x00" * 16))
    assert auth is not None and auth.user == "u" and auth.domain == "d"


def test_parse_rejects_wrong_magic_type_and_short():
    assert ntlm_seal.parse_challenge(b"nope") is None
    assert ntlm_seal.parse_challenge(b"NTLMSSP\x00" + struct.pack("<I", 3) + b"\x00" * 20) is None
    assert ntlm_seal.parse_authenticate(b"short") is None
    assert ntlm_seal.parse_authenticate(b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 60) is None
    # a type-3 with a too-short NT response is not NTLMv2
    short_nt = _make_authenticate("u", "d", b"\x00" * 10, b"\x00" * 16)
    assert ntlm_seal.parse_authenticate(short_nt) is None


def test_field_reader_tolerates_a_short_token():
    assert ntlm_seal._field(b"tiny", 52) == b""


def test_exported_session_key_validates_the_password():
    chal = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    nt, _ = _nt_response("Correct1!", "u", "d", chal)
    auth = ntlm_seal.parse_authenticate(_make_authenticate("u", "d", nt, b"\x00" * 16))
    # key exchange off → ExportedSessionKey is the session base key itself
    auth.flags = 0
    assert ntlm_seal.exported_session_key("Correct1!", auth, chal) is not None
    assert ntlm_seal.exported_session_key("Wrong", auth, chal) is None


def test_unsealer_round_trips_a_message():
    key = ntlm_seal.sealing_key(b"EXPORTEDKEY16byt", outbound_from_client=True)
    sealed = RC4(key).update(b"secret body")
    assert ntlm_seal.Unsealer(key).unseal(sealed) == b"secret body"


# ── WinRM session decryption ──────────────────────────────────────────────────

def test_decrypt_session_recovers_commands_and_flag():
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    session = winrm.decrypt_session(c2s, s2c, "Password1!")
    assert session is not None
    assert "reg save HKLM\\SYSTEM C:\\SYSTEM" in session["commands"]
    assert "C:\\SYSTEM" in session["files"]
    assert "THM{round_trip_flag}" in session["flags"]


def test_decrypt_session_needs_a_handshake():
    assert winrm.decrypt_session(b"no ntlm here", b"none either", "pw") is None


def test_decrypt_session_rejects_the_wrong_password():
    c2s, s2c = build_session("RightPass1", c2s_plain=[_SOAP_CMD], s2c_plain=[])
    assert winrm.decrypt_session(c2s, s2c, "WrongPass") is None


def test_stream_helpers():
    assert winrm._reassemble([(2, b"b"), (1, b"a"), (1, b"a")]) == b"ab"
    tok = base64.b64encode(b"NTLMSSP\x00rest").decode()
    assert winrm._ntlm_tokens(b"Authorization: Negotiate " + tok.encode())[0].startswith(b"NTLMSSP")
    assert winrm._ntlm_tokens(b"Authorization: Negotiate !!!bad") == []
    assert winrm._ntlm_tokens(b"Authorization: Negotiate " + base64.b64encode(b"Kerberos").decode().encode()) == []


def test_command_cleaning_and_flag_collection():
    cmds, files = [], []
    # Real Evil-WinRM: a <rsp:Command> wrapper (Invoke-Expression) plus the actual
    # command carried as base64 PSRP in <rsp:Arguments>. The wrapper and the
    # (get-location).path prompt refresh are noise; the operator command is not.
    args = base64.b64encode(
        b'<S N="V">reg save HKLM\\SYSTEM C:\\SYSTEM</S>'
        b'<S N="V">(get-location).path</S>'       # Evil-WinRM prompt noise → dropped
        b'<S N="V">123</S>')                        # no letters → not a command
    data = (b'<rsp:Command>Invoke-Expression</rsp:Command>'            # wrapper → dropped
            b'<rsp:Command>whoami /all\r\nif (!$?) { exit 1 }</rsp:Command>'
            b'<rsp:Arguments>' + args + b'</rsp:Arguments>')
    winrm._collect_commands(data, cmds, files)
    assert cmds == ["whoami /all", "reg save HKLM\\SYSTEM C:\\SYSTEM"]
    assert files == ["C:\\SYSTEM"]                  # reg save target carved
    assert "Invoke-Expression" not in cmds and "(get-location).path" not in cmds
    assert "123" not in cmds
    # A non-base64 <rsp:Arguments> blob is skipped rather than raising.
    skip_c, skip_f = [], []
    winrm._collect_commands(b"<rsp:Arguments>A=B=</rsp:Arguments>", skip_c, skip_f)
    assert skip_c == []
    flags = []
    winrm._collect_flags(b"result THM{x} THM{x}", flags)
    assert flags == ["THM{x}"]


def test_iter_sealed_stops_cleanly_on_a_truncated_stream():
    assert list(winrm._iter_sealed(b"no original content here")) == []
    assert list(winrm._iter_sealed(b"OriginalContent: Length=5\r\nno octet stream")) == []
    # header present but truncated before the signature length
    assert list(winrm._iter_sealed(
        b"OriginalContent: Length=5\r\napplication/octet-stream\r\nAB")) == []


def test_decode_psrp_skips_bad_base64():
    assert winrm._decode_psrp(b">@@@<") == b""


# ── full capture + the CLI command ────────────────────────────────────────────

def _winrm_pcap(path, c2s, s2c, client="10.0.0.9", server="10.0.0.5"):
    from scapy.layers.inet import UDP
    from scapy.utils import wrpcap
    pkts = [
        IP(src=client, dst=server) / UDP(dport=53) / b"dns",                        # non-TCP
        IP(src=client, dst=server) / TCP(sport=40001, dport=80, flags="PA", seq=1) / b"web",  # off-port
        IP(src=client, dst=server) / TCP(sport=40000, dport=5985, flags="A", seq=1),  # no payload
        IP(src=client, dst=server) / TCP(sport=40000, dport=5985, flags="PA", seq=1) / c2s,
        IP(src=server, dst=client) / TCP(sport=5985, dport=40000, flags="PA", seq=1) / s2c,
    ]
    wrpcap(str(path), [IP(bytes(p)) for p in pkts])


def test_decrypt_capture_over_a_synthetic_pcap(tmp_path):
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    pcap = tmp_path / "winrm.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    result = winrm.decrypt_capture(str(pcap), "Password1!")
    assert result and result.sessions == 1
    assert "reg save HKLM\\SYSTEM C:\\SYSTEM" in result.commands
    assert "THM{round_trip_flag}" in result.flags
    # a wrong password unlocks nothing
    assert not winrm.decrypt_capture(str(pcap), "nope")


def test_the_crack_cli_reports_nothing_without_a_roast(tmp_path):
    from click.testing import CliRunner

    from packetiq.cli import main
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    out = CliRunner().invoke(main, ["crack", str(pcap)])
    assert out.exit_code == 0 and "No AS-REP roastable" in out.output


def test_the_crack_cli_end_to_end(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from packetiq.cli import main
    from packetiq.detection import kerberos as kerb

    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    # inject a roast for a password the bundled list contains
    monkeypatch.setattr(kerb.KerberosAccumulator, "summary",
                        lambda self: {"asrep_hashes": {"larry.doe": make_asrep_hash("Password1!")}})
    wl = tmp_path / "wl.txt"
    wl.write_text("nope\nPassword1!\n", encoding="utf-8")
    out = CliRunner().invoke(main, ["crack", str(pcap), "--wordlist", str(wl)])
    assert out.exit_code == 0
    assert "Password1!" in out.output
    assert "reg save HKLM" in out.output
    assert "THM{round_trip_flag}" in out.output
    assert "C:\\SYSTEM" in out.output


def test_the_crack_cli_handles_a_session_it_cannot_decrypt(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from packetiq.cli import main
    from packetiq.detection import kerberos as kerb

    # the WinRM session was sealed with a different password than the roast we crack
    c2s, s2c = build_session("DifferentPw9", c2s_plain=[_SOAP_CMD], s2c_plain=[])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    monkeypatch.setattr(kerb.KerberosAccumulator, "summary",
                        lambda self: {"asrep_hashes": {"u": make_asrep_hash("Password1!")}})
    out = CliRunner().invoke(main, ["crack", str(pcap)])
    assert out.exit_code == 0
    assert "CRACKED" in out.output
    assert "WINRM SESSION DECRYPTED" not in out.output


def test_the_crack_cli_notes_an_uncracked_roast(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from packetiq.cli import main
    from packetiq.detection import kerberos as kerb

    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, *build_session("Password1!", c2s_plain=[_SOAP_CMD]))
    monkeypatch.setattr(kerb.KerberosAccumulator, "summary",
                        lambda self: {"asrep_hashes": {"svc": make_asrep_hash("UnguessableXyz9")}})
    out = CliRunner().invoke(main, ["crack", str(pcap)])
    assert out.exit_code == 0 and "not cracked" in out.output


# ── recover() orchestration and the copilot wiring ────────────────────────────

def test_recover_cracks_and_decrypts(tmp_path, monkeypatch):
    from packetiq.offline import recover as rec_mod
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    monkeypatch.setattr(rec_mod, "_asrep_hashes",
                        lambda p: {"larry.doe": make_asrep_hash("Password1!")})
    r = rec_mod.recover(str(pcap))
    assert r.credentials == {"larry.doe": "Password1!"}
    assert "reg save HKLM\\SYSTEM C:\\SYSTEM" in r.commands
    assert "THM{round_trip_flag}" in r.flags
    assert r.exfiltrated_files == ["C:\\SYSTEM"] and bool(r) is True
    d = r.to_dict()
    assert d["credentials"]["larry.doe"] == "Password1!" and d["roasts"] == 1


def test_recover_with_no_roast_is_empty(tmp_path, monkeypatch):
    from packetiq.offline import recover as rec_mod
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, *build_session("x", c2s_plain=[_SOAP_CMD]))
    monkeypatch.setattr(rec_mod, "_asrep_hashes", lambda p: {})
    r = rec_mod.recover(str(pcap))
    assert not r and r.roasts == 0 and r.to_dict()["commands"] == []


def test_recover_notes_an_uncracked_roast(tmp_path, monkeypatch):
    from packetiq.offline import recover as rec_mod
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, *build_session("x", c2s_plain=[_SOAP_CMD]))
    monkeypatch.setattr(rec_mod, "_asrep_hashes", lambda p: {"svc": make_asrep_hash("Unguessable9")})
    r = rec_mod.recover(str(pcap))
    assert r.roasts == 1 and r.credentials == {}


def test_asrep_hashes_is_empty_for_a_capture_without_kerberos(tmp_path):
    from packetiq.offline import recover as rec_mod
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, *build_session("x", c2s_plain=[_SOAP_CMD]))
    assert rec_mod._asrep_hashes(str(pcap)) == {}
    assert rec_mod._asrep_hashes(str(tmp_path / "nope.pcap")) == {}   # unreadable → {}


# ── the copilot context section and the WinRM note ────────────────────────────

def test_the_offline_recovery_context_section():
    from packetiq.copilot.context_builder import _offline_recovery
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _offline_recovery(ExtractionResult()) == ""
    r = ExtractionResult()
    r.offline = {"credentials": {"larry.doe": "Password1!"},
                 "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM"],
                 "exfiltrated_files": ["C:\\SYSTEM"], "flags": ["THM{x}"]}
    text = _offline_recovery(r)
    assert "OFFLINE RECOVERY" in text
    assert "Password1!" in text and "reg save HKLM\\SYSTEM C:\\SYSTEM" in text
    assert "C:\\SYSTEM" in text and "THM{x}" in text


def test_the_winrm_note_changes_once_commands_are_recovered():
    from packetiq.copilot.context_builder import _remote_management
    from packetiq.extractor.data_extractor import ExtractionResult

    r = ExtractionResult()
    r.winrm = {"requests": 5, "sessions": 1}
    assert "--crack" in _remote_management(r)              # hint when not yet recovered
    r.offline = {"commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM"]}
    assert "RECOVERED by offline decryption" in _remote_management(r)


# ── the CLI --crack wiring on chat and analyze ────────────────────────────────

def _mock_roast(monkeypatch, password="Password1!"):
    from packetiq.detection import kerberos as kerb
    monkeypatch.setattr(kerb.KerberosAccumulator, "summary",
                        lambda self: {"asrep_hashes": {"larry.doe": make_asrep_hash(password)}})


def test_apply_offline_recovery_helper(tmp_path, monkeypatch):
    from packetiq import cli
    from packetiq.extractor.data_extractor import ExtractionResult
    from packetiq.offline import recover as rec_mod

    # not cracking, a roast is present → hints, returns None
    res = ExtractionResult()
    res.kerberos = {"asrep_hashes": {"u": "h"}}
    assert cli._apply_offline_recovery(res, "x.pcap", False, None) is None
    # cracking → recovers and folds into result.offline
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    monkeypatch.setattr(rec_mod, "_asrep_hashes",
                        lambda p: {"larry.doe": make_asrep_hash("Password1!")})
    res2 = ExtractionResult()
    rec = cli._apply_offline_recovery(res2, str(pcap), True, None)
    assert rec and res2.offline["credentials"]["larry.doe"] == "Password1!"
    cli._print_offline_recovery(rec)
    # cracking but no roast → returns an empty recovery
    monkeypatch.setattr(rec_mod, "_asrep_hashes", lambda p: {})
    assert not cli._apply_offline_recovery(ExtractionResult(), str(pcap), True, None)


def test_analyze_crack_shows_the_recovery(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from packetiq.cli import main
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    _mock_roast(monkeypatch)
    out = CliRunner().invoke(main, ["analyze", str(pcap), "--crack"])
    assert out.exit_code == 0
    assert "CRACKED larry.doe: Password1!" in out.output
    assert "reg save HKLM" in out.output and "THM{round_trip_flag}" in out.output


def test_chat_crack_feeds_the_copilot_before_needing_a_provider(tmp_path, monkeypatch):
    from click.testing import CliRunner

    from packetiq.cli import main
    from packetiq.copilot.multi_provider import MultiProviderClient
    c2s, s2c = build_session("Password1!", c2s_plain=[_SOAP_CMD], s2c_plain=[_soap_flag()])
    pcap = tmp_path / "w.pcap"
    _winrm_pcap(pcap, c2s, s2c)
    _mock_roast(monkeypatch)
    monkeypatch.setattr(MultiProviderClient, "available", lambda self: False)
    out = CliRunner().invoke(main, ["chat", str(pcap), "--crack"])
    # the offline recovery ran and would reach the copilot context
    assert "CRACKED larry.doe: Password1!" in out.output
    assert "THM{round_trip_flag}" in out.output
