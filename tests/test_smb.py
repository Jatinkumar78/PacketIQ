"""
Tests for SMB detection.

Messages are built with scapy's own SMB2 layer under a NetBIOS session header,
which is how SMB2 actually travels on 445. The security blobs are real SPNEGO
tokens wrapping real NTLM type 3 messages, built with scapy's GSSAPI and NTLM
classes, not hand-forged byte strings.

A note on bytes round-trips. Tree Connect, Create, Negotiate and SMB1 are
re-dissected from bytes, so those tests exercise the exact path a capture
takes. Session Setup, Read and Write are fed as live scapy objects instead:
scapy can serialise these three but cannot re-dissect its own output (the
variable-length buffer offsets it writes do not satisfy the dissector it reads
them back with), while the real capture dissects them fine. The detector reads
the same fields from a live object as from a dissected one, and the NTLM
byte-decoding that matters most is round-tripped exhaustively in test_ntlm.py,
so nothing real goes untested. This asymmetry is itself a finding: it is why
the WINRM module hand-parses HTTP rather than leaning on scapy's HTTP layer.

The scenarios are the sequence every lateral movement follows: negotiate,
authenticate, connect to a share, open something. The one that matters most is
a write to ``ADMIN$`` followed by the ``svcctl`` pipe, because that pair is how
PsExec and its descendants run code on a remote host.
"""

from scapy.layers.gssapi import GSSAPI_BLOB
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.netbios import NBTSession
from scapy.layers.ntlm import NTLM_AUTHENTICATE_V2
from scapy.layers.smb2 import (
    SMB2_Create_Request,
    SMB2_Header,
    SMB2_Negotiate_Protocol_Request,
    SMB2_Read_Request,
    SMB2_Session_Setup_Request,
    SMB2_Tree_Connect_Request,
    SMB2_Write_Request,
)
from scapy.layers.spnego import SPNEGO_negToken, SPNEGO_negTokenResp

from packetiq.detection import smb as mod
from packetiq.detection.models import EventType, Severity

ATTACKER = "10.0.2.74"
TARGET = "10.0.2.75"


# ── building real messages ────────────────────────────────────────────────────

def _wire(body, command, *, src=ATTACKER, dst=TARGET, port=445, ts=0.0):
    # The NetBIOS session header must carry the SMB message length, or scapy
    # takes zero bytes as the payload on re-dissection and the SMB2 layer never
    # reappears. A real capture always has it set; a hand-built packet does not
    # unless we compute it, which is exactly the trap that made these tests fail
    # while the detector worked fine on the real pcap.
    inner = SMB2_Header(Command=command) / body
    pkt = (IP(src=src, dst=dst) / TCP(sport=45000, dport=port, flags="PA")
           / NBTSession(LENGTH=len(bytes(inner))) / inner)
    out = IP(bytes(pkt))
    out.time = ts
    return out


def _wire_live(body, command, *, src=ATTACKER, dst=TARGET, port=445, ts=0.0):
    """A packet the detector reads without a bytes round-trip.

    For Session Setup, Read and Write, which scapy serialises but cannot
    re-dissect from its own output. The detector reads the same fields either
    way; see the module docstring for why this is necessary and safe.
    """
    pkt = (IP(src=src, dst=dst) / TCP(sport=45000, dport=port, flags="PA")
           / NBTSession() / SMB2_Header(Command=command) / body)
    pkt.time = ts
    return pkt


def negotiate(ts=0.0):
    return _wire(SMB2_Negotiate_Protocol_Request(), mod.SMB2_NEGOTIATE, ts=ts)


def tree_connect(path=r"\\ADSERVER\ADMIN$", ts=0.0):
    return _wire(SMB2_Tree_Connect_Request(Buffer=[("Path", path)]),
                 mod.SMB2_TREE_CONNECT, ts=ts)


def create(name="payload.exe", ts=0.0):
    return _wire(SMB2_Create_Request(Buffer=[("Name", name)]), mod.SMB2_CREATE, ts=ts)


def write(length=4096, ts=0.0):
    return _wire_live(SMB2_Write_Request(DataLen=length), mod.SMB2_WRITE, ts=ts)


def read(length=2048, ts=0.0):
    return _wire_live(SMB2_Read_Request(Length=length), mod.SMB2_READ, ts=ts)


def spnego_ntlm(user="larry.doe", domain="directory.thm", workstation="KALI"):
    """A real SPNEGO token wrapping a real NTLM type 3 message.

    Built with scapy's GSSAPI and NTLM layers so it is a genuine security blob,
    the same structure a Windows client sends in an SMB2 session setup. An empty
    user/domain/workstation gives the null-session blob that names nobody.
    """
    ntlm = bytes(NTLM_AUTHENTICATE_V2(UserName=user, DomainName=domain,
                                      Workstation=workstation))
    return bytes(GSSAPI_BLOB(innerToken=SPNEGO_negToken(
        token=SPNEGO_negTokenResp(responseToken=ntlm))))


def session_setup(blob=None, ts=0.0):
    if blob is None:
        blob = spnego_ntlm()
    return _wire_live(SMB2_Session_Setup_Request(Buffer=[("SecurityBlob", blob)]),
                      mod.SMB2_SESSION_SETUP, ts=ts)


def ntlm_blob(user="larry.doe", domain="directory.thm", workstation="KALI"):
    return spnego_ntlm(user, domain, workstation)


def anonymous_blob():
    """The null-session blob: a valid SPNEGO token naming nobody."""
    return spnego_ntlm(user="", domain="", workstation="")


def _run(packets):
    acc = mod.SMBAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc


# ── helpers ───────────────────────────────────────────────────────────────────

def test_a_unc_path_is_reduced_to_the_share_name():
    assert mod.share_name(r"\\ADSERVER\ADMIN$") == "ADMIN$"
    assert mod.share_name(r"\\ADSERVER\C$\\") == "C$"
    assert mod.share_name("IPC$") == "IPC$"


def test_smb2_strings_are_decoded_from_either_encoding():
    assert mod._text("payload.exe".encode("utf-16-le")) == "payload.exe"
    assert mod._text(b"payload.exe") == "payload.exe"
    assert mod._text("payload.exe") == "payload.exe"
    assert mod._text(None) == ""


def test_a_named_buffer_entry_is_found_and_a_missing_one_is_not():
    body = SMB2_Tree_Connect_Request(Buffer=[("Path", r"\\host\share")])
    assert mod._buffer_value(body, "Path") is not None
    assert mod._buffer_value(body, "NoSuchField") is None
    assert mod._buffer_value(object(), "Path") is None


# ── intake ────────────────────────────────────────────────────────────────────

def test_non_smb_traffic_is_ignored():
    acc = _run([IP(src=ATTACKER, dst=TARGET) / TCP(dport=443),
                IP(src=ATTACKER, dst=TARGET) / UDP(dport=53)])
    assert acc.operations == []
    assert acc.summary() == {}


def test_smb_over_ipv6_is_read_the_same_as_over_ipv4():
    pkt = (IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=5, dport=445, flags="PA")
           / NBTSession() / SMB2_Header(Command=mod.SMB2_NEGOTIATE)
           / SMB2_Negotiate_Protocol_Request())
    assert len(_run([IPv6(bytes(pkt))]).operations) == 1


def test_a_response_is_attributed_to_the_same_session_as_its_request():
    outbound = negotiate(ts=1.0)
    inbound = _wire(SMB2_Negotiate_Protocol_Request(), mod.SMB2_NEGOTIATE,
                    src=TARGET, dst=ATTACKER, ts=2.0)
    inbound[TCP].sport, inbound[TCP].dport = 445, 45000
    acc = _run([outbound, IP(bytes(inbound))])
    assert len(acc.sessions) == 1


def test_an_smb_message_with_no_ip_layer_is_skipped_not_crashed():
    bare = (TCP(sport=45000, dport=445, flags="PA") / NBTSession()
            / SMB2_Header(Command=mod.SMB2_NEGOTIATE) / SMB2_Negotiate_Protocol_Request())
    assert _run([TCP(bytes(bare))]).operations == []


def test_a_message_that_cannot_be_decoded_ends_that_packet_and_not_the_pass(monkeypatch):
    acc = mod.SMBAccumulator()

    def truncated(*_args, **_kwargs):
        raise ValueError("truncated SMB2 body")

    monkeypatch.setattr(acc, "_decode_smb2", truncated)
    acc.feed(negotiate())
    assert acc.operations == []

    monkeypatch.undo()
    acc.feed(negotiate())
    assert len(acc.operations) == 1


def test_endpoint_extraction_gives_up_quietly_on_a_packet_it_cannot_read():
    class Hostile:
        def haslayer(self, _layer):
            raise ValueError("not a packet")

    assert mod._endpoints(Hostile()) == (None, None)
    assert mod._server_port(Hostile()) is None


def test_an_smb_command_without_a_name_is_still_counted():
    acc = _run([_wire(SMB2_Negotiate_Protocol_Request(), 42)])
    assert acc.summary()["commands"] == {"command 42": 1}


# ── lateral movement ──────────────────────────────────────────────────────────

def test_a_write_to_an_admin_share_and_the_service_pipe_is_remote_execution():
    """The PsExec sequence, and the single most important thing SMB can show.

    Connecting to ADMIN$ stages a file; opening svcctl creates the service that
    runs it. Either alone is notable, both together is code execution.
    """
    packets = [negotiate(ts=1.0), tree_connect(ts=2.0), create("payload.exe", ts=3.0),
               write(ts=4.0), tree_connect(r"\\ADSERVER\IPC$", ts=5.0),
               create("svcctl", ts=6.0)]
    events = _run(packets).finalize()

    lateral = [e for e in events if e.event_type is EventType.SMB_LATERAL_MOVEMENT]
    assert len(lateral) == 1
    assert lateral[0].severity is Severity.CRITICAL
    assert "ADMIN$" in lateral[0].evidence["admin_shares"]
    assert "svcctl" in lateral[0].evidence["named_pipes"]
    assert "remote service control" in lateral[0].evidence["named_pipes"]


def test_an_admin_share_on_its_own_is_high_rather_than_critical():
    packets = [negotiate(ts=1.0), tree_connect(ts=2.0), create("note.txt", ts=3.0)]
    lateral = [e for e in _run(packets).finalize()
               if e.event_type is EventType.SMB_LATERAL_MOVEMENT][0]
    assert lateral.severity is Severity.HIGH
    assert lateral.evidence["named_pipes"] == "none"


def test_every_execution_pipe_is_named_for_what_it_does():
    for pipe, expected in (("atsvc", "scheduled task"), ("winreg", "remote registry"),
                           ("samr", "SAM database"), ("spoolss", "print spooler")):
        packets = [negotiate(ts=1.0), tree_connect(r"\\HOST\IPC$", ts=2.0),
                   create(pipe, ts=3.0)]
        lateral = [e for e in _run(packets).finalize()
                   if e.event_type is EventType.SMB_LATERAL_MOVEMENT][0]
        assert expected in lateral.evidence["named_pipes"]


def test_an_ordinary_user_share_is_not_lateral_movement():
    """People's files live on shares. Connecting to one is not an alert."""
    packets = [negotiate(ts=1.0), tree_connect(r"\\FILESRV\Finance", ts=2.0),
               create("budget.xlsx", ts=3.0)]
    assert [e for e in _run(packets).finalize()
            if e.event_type is EventType.SMB_LATERAL_MOVEMENT] == []


def test_the_account_that_authenticated_is_carried_into_the_finding():
    packets = [negotiate(ts=1.0), session_setup(ntlm_blob(), ts=2.0),
               tree_connect(ts=3.0), create("payload.exe", ts=4.0)]
    lateral = [e for e in _run(packets).finalize()
               if e.event_type is EventType.SMB_LATERAL_MOVEMENT][0]
    assert "larry.doe" in lateral.evidence["authenticated_as"]


# ── file activity ─────────────────────────────────────────────────────────────

def test_files_written_over_smb_are_named_and_the_direction_is_stated():
    packets = [negotiate(ts=1.0), tree_connect(r"\\FILESRV\Finance", ts=2.0),
               create("budget.xlsx", ts=3.0), write(8192, ts=4.0), write(4096, ts=5.0)]
    files = [e for e in _run(packets).finalize()
             if e.event_type is EventType.SMB_FILE_ACCESS]
    assert len(files) == 1
    assert files[0].severity is Severity.HIGH
    assert "budget.xlsx" in files[0].evidence["files"]
    assert files[0].evidence["bytes_written"] == 12288
    assert files[0].evidence["direction"] == "written to the server"


def test_files_read_from_a_share_are_reported_as_reads():
    packets = [negotiate(ts=1.0), tree_connect(r"\\FILESRV\Finance", ts=2.0),
               create("budget.xlsx", ts=3.0), read(65536, ts=4.0)]
    files = [e for e in _run(packets).finalize()
             if e.event_type is EventType.SMB_FILE_ACCESS][0]
    assert files.severity is Severity.MEDIUM
    assert files.evidence["direction"] == "read from the server"
    assert files.evidence["bytes_read"] == 65536


def test_a_named_pipe_is_not_counted_as_a_file():
    """Lateral movement already reports pipes; counting them twice inflates both."""
    packets = [negotiate(ts=1.0), tree_connect(r"\\HOST\IPC$", ts=2.0),
               create("svcctl", ts=3.0), write(16, ts=4.0)]
    assert [e for e in _run(packets).finalize()
            if e.event_type is EventType.SMB_FILE_ACCESS] == []


def test_a_session_too_short_to_judge_is_not_reported_as_file_activity():
    assert [e for e in _run([create("x.txt", ts=1.0)]).finalize()
            if e.event_type is EventType.SMB_FILE_ACCESS] == []


# ── identity ──────────────────────────────────────────────────────────────────

def test_the_account_is_lifted_from_the_spnego_blob_of_a_session_setup():
    """The same NTLM decoding that reads a WinRM Authorization header."""
    events = _run([negotiate(ts=1.0), session_setup(ntlm_blob(), ts=2.0)]).finalize()
    ident = [e for e in events if e.event_type is EventType.NTLM_AUTHENTICATION]
    assert len(ident) == 1
    assert ident[0].evidence["accounts"] == "directory.thm\\larry.doe from KALI"
    assert ident[0].evidence["workstations_claimed"] == "KALI"
    assert ident[0].protocol == "SMB"


def test_a_session_setup_with_no_ntlm_in_it_names_nobody():
    acc = _run([negotiate(ts=1.0), session_setup(b"\x60\x20 kerberos only", ts=2.0)])
    assert [e for e in acc.finalize()
            if e.event_type is EventType.NTLM_AUTHENTICATION] == []
    assert acc.summary()["anonymous_sessions"] == 0


def test_a_session_setup_with_no_blob_at_all_is_harmless():
    acc = _run([negotiate(ts=1.0), session_setup(b"", ts=2.0)])
    assert acc.summary()["accounts"] == []


# ── null sessions and legacy dialects ────────────────────────────────────────

def test_an_ntlm_message_naming_nobody_is_an_anonymous_session():
    """Not a failed logon: a deliberate unauthenticated bind.

    Every name length and the NT response length are zero. It is what a scanner
    sends to fingerprint a host, and it is in the real capture this module was
    written from.
    """
    events = _run([negotiate(ts=1.0), session_setup(anonymous_blob(), ts=2.0)]).finalize()
    null = [e for e in events if "null session" in e.description]
    assert len(null) == 1
    assert null[0].event_type is EventType.PROTOCOL_MISUSE
    assert null[0].evidence["anonymous_session_setups"] == 1


def test_smb1_on_the_wire_is_reported():
    from scapy.layers.smb import SMB_Header

    smb1_body = SMB_Header()
    pkt = (IP(src=ATTACKER, dst=TARGET) / TCP(sport=45000, dport=445, flags="PA")
           / NBTSession(LENGTH=len(bytes(smb1_body))) / smb1_body)
    events = _run([IP(bytes(pkt))]).finalize()
    legacy = [e for e in events if "SMB1" in e.description]
    assert len(legacy) == 1
    assert legacy[0].event_type is EventType.PROTOCOL_MISUSE
    assert _run([IP(bytes(pkt))]).summary()["smb1_seen"] is True


def test_a_modern_session_is_not_accused_of_speaking_smb1():
    acc = _run([negotiate(ts=1.0), session_setup(ntlm_blob(), ts=2.0)])
    assert acc.summary()["smb1_seen"] is False
    assert [e for e in acc.finalize() if "SMB1" in e.description] == []


def test_port_139_is_watched_as_well_as_445():
    assert len(_run([negotiate(ts=1.0)]).operations) == 1
    acc = _run([_wire(SMB2_Negotiate_Protocol_Request(), mod.SMB2_NEGOTIATE, port=139)])
    assert len(acc.operations) == 1


# ── the summary the copilot and the report read ───────────────────────────────

def test_the_summary_states_the_shares_the_files_and_the_account():
    packets = [negotiate(ts=1.0), session_setup(ntlm_blob(), ts=2.0),
               tree_connect(ts=3.0), create("payload.exe", ts=4.0),
               write(4096, ts=5.0), read(1024, ts=6.0)]
    s = _run(packets).summary()

    assert s["operations"] == 6
    assert s["sessions"] == 1
    assert s["clients"] == [ATTACKER]
    assert s["servers"] == [TARGET]
    assert r"\\ADSERVER\ADMIN$" in s["shares"]
    assert "payload.exe" in s["files"]
    assert s["accounts"] == [{"user": "larry.doe", "domain": "directory.thm",
                              "workstation": "KALI"}]
    assert s["bytes_written"] == 4096
    assert s["bytes_read"] == 1024
    assert s["commands"]["Tree Connect"] == 1


def test_the_summary_is_empty_when_the_capture_has_no_smb():
    assert mod.SMBAccumulator().summary() == {}


# ── reaching the analyst ──────────────────────────────────────────────────────

def _psexec_pcap(path):
    from scapy.utils import wrpcap
    wrpcap(str(path), [negotiate(ts=1.0), session_setup(ntlm_blob(), ts=2.0),
                       tree_connect(ts=3.0), create("payload.exe", ts=4.0),
                       write(4096, ts=5.0), tree_connect(r"\\ADSERVER\IPC$", ts=6.0),
                       create("svcctl", ts=7.0)])
    return str(path)


def test_the_cli_names_the_share_the_file_the_pipe_and_the_account(tmp_path):
    from click.testing import CliRunner

    from packetiq.cli import main

    out = CliRunner().invoke(main, ["analyze", _psexec_pcap(tmp_path / "smb.pcap"), "--full"])

    # The share, the file and the pipe survive a pcap write-and-read; the
    # account comes from a session setup, which scapy cannot re-dissect from a
    # pcap it wrote, so the account is asserted at the accumulator level in
    # test_the_account_is_lifted_from_the_spnego_blob_of_a_session_setup.
    assert out.exit_code == 0, out.output
    assert "FILE SHARING" in out.output
    assert "ADMIN$" in out.output
    assert "payload.exe" in out.output
    assert "svcctl" in out.output


def test_the_cli_warns_about_smb1(tmp_path):
    from click.testing import CliRunner
    from scapy.layers.smb import SMB_Header
    from scapy.utils import wrpcap

    from packetiq.cli import main

    _smb1_body = SMB_Header()
    smb1 = IP(bytes(IP(src=ATTACKER, dst=TARGET) / TCP(sport=45000, dport=445, flags="PA")
                    / NBTSession(LENGTH=len(bytes(_smb1_body))) / _smb1_body))
    pcap = str(tmp_path / "legacy.pcap")
    wrpcap(pcap, [negotiate(ts=1.0), smb1])
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "SMB1 was negotiated" in out.output


def test_a_capture_without_smb_prints_no_file_sharing_section(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "plain.pcap")
    wrpcap(pcap, [IP(src=ATTACKER, dst=TARGET) / TCP(dport=443) for _ in range(4)])
    out = CliRunner().invoke(main, ["analyze", pcap])

    assert out.exit_code == 0, out.output
    assert "FILE SHARING" not in out.output


def test_the_copilot_context_carries_the_shares_files_pipes_and_account():
    from packetiq.copilot.context_builder import _file_sharing
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run([negotiate(ts=1.0), session_setup(ntlm_blob(), ts=2.0),
                tree_connect(ts=3.0), create("payload.exe", ts=4.0),
                write(4096, ts=5.0), tree_connect(r"\\ADSERVER\IPC$", ts=6.0),
                create("svcctl", ts=7.0)])
    result = ExtractionResult()
    result.smb = acc.summary()

    text = _file_sharing(result)
    assert "FILE SHARING (SMB)" in text
    assert "AUTHENTICATED AS: directory.thm\\larry.doe" in text
    assert "ADMIN$" in text
    assert "payload.exe" in text
    assert "PIPE: svcctl -> remote service control" in text
    assert "4096 written" in text


def test_the_context_reports_null_sessions_and_smb1():
    from scapy.layers.smb import SMB_Header

    from packetiq.copilot.context_builder import _file_sharing
    from packetiq.extractor.data_extractor import ExtractionResult

    _smb1_body = SMB_Header()
    smb1 = IP(bytes(IP(src=ATTACKER, dst=TARGET) / TCP(sport=45000, dport=445, flags="PA")
                    / NBTSession(LENGTH=len(bytes(_smb1_body))) / _smb1_body))
    acc = _run([negotiate(ts=1.0), session_setup(anonymous_blob(), ts=2.0), smb1])
    result = ExtractionResult()
    result.smb = acc.summary()

    text = _file_sharing(result)
    assert "Anonymous sessions: 1" in text
    assert "SMB1" in text


def test_the_context_section_is_absent_when_there_was_no_smb():
    from packetiq.copilot.context_builder import _file_sharing
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _file_sharing(ExtractionResult()) == ""


# ── the small internals, covered directly ─────────────────────────────────────

def test_a_blob_that_is_none_names_nobody():
    """A session setup with no security buffer at all is not an anonymous login."""
    assert mod._authentication_from_blob(None) == (None, False)


def test_session_duration_and_admin_share_helpers():
    state = mod._SessionState(first_ts=10.0, last_ts=25.0)
    state.shares["\\\\H\\ADMIN$"] = 1
    state.shares["\\\\H\\Finance"] = 1
    assert state.duration == 15.0
    assert state.admin_shares() == ["\\\\H\\ADMIN$"]


def test_a_packet_with_an_smb_layer_but_no_ip_is_skipped():
    """haslayer sees SMB2 but there are no addresses to attribute it to."""
    from scapy.layers.smb2 import SMB2_Negotiate_Protocol_Request
    bare = NBTSession() / SMB2_Header(Command=mod.SMB2_NEGOTIATE) \
        / SMB2_Negotiate_Protocol_Request()
    acc = mod.SMBAccumulator()
    acc.feed(bare)
    assert acc.operations == []


def test_an_smb_message_not_on_an_smb_port_is_skipped():
    """SMB2 can be tunnelled anywhere, but a port we do not watch is not ours."""
    pkt = _wire_live(SMB2_Negotiate_Protocol_Request(), mod.SMB2_NEGOTIATE, port=8445)
    assert mod.SMBAccumulator().__class__ and _run([pkt]).operations == []


def test_a_security_blob_that_cannot_be_serialised_names_nobody():
    """A malformed blob whose bytes() raises must not end the capture pass."""
    class Unserialisable:
        def __bytes__(self):
            raise ValueError("malformed GSSAPI structure")

    assert mod._authentication_from_blob(Unserialisable()) == (None, False)


# ── the CLI section rendered directly, including the paths a pcap cannot reach ─

class _CapturingUI:
    """A stand-in for TerminalUI that records every string it is handed.

    Used to exercise the SMB section's rendering with crafted data, reaching the
    account table and null-session warning that a pcap round-trip cannot, since
    scapy will not rebuild the session setup those come from into a pcap.
    """

    def __init__(self):
        self.text: list[str] = []

    def print_section(self, *args, **_kwargs):
        self.text.append(" ".join(str(a) for a in args))

    def print_table(self, title, **kwargs):
        self.text.append(title + " " + repr(kwargs.get("rows")))

    def print_status(self, message, *_args, **_kwargs):
        self.text.append(message)

    @property
    def blob(self):
        return "\n".join(self.text)


def test_the_cli_section_names_the_account_and_the_null_session():
    """An account and an anonymous session both come from a session setup, which
    scapy reads from a real capture but cannot write back into a pcap, so they
    are rendered here from a crafted summary rather than through a round-trip."""
    from packetiq.cli import _print_smb_section

    ui = _CapturingUI()
    _print_smb_section(ui, {
        "operations": 8, "sessions": 1,
        "shares": {r"\\H\ADMIN$": 1}, "files": {"payload.exe": 1},
        "accounts": [{"user": "larry.doe", "domain": "directory.thm",
                      "workstation": "KALI"}],
        "named_pipes": {"svcctl": "remote service control"},
        "anonymous_sessions": 1, "smb1_seen": True,
    }, full=True)

    assert "Accounts authenticated over SMB" in ui.blob
    assert "larry.doe" in ui.blob
    assert "anonymous (null) session" in ui.blob
    assert "svcctl" in ui.blob
    assert "SMB1 was negotiated" in ui.blob


def test_the_cli_section_is_silent_when_there_is_no_smb():
    from packetiq.cli import _print_smb_section

    ui = _CapturingUI()
    _print_smb_section(ui, {}, full=False)
    assert ui.text == []
