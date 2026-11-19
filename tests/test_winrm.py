"""
Tests for WinRM / WS-Management detection and the NTLM identity it carries.

The NTLM messages here are built with scapy's own NTLM layer and base64-encoded
exactly as a client puts them in an `Authorization` header, so the decode path
under test is the one a capture takes. The HTTP requests are assembled as real
bytes on TCP 5985, because that is what the accumulator reads: it hand-parses
the request head rather than relying on a port binding.

The scenarios come from a real intrusion capture in which 793 WS-Management
requests ran for two minutes authenticated as `directory.thm\\larry.doe` from a
client calling itself `KALI`, driven by a Ruby WinRM client.
"""

import base64

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ntlm import NTLM_AUTHENTICATE_V2, NTLM_NEGOTIATE

from packetiq.detection import ntlm, winrm
from packetiq.detection.models import EventType, Severity

ATTACKER = "10.0.2.74"
TARGET = "10.0.2.75"
RUBY_AGENT = "Ruby WinRM Client (2.8.3, ruby 3.1.2 (2022-04-12))"
MS_AGENT = "Microsoft WinRM Client"


# ── building real requests ────────────────────────────────────────────────────

def ntlm_authenticate(user="larry.doe", domain="directory.thm", workstation="KALI"):
    """A base64 NTLM type 3 token, exactly as it rides an Authorization header."""
    msg = NTLM_AUTHENTICATE_V2(UserName=user, DomainName=domain, Workstation=workstation)
    return base64.b64encode(bytes(msg)).decode("ascii")


def ntlm_negotiate():
    """A type 1 token: a real NTLM message that names nobody."""
    return base64.b64encode(bytes(NTLM_NEGOTIATE())).decode("ascii")


def wsman(*, agent=RUBY_AGENT, authorization=None, encrypted=True, body=b"",
          path="/wsman", method="POST", port=5985, src=ATTACKER, dst=TARGET,
          content_type=None, ts=0.0):
    if content_type is None:
        content_type = ('multipart/encrypted;protocol="application/'
                        'HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"'
                        if encrypted else "application/soap+xml;charset=UTF-8")
    head = [f"{method} {path} HTTP/1.1", f"Host: {dst}:{port}"]
    if content_type:
        head.append(f"Content-Type: {content_type}")
    if agent:
        head.append(f"User-Agent: {agent}")
    if authorization:
        head.append(f"Authorization: {authorization}")
    head.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + body

    pkt = IP(src=src, dst=dst) / TCP(sport=54321, dport=port, flags="PA") / raw
    pkt = IP(bytes(pkt))
    pkt.time = ts
    return pkt


def _run(packets):
    acc = winrm.WinRMAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc


def _session(n=10, **kw):
    return [wsman(ts=float(i), **kw) for i in range(n)]


# ── header parsing ────────────────────────────────────────────────────────────

def test_a_request_head_is_split_into_its_method_path_and_headers():
    raw = (b"POST /wsman HTTP/1.1\r\nHost: dc\r\nUser-Agent: x\r\n"
           b"Content-Length: 4\r\n\r\nbody")
    method, path, headers, body_len = winrm._parse_head(raw)
    assert method == "POST"
    assert path == "/wsman"
    assert headers["user-agent"] == "x"
    assert body_len == 4


def test_bytes_that_are_not_an_http_request_are_rejected():
    """TCP 5985 also carries response and continuation segments."""
    assert winrm._parse_head(b"HTTP/1.1 401 Unauthorized\r\n\r\n") is None
    assert winrm._parse_head(b"\x16\x03\x01 binary nonsense") is None
    assert winrm._parse_head(b"") is None


def test_a_header_line_with_no_colon_does_not_break_the_parse():
    raw = b"POST /wsman HTTP/1.1\r\ngarbage-line\r\nHost: dc\r\n\r\n"
    _method, _path, headers, _ = winrm._parse_head(raw)
    assert headers == {"host": "dc"}


def test_a_request_head_with_no_body_separator_reports_no_body():
    raw = b"POST /wsman HTTP/1.1\r\nHost: dc\r\n"
    _method, _path, _headers, body_len = winrm._parse_head(raw)
    assert body_len == 0


# ── NTLM decoding ─────────────────────────────────────────────────────────────

def test_the_account_and_workstation_are_read_from_the_ntlm_type_three_message():
    """This is the identity the whole module exists to recover.

    It stays in clear text even though the session payload does not, which is
    what makes a WinRM capture answerable at all.
    """
    identity, is_ntlm = ntlm.decode_ntlm(ntlm_authenticate())
    assert is_ntlm
    assert identity.user == "larry.doe"
    assert identity.domain == "directory.thm"
    assert identity.workstation == "KALI"
    assert str(identity) == "directory.thm\\larry.doe from KALI"


def test_an_identity_without_a_workstation_still_reads_sensibly():
    identity = winrm.NTLMIdentity(user="svc", domain="CORP")
    assert str(identity) == "CORP\\svc"
    assert winrm.NTLMIdentity(user="solo").__str__() == "solo"
    assert str(winrm.NTLMIdentity()) == "?"


def test_an_ntlm_negotiate_is_recognised_as_ntlm_but_names_nobody():
    """Type 1 starts the handshake and carries no account."""
    identity, is_ntlm = ntlm.decode_ntlm(ntlm_negotiate())
    assert is_ntlm
    assert identity is None


def test_a_token_that_is_not_ntlm_at_all_is_not_mistaken_for_one():
    """Kerberos also travels as `Authorization: Negotiate`."""
    kerberos_ish = base64.b64encode(b"\x60\x82\x04\x00 not NTLMSSP").decode()
    assert ntlm.decode_ntlm(kerberos_ish) == (None, False)
    assert ntlm.decode_ntlm("not even base64 !!!") == (None, False)
    assert ntlm.decode_ntlm(base64.b64encode(b"NTLMSSP\x00").decode()) == (None, False)


def test_an_ntlm_message_that_names_nothing_yields_no_identity():
    empty = NTLM_AUTHENTICATE_V2(UserName="", DomainName="", Workstation="")
    identity, is_ntlm = ntlm.decode_ntlm(base64.b64encode(bytes(empty)).decode())
    assert is_ntlm
    assert identity is None


# ── intake ────────────────────────────────────────────────────────────────────

def test_traffic_on_other_ports_is_not_winrm():
    acc = _run([wsman(port=443), IP(src=ATTACKER, dst=TARGET) / UDP(dport=5985)])
    assert acc.requests == []
    assert acc.summary() == {}


def test_both_winrm_ports_are_read():
    acc = _run([wsman(port=5985), wsman(port=5986)])
    assert len(acc.requests) == 2


def test_an_empty_tcp_segment_on_the_winrm_port_is_skipped():
    bare = IP(src=ATTACKER, dst=TARGET) / TCP(sport=54321, dport=5985, flags="A")
    assert _run([IP(bytes(bare))]).requests == []


def test_winrm_over_ipv6_is_read_the_same_as_over_ipv4():
    raw = b"POST /wsman HTTP/1.1\r\nHost: dc\r\nUser-Agent: x\r\n\r\n"
    pkt = IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=5, dport=5985, flags="PA") / raw
    assert len(_run([IPv6(bytes(pkt))]).requests) == 1


def test_a_request_with_no_ip_layer_is_skipped_not_crashed():
    raw = b"POST /wsman HTTP/1.1\r\nHost: dc\r\n\r\n"
    bare = TCP(sport=54321, dport=5985, flags="PA") / raw
    assert _run([TCP(bytes(bare))]).requests == []


# ── the session finding ───────────────────────────────────────────────────────

def test_a_sustained_session_from_tooling_is_critical():
    """Volume alone is a session; tooling alone is suspicious; both is an intrusion."""
    packets = _session(120, authorization=f"Negotiate {ntlm_authenticate()}")
    events = _run(packets).finalize()

    exec_events = [e for e in events if e.event_type is EventType.WINRM_EXECUTION]
    assert len(exec_events) == 1
    assert exec_events[0].severity is Severity.CRITICAL
    assert "larry.doe" in exec_events[0].evidence["authenticated_as"]
    assert RUBY_AGENT in exec_events[0].evidence["non_windows_client"]
    assert exec_events[0].evidence["mitre"] == f"{winrm.MITRE_WINRM} / {winrm.MITRE_EXEC}"


def test_microsofts_own_client_doing_a_little_work_is_only_medium():
    """An administrator running a management task is not an alert."""
    exec_events = [e for e in _run(_session(10, agent=MS_AGENT)).finalize()
                   if e.event_type is EventType.WINRM_EXECUTION]
    assert len(exec_events) == 1
    assert exec_events[0].severity is Severity.MEDIUM
    assert exec_events[0].evidence["non_windows_client"] == "no"


def test_microsofts_own_client_doing_a_great_deal_of_work_is_high():
    exec_events = [e for e in _run(_session(150, agent=MS_AGENT)).finalize()
                   if e.event_type is EventType.WINRM_EXECUTION]
    assert exec_events[0].severity is Severity.HIGH


def test_one_or_two_management_calls_are_not_reported_as_a_session():
    assert _run(_session(3, agent=MS_AGENT)).finalize() == []


def test_the_finding_says_the_commands_are_not_recoverable():
    """The module must not imply it knows what was run.

    The payload is SPNEGO-encrypted. Saying so in the evidence is what stops a
    reader, or a model reading the same evidence, from filling in the gap.
    """
    event = [e for e in _run(_session(10)).finalize()
             if e.event_type is EventType.WINRM_EXECUTION][0]
    assert "not recoverable" in event.evidence["note"]
    assert event.evidence["encrypted_requests"] == 10


def test_https_winrm_is_reported_as_the_safer_transport():
    event = [e for e in _run(_session(10, port=5986)).finalize()
             if e.event_type is EventType.WINRM_EXECUTION][0]
    assert event.evidence["transport"] == "HTTPS (5986)"


def test_a_client_that_sends_no_user_agent_is_reported_as_such():
    event = [e for e in _run(_session(10, agent=None)).finalize()
             if e.event_type is EventType.WINRM_EXECUTION][0]
    assert event.evidence["client_software"] == "not sent"


# ── the SOAP envelope, while it is still readable ─────────────────────────────

def test_the_action_and_resource_are_read_before_session_encryption_starts():
    """The first requests of a session are in clear text, and name the intent."""
    body = (b'<s:Envelope><s:Header><a:Action>http://schemas.xmlsoap.org/ws/2004/09/'
            b'transfer/Create</a:Action><w:ResourceURI>http://schemas.microsoft.com/'
            b'powershell/Microsoft.PowerShell</w:ResourceURI></s:Header></s:Envelope>')
    acc = _run([wsman(encrypted=False, body=body)] + _session(9))
    event = [e for e in acc.finalize() if e.event_type is EventType.WINRM_EXECUTION][0]
    assert event.evidence["channel"] == "PowerShell Remoting"
    assert "opened a shell" in event.evidence["actions_observed"]


def test_wmi_over_winrm_is_named_separately_from_powershell_remoting():
    body = (b'<s:Envelope><w:ResourceURI>http://schemas.microsoft.com/wbem/wsman/1/'
            b'wmi/root/cimv2</w:ResourceURI></s:Envelope>')
    acc = _run([wsman(encrypted=False, body=body)] + _session(9))
    event = [e for e in acc.finalize() if e.event_type is EventType.WINRM_EXECUTION][0]
    assert event.evidence["channel"] == "WMI over WinRM"


def test_an_encrypted_body_is_not_searched_for_an_action():
    """There is nothing readable in there, and pretending otherwise invents facts."""
    acc = _run(_session(10, body=b"transfer/Create but encrypted"))
    event = [e for e in acc.finalize() if e.event_type is EventType.WINRM_EXECUTION][0]
    assert event.evidence["actions_observed"] == "none in clear text"
    assert event.evidence["channel"] == "WS-Management"


# ── the identity finding ──────────────────────────────────────────────────────

def test_an_ntlm_identity_over_plain_http_is_reported_as_exposed():
    packets = _session(10, authorization=f"Negotiate {ntlm_authenticate()}")
    ident = [e for e in _run(packets).finalize()
             if e.event_type is EventType.NTLM_AUTHENTICATION]
    assert len(ident) == 1
    assert ident[0].severity is Severity.HIGH
    assert ident[0].evidence["workstations_claimed"] == "KALI"
    assert ident[0].evidence["transport"] == "HTTP (5985)"
    assert ident[0].evidence["mitre"] == winrm.MITRE_NTLM


def test_the_same_identity_over_https_is_ranked_lower():
    packets = _session(10, port=5986, authorization=f"Negotiate {ntlm_authenticate()}")
    ident = [e for e in _run(packets).finalize()
             if e.event_type is EventType.NTLM_AUTHENTICATION][0]
    assert ident.severity is Severity.MEDIUM


def test_a_workstation_name_is_described_as_a_claim_not_as_proof():
    """It is whatever the client chose to send, and the wording has to say so."""
    packets = _session(10, authorization=f"Negotiate {ntlm_authenticate()}")
    ident = [e for e in _run(packets).finalize()
             if e.event_type is EventType.NTLM_AUTHENTICATION][0]
    assert "not proof" in ident.evidence["note"]


def test_no_identity_finding_when_no_ntlm_was_seen():
    assert [e for e in _run(_session(10)).finalize()
            if e.event_type is EventType.NTLM_AUTHENTICATION] == []


def test_a_non_ntlm_authorization_header_is_recorded_but_names_nobody():
    """Basic and Kerberos both appear on WinRM; neither yields an NTLM identity."""
    acc = _run(_session(10, authorization="Basic dXNlcjpwYXNz"))
    assert [e for e in acc.finalize()
            if e.event_type is EventType.NTLM_AUTHENTICATION] == []
    assert acc.requests[0].auth_scheme == "Basic"


def test_an_identity_seen_many_times_is_listed_once():
    packets = _session(20, authorization=f"Negotiate {ntlm_authenticate()}")
    ident = [e for e in _run(packets).finalize()
             if e.event_type is EventType.NTLM_AUTHENTICATION][0]
    assert ident.evidence["accounts"] == "directory.thm\\larry.doe from KALI"


# ── the summary the copilot and the report read ───────────────────────────────

def test_the_summary_states_the_session_and_warns_about_the_encryption():
    acc = _run(_session(12, authorization=f"Negotiate {ntlm_authenticate()}"))
    s = acc.summary()

    assert s["requests"] == 12
    assert s["sessions"] == 1
    assert s["clients"] == [ATTACKER]
    assert s["targets"] == [TARGET]
    assert s["accounts"] == [{"user": "larry.doe", "domain": "directory.thm",
                              "workstation": "KALI"}]
    assert s["user_agents"][RUBY_AGENT] == 12
    assert s["encrypted_requests"] == 12
    assert s["cleartext_requests"] == 0
    assert "not recoverable" in s["note"]


def test_the_summary_is_empty_when_the_capture_has_no_winrm():
    assert winrm.WinRMAccumulator().summary() == {}


def test_two_clients_against_one_target_are_two_sessions():
    acc = _run(_session(6) + _session(6, src="10.0.2.80"))
    s = acc.summary()
    assert s["sessions"] == 2
    assert s["clients"] == ["10.0.2.74", "10.0.2.80"]


# ── reaching the analyst ──────────────────────────────────────────────────────

def _winrm_pcap(path, n=12):
    from scapy.utils import wrpcap
    wrpcap(str(path), _session(n, authorization=f"Negotiate {ntlm_authenticate()}"))
    return str(path)


def test_the_cli_names_the_account_and_refuses_to_guess_the_commands(tmp_path):
    """End to end: parser, engine pass, detector and rendering together."""
    from click.testing import CliRunner

    from packetiq.cli import main

    pcap = _winrm_pcap(tmp_path / "winrm.pcap")
    result = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert result.exit_code == 0, result.output
    assert "REMOTE MANAGEMENT" in result.output
    assert "larry.doe" in result.output
    assert "KALI" in result.output
    assert "Ruby WinRM Client" in result.output
    assert "NOT recoverable" in result.output


def test_a_capture_without_winrm_prints_no_remote_management_section(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "plain.pcap")
    wrpcap(pcap, [IP(src=ATTACKER, dst=TARGET) / TCP(dport=443) for _ in range(4)])
    out = CliRunner().invoke(main, ["analyze", pcap])

    assert out.exit_code == 0, out.output
    assert "REMOTE MANAGEMENT" not in out.output


def test_the_copilot_context_gives_the_account_and_forbids_inventing_commands():
    """The model is told what is knowable and what is not, in the same breath."""
    from packetiq.copilot.context_builder import _remote_management
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run(_session(40, authorization=f"Negotiate {ntlm_authenticate()}"))
    result = ExtractionResult()
    result.winrm = acc.summary()

    text = _remote_management(result)
    assert "REMOTE MANAGEMENT" in text
    assert "AUTHENTICATED AS   : directory.thm\\larry.doe" in text
    assert "client called itself KALI" in text
    assert "Do not invent which commands ran" in text
    assert "--crack" in text          # points to the offline recovery path
    assert RUBY_AGENT in text


def test_the_context_section_is_absent_when_the_capture_had_no_winrm():
    from packetiq.copilot.context_builder import _remote_management
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _remote_management(ExtractionResult()) == ""


def test_the_context_reports_actions_when_any_were_in_clear_text():
    from packetiq.copilot.context_builder import _remote_management
    from packetiq.extractor.data_extractor import ExtractionResult

    body = (b'<s:Envelope><a:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/'
            b'Create</a:Action></s:Envelope>')
    acc = _run([wsman(encrypted=False, body=body)] + _session(9))
    result = ExtractionResult()
    result.winrm = acc.summary()

    assert "Actions in clear" in _remote_management(result)
    assert "opened a shell" in _remote_management(result)


def test_an_account_with_no_domain_is_still_printed_in_the_context():
    from packetiq.copilot.context_builder import _remote_management
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run(_session(10, authorization="Negotiate " + ntlm_authenticate(
        user="svc_backup", domain="", workstation="")))
    result = ExtractionResult()
    result.winrm = acc.summary()

    text = _remote_management(result)
    assert "svc_backup" in text
    assert "client called itself not sent" in text


def test_an_account_with_no_domain_is_still_recovered():
    identity, is_ntlm = ntlm.decode_ntlm(
        ntlm_authenticate(user="svc_backup", domain="", workstation=""))
    assert is_ntlm
    assert identity.user == "svc_backup"
    assert identity.domain == ""


def test_a_truncated_ntlm_type_three_message_names_nobody_but_is_still_ntlm():
    """Counting the handshake matters even when the message cannot be parsed."""
    truncated = base64.b64encode(b"NTLMSSP\x00\x03\x00\x00\x00" + b"\xff" * 8).decode()
    identity, is_ntlm = ntlm.decode_ntlm(truncated)
    assert is_ntlm
    assert identity is None


def test_an_authorization_header_in_a_scheme_we_do_not_read_is_still_recorded():
    """Kerberos over WinRM uses the same Negotiate scheme as NTLM."""
    kerberos_token = base64.b64encode(b"\x60\x82\x04\x00 SPNEGO/Kerberos").decode()
    acc = _run(_session(6, authorization=f"Negotiate {kerberos_token}"))
    assert acc.requests[0].auth_scheme == "Negotiate"
    assert [e for e in acc.finalize()
            if e.event_type is EventType.NTLM_AUTHENTICATION] == []


def test_a_tcp_segment_on_the_winrm_port_that_is_not_a_request_is_skipped():
    """Responses and continuation segments share the port with requests."""
    response = (b"HTTP/1.1 401 Unauthorized\r\n"
                b"WWW-Authenticate: Negotiate\r\n\r\n")
    pkt = IP(src=TARGET, dst=ATTACKER) / TCP(sport=5985, dport=54321, flags="PA") / response
    continuation = IP(src=ATTACKER, dst=TARGET) / TCP(sport=54321, dport=5985,
                                                      flags="PA") / b"--Encrypted Boundary--"
    acc = _run([IP(bytes(pkt)), IP(bytes(continuation))])
    assert acc.requests == []


def test_the_context_tells_the_model_the_flag_and_commands_are_not_in_the_packets():
    """Q5/Q6 of a directory capture: the command text and any flag are inside
    SPNEGO session encryption, so the model must point to host logs, not guess."""
    from packetiq.copilot.context_builder import _remote_management
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run(_session(40, authorization=f"Negotiate {ntlm_authenticate()}"))
    result = ExtractionResult()
    result.winrm = acc.summary()

    text = _remote_management(result)
    assert "not in the packets" in text
    assert "flag" in text.lower()
    assert "PowerShell operational and WinRM event logs" in text
    # and it now names the offline path that can recover them
    assert "packetiq crack" in text
