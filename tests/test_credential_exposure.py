"""
Plaintext-credential detection.

Six protocol handlers read attacker- or user-controlled payload bytes with regular
expressions and base64 decoding; most had no direct coverage. The risk here is
two-sided — a missed credential is a missed incident, but a false one accuses a
user of leaking a password they never sent — so both directions are asserted.

The dispatch table is checked against the handlers too: `CRED_PORTS` used to be
decorative, with the real port lists hardcoded separately inside `scan_record`.
"""

import base64

import pytest

from packetiq.detection.credential import (
    CRED_PORTS,
    _safe_b64,
    detect_from_stream,
    scan_record,
)
from packetiq.detection.models import EventType, Severity
from packetiq.parser.pcap_parser import RawPacketRecord


def _rec(payload: bytes, dport=80, sport=51000, src="192.168.1.10", dst="93.184.216.34"):
    return RawPacketRecord(
        index=0, timestamp=1700000000.0, size=len(payload) + 54,
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        protocol="TCP", raw_payload=payload, payload_size=len(payload),
    )


def _scan(*records):
    events: list = []
    seen: set = set()
    for r in records:
        scan_record(r, seen, events)
    return events


# --------------------------------------------------------------------------- #
#  Dispatch table                                                               #
# --------------------------------------------------------------------------- #

def test_every_listed_port_is_actually_inspected():
    """The table is the dispatch source; an entry that does nothing is a lie."""
    payloads = {
        "FTP":    b"USER admin\r\nPASS hunter2\r\n",
        "TELNET": b"login: administrator\r\npassword: secret123\r\n",
        "SMTP":   b"AUTH LOGIN " + base64.b64encode(b"user@example.com") + b"\r\n",
        "HTTP":   b"POST /login HTTP/1.1\r\n\r\nuser=bob&password=s3cret",
        "POP3":   b"PASS hunter2\r\n",
        "IMAP":   b"a1 LOGIN bob s3cret\r\n",
    }
    for port, proto in CRED_PORTS.items():
        assert _scan(_rec(payloads[proto], dport=port)), f"port {port} ({proto}) inspected nothing"


def test_a_port_not_in_the_table_is_left_alone():
    assert _scan(_rec(b"USER admin\r\nPASS hunter2\r\n", dport=9999)) == []


def test_credentials_are_found_on_the_reply_direction_too():
    """Server→client packets carry the same session; source port must match too."""
    assert _scan(_rec(b"USER admin\r\nPASS hunter2\r\n", dport=51000, sport=21))


# --------------------------------------------------------------------------- #
#  HTTP                                                                         #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("field", [
    b"password", b"passwd", b"pass", b"pwd", b"secret", b"token", b"api_key", b"apikey",
])
def test_every_credential_field_name_in_a_post_body_is_caught(field):
    body = b"POST /login HTTP/1.1\r\nHost: x\r\n\r\nuser=bob&" + field + b"=s3cr3t"
    events = _scan(_rec(body))
    assert events
    assert events[0].event_type is EventType.CREDENTIAL_EXPOSURE


def test_http_basic_auth_is_decoded_to_show_the_account():
    token = base64.b64encode(b"admin:hunter2").decode()
    payload = f"GET /admin HTTP/1.1\r\nAuthorization: Basic {token}\r\n\r\n".encode()
    events = _scan(_rec(payload))
    assert events
    joined = str(events[0].evidence) + events[0].description
    assert "admin" in joined


def test_an_ordinary_page_request_is_not_flagged():
    payload = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
               b"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n")
    assert _scan(_rec(payload)) == []


def test_the_word_password_in_prose_without_a_value_is_not_flagged():
    payload = b"GET /help/password HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert _scan(_rec(payload)) == []


def test_http_credentials_are_found_on_the_alternate_ports():
    body = b"POST /login HTTP/1.1\r\n\r\npassword=s3cret"
    for port in (80, 8000, 8080):
        assert _scan(_rec(body, dport=port)), f"missed on port {port}"


# --------------------------------------------------------------------------- #
#  FTP / SMTP / IMAP / POP3 / Telnet                                            #
# --------------------------------------------------------------------------- #

def test_ftp_user_and_pass_are_reported():
    events = _scan(_rec(b"USER admin\r\n", dport=21), _rec(b"PASS hunter2\r\n", dport=21))
    assert events
    assert any(e.protocol == "FTP" for e in events)


def test_smtp_auth_login_is_reported():
    payload = b"AUTH LOGIN " + base64.b64encode(b"user@example.com") + b"\r\n"
    events = _scan(_rec(payload, dport=25))
    assert events
    assert events[0].protocol == "SMTP"


def test_smtp_auth_plain_is_reported_on_the_submission_port():
    payload = b"AUTH PLAIN " + base64.b64encode(b"\x00user\x00pass") + b"\r\n"
    assert _scan(_rec(payload, dport=587))


def test_imap_login_is_reported():
    events = _scan(_rec(b"a001 LOGIN bob s3cret\r\n", dport=143))
    assert events
    assert events[0].protocol == "IMAP"


def test_pop3_pass_is_reported():
    events = _scan(_rec(b"PASS hunter2\r\n", dport=110))
    assert events
    assert events[0].protocol == "POP3"


def test_a_telnet_session_is_critical_because_everything_is_cleartext():
    events = _scan(_rec(b"Last login: Mon Jan  1 00:00:00\r\nusername: ", dport=23))
    assert events
    assert events[0].severity is Severity.CRITICAL
    assert events[0].protocol == "TELNET"


def test_telnet_option_negotiation_alone_is_not_a_session():
    """IAC control bytes are protocol setup, not user data."""
    assert _scan(_rec(b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27", dport=23)) == []


# --------------------------------------------------------------------------- #
#  Deduplication and robustness                                                 #
# --------------------------------------------------------------------------- #

def test_the_same_exposure_is_reported_once_per_flow():
    """A long session would otherwise emit thousands of identical findings."""
    payload = b"POST /login HTTP/1.1\r\n\r\npassword=s3cret"
    events = _scan(*[_rec(payload) for _ in range(20)])
    assert len(events) == 1


def test_different_hosts_are_reported_separately():
    payload = b"POST /login HTTP/1.1\r\n\r\npassword=s3cret"
    events = _scan(_rec(payload, src="192.168.1.10"), _rec(payload, src="192.168.1.11"))
    assert len(events) == 2


@pytest.mark.parametrize("payload", [
    b"", b"a", b"\x00\x01\x02", bytes(range(256)), b"\xff" * 500,
])
def test_short_or_binary_payloads_never_raise(payload):
    _scan(_rec(payload, dport=21))
    _scan(_rec(payload, dport=80))
    _scan(_rec(payload, dport=23))


def test_a_record_with_no_payload_is_skipped():
    rec = RawPacketRecord(index=0, timestamp=1.0, size=54, src_ip="1.1.1.1",
                          dst_ip="2.2.2.2", src_port=1, dst_port=21, protocol="TCP")
    assert _scan(rec) == []


def test_the_streaming_entry_point_dedupes_across_the_whole_capture():
    payload = b"POST /login HTTP/1.1\r\n\r\npassword=s3cret"
    events = detect_from_stream(iter([_rec(payload) for _ in range(5)]))
    assert len(events) == 1


# --------------------------------------------------------------------------- #
#  base64 helper                                                                #
# --------------------------------------------------------------------------- #

def test_base64_decoding_is_padding_tolerant():
    assert _safe_b64(base64.b64encode(b"admin:pw").rstrip(b"=")) == "admin:pw"


def test_base64_decoding_of_junk_does_not_raise():
    assert _safe_b64(b"!!!not-base64!!!") in (None, "")


def test_base64_decoding_of_non_utf8_is_replaced_not_fatal():
    out = _safe_b64(base64.b64encode(b"\xff\xfe\xfd"))
    assert out is not None
