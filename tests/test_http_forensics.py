"""
Tests for HTTP deep inspection.

Each HTTP message is built as a real request or response and carried in a TCP
segment, reassembled by the accumulator exactly as it reassembles a capture. The
scenarios are what a SOC reads an HTTP exchange for: the password in a POST, the
session cookie, the uploaded file, and the flag hidden in a gzip'd response.
Every value is invented for the test.
"""

import gzip
import zlib

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from packetiq.detection import http_forensics as mod
from packetiq.detection.models import EventType, Severity

CLIENT = "10.0.0.9"
SERVER = "10.0.0.5"


# ── building HTTP streams ─────────────────────────────────────────────────────

def _http(start, headers, body=b""):
    h = start + b"\r\n"
    for k, v in headers.items():
        h += k + b": " + v + b"\r\n"
    if body:
        h += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    return h + b"\r\n" + body


def _req(payload, *, sport=50000, dport=80, seq=1000):
    p = IP(src=CLIENT, dst=SERVER) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / payload
    return IP(bytes(p))


def _resp(payload, *, sport=80, dport=50000, seq=1000):
    p = IP(src=SERVER, dst=CLIENT) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / payload
    return IP(bytes(p))


def _run(packets):
    acc = mod.HTTPForensicsAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc, acc.finalize()


# ── credentials ───────────────────────────────────────────────────────────────

def test_a_post_login_form_recovers_the_username_and_password():
    msg = _http(b"POST /login HTTP/1.1",
                {b"Host": b"victim.test",
                 b"Content-Type": b"application/x-www-form-urlencoded"},
                b"username=jenny&password=s3cret&remember=1")
    acc, events = _run([_req(msg)])
    creds = acc.summary()["credentials"]
    assert creds[0]["username"] == "jenny" and creds[0]["password"] == "s3cret"
    cred_events = [e for e in events if e.event_type is EventType.CREDENTIAL_EXPOSURE]
    assert cred_events and cred_events[0].severity is Severity.CRITICAL
    assert "s3cret" in cred_events[0].description
    assert acc.summary()["posts"][0]["params"]["username"] == "jenny"


def test_http_basic_auth_is_decoded_to_a_credential():
    import base64
    token = base64.b64encode(b"admin:hunter2").decode()
    msg = _http(b"GET /secure HTTP/1.1",
                {b"Host": b"victim.test", b"Authorization": b"Basic " + token.encode()})
    acc, events = _run([_req(msg)])
    creds = acc.summary()["credentials"]
    assert creds[0]["username"] == "admin" and creds[0]["password"] == "hunter2"
    assert any(e.event_type is EventType.CREDENTIAL_EXPOSURE for e in events)


def test_a_bearer_token_is_captured_as_a_credential():
    msg = _http(b"GET /api HTTP/1.1",
                {b"Host": b"api.test", b"Authorization": b"Bearer s3cr3t-token-value"})
    acc, _ = _run([_req(msg)])
    creds = acc.summary()["credentials"]
    assert creds[0]["password"] == "s3cr3t-token-value" and creds[0]["via"] == "HTTP Bearer token"


def test_a_post_without_both_fields_is_not_a_credential():
    msg = _http(b"POST /search HTTP/1.1",
                {b"Host": b"victim.test",
                 b"Content-Type": b"application/x-www-form-urlencoded"},
                b"query=hello&page=2")
    acc, _ = _run([_req(msg)])
    assert acc.summary().get("credentials", []) == []
    assert acc.summary()["posts"][0]["params"]["query"] == "hello"


# ── cookies, headers, uploads ─────────────────────────────────────────────────

def test_a_session_cookie_is_called_out():
    msg = _http(b"GET / HTTP/1.1",
                {b"Host": b"victim.test", b"Cookie": b"theme=dark; PHPSESSID=abc123def; lang=en"})
    acc, _ = _run([_req(msg)])
    session = acc.summary()["session_cookies"]
    assert any(c["name"] == "PHPSESSID" and c["value"] == "abc123def" for c in session)
    assert acc.summary()["cookie_count"] == 3


def test_custom_x_headers_and_user_agent_are_captured():
    msg = _http(b"GET / HTTP/1.1",
                {b"Host": b"victim.test", b"X-Api-Key": b"key-abcdef", b"X-Forwarded-For": b"1.2.3.4"})
    acc, _ = _run([_req(msg)])
    headers = acc.summary()["custom_headers"]
    assert headers["x-api-key"] == "key-abcdef" and headers["x-forwarded-for"] == "1.2.3.4"


def test_a_multipart_upload_recovers_the_filename():
    boundary = b"----BoundaryXYZ"
    body = (b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="payload.bin"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            b"some uploaded bytes\r\n"
            b"--" + boundary + b"--\r\n")
    msg = _http(b"POST /upload HTTP/1.1",
                {b"Host": b"victim.test",
                 b"Content-Type": b"multipart/form-data; boundary=" + boundary},
                body)
    acc, events = _run([_req(msg)])
    uploads = acc.summary()["uploads"]
    assert uploads[0]["filename"] == "payload.bin" and uploads[0]["field"] == "file"
    assert any(e.event_type is EventType.SUSPICIOUS_FILE_TRANSFER and "payload.bin" in e.description
               for e in events)


# ── decompression and body hunting ────────────────────────────────────────────

def test_a_gzip_response_body_is_decompressed_and_hunted():
    body = gzip.compress(b"<html>page THM{gzip_body_flag} end</html>")
    msg = _http(b"HTTP/1.1 200 OK",
                {b"Content-Type": b"text/html", b"Content-Encoding": b"gzip"}, body)
    acc, events = _run([_resp(msg)])
    assert acc.summary()["decompressed"][0]["encoding"] == "gzip"
    flag = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert flag and flag[0].evidence["value"] == "THM{gzip_body_flag}"


def test_a_deflate_response_body_is_decompressed():
    body = zlib.compress(b"deflated THM{deflate_flag} content")
    msg = _http(b"HTTP/1.1 200 OK", {b"Content-Encoding": b"deflate"}, body)
    acc, events = _run([_resp(msg)])
    assert acc.summary()["decompressed"][0]["encoding"] == "deflate"
    assert any(e.evidence.get("value") == "THM{deflate_flag}" for e in events)


def test_an_uncompressed_response_body_is_hunted_directly():
    msg = _http(b"HTTP/1.1 200 OK", {b"Content-Type": b"text/plain"},
                b"the answer is THM{plain_body_flag} ok")
    acc, events = _run([_resp(msg)])
    assert any(e.evidence.get("value") == "THM{plain_body_flag}" for e in events)
    assert acc.summary().get("decompressed", []) == []


def test_a_corrupt_compressed_body_yields_nothing():
    msg = _http(b"HTTP/1.1 200 OK", {b"Content-Encoding": b"gzip"}, b"not actually gzip data")
    acc, _ = _run([_resp(msg)])
    assert acc.summary() == {}


def test_a_secret_in_a_request_body_is_recovered():
    msg = _http(b"POST /api HTTP/1.1", {b"Host": b"api.test", b"Content-Type": b"application/json"},
                b'{"key": "AKIAIOSFODNN7EXAMPLE"}')
    acc, events = _run([_req(msg)])
    assert any("AKIAIOSFODNN7EXAMPLE" in e.evidence.get("value", "") for e in events
               if e.event_type is EventType.EXTRACTED_SECRET)


def test_an_encoded_payload_in_a_body_is_decoded():
    import base64
    blob = base64.b64encode(b"<?php sys~tem($_GET[0]); ?>".replace(b"~", b""))
    msg = _http(b"HTTP/1.1 200 OK", {b"Content-Type": b"text/plain"}, blob)
    acc, events = _run([_resp(msg)])
    decoded = [e for e in events if e.event_type is EventType.ENCODED_PAYLOAD]
    assert decoded and "<?php" in decoded[0].evidence["decoded_preview"]


def test_a_flag_seen_in_two_bodies_is_reported_once():
    msg = _http(b"HTTP/1.1 200 OK", {}, b"THM{dupe_flag} here")
    acc, events = _run([_resp(msg, seq=1000), _resp(msg, sport=80, dport=50001, seq=5000)])
    flags = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert len(flags) == 1


# ── decompression helper, directly ────────────────────────────────────────────

def test_decompress_handles_gzip_zlib_raw_deflate_and_junk():
    assert mod._decompress(gzip.compress(b"hi there"), b"gzip") == b"hi there"
    assert mod._decompress(zlib.compress(b"hi there"), b"deflate") == b"hi there"
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    raw = co.compress(b"raw deflate") + co.flush()
    assert mod._decompress(raw, b"deflate") == b"raw deflate"
    assert mod._decompress(b"garbage", b"gzip") == b""
    assert mod._decompress(b"\xff\xff bad", b"deflate") == b""
    assert mod._decompress(b"whatever", b"br") == b""


# ── message parsing helpers ───────────────────────────────────────────────────

def test_post_params_only_parses_urlencoded_bodies():
    assert mod._post_params(b"a=1&b=2", b"application/x-www-form-urlencoded") == [("a", "1"), ("b", "2")]
    assert mod._post_params(b"{}", b"application/json") == []


def test_multipart_is_empty_for_a_non_multipart_body():
    assert mod._multipart_uploads(b"a=1", b"application/x-www-form-urlencoded") == []


def test_basic_auth_rejects_non_basic_and_bad_base64():
    assert mod._basic_auth({b"authorization": b"Bearer xyz"}) is None
    assert mod._basic_auth({b"authorization": b"Basic !!!notbase64!!!"}) is None
    assert mod._basic_auth({}) is None


def test_bearer_and_cookie_and_header_helpers():
    assert mod._bearer_token({b"authorization": b"Bearer abc"}) == "abc"
    assert mod._bearer_token({}) == ""
    assert mod._cookies({b"cookie": b"a=1; b=2; junk"}) == [("a", "1"), ("b", "2")]
    assert mod._custom_headers({b"x-real-ip": b"1.1.1.1", b"host": b"h"}) == {"x-real-ip": "1.1.1.1"}


def test_iter_messages_handles_bad_content_length_and_chunked():
    # Non-numeric Content-Length → treated as no body.
    stream = _http(b"GET /a HTTP/1.1", {b"Host": b"h", b"Content-Length": b"abc"})
    msgs = list(mod._iter_messages(stream))
    assert msgs and msgs[0][2] == b""
    # Chunked response with no Content-Length → body empty (honest, not misparsed).
    chunked = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    acc, _ = _run([_resp(chunked)])
    assert acc.summary() == {}


def test_the_message_cap_is_honoured(monkeypatch):
    monkeypatch.setattr(mod, "_MAX_MESSAGES", 1)
    two = _http(b"GET /a HTTP/1.1", {b"Host": b"h"}) + _http(b"GET /b HTTP/1.1", {b"Host": b"h"})
    assert len(list(mod._iter_messages(two))) == 1


# ── intake and reassembly ─────────────────────────────────────────────────────

def test_non_http_ports_and_non_tcp_are_ignored():
    acc, events = _run([
        _req(_http(b"GET / HTTP/1.1", {b"Host": b"h"}), dport=12345, sport=12346),
        IP(bytes(IP(src=CLIENT, dst=SERVER) / UDP(dport=80) / b"GET / HTTP/1.1")),
    ])
    assert acc.summary() == {} and events == []


def test_an_empty_and_an_ipless_packet_are_skipped():
    empty = IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=80, flags="A", seq=1)
    ipless = TCP(sport=50000, dport=80, flags="PA", seq=1) / b"GET / HTTP/1.1\r\n\r\n"
    acc, _ = _run([IP(bytes(empty)), TCP(bytes(ipless))])
    assert acc.summary() == {}


def test_the_flow_count_is_capped(monkeypatch):
    monkeypatch.setattr(mod, "_MAX_FLOWS", 1)
    acc = mod.HTTPForensicsAccumulator()
    acc.feed(_req(b"GET /a HTTP/1.1\r\n\r\n", sport=50000))
    acc.feed(_req(b"GET /b HTTP/1.1\r\n\r\n", sport=50001))
    assert acc.skipped == 1


def test_the_bytes_per_flow_are_capped(monkeypatch):
    monkeypatch.setattr(mod, "_MAX_STREAM_BYTES", 8)
    acc = mod.HTTPForensicsAccumulator()
    acc.feed(_req(b"AAAAAAAAAA", seq=1000))
    acc.feed(_req(b"BBBBBBBBBB", seq=2000))
    key = next(iter(acc.segments))
    assert len(acc.segments[key]) == 1


def test_requests_are_reassembled_in_sequence_order():
    msg = _http(b"POST /login HTTP/1.1",
                {b"Host": b"h", b"Content-Type": b"application/x-www-form-urlencoded"},
                b"username=bob&password=pw")
    half = len(msg) // 2
    a = _req(msg[:half], seq=1000)
    b = _req(msg[half:], seq=1000 + half)
    acc, _ = _run([b, a])   # out of order
    assert acc.summary()["credentials"][0]["username"] == "bob"


def test_a_retransmitted_segment_is_counted_once():
    msg = _http(b"HTTP/1.1 200 OK", {}, b"body THM{retrans_flag} end")
    dup = _resp(msg, seq=1000)
    acc, events = _run([dup, dup])    # same segment twice
    flags = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert len(flags) == 1 and flags[0].evidence["value"] == "THM{retrans_flag}"


def test_http_over_ipv6_is_read_the_same_as_over_ipv4():
    msg = _http(b"POST /login HTTP/1.1",
                {b"Host": b"v6.test", b"Content-Type": b"application/x-www-form-urlencoded"},
                b"username=v6user&password=v6pass")
    pkt = IPv6(src="fd00::9", dst="fd00::5") / TCP(sport=50000, dport=80, flags="PA", seq=1000) / msg
    acc, _ = _run([IPv6(bytes(pkt))])
    assert acc.summary()["credentials"][0]["username"] == "v6user"


def test_a_line_that_is_not_a_request_or_response_is_skipped():
    acc, _ = _run([_req(b"GARBAGE not http\r\n\r\nbody here\r\n\r\n")])
    assert acc.summary() == {}


def test_the_summary_is_empty_without_findings():
    assert mod.HTTPForensicsAccumulator().summary() == {}


def test_dedupe_keeps_one_per_key():
    rows = [{"a": 1, "b": 2}, {"a": 1, "b": 2}, {"a": 1, "b": 3}]
    assert len(mod._dedupe(rows, ("a", "b"))) == 2


def test_endpoint_extraction_gives_up_on_an_unreadable_packet():
    class Hostile:
        def haslayer(self, _layer):
            raise ValueError("nope")

    assert mod._endpoints(Hostile()) == (None, None)


# ── reaching the analyst: context and CLI ─────────────────────────────────────

_FULL = {
    "transactions": 3,
    "credentials": [{"host": "victim.test", "username": "jenny", "password": "s3cret",
                     "via": "HTTP POST form"}],
    "session_cookies": [{"host": "victim.test", "name": "PHPSESSID", "value": "abc123"}],
    "cookie_count": 3,
    "custom_headers": {"x-api-key": "key-abc"},
    "posts": [{"host": "victim.test", "path": "/login", "params": {"username": "jenny"}}],
    "uploads": [{"host": "victim.test", "filename": "shell.php", "field": "file"}],
    "decompressed": [{"server": SERVER, "encoding": "gzip", "bytes": 1200}],
    "flags": [{"value": "THM{http_flag}"}],
    "secrets": [{"kind": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE", "detail": "AWS access key id"}],
}


def test_the_copilot_context_carries_the_http_findings():
    from packetiq.copilot.context_builder import _http_forensics
    from packetiq.extractor.data_extractor import ExtractionResult

    result = ExtractionResult()
    result.http_forensics = _FULL
    text = _http_forensics(result)
    assert "HTTP DEEP INSPECTION" in text
    assert "jenny" in text and "s3cret" in text
    assert "PHPSESSID" in text
    assert "x-api-key" in text
    assert "shell.php" in text
    assert "THM{http_flag}" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text


def test_the_context_section_is_absent_without_http_forensics():
    from packetiq.copilot.context_builder import _http_forensics
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _http_forensics(ExtractionResult()) == ""


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


def test_the_cli_section_renders_the_http_findings():
    from packetiq.cli import _print_http_forensics_section

    ui = _CapturingUI()
    _print_http_forensics_section(ui, _FULL)
    assert "s3cret" in ui.blob and "PHPSESSID" in ui.blob and "shell.php" in ui.blob


def test_the_cli_section_is_silent_without_http_forensics():
    from packetiq.cli import _print_http_forensics_section

    ui = _CapturingUI()
    _print_http_forensics_section(ui, {})
    assert ui.text == []
