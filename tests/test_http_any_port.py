"""
HTTP must be recognised from the payload bytes, not from the TCP port.

Scapy binds its HTTP dissector to TCP 80 and 8080 and nothing else, so
byte-identical HTTP served on 8000 / 8888 / 3128 / 81 used to parse as anonymous
TCP: no ``has_http``, no method / Host / User-Agent / Server. Everything built on
those fields went blind with it — HTTP inspection, HTTP beaconing evidence and
server-banner CVE matching — on exactly the ports C2 traffic prefers. The real
CTU-13 corpus carries this: malware config fetches on 3389, botnet polling on
179, and .exe downloads on 88.

The negative cases matter as much as the positive ones. Claiming HTTP for
anything that merely sits on a web-ish port would invent evidence, so these
assert the parser stays silent on payloads that are not HTTP/1.x.
"""

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap

from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser

REQUEST = (
    b"GET /tool/train/q.txt HTTP/1.1\r\n"
    b"Host: zxc.example.cn\r\n"
    b"User-Agent: VBTagEdit\r\n"
    b"Accept: */*\r\n\r\n"
)
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 2\r\n\r\nhi"
)

# 80 and 8080 are Scapy's own bindings; the rest are the regression. 3389/179/88
# are the RDP/BGP/Kerberos ports the CTU-13 captures actually carry HTTP on.
HTTP_PORTS = [80, 8080, 8000, 8888, 3128, 81, 8443, 3389, 179, 88]


def _write(tmp_path, packets, name="c.pcap"):
    path = tmp_path / name
    wrpcap(str(path), packets)
    return str(path)


def _exchange(port, client_port):
    return [
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=client_port, dport=port, flags="PA") / Raw(REQUEST),
        Ether() / IP(src="203.0.113.9", dst="10.0.0.5")
        / TCP(sport=port, dport=client_port, flags="PA") / Raw(RESPONSE),
    ]


@pytest.fixture
def all_ports_pcap(tmp_path):
    packets = []
    for i, port in enumerate(HTTP_PORTS):
        packets += _exchange(port, 51000 + i)
    return _write(tmp_path, packets)


def test_http_recognised_on_every_port(all_ports_pcap):
    """Every request and response is flagged, whatever port carried it."""
    records = list(PCAPParser(all_ports_pcap).stream())
    assert len(records) == 2 * len(HTTP_PORTS)

    missed = sorted(
        {r.dst_port, r.src_port} & set(HTTP_PORTS)
        for r in records
        if not r.has_http
    )
    assert not missed, f"HTTP not detected on ports: {missed}"


def test_request_fields_extracted_on_a_non_standard_port(all_ports_pcap):
    """Method / path / Host / User-Agent survive off port 80 — the C2 evidence."""
    reqs = [r for r in PCAPParser(all_ports_pcap).stream() if r.dst_port == 3389]
    assert len(reqs) == 1
    r = reqs[0]
    assert r.http_method == "GET"
    assert r.http_path == "/tool/train/q.txt"
    assert r.http_host == "zxc.example.cn"
    assert r.http_user_agent == "VBTagEdit"


def test_response_fields_extracted_on_a_non_standard_port(all_ports_pcap):
    """The Server banner is the plaintext CVE hint; it must survive too."""
    resps = [r for r in PCAPParser(all_ports_pcap).stream() if r.src_port == 3389]
    assert len(resps) == 1
    assert resps[0].http_status == 200
    assert resps[0].http_server == "nginx/1.24.0"


def test_display_protocol_is_http_not_the_port_service(all_ports_pcap):
    """Composition must read HTTP, not "RDP", when the bytes say HTTP."""
    for r in PCAPParser(all_ports_pcap).stream():
        assert r.display_protocol == "HTTP", f"port {r.src_port}->{r.dst_port}"


def test_extractor_receives_the_recovered_requests(all_ports_pcap):
    """The whole point: the recovered HTTP has to reach the detectors."""
    extractor = DataExtractor()
    for record in PCAPParser(all_ports_pcap).stream():
        extractor.feed(record)
    result = extractor.finalize()

    assert len(result.http_requests) == len(HTTP_PORTS)
    assert len(result.http_responses) == len(HTTP_PORTS)
    banners = {b["value"] for b in result.software_banners}
    assert "nginx/1.24.0" in banners
    assert "VBTagEdit" in banners


def test_extractor_records_the_real_server_port(all_ports_pcap):
    """Findings quote a port; it has to be the one the traffic used."""
    extractor = DataExtractor()
    for record in PCAPParser(all_ports_pcap).stream():
        extractor.feed(record)
    result = extractor.finalize()

    assert sorted(r["port"] for r in result.http_requests) == sorted(HTTP_PORTS)
    # Responses come from the server, so its port is the source port.
    assert sorted(r["port"] for r in result.http_responses) == sorted(HTTP_PORTS)


def test_http_attack_finding_quotes_the_port_it_was_seen_on(tmp_path):
    """An attack served on 8888 must not be reported against port 80."""
    from packetiq.detection.http_inspect import detect

    payload = (
        b"GET /index.php?id=1' OR 1=1-- HTTP/1.1\r\n"
        b"Host: victim.test\r\n"
        b"User-Agent: sqlmap/1.7\r\n\r\n"
    )
    path = _write(
        tmp_path,
        [Ether() / IP(src="10.0.0.7", dst="10.0.0.8")
         / TCP(sport=44444, dport=8888, flags="PA") / Raw(payload)],
        name="attack.pcap",
    )
    extractor = DataExtractor()
    for record in PCAPParser(path).stream():
        extractor.feed(record)

    events = detect(extractor.finalize())
    assert events, "SQL injection on a non-standard port was not detected"
    assert {e.dst_port for e in events} == {8888}


# A crude scanner leaves spaces unencoded in the request target. Scapy's Path
# field stops at the first space, so on port 80 the injection itself was being
# discarded before any detector saw it — and the parse differed by port.
SPACED_INJECTION = (
    b"GET /index.php?id=1' OR 1=1-- HTTP/1.1\r\n"
    b"Host: victim.test\r\n\r\n"
)


@pytest.mark.parametrize("port", [80, 8080, 8888])
def test_unencoded_spaces_in_the_target_are_preserved(tmp_path, port):
    """The full request-target survives on every port, Scapy-bound or not."""
    path = _write(
        tmp_path,
        [Ether() / IP(src="10.0.0.7", dst="10.0.0.8")
         / TCP(sport=44445, dport=port, flags="PA") / Raw(SPACED_INJECTION)],
        name=f"spaced_{port}.pcap",
    )
    (r,) = list(PCAPParser(path).stream())
    assert r.has_http is True
    assert r.http_method == "GET"
    assert r.http_path == "/index.php?id=1' OR 1=1--"


def test_spaced_injection_is_detected_on_the_scapy_bound_port(tmp_path):
    """Port 80 must reach the same finding, not lose it to a truncated path."""
    from packetiq.detection.http_inspect import detect

    path = _write(
        tmp_path,
        [Ether() / IP(src="10.0.0.7", dst="10.0.0.8")
         / TCP(sport=44446, dport=80, flags="PA") / Raw(SPACED_INJECTION)],
        name="spaced80.pcap",
    )
    extractor = DataExtractor()
    for record in PCAPParser(path).stream():
        extractor.feed(record)

    events = detect(extractor.finalize())
    assert [e.evidence["attack_type"] for e in events] == ["SQL injection"]
    assert events[0].dst_port == 80


def test_a_proven_http_flow_keeps_its_label_for_later_segments(tmp_path):
    """Continuation segments have no start line, so the port table would name
    them by port — calling the rest of an HTTP session on 3389 "RDP"."""
    client, server = 1057, 3389
    packets = [
        # Handshake precedes any evidence, so it stays TCP-by-port.
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=client, dport=server, flags="S"),
        # The request proves the flow is HTTP.
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=client, dport=server, flags="PA") / Raw(REQUEST),
        # Response headers, then a body-only continuation with no start line.
        Ether() / IP(src="203.0.113.9", dst="10.0.0.5")
        / TCP(sport=server, dport=client, flags="PA") / Raw(RESPONSE),
        Ether() / IP(src="203.0.113.9", dst="10.0.0.5")
        / TCP(sport=server, dport=client, flags="PA") / Raw(b"\x00\x01more body bytes"),
        # A bare ACK carries no protocol data at all.
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=client, dport=server, flags="A"),
    ]
    path = _write(tmp_path, packets, name="flow.pcap")
    labels = [r.display_protocol for r in PCAPParser(path).stream()]

    # The continuation is labelled by the flow, not by port 3389's service name.
    assert labels[1:] == ["HTTP", "HTTP", "HTTP", "TCP"]
    assert "RDP" not in labels[1:]


def test_a_plain_tcp_flow_is_not_relabelled_http(tmp_path):
    """The memo must not leak across flows on the same port."""
    packets = [
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=1057, dport=3389, flags="PA") / Raw(REQUEST),
        # Different client port — a separate flow that never showed HTTP.
        Ether() / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=2000, dport=3389, flags="PA") / Raw(b"\x03\x00\x00\x13 RDP-ish"),
    ]
    path = _write(tmp_path, packets, name="two_flows.pcap")
    http, other = list(PCAPParser(path).stream())
    assert http.display_protocol == "HTTP"
    assert other.has_http is False
    assert other.display_protocol == "RDP"


# ── Negative controls: never invent HTTP ──────────────────────────────────────

NOT_HTTP = {
    # TLS record header, then random-looking handshake bytes.
    "tls_client_hello": bytes.fromhex("160303006d010000690303") + b"\xab" * 40,
    "ssh_banner": b"SSH-2.0-OpenSSH_9.6\r\n",
    # Starts with "PRI * HTTP/2.0" — an HTTP/2 preface is not an HTTP/1 request.
    "http2_preface": b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04\x00",
    # First byte is 0x47 == b"G", which passes the fast pre-check.
    "binary_starting_with_G": b"G" + bytes(range(60)),
    # A valid request line, but in the body rather than at the start.
    "request_line_inside_body": b"data=GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n",
    "smtp_greeting": b"220 mail.example.test ESMTP\r\n",
    "http_0_9_request": b"GET /\r\n",
    "status_line_without_code": b"HTTP/1.1 OK\r\nServer: x\r\n\r\n",
    "lowercase_method": b"get / HTTP/1.1\r\nHost: a.test\r\n\r\n",
    # Header block has not arrived yet — no CRLF to terminate the start line.
    "truncated_request_line": b"GET /index.html HTTP/1.1",
}


@pytest.fixture
def not_http_pcap(tmp_path):
    packets = [
        Ether() / IP(src="10.0.0.2", dst="10.0.0.3")
        / TCP(sport=40000 + i, dport=8000, flags="PA") / Raw(payload)
        for i, payload in enumerate(NOT_HTTP.values())
    ]
    return _write(tmp_path, packets, name="not_http.pcap")


def test_non_http_payloads_are_never_labelled_http(not_http_pcap):
    records = list(PCAPParser(not_http_pcap).stream())
    assert len(records) == len(NOT_HTTP)

    false_positives = [
        name for name, r in zip(NOT_HTTP, records) if r.has_http
    ]
    assert not false_positives, f"falsely detected as HTTP: {false_positives}"


def test_non_http_payloads_leave_every_http_field_unset(not_http_pcap):
    for name, r in zip(NOT_HTTP, list(PCAPParser(not_http_pcap).stream())):
        assert r.http_method is None, name
        assert r.http_host is None, name
        assert r.http_status is None, name
        assert r.http_server is None, name


def test_header_lookup_stops_at_the_blank_line(tmp_path):
    """A body containing "Host:" must not be read as a header."""
    payload = (
        b"POST /submit HTTP/1.1\r\n"
        b"User-Agent: probe/1.0\r\n\r\n"
        b"Host: not-a-header.test\r\n"
    )
    path = _write(
        tmp_path,
        [Ether() / IP(src="10.0.0.5", dst="10.0.0.6")
         / TCP(sport=5555, dport=8000, flags="PA") / Raw(payload)],
        name="body.pcap",
    )
    (r,) = list(PCAPParser(path).stream())
    assert r.has_http is True
    assert r.http_method == "POST"
    assert r.http_user_agent == "probe/1.0"
    assert r.http_host is None


def test_headers_beyond_the_raw_payload_cap_are_still_read(tmp_path):
    """record.raw_payload is capped at 512 bytes; header parsing must not be."""
    filler = b"X-Pad: " + b"p" * 900 + b"\r\n"
    payload = (
        b"GET /late HTTP/1.1\r\n" + filler
        + b"Host: far-header.test\r\n\r\n"
    )
    path = _write(
        tmp_path,
        [Ether() / IP(src="10.0.0.5", dst="10.0.0.6")
         / TCP(sport=5556, dport=8000, flags="PA") / Raw(payload)],
        name="long.pcap",
    )
    (r,) = list(PCAPParser(path).stream())
    assert len(r.raw_payload) == 512
    assert r.http_host == "far-header.test"
