"""Packet-list protocol labelling must match Wireshark's Protocol column.

Wireshark labels a packet by the highest layer *actually present*: a TCP
segment is only "HTTP"/"TLS" when its payload really carries that protocol;
handshake / ACK / keep-alive segments stay "TCP", regardless of port.
Regression test for the old behaviour that called every :80 packet "HTTP" and
every :443 packet "TCP/443".
"""

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw

from packetiq.inspect import summarize

_TLS_CLIENT_HELLO = bytes([0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28,
                           0x03, 0x03]) + b"\x00" * 40
_TLS_APP_DATA = bytes([0x17, 0x03, 0x03, 0x01, 0x00]) + b"\x00" * 40
_HTTP_GET = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
_HTTP_RESP = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nhi"


def _proto(pkt):
    return summarize(pkt, 0)["proto"]


def test_bare_handshake_on_port80_is_tcp_not_http():
    # SYN and ACK carry no HTTP message → Wireshark shows "TCP".
    assert _proto(IP() / TCP(sport=5001, dport=80, flags="S")) == "TCP"
    assert _proto(IP() / TCP(sport=5001, dport=80, flags="A")) == "TCP"


def test_actual_http_message_is_http():
    assert _proto(IP() / TCP(sport=5001, dport=80, flags="PA") / Raw(_HTTP_GET)) == "HTTP"
    assert _proto(IP() / TCP(sport=80, dport=5001, flags="PA") / Raw(_HTTP_RESP)) == "HTTP"


def test_http_detected_on_nonstandard_port():
    # Wireshark's heuristic dissector finds HTTP regardless of port.
    assert _proto(IP() / TCP(sport=5, dport=8000, flags="PA") / Raw(_HTTP_GET)) == "HTTP"


def test_bare_handshake_on_port443_is_tcp_not_tls():
    assert _proto(IP() / TCP(sport=5002, dport=443, flags="S")) == "TCP"
    assert _proto(IP() / TCP(sport=5002, dport=443, flags="A")) == "TCP"


def test_tls_records_labelled_tls():
    assert _proto(IP() / TCP(sport=5002, dport=443, flags="PA") / Raw(_TLS_CLIENT_HELLO)) == "TLS"
    assert _proto(IP() / TCP(sport=5002, dport=443, flags="PA") / Raw(_TLS_APP_DATA)) == "TLS"


def test_never_emits_synthetic_tcp443_label():
    for flags in ("S", "SA", "A", "PA", "FA", "R"):
        assert summarize(IP() / TCP(dport=443, flags=flags), 0)["proto"] != "TCP/443"


def test_wireshark_style_info_strings():
    syn = summarize(IP() / TCP(sport=51000, dport=80, flags="S"), 0)["info"]
    assert "51000 → 80" in syn and "[SYN]" in syn and "Len=0" in syn

    http = summarize(IP() / TCP(dport=80, flags="PA") / Raw(_HTTP_GET), 0)["info"]
    assert http.startswith("GET /index.html HTTP/1.1")

    tls = summarize(IP() / TCP(dport=443, flags="PA") / Raw(_TLS_CLIENT_HELLO), 0)["info"]
    assert "Client Hello" in tls


def test_dns_unaffected():
    dns = IP(dst="8.8.8.8") / UDP(sport=5, dport=53) / DNS(rd=1, qd=DNSQR(qname="x.com"))
    assert _proto(dns) == "DNS"
