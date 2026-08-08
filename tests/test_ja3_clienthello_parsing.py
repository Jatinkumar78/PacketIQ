"""JA3/JA4 ClientHello parsing for the extension arms the fixture never carries.

The synthetic capture has no real TLS handshake, so the parser is exercised only
by whatever ClientHellos happen to appear in the sample pcaps. Two extensions —
signature_algorithms and a one-character ALPN — feed JA4 directly: parse them
wrong and the fingerprint changes, which silently breaks every blocklist match.
"""

import struct

import pytest

from packetiq.detection import ja3
from packetiq.parser.pcap_parser import RawPacketRecord


def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!HH", etype, len(data)) + data


def _client_hello(extensions: bytes = b"", ciphers=(0x1301, 0xC02F),
                  version: int = 0x0303) -> bytes:
    """A structurally valid TLS ClientHello record."""
    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    body = (
        struct.pack("!H", version)          # client_version
        + b"\x00" * 32                      # random
        + b"\x00"                           # session_id length
        + struct.pack("!H", len(cipher_bytes)) + cipher_bytes
        + b"\x01\x00"                       # compression: 1 method, null
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _sni(host: str) -> bytes:
    name = host.encode()
    entry = b"\x00" + struct.pack("!H", len(name)) + name
    return _ext(0x0000, struct.pack("!H", len(entry)) + entry)


def _alpn(*protocols: str) -> bytes:
    entries = b"".join(bytes([len(p)]) + p.encode() for p in protocols)
    return _ext(0x0010, struct.pack("!H", len(entries)) + entries)


def _sig_algs(*algs: int) -> bytes:
    body = b"".join(struct.pack("!H", a) for a in algs)
    return _ext(0x000d, struct.pack("!H", len(body)) + body)


def _supported_versions(*versions: int) -> bytes:
    body = b"".join(struct.pack("!H", v) for v in versions)
    return _ext(0x002b, bytes([len(body)]) + body)


# ── Parsing ──────────────────────────────────────────────────────────────────

def test_a_minimal_client_hello_parses():
    parsed = ja3._parse_client_hello(_client_hello())

    assert parsed is not None
    assert parsed["version_str"] == "TLSv1.2"
    assert parsed["ciphers"] == [0x1301, 0xC02F]


@pytest.mark.parametrize("payload,why", [
    (b"\x16\x03\x01\x00\x05", "too short to be a ClientHello"),
    (b"\x17\x03\x03" + b"\x00" * 60, "application data, not a handshake"),
    (b"\x16\x03\x01\x00\x3c\x02" + b"\x00" * 60, "ServerHello, not ClientHello"),
])
def test_bytes_that_are_not_a_client_hello_yield_nothing(payload, why):
    assert ja3._parse_client_hello(payload) is None, why


def test_signature_algorithms_are_extracted():
    """JA4_c is a hash over this list; dropping it changes every fingerprint."""
    algs = (0x0403, 0x0804, 0x0401)
    parsed = ja3._parse_client_hello(_client_hello(_sig_algs(*algs)))

    assert parsed["sigalgs"] == list(algs)


def test_an_empty_signature_algorithms_list_parses_to_nothing():
    parsed = ja3._parse_client_hello(_client_hello(_ext(0x000d, b"\x00\x00")))
    assert parsed["sigalgs"] == []


def test_supported_groups_and_point_formats_are_extracted():
    curves = struct.pack("!H", 4) + struct.pack("!HH", 0x001d, 0x0017)
    parsed = ja3._parse_client_hello(_client_hello(
        _ext(0x000a, curves) + _ext(0x000b, b"\x01\x00")))

    assert parsed["curves"] == [0x001d, 0x0017]
    assert parsed["point_fmts"] == [0x00]


def test_the_server_name_is_extracted():
    parsed = ja3._parse_client_hello(_client_hello(_sni("example.com")))
    assert parsed["sni"] == "example.com"


def test_supported_versions_are_extracted():
    parsed = ja3._parse_client_hello(_client_hello(_supported_versions(0x0304, 0x0303)))
    assert parsed["sup_versions"] == [0x0304, 0x0303]


# ── JA4 assembly ─────────────────────────────────────────────────────────────

def test_a_two_character_alpn_uses_its_first_and_last_characters():
    parsed = ja3._parse_client_hello(_client_hello(_alpn("h2") + _supported_versions(0x0304)))
    ja4 = ja3._compute_ja4(parsed)

    assert parsed["alpn"] == ["h2"]
    assert ja4.startswith("t13i"), ja4
    assert ja4.split("_")[0].endswith("h2")


def test_a_longer_alpn_still_uses_first_and_last():
    parsed = ja3._parse_client_hello(_client_hello(_alpn("http/1.1")))
    assert ja3._compute_ja4(parsed).split("_")[0].endswith("h1")


def test_a_single_character_alpn_is_doubled():
    """The FoxIO spec always yields a two-character ALPN word.

    A one-character protocol label has no distinct last character, so the first
    is repeated — without this branch the JA4_a field would come out short and
    every fingerprint from such a client would mismatch.
    """
    parsed = ja3._parse_client_hello(_client_hello(_alpn("h")))
    assert parsed["alpn"] == ["h"]
    assert ja3._compute_ja4(parsed).split("_")[0].endswith("hh")


def test_no_alpn_at_all_yields_the_zero_word():
    parsed = ja3._parse_client_hello(_client_hello())
    assert ja3._compute_ja4(parsed).split("_")[0].endswith("00")


def test_the_sni_flag_distinguishes_domain_from_ip_destinations():
    with_sni = ja3._compute_ja4(ja3._parse_client_hello(_client_hello(_sni("example.com"))))
    without = ja3._compute_ja4(ja3._parse_client_hello(_client_hello()))

    assert with_sni[3] == "d"
    assert without[3] == "i"


def test_the_ja4_version_prefers_supported_versions_over_the_record_version():
    """A TLS 1.3 client still writes 0x0303 in the ClientHello for compatibility."""
    parsed = ja3._parse_client_hello(_client_hello(_supported_versions(0x0304),
                                                   version=0x0303))
    assert ja3._compute_ja4(parsed).startswith("t13")


# ── Streaming pass ───────────────────────────────────────────────────────────

def _record(payload: bytes, dport=443):
    return RawPacketRecord(
        index=0, timestamp=1700000000.0, size=len(payload) + 54,
        src_ip="192.168.1.50", dst_ip="185.199.108.153",
        src_port=51000, dst_port=dport,
        protocol="TCP", raw_payload=payload, payload_size=len(payload),
    )


def test_the_stream_pass_is_a_no_op_without_a_blocklist(monkeypatch):
    """No JA3 threat-intel feed means no findings — never a guessed one.

    The whole pass short-circuits rather than fingerprinting every handshake it
    can never match against anything.
    """
    monkeypatch.setattr(ja3, "load_blocklist", lambda *a, **kw: {})
    det = ja3.JA3Detector()

    assert det.detect_from_stream(iter([_record(_client_hello())])) == []
    assert det.active is False


def test_a_blocklisted_fingerprint_is_reported(monkeypatch):
    hello = _client_hello(_sni("c2.example-evil.xyz"))
    parsed = ja3._parse_client_hello(hello)
    digest = ja3._compute_ja3(parsed)

    monkeypatch.setattr(ja3, "load_blocklist", lambda *a, **kw: {digest: "Emotet"})
    events = ja3.JA3Detector().detect_from_stream(iter([_record(hello)]))

    assert len(events) == 1
    assert events[0].evidence["ja3_hash"] == digest
    assert events[0].evidence["sni"] == "c2.example-evil.xyz"


def test_an_unlisted_fingerprint_is_not_reported(monkeypatch):
    monkeypatch.setattr(ja3, "load_blocklist", lambda *a, **kw: {"0" * 32: "Something"})
    assert ja3.JA3Detector().detect_from_stream(iter([_record(_client_hello())])) == []


def test_traffic_on_a_non_tls_port_is_not_fingerprinted(monkeypatch):
    monkeypatch.setattr(ja3, "load_blocklist", lambda *a, **kw: {"0" * 32: "x"})
    det = ja3.JA3Detector().begin()
    det.feed(_record(_client_hello(), dport=22))

    assert det.ja3_flows == {}
