"""
JA3 / JA4 TLS client fingerprinting.

This detector reads attacker-controlled bytes straight off the wire and walks
nested length-prefixed TLS structures by hand, which is exactly the shape of code
that crashes on a truncated or hostile record. Most of it was unexercised.

Two properties are load-bearing and asserted throughout:

  * **Nothing is invented.** With no threat-intel feed loaded the detector must
    produce zero events rather than guess from a hardcoded list.
  * **A malformed record is skipped, not fatal.** Every truncation of a valid
    ClientHello is fed back in; none may raise.
"""

import hashlib
import struct

import pytest

from packetiq.detection.ja3 import (
    JA3Detector,
    _compute_ja3,
    _compute_ja4,
    _parse_client_hello,
    _severity_for,
    load_blocklist,
)
from packetiq.detection.models import EventType, Severity
from packetiq.parser.pcap_parser import RawPacketRecord

# --------------------------------------------------------------------------- #
#  A real-shaped ClientHello                                                    #
# --------------------------------------------------------------------------- #

def build_client_hello(
    version=0x0303,
    ciphers=(0x1301, 0x1302, 0xC02B),
    curves=(0x001D, 0x0017),
    point_fmts=(0x00,),
    sni="example.com",
    alpn=("h2", "http/1.1"),
    sup_versions=(0x0304, 0x0303),
    include_grease=False,
):
    """Assemble a syntactically valid TLS 1.2/1.3 ClientHello record."""
    cs = list(ciphers)
    if include_grease:
        cs = [0x0A0A, *cs]
    cipher_bytes = b"".join(struct.pack("!H", c) for c in cs)

    exts = b""

    def ext(etype, body):
        return struct.pack("!HH", etype, len(body)) + body

    if include_grease:
        exts += ext(0x1A1A, b"")

    if sni:
        host = sni.encode()
        entry = struct.pack("!BH", 0, len(host)) + host
        exts += ext(0x0000, struct.pack("!H", len(entry)) + entry)

    if curves:
        body = b"".join(struct.pack("!H", c) for c in curves)
        if include_grease:
            body = struct.pack("!H", 0x2A2A) + body
        exts += ext(0x000A, struct.pack("!H", len(body)) + body)

    if point_fmts:
        body = bytes(point_fmts)
        exts += ext(0x000B, bytes([len(body)]) + body)

    if sup_versions:
        body = b"".join(struct.pack("!H", v) for v in sup_versions)
        exts += ext(0x002B, bytes([len(body)]) + body)

    if alpn:
        names = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        exts += ext(0x0010, struct.pack("!H", len(names)) + names)

    body = (
        struct.pack("!H", version)
        + b"\x00" * 32                                  # random
        + b"\x00"                                       # session id length
        + struct.pack("!H", len(cipher_bytes)) + cipher_bytes
        + b"\x01\x00"                                   # compression methods
        + struct.pack("!H", len(exts)) + exts
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


HELLO = build_client_hello()


def _record(payload, dst_port=443, src="192.168.1.10", dst="93.184.216.34"):
    return RawPacketRecord(
        index=0,
        timestamp=1700000000.0,
        size=len(payload) + 54,
        src_ip=src,
        dst_ip=dst,
        src_port=51000,
        dst_port=dst_port,
        protocol="TCP",
        raw_payload=payload,
        payload_size=len(payload),
    )


# --------------------------------------------------------------------------- #
#  ClientHello parsing                                                          #
# --------------------------------------------------------------------------- #

def test_a_valid_client_hello_yields_every_field():
    parsed = _parse_client_hello(HELLO)
    assert parsed is not None
    assert parsed["version"] == 0x0303
    assert parsed["version_str"] == "TLSv1.2"
    assert parsed["ciphers"] == [0x1301, 0x1302, 0xC02B]
    assert parsed["curves"] == [0x001D, 0x0017]
    assert parsed["point_fmts"] == [0x00]
    assert parsed["sni"] == "example.com"
    assert parsed["alpn"][0] == "h2"
    assert 0x0304 in parsed["sup_versions"]


def test_grease_values_are_filtered_out():
    """RFC 8701 GREASE is random padding; leaving it in makes the hash unstable."""
    parsed = _parse_client_hello(build_client_hello(include_grease=True))
    assert 0x0A0A not in parsed["ciphers"]
    assert 0x1A1A not in parsed["extensions"]
    assert 0x2A2A not in parsed["curves"]


def test_a_hello_without_sni_is_still_parsed():
    parsed = _parse_client_hello(build_client_hello(sni=""))
    assert parsed is not None
    assert parsed["sni"] == ""


@pytest.mark.parametrize("payload,reason", [
    (b"", "empty"),
    (b"\x16\x03\x01", "too short for a record header"),
    (b"\x17\x03\x03" + b"\x00" * 100, "application data, not a handshake"),
    (b"\x16\x03\x01\x00\x40\x02" + b"\x00" * 100, "ServerHello, not ClientHello"),
    (b"GET / HTTP/1.1\r\n\r\n" + b"\x00" * 60, "plain HTTP"),
    (b"\x00" * 200, "all zeroes"),
])
def test_non_client_hello_payloads_are_rejected(payload, reason):
    assert _parse_client_hello(payload) is None, reason


def test_every_truncation_of_a_valid_hello_is_survivable():
    """A cut-off TLS record must never raise out of the detector."""
    for n in range(len(HELLO)):
        _parse_client_hello(HELLO[:n])       # must not raise


def test_a_hello_with_a_lying_length_field_does_not_crash():
    corrupt = bytearray(HELLO)
    corrupt[3:5] = struct.pack("!H", 0xFFFF)     # record claims to be huge
    _parse_client_hello(bytes(corrupt))


# --------------------------------------------------------------------------- #
#  Fingerprint computation                                                      #
# --------------------------------------------------------------------------- #

def test_ja3_is_a_stable_md5():
    parsed = _parse_client_hello(HELLO)
    h = _compute_ja3(parsed)
    assert len(h) == 32
    assert all(c in "0123456789abcdef" for c in h)
    assert h == _compute_ja3(_parse_client_hello(HELLO))


def test_ja3_matches_the_documented_construction():
    """JA3 = MD5(version,ciphers,extensions,curves,point_formats)."""
    p = _parse_client_hello(HELLO)
    expected_str = ",".join([
        str(p["version"]),
        "-".join(str(c) for c in p["ciphers"]),
        "-".join(str(e) for e in p["extensions"]),
        "-".join(str(c) for c in p["curves"]),
        "-".join(str(f) for f in p["point_fmts"]),
    ])
    assert _compute_ja3(p) == hashlib.md5(  # noqa: S324 — JA3 is defined as MD5
        expected_str.encode()
    ).hexdigest()


def test_a_different_client_produces_a_different_ja3():
    a = _compute_ja3(_parse_client_hello(HELLO))
    b = _compute_ja3(_parse_client_hello(build_client_hello(ciphers=(0x009C, 0x009D))))
    assert a != b


def test_grease_does_not_change_the_fingerprint():
    """Two runs of the same client differ only in GREASE; the hash must not."""
    plain = _compute_ja3(_parse_client_hello(build_client_hello()))
    greased = _compute_ja3(_parse_client_hello(build_client_hello(include_grease=True)))
    assert plain == greased


def test_ja4_has_the_three_part_foxio_shape():
    ja4 = _compute_ja4(_parse_client_hello(HELLO))
    a, b, c = ja4.split("_")
    assert a.startswith("t13d")            # TLS 1.3, SNI present
    assert a.endswith("h2")                # first ALPN protocol
    assert len(b) == 12 and len(c) == 12


def test_ja4_marks_the_absence_of_sni():
    # JA4_a is t<version><sni flag>… — 'i' = no SNI, 'd' = domain present.
    assert _compute_ja4(_parse_client_hello(build_client_hello(sni="")))[3] == "i"
    assert _compute_ja4(_parse_client_hello(HELLO))[3] == "d"


def test_ja4_falls_back_when_there_is_no_alpn():
    ja4 = _compute_ja4(_parse_client_hello(build_client_hello(alpn=())))
    assert ja4.split("_")[0].endswith("00")


# --------------------------------------------------------------------------- #
#  Blocklist loading                                                            #
# --------------------------------------------------------------------------- #

def test_the_bundled_blocklist_loads():
    bl = load_blocklist()
    assert isinstance(bl, dict)
    for k in bl:
        assert len(k) == 32


def test_a_user_supplied_feed_is_read(tmp_path):
    csv_path = tmp_path / "ja3.csv"
    csv_path.write_text(
        "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
        "e7d705a3286e19ea42f587b344ee6865,2021-01-01,2021-06-01,Cobalt Strike\n"
        "a0e9f5d64349fb13191bc781f81f42e1,2021-01-01,2021-06-01,\n",
        encoding="utf-8",
    )
    bl = load_blocklist(str(csv_path))
    assert bl["e7d705a3286e19ea42f587b344ee6865"] == "Cobalt Strike"
    assert bl["a0e9f5d64349fb13191bc781f81f42e1"] == "Known-malicious (JA3 feed)"


def test_malformed_rows_are_skipped_not_fatal(tmp_path):
    csv_path = tmp_path / "ja3.csv"
    csv_path.write_text(
        "\n"
        "not-a-hash,x,y,z\n"
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ,x,y,nonhex\n"
        "e7d705a3286e19ea42f587b344ee6865,2021-01-01,2021-06-01,Emotet\n",
        encoding="utf-8",
    )
    bl = load_blocklist(str(csv_path))
    assert list(bl) == ["e7d705a3286e19ea42f587b344ee6865"]


def test_a_missing_feed_yields_an_empty_blocklist(tmp_path):
    assert load_blocklist(str(tmp_path / "absent.csv")) == {}


@pytest.mark.parametrize("reason,expected", [
    ("Cobalt Strike", Severity.CRITICAL),
    ("cobalt strike", Severity.CRITICAL),
    ("  Emotet  ", Severity.CRITICAL),
    ("TrickBot", Severity.CRITICAL),
    ("Adware", Severity.HIGH),
    ("", Severity.HIGH),
])
def test_severity_is_raised_for_known_ransomware_families(reason, expected):
    assert _severity_for(reason) is expected


# --------------------------------------------------------------------------- #
#  Detector behaviour                                                           #
# --------------------------------------------------------------------------- #

def test_no_feed_means_no_events_ever(monkeypatch):
    """The contract: absent intel produces silence, never a fabricated hit."""
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist", lambda *a, **k: {})
    det = JA3Detector().begin()
    assert det.active is False
    det.feed(_record(HELLO))
    assert det.finalize() == []


def test_a_fingerprint_on_the_blocklist_is_flagged(monkeypatch):
    ja3_hash = _compute_ja3(_parse_client_hello(HELLO))
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist",
                        lambda *a, **k: {ja3_hash: "Cobalt Strike"})

    det = JA3Detector().begin()
    det.feed(_record(HELLO))
    det.feed(_record(HELLO))
    events = det.finalize()

    assert len(events) == 1
    e = events[0]
    assert e.event_type is EventType.JA3_ANOMALY
    assert e.severity is Severity.CRITICAL
    assert e.src_ip == "192.168.1.10"
    assert e.dst_port == 443
    assert e.packet_count == 2
    assert e.evidence["ja3_hash"] == ja3_hash
    assert e.evidence["malware"] == "Cobalt Strike"
    assert e.evidence["sni"] == "example.com"
    assert e.evidence["ja4"].startswith("t13d")


def test_a_fingerprint_absent_from_the_feed_is_not_flagged(monkeypatch):
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist",
                        lambda *a, **k: {"0" * 32: "Some Malware"})
    det = JA3Detector().begin()
    det.feed(_record(HELLO))
    assert det.finalize() == []


def test_traffic_on_a_non_tls_port_is_ignored(monkeypatch):
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist",
                        lambda *a, **k: {_compute_ja3(_parse_client_hello(HELLO)): "X"})
    det = JA3Detector().begin()
    det.feed(_record(HELLO, dst_port=12345))
    assert det.finalize() == []


@pytest.mark.parametrize("port", [443, 8443, 4443, 993, 995, 465])
def test_tls_is_recognised_on_every_stream_port(port, monkeypatch):
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist",
                        lambda *a, **k: {_compute_ja3(_parse_client_hello(HELLO)): "X"})
    det = JA3Detector().begin()
    det.feed(_record(HELLO, dst_port=port))
    assert len(det.finalize()) == 1


def test_a_record_without_payload_is_ignored(monkeypatch):
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist", lambda *a, **k: {"a" * 32: "X"})
    det = JA3Detector().begin()
    det.feed(_record(b""))
    assert det.finalize() == []


def test_the_streaming_entry_point_matches_the_incremental_one(monkeypatch):
    ja3_hash = _compute_ja3(_parse_client_hello(HELLO))
    monkeypatch.setattr("packetiq.detection.ja3.load_blocklist",
                        lambda *a, **k: {ja3_hash: "Dridex"})
    events = JA3Detector().detect_from_stream(iter([_record(HELLO)]))
    assert len(events) == 1
    assert events[0].evidence["ja3_hash"] == ja3_hash


def test_finalize_before_begin_returns_nothing():
    """Defensive: the engine may skip this detector entirely."""
    assert JA3Detector().finalize() == []
