"""TLS certificate carving and analysis, driven with real X.509 certificates.

The detector reassembles the server's handshake bytes by hand and parses the
leaf certificate out of them, so every test here builds a genuine DER
certificate with `cryptography` and wraps it in real TLS record framing. Nothing
is stubbed except the two failure modes that cannot be produced on a machine
where the library is installed and current.
"""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from packetiq.detection import tls_inspect
from packetiq.detection.models import EventType, Severity

NOW = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)   # 1700000000.0
TS = NOW.timestamp()


# ── Certificate and handshake construction ───────────────────────────────────

def _make_cert(not_before, not_after, subject_cn="server.example", issuer_cn=None):
    """A real self-signed (or differently-issued) leaf certificate, DER encoded."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or subject_cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _tls12_certificate_message(der: bytes) -> bytes:
    """Handshake type 0x0b with a TLS 1.2 certificate_list (no request context)."""
    entry = len(der).to_bytes(3, "big") + der
    body = len(entry).to_bytes(3, "big") + entry
    return b"\x0b" + len(body).to_bytes(3, "big") + body


def _tls13_certificate_message(der: bytes) -> bytes:
    """TLS 1.3 prefixes a one-byte request context (0) before the list."""
    entry = len(der).to_bytes(3, "big") + der + b"\x00\x00"   # + empty extensions
    body = b"\x00" + len(entry).to_bytes(3, "big") + entry
    return b"\x0b" + len(body).to_bytes(3, "big") + body


def _records(payload: bytes, rtype=0x16, chunk=1200) -> bytes:
    """Frame bytes as one or more TLS records, fragmented like a real server."""
    out = b""
    for i in range(0, len(payload), chunk):
        part = payload[i:i + chunk]
        out += bytes([rtype]) + b"\x03\x03" + len(part).to_bytes(2, "big") + part
    return out


def _feed(acc, server_bytes, server_ip="185.199.108.153", client_ip="192.168.1.50",
          sport=443, seg=600):
    for i in range(0, len(server_bytes), seg):
        pkt = (Ether() / IP(src=server_ip, dst=client_ip) /
               TCP(sport=sport, dport=51000) / server_bytes[i:i + seg])
        pkt.time = TS
        acc.feed(pkt)


def _analyse(der, server_ip="185.199.108.153", tls13=False):
    acc = tls_inspect.TLSCertAccumulator()
    msg = _tls13_certificate_message(der) if tls13 else _tls12_certificate_message(der)
    _feed(acc, _records(msg), server_ip=server_ip)
    return acc.finalize()


# ── feed() packet filtering ──────────────────────────────────────────────────

def test_a_packet_with_no_ip_layer_is_ignored():
    """TCP without IP happens in malformed or tunnelled captures; it must not raise."""
    acc = tls_inspect.TLSCertAccumulator()
    acc.feed(Ether() / TCP(sport=443, dport=51000))
    assert acc.buffers == {}


def test_a_non_tcp_packet_is_ignored():
    acc = tls_inspect.TLSCertAccumulator()
    acc.feed(Ether() / ARP())
    assert acc.buffers == {}


def test_ipv6_server_traffic_is_reassembled():
    """The IPv6 arm of the address extraction — the fixture capture is IPv4 only."""
    acc = tls_inspect.TLSCertAccumulator()
    pkt = (Ether() / IPv6(src="2606:4700::1111", dst="fd00::50") /
           TCP(sport=443, dport=51000) / b"\x16\x03\x03\x00\x04abcd")
    pkt.time = TS
    acc.feed(pkt)

    assert list(acc.buffers) == [("2606:4700::1111", 443, "fd00::50")]


def test_client_to_server_traffic_is_not_buffered():
    """Only the side sourced *from* a TLS port sends the certificate."""
    acc = tls_inspect.TLSCertAccumulator()
    pkt = Ether() / IP(src="192.168.1.50", dst="185.199.108.153") / TCP(sport=51000, dport=443)
    pkt.time = TS
    acc.feed(pkt / b"\x16\x03\x03\x00\x04abcd")

    assert acc.buffers == {}


def test_an_empty_tcp_payload_adds_nothing():
    acc = tls_inspect.TLSCertAccumulator()
    pkt = Ether() / IP(src="185.199.108.153", dst="192.168.1.50") / TCP(sport=443, dport=51000)
    pkt.time = TS
    acc.feed(pkt)
    assert acc.buffers == {}


def test_a_flow_stops_being_reassembled_past_the_byte_cap():
    """A 32 KB cap keeps one long-lived TLS session from growing without bound.

    Once tripped the flow is marked done and later packets are dropped on the
    `key in self.done` check — the two halves of the same guard.
    """
    acc = tls_inspect.TLSCertAccumulator()
    _feed(acc, b"\x00" * (tls_inspect._MAX_FLOW_BYTES + 2000), seg=1400)
    key = ("185.199.108.153", 443, "192.168.1.50")
    assert key in acc.done

    size_at_cap = len(acc.buffers[key])
    _feed(acc, b"\xff" * 1400, seg=1400)
    assert len(acc.buffers[key]) == size_at_cap, "a done flow must not keep growing"


# ── Certificate carving ──────────────────────────────────────────────────────

def test_a_self_signed_certificate_is_carved_and_flagged():
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=30))
    events = _analyse(der)

    assert len(events) == 1
    assert events[0].event_type == EventType.TLS_ANOMALY
    assert "self-signed" in events[0].evidence["flags"]


def test_a_tls13_certificate_message_is_carved_too():
    """The 1-byte request context shifts every length field; both offsets are tried."""
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=30))
    events = _analyse(der, tls13=True)

    assert len(events) == 1
    assert "self-signed" in events[0].evidence["flags"]


def test_a_flow_carrying_no_certificate_produces_nothing():
    """Application data records only — the handshake walk finds no 0x0b message."""
    acc = tls_inspect.TLSCertAccumulator()
    _feed(acc, _records(b"encrypted payload bytes", rtype=0x17))
    assert acc.finalize() == []


def test_handshake_records_without_a_certificate_message_produce_nothing():
    """ServerHello (0x02) alone: the walk runs to the end and returns None."""
    hello = b"\x02" + (32).to_bytes(3, "big") + b"\x00" * 32
    assert tls_inspect._extract_leaf_cert(_records(hello)) is None


def test_a_truncated_record_stops_the_walk_instead_of_over_reading():
    """A capture cut mid-record claims more bytes than it carries.

    Trusting that length would read past the buffer; the walk breaks instead.
    """
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=30))
    full = _records(_tls12_certificate_message(der))
    assert tls_inspect._extract_leaf_cert(full[:len(full) // 2]) is None


def test_a_zero_length_record_stops_the_walk():
    assert tls_inspect._extract_leaf_cert(b"\x16\x03\x03\x00\x00") is None


def test_a_certificate_message_too_short_to_hold_a_certificate_yields_none():
    assert tls_inspect._first_cert(b"\x00\x00") is None


def test_a_certificate_message_whose_payload_is_not_der_yields_none():
    """Neither offset finds a DER SEQUENCE tag, so nothing is guessed."""
    body = (4).to_bytes(3, "big") + (4).to_bytes(3, "big") + b"\xff\xff\xff\xff"
    assert tls_inspect._first_cert(body) is None


def test_bytes_that_parse_as_a_certificate_message_but_not_as_x509_yield_none():
    """`\\x30` starts a DER SEQUENCE, so carving succeeds and x509 parsing fails."""
    junk = b"\x30\x82\x01\x00" + b"\x41" * 250
    entry = len(junk).to_bytes(3, "big") + junk
    body = len(entry).to_bytes(3, "big") + entry
    msg = b"\x0b" + len(body).to_bytes(3, "big") + body

    acc = tls_inspect.TLSCertAccumulator()
    _feed(acc, _records(msg))
    assert acc.finalize() == []


# ── Certificate judgement ────────────────────────────────────────────────────

def test_an_expired_certificate_is_high():
    der = _make_cert(NOW - timedelta(days=400), NOW - timedelta(days=10))
    ev = _analyse(der)[0]

    assert "expired" in ev.evidence["flags"]
    assert ev.severity == Severity.HIGH


def test_a_not_yet_valid_certificate_is_flagged():
    """Clock skew or a backdated implant. Reported against the capture time, not now."""
    der = _make_cert(NOW + timedelta(days=10), NOW + timedelta(days=400))
    ev = _analyse(der)[0]

    assert "not-yet-valid" in ev.evidence["flags"]


def test_an_abnormally_long_validity_is_flagged():
    """Public CAs are capped near 398 days; a decade-long leaf is home-made."""
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=3650))
    ev = _analyse(der)[0]

    assert any(f.startswith("long-validity") for f in ev.evidence["flags"])


def test_a_clean_ca_issued_certificate_is_not_reported():
    """Different issuer, in date, normal validity — nothing to say about it.

    This is the test that keeps the detector from flagging ordinary HTTPS.
    """
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=300),
                     subject_cn="www.example.com", issuer_cn="Example CA R3")
    assert _analyse(der) == []


def test_the_same_certificate_on_two_connections_is_reported_once():
    """Deduplicated on the SHA-256 fingerprint, not the flow tuple."""
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=30))
    acc = tls_inspect.TLSCertAccumulator()
    msg = _records(_tls12_certificate_message(der))
    _feed(acc, msg, client_ip="192.168.1.50")
    _feed(acc, msg, client_ip="192.168.1.51")

    assert len(acc.buffers) == 2, "two distinct flows should be reassembled"
    assert len(acc.finalize()) == 1, "one certificate is one finding"


def test_a_self_signed_certificate_on_an_external_server_is_escalated():
    """MEDIUM internally, HIGH when the server is out on the internet."""
    der = _make_cert(NOW - timedelta(days=30), NOW + timedelta(days=30))

    internal = _analyse(der, server_ip="192.168.1.99")[0]
    external = _analyse(der, server_ip="185.199.108.153")[0]

    assert internal.severity == Severity.MEDIUM
    assert external.severity == Severity.HIGH


def _analyze_with_cert_object(monkeypatch, der, obj):
    """Run _analyze_cert against a stand-in certificate object.

    The function loads the DER itself, so the only way to hand it a differently
    shaped certificate is to intercept the loader.
    """
    import cryptography.x509 as real_x509
    monkeypatch.setattr(real_x509, "load_der_x509_certificate", lambda d: obj)
    return tls_inspect._analyze_cert(der, ("185.199.108.153", 443, "192.168.1.50"),
                                     TS, set())


def test_a_certificate_with_an_unreadable_name_still_produces_a_finding(monkeypatch):
    """`_cn` falls back to the RFC4514 string, then to "" if even that fails.

    An expired certificate is still worth reporting when its subject cannot be
    rendered — returning nothing there would drop the finding entirely.
    """
    class Nameless:
        def get_attributes_for_oid(self, oid):
            raise ValueError("no such attribute")

        def rfc4514_string(self):
            raise ValueError("unrenderable")

    der = _make_cert(NOW - timedelta(days=400), NOW - timedelta(days=10))
    cert = x509.load_der_x509_certificate(der)

    class Shim:
        subject = Nameless()
        issuer = Nameless()
        not_valid_before_utc = cert.not_valid_before_utc
        not_valid_after_utc = cert.not_valid_after_utc

        def fingerprint(self, algo):
            return cert.fingerprint(algo)

    ev = _analyze_with_cert_object(monkeypatch, der, Shim())

    assert ev is not None
    assert ev.evidence["subject_cn"] == ""
    assert "expired" in ev.evidence["flags"]


def test_an_older_cryptography_without_the_utc_properties_still_works(monkeypatch):
    """`not_valid_before_utc` arrived in cryptography 42.

    The AttributeError fallback is what keeps the detector working on an older
    library, and it cannot be reached on a machine that has a current one.
    """
    der = _make_cert(NOW - timedelta(days=400), NOW - timedelta(days=10))
    cert = x509.load_der_x509_certificate(der)

    class Legacy:
        subject = cert.subject
        issuer = cert.issuer
        # naive datetimes, exactly as the pre-42 API returned them
        not_valid_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_valid_after = cert.not_valid_after_utc.replace(tzinfo=None)

        def fingerprint(self, algo):
            return cert.fingerprint(algo)

    ev = _analyze_with_cert_object(monkeypatch, der, Legacy())

    assert ev is not None
    assert "expired" in ev.evidence["flags"]


# ── Availability and the file-level entry point ──────────────────────────────

def test_the_detector_is_a_no_op_without_cryptography(monkeypatch):
    """It must return nothing rather than guess at certificates it cannot parse."""
    import builtins
    real_import = builtins.__import__

    def no_cryptography(name, *a, **kw):
        if name == "cryptography":
            raise ImportError("not installed")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_cryptography)
    assert tls_inspect.make_accumulator() is None
    assert tls_inspect.analyze("/nonexistent.pcap") == []


def test_analyze_reads_a_real_pcap_end_to_end(tmp_path):
    from scapy.utils import wrpcap

    der = _make_cert(NOW - timedelta(days=400), NOW - timedelta(days=10))
    payload = _records(_tls12_certificate_message(der))
    pkts = []
    for i in range(0, len(payload), 600):
        p = (Ether() / IP(src="185.199.108.153", dst="192.168.1.50") /
             TCP(sport=443, dport=51000) / payload[i:i + 600])
        p.time = TS
        pkts.append(p)
    path = tmp_path / "tls.pcap"
    wrpcap(str(path), pkts)

    events = tls_inspect.analyze(str(path))
    assert len(events) == 1 and "expired" in events[0].evidence["flags"]


def test_an_unreadable_capture_yields_no_findings(tmp_path):
    bad = tmp_path / "truncated.pcap"
    bad.write_bytes(b"not a pcap at all")
    assert tls_inspect.analyze(str(bad)) == []
