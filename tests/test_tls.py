"""Tests for JA4 fingerprinting and TLS certificate inspection."""

import re

from packetiq.detection import ja3, tls_inspect
from packetiq.detection.models import EventType


def test_ja4_format():
    """JA4 must follow t<ver><sni><nn><nn><alpn>_<12hex>_<12hex>."""
    data = {
        "version": 0x0303,
        "sup_versions": [0x0304, 0x0303],
        "sni": "example.com",
        "ciphers": [0x1301, 0x1302, 0xc02b],
        "extensions": [0x0000, 0x000a, 0x000b, 0x000d, 0x0010, 0x002b],
        "sigalgs": [0x0403, 0x0804],
        "alpn": ["h2"],
    }
    ja4 = ja3._compute_ja4(data)
    assert re.match(r"^t\d\d[di]\d{2}\d{2}..\_[0-9a-f]{12}_[0-9a-f]{12}$", ja4), ja4
    # TLS 1.3 + SNI present + ALPN h2
    assert ja4.startswith("t13d")
    assert ja4.split("_")[0].endswith("h2")


def test_self_signed_cert_detected(tmp_path):
    """Generate a real self-signed cert, wrap it in a TLS Certificate handshake
    record, and confirm tls_inspect flags it."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "evil-c2.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)           # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(__import__("cryptography.hazmat.primitives.serialization",
                                       fromlist=["Encoding"]).Encoding.DER)

    # TLS Certificate handshake (1.2 layout): cert_list_len(3) + cert_len(3) + cert
    cert_msg = len(der).to_bytes(3, "big") + der
    cert_msg = len(cert_msg).to_bytes(3, "big") + cert_msg
    hs = b"\x0b" + len(cert_msg).to_bytes(3, "big") + cert_msg     # handshake: type 0x0b
    record = b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs     # TLS record (handshake)

    # server (443) -> client; chunk across two packets to exercise reassembly
    pkts = []
    mid = len(record) // 2
    for chunk in (record[:mid], record[mid:]):
        p = Ether() / IP(src="203.0.113.9", dst="10.0.0.5") / TCP(sport=443, dport=51000, flags="PA") / Raw(load=chunk)
        p.time = 1700000000.0
        pkts.append(p)
    pcap = tmp_path / "tls.pcap"
    wrpcap(str(pcap), pkts)

    events = tls_inspect.analyze(str(pcap))
    assert any(e.event_type == EventType.TLS_ANOMALY and "self-signed" in e.evidence.get("flags", [])
               for e in events), [e.description for e in events]
