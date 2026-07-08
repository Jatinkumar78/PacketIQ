"""
TLS certificate inspection.

Carves the server's leaf X.509 certificate out of the TLS handshake (a light
reassembly of the server->client byte stream) and flags:

  - self-signed certificates              (issuer == subject)
  - expired / not-yet-valid certificates  (relative to the capture time)
  - abnormally long validity periods      (> 825 days)

Requires the `cryptography` package; if it is not installed this detector is a
no-op (it never fabricates a finding).

Runs as its own PCAP pass because certificates are multi-kilobyte and span many
TCP segments — larger than the per-packet payload the main parser keeps.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.utils.helpers import is_private_ip

_TLS_PORTS = {443, 8443, 4443, 993, 995, 465, 990, 5061}
_MAX_FLOW_BYTES = 32 * 1024     # cap reassembly per flow
_LONG_VALIDITY_DAYS = 825


def analyze(pcap_path: str) -> list[DetectionEvent]:
    try:
        from cryptography import x509  # noqa: F401
    except Exception:
        return []   # cert analysis unavailable — never guess

    # server flow key (server_ip, server_port, client_ip) -> accumulated bytes
    buffers: dict[tuple, bytearray] = defaultdict(bytearray)
    done: set = set()
    meta: dict[tuple, dict] = {}

    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                if not pkt.haslayer(TCP):
                    continue
                if pkt.haslayer(IP):
                    src, dst = pkt[IP].src, pkt[IP].dst
                elif pkt.haslayer(IPv6):
                    src, dst = pkt[IPv6].src, pkt[IPv6].dst
                else:
                    continue
                tcp = pkt[TCP]
                # server = the side on a TLS port (it sends the certificate)
                if tcp.sport in _TLS_PORTS:
                    server_ip, server_port, client_ip = src, tcp.sport, dst
                else:
                    continue
                key = (server_ip, server_port, client_ip)
                if key in done:
                    continue
                payload = bytes(tcp.payload)
                if not payload:
                    continue
                buf = buffers[key]
                buf += payload
                meta.setdefault(key, {"ts": float(pkt.time)})
                if len(buf) > _MAX_FLOW_BYTES:
                    done.add(key)
    except Exception:
        return []

    events: list[DetectionEvent] = []
    seen_certs: set = set()
    for key, buf in buffers.items():
        der = _extract_leaf_cert(bytes(buf))
        if not der:
            continue
        ev = _analyze_cert(der, key, meta.get(key, {}).get("ts", 0.0), seen_certs)
        if ev:
            events.append(ev)
    return events


def _extract_leaf_cert(server_bytes: bytes) -> Optional[bytes]:
    """Reassemble TLS handshake records and return the leaf certificate DER."""
    # 1) collect handshake-record (0x16) fragments
    hs = bytearray()
    pos = 0
    n = len(server_bytes)
    while pos + 5 <= n:
        rtype = server_bytes[pos]
        rlen = int.from_bytes(server_bytes[pos + 3:pos + 5], "big")
        if rlen <= 0 or pos + 5 + rlen > n:
            break
        if rtype == 0x16:
            hs += server_bytes[pos + 5:pos + 5 + rlen]
        pos += 5 + rlen

    # 2) walk handshake messages, find Certificate (0x0b)
    p = 0
    while p + 4 <= len(hs):
        htype = hs[p]
        hlen = int.from_bytes(hs[p + 1:p + 4], "big")
        body = hs[p + 4:p + 4 + hlen]
        if htype == 0x0b:
            return _first_cert(bytes(body))
        p += 4 + hlen
    return None


def _first_cert(body: bytes) -> Optional[bytes]:
    """Extract the first cert DER from a Certificate message (TLS 1.2 or 1.3)."""
    for offset in (0, 1):           # TLS1.2 (no context) / TLS1.3 (1-byte ctx len = 0)
        if len(body) < offset + 6:
            continue
        cert_len = int.from_bytes(body[offset + 3:offset + 6], "big")
        cert = body[offset + 6:offset + 6 + cert_len]
        if cert[:1] == b"\x30":     # DER SEQUENCE
            return cert
    return None


def _analyze_cert(der: bytes, key: tuple, ts: float, seen: set) -> Optional[DetectionEvent]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    server_ip, server_port, client_ip = key

    def _cn(name) -> str:
        try:
            attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            return attrs[0].value if attrs else name.rfc4514_string()
        except Exception:
            return ""

    subject = _cn(cert.subject)
    issuer = _cn(cert.issuer)

    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:                     # older cryptography
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

    ref = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else datetime.now(timezone.utc)

    flags = []
    severity = Severity.LOW
    if cert.issuer == cert.subject:
        flags.append("self-signed")
        severity = Severity.MEDIUM
    if ref > not_after:
        flags.append("expired")
        severity = Severity.HIGH
    elif ref < not_before:
        flags.append("not-yet-valid")
        severity = Severity.MEDIUM
    if (not_after - not_before).days > _LONG_VALIDITY_DAYS:
        flags.append(f"long-validity({(not_after - not_before).days}d)")

    if not flags:
        return None

    fp = cert.fingerprint(hashes.SHA256()).hex()
    if fp in seen:
        return None
    seen.add(fp)

    # external servers with dodgy certs are more interesting than internal ones
    if not is_private_ip(server_ip) and severity == Severity.MEDIUM:
        severity = Severity.HIGH

    return DetectionEvent(
        event_type   = EventType.TLS_ANOMALY,
        severity     = severity,
        src_ip       = client_ip,
        dst_ip       = server_ip,
        dst_port     = server_port,
        protocol     = "TLS",
        timestamp    = ts,
        packet_count = 1,
        confidence   = 0.8,
        description  = (
            f"Suspicious TLS certificate from {server_ip}:{server_port} "
            f"({', '.join(flags)}) — CN={subject or '?'}"
        ),
        evidence     = {
            "flags":       flags,
            "subject_cn":  subject,
            "issuer_cn":   issuer,
            "not_before":  not_before.strftime("%Y-%m-%d"),
            "not_after":   not_after.strftime("%Y-%m-%d"),
            "sha256":      fp,
        },
    )
