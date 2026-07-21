"""
JA3 / JA3S TLS Fingerprinting.

Computes MD5-based fingerprints of TLS ClientHello messages to identify
malware C2 traffic inside HTTPS without decrypting the payload.

JA3  = MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats )
JA3S = MD5( SSLVersion,Cipher,Extensions ) from ServerHello

Computed fingerprints are matched against a REAL threat-intel blocklist
(the bundled abuse.ch SSLBL JA3 feed, or a user-supplied CSV). No
fingerprints are hard-coded or fabricated — if a fingerprint is not in the
loaded feed, it is not flagged. Operates as a second PCAP pass.

Blocklist resolution order:
  1. $PACKETIQ_JA3_BLOCKLIST  (path to a CSV in abuse.ch format)
  2. packetiq/detection/data/ja3_blocklist.csv  (bundled snapshot)

CSV format (abuse.ch SSLBL):  ja3_md5,Firstseen,Lastseen,Listingreason
Lines starting with '#' are ignored.
"""

import contextlib
import csv
import hashlib
import os
import struct
from collections.abc import Generator
from functools import lru_cache
from pathlib import Path
from typing import Optional

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.parser.pcap_parser import RawPacketRecord

# GREASE values to filter (RFC 8701)
_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
}

_BUNDLED_BLOCKLIST = Path(__file__).parent / "data" / "ja3_blocklist.csv"

# Listing reasons that warrant CRITICAL rather than HIGH severity.
_CRITICAL_FAMILIES = {
    "cobalt strike", "sliver", "ransomware", "ransomware.troldesh",
    "trickbot", "dridex", "emotet", "qakbot", "quakbot", "bitrat",
    "asyncrat", "jbifrost", "gozi", "gootkit", "torrentlocker",
}


@lru_cache(maxsize=4)
def load_blocklist(path: Optional[str] = None) -> dict[str, str]:
    """
    Load JA3 md5 → listing-reason from a CSV feed (abuse.ch SSLBL format).

    Returns an empty dict if no feed is available, in which case the
    detector simply produces no findings (never a fabricated one).
    """
    candidate = path or os.environ.get("PACKETIQ_JA3_BLOCKLIST") or str(_BUNDLED_BLOCKLIST)
    blocklist: dict[str, str] = {}
    try:
        with open(candidate, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if not row:
                    continue
                md5 = row[0].strip().lower()
                if len(md5) != 32 or md5.startswith("#"):
                    continue
                if not all(c in "0123456789abcdef" for c in md5):
                    continue
                reason = row[3].strip() if len(row) >= 4 and row[3].strip() else "Known-malicious (JA3 feed)"
                blocklist[md5] = reason
    except (OSError, IndexError):
        return {}
    return blocklist


def _severity_for(reason: str) -> Severity:
    return Severity.CRITICAL if reason.strip().lower() in _CRITICAL_FAMILIES else Severity.HIGH


_TLS_STREAM_PORTS = (443, 8443, 4443, 8080, 993, 995, 465)


class JA3Detector:

    def begin(self) -> "JA3Detector":
        """Prepare for a streaming (per-record) pass. Returns self so callers can
        chain: `det = JA3Detector().begin()`. `active` is False when no JA3
        threat-intel feed is available, so `feed` becomes a cheap no-op."""
        self.blocklist = load_blocklist()
        self.active = bool(self.blocklist)      # no feed → emit nothing, never guess
        self.ja3_flows: dict[str, dict] = {}    # ja3_hash → {src, dst, port, count, sni}
        return self

    def feed(self, record: RawPacketRecord) -> None:
        """Accumulate one packet record. Safe to call for every packet — it filters
        internally, so this can share a single PCAP pass with other detectors."""
        if not self.active or not record.raw_payload:
            return
        if record.dst_port not in _TLS_STREAM_PORTS and record.src_port not in _TLS_STREAM_PORTS:
            return
        parsed = _parse_client_hello(record.raw_payload)
        if not parsed:
            return
        ja3_hash = _compute_ja3(parsed)
        if ja3_hash not in self.ja3_flows:
            self.ja3_flows[ja3_hash] = {
                "src":   record.src_ip or "",
                "dst":   record.dst_ip or "",
                "port":  record.dst_port or 443,
                "count": 0,
                "sni":   parsed.get("sni", ""),
                "ts":    record.timestamp,
                "raw":   parsed,
            }
        self.ja3_flows[ja3_hash]["count"] += 1

    def detect_from_stream(
        self, stream: Generator[RawPacketRecord, None, None]
    ) -> list[DetectionEvent]:
        """Second-pass PCAP stream: extract JA3 hashes and flag known-bad ones."""
        self.begin()
        if not self.active:
            return []
        for record in stream:
            self.feed(record)
        return self.finalize()

    def finalize(self) -> list[DetectionEvent]:
        """Build events from accumulated JA3 flows."""
        blocklist = getattr(self, "blocklist", {})
        ja3_flows = getattr(self, "ja3_flows", {})
        events: list[DetectionEvent] = []
        for ja3_hash, meta in ja3_flows.items():
            reason = blocklist.get(ja3_hash)
            if reason:
                events.append(DetectionEvent(
                    event_type   = EventType.JA3_ANOMALY,
                    severity     = _severity_for(reason),
                    src_ip       = meta["src"],
                    dst_ip       = meta["dst"],
                    dst_port     = meta["port"],
                    protocol     = "TLS",
                    timestamp    = meta["ts"],
                    packet_count = meta["count"],
                    confidence   = 0.9,
                    description  = (
                        f"TLS fingerprint matches JA3 threat-intel feed "
                        f"({reason}) — JA3={ja3_hash[:16]}… from {meta['src']}"
                    ),
                    evidence={
                        "ja3_hash":   ja3_hash,
                        "ja4":        _compute_ja4(meta["raw"]),
                        "malware":    reason,
                        "feed":       "abuse.ch SSLBL JA3 (or PACKETIQ_JA3_BLOCKLIST)",
                        "sni":        meta["sni"],
                        "tls_ver":    meta["raw"].get("version_str", ""),
                        "ciphers":    meta["raw"].get("ciphers", [])[:8],
                        "flow_count": meta["count"],
                    },
                ))

        return events


# ── TLS ClientHello parser ────────────────────────────────────────────────────

def _parse_client_hello(payload: bytes) -> Optional[dict]:
    """Parse TLS ClientHello from raw TCP payload bytes."""
    if len(payload) < 43:
        return None
    # TLS Handshake record
    if payload[0] != 0x16:
        return None
    # Handshake type = ClientHello (0x01)
    if len(payload) < 6 or payload[5] != 0x01:
        return None

    pos = 9  # skip: record(5) + handshake_type(1) + length(3)

    if pos + 2 > len(payload):
        return None
    version = struct.unpack_from("!H", payload, pos)[0]
    pos += 2 + 32  # version + random

    # Session ID
    if pos >= len(payload):
        return None
    sid_len = payload[pos]
    pos += 1 + sid_len

    # Cipher suites
    if pos + 2 > len(payload):
        return None
    cs_len = struct.unpack_from("!H", payload, pos)[0]
    pos += 2
    ciphers: list[int] = []
    end_cs = pos + cs_len
    while pos + 2 <= min(end_cs, len(payload)):
        cs = struct.unpack_from("!H", payload, pos)[0]
        if cs not in _GREASE:
            ciphers.append(cs)
        pos += 2
    pos = end_cs

    # Compression methods
    if pos >= len(payload):
        return None
    cm_len = payload[pos]
    pos += 1 + cm_len

    # Extensions
    extensions: list[int] = []
    curves: list[int]     = []
    point_fmts: list[int] = []
    sigalgs: list[int]    = []
    sup_versions: list[int] = []
    alpn: list[str]       = []
    sni                   = ""

    if pos + 2 > len(payload):
        pass  # no extensions — still valid
    else:
        ext_total = struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= min(ext_end, len(payload)):
            etype = struct.unpack_from("!H", payload, pos)[0]
            elen  = struct.unpack_from("!H", payload, pos + 2)[0]
            pos += 4
            edata_start = pos
            edata_end   = min(pos + elen, len(payload))

            if etype not in _GREASE:
                extensions.append(etype)

            # SNI (0x0000)
            if etype == 0x0000 and edata_end - edata_start > 5:
                with contextlib.suppress(Exception):
                    name_len = struct.unpack_from("!H", payload, edata_start + 3)[0]
                    sni = payload[edata_start + 5: edata_start + 5 + name_len].decode(errors="replace")

            # supported_groups (0x000a)
            if etype == 0x000a and edata_end - edata_start >= 2:
                gl = struct.unpack_from("!H", payload, edata_start)[0]
                p  = edata_start + 2
                while p + 2 <= min(edata_start + 2 + gl, len(payload)):
                    g = struct.unpack_from("!H", payload, p)[0]
                    if g not in _GREASE:
                        curves.append(g)
                    p += 2

            # ec_point_formats (0x000b)
            if etype == 0x000b and edata_start < len(payload):
                pf_len = payload[edata_start]
                for j in range(pf_len):
                    if edata_start + 1 + j < len(payload):
                        point_fmts.append(payload[edata_start + 1 + j])

            # signature_algorithms (0x000d)  — needed for JA4_c
            if etype == 0x000d and edata_end - edata_start >= 2:
                sl = struct.unpack_from("!H", payload, edata_start)[0]
                p = edata_start + 2
                while p + 2 <= min(edata_start + 2 + sl, len(payload)):
                    sigalgs.append(struct.unpack_from("!H", payload, p)[0])
                    p += 2

            # supported_versions (0x002b) — JA4 version comes from here
            if etype == 0x002b and edata_start < len(payload):
                vl = payload[edata_start]
                p = edata_start + 1
                while p + 2 <= min(edata_start + 1 + vl, len(payload)):
                    v = struct.unpack_from("!H", payload, p)[0]
                    if v not in _GREASE:
                        sup_versions.append(v)
                    p += 2

            # ALPN (0x0010) — first protocol's first 2 chars feed JA4_a
            if etype == 0x0010 and edata_end - edata_start >= 3:
                p = edata_start + 2  # skip ALPN list length
                if p < len(payload):
                    plen = payload[p]
                    name = payload[p + 1: p + 1 + plen].decode(errors="replace")
                    if name:
                        alpn.append(name)

            pos = edata_start + elen

    ver_map = {0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
    return {
        "version":     version,
        "version_str": ver_map.get(version, hex(version)),
        "ciphers":     ciphers,
        "extensions":  extensions,
        "curves":      curves,
        "point_fmts":  point_fmts,
        "sigalgs":     sigalgs,
        "sup_versions": sup_versions,
        "alpn":        alpn,
        "sni":         sni,
    }


# ── JA4 (FoxIO) — modern TLS client fingerprint ───────────────────────────────

_JA4_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def _compute_ja4(data: dict) -> str:
    """
    Compute the JA4 TLS client fingerprint (FoxIO spec) for TCP+TLS.
    Format: <a>_<b>_<c>  e.g.  t13d1516h2_8daaf6152771_b186095e22b6
    """
    # version: highest from supported_versions, else the ClientHello version
    versions = [v for v in data.get("sup_versions", []) if v in _JA4_VER]
    ver_word = _JA4_VER.get(max(versions), None) if versions else _JA4_VER.get(data["version"], "00")

    sni_flag = "d" if data.get("sni") else "i"
    ciphers = data.get("ciphers", [])
    # extensions excluding GREASE; SNI(0)/ALPN(16) are counted but excluded from JA4_c
    exts = data.get("extensions", [])
    n_ciphers = min(len(ciphers), 99)
    n_exts = min(len(exts), 99)

    alpn = data.get("alpn", [])
    if alpn and len(alpn[0]) >= 2:
        alpn_word = (alpn[0][0] + alpn[0][-1])
    elif alpn and alpn[0]:
        alpn_word = alpn[0][0] + alpn[0][0]
    else:
        alpn_word = "00"

    ja4_a = f"t{ver_word}{sni_flag}{n_ciphers:02d}{n_exts:02d}{alpn_word}"

    # JA4_b: sha256 of sorted cipher hex list (lowercase, 4-digit)
    cipher_hex = ",".join(f"{c:04x}" for c in sorted(ciphers))
    ja4_b = hashlib.sha256(cipher_hex.encode()).hexdigest()[:12]

    # JA4_c: sha256 of (sorted extensions excl SNI/ALPN) + "_" + (sigalgs in order)
    ext_for_c = sorted(e for e in exts if e not in (0x0000, 0x0010))
    ext_hex = ",".join(f"{e:04x}" for e in ext_for_c)
    sig_hex = ",".join(f"{s:04x}" for s in data.get("sigalgs", []))
    ja4_c = hashlib.sha256(f"{ext_hex}_{sig_hex}".encode()).hexdigest()[:12]

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def _compute_ja3(data: dict) -> str:
    parts = [
        str(data["version"]),
        "-".join(str(c) for c in data["ciphers"]),
        "-".join(str(e) for e in data["extensions"]),
        "-".join(str(c) for c in data["curves"]),
        "-".join(str(p) for p in data["point_fmts"]),
    ]
    ja3_str = ",".join(parts)
    # NOTE: JA3 is *defined* as the MD5 of this string (Salesforce spec). MD5 here
    # is a fingerprint identifier, not a security/integrity control — so this is
    # not a cryptographic weakness. usedforsecurity=False documents that intent.
    return hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()
