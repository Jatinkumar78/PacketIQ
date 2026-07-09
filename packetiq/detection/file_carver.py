"""
File carving + hash reputation.

Reassembles TCP streams (ordering segments by sequence number), carves files
transferred over HTTP and FTP-DATA, identifies them by magic bytes, SHA-256s
them, and checks the hash against the bundled MalwareBazaar feed.

Findings:
  - MALICIOUS_FILE (CRITICAL) — carved file's SHA-256 is in the malware feed
  - MALICIOUS_FILE (MEDIUM)   — executable (PE/ELF/Mach-O) transferred over
                                cleartext HTTP (worth reviewing; hash provided)

Runs as its own PCAP pass reading full payloads (the main parser keeps only the
first bytes of each packet, which is too little for multi-KB files).
"""

import hashlib
from collections import defaultdict
from typing import Optional

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.utils.helpers import is_private_ip

_HTTP_PORTS = {80, 8080, 8000, 8888}
_FTP_DATA_PORTS = {20}
_MAX_STREAM_BYTES = 8 * 1024 * 1024     # cap reassembly per flow (8 MB)
_MIN_FILE_BYTES = 64

# magic bytes -> (file type, is_executable)
_MAGIC = [
    (b"MZ",            "PE/EXE (Windows)", True),
    (b"\x7fELF",       "ELF (Linux)",      True),
    (b"\xfe\xed\xfa",  "Mach-O (macOS)",   True),
    (b"\xcf\xfa\xed\xfe", "Mach-O (macOS)", True),
    (b"%PDF",          "PDF",              False),
    (b"PK\x03\x04",    "ZIP/Office/JAR",   False),
    (b"Rar!\x1a\x07",  "RAR archive",      False),
    (b"\x1f\x8b",      "GZIP",             False),
    (b"\xd0\xcf\x11\xe0", "MS Office (OLE)", False),
    (b"\x4d\x5a",      "PE/EXE (Windows)", True),
]


class FileCarverAccumulator:
    """Collects server→client TCP segments over a single PCAP pass, then reassembles
    and carves files in finalize(). `feed(pkt)` filters internally, so this can share
    one PcapReader loop with other packet-level detectors."""

    def __init__(self) -> None:
        # flow direction key (src, sport, dst, dport) -> list[(seq, payload)]
        self.segments: dict[tuple, list] = defaultdict(list)
        self.sizes: dict[tuple, int] = defaultdict(int)
        self.meta: dict[tuple, dict] = {}

    def feed(self, pkt) -> None:
        if not pkt.haslayer(TCP):
            return
        if pkt.haslayer(IP):
            src, dst = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src, dst = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return
        tcp = pkt[TCP]
        # we want server->client (download) streams on file-bearing ports
        if tcp.sport not in (_HTTP_PORTS | _FTP_DATA_PORTS):
            return
        payload = bytes(tcp.payload)
        if not payload:
            return
        key = (src, tcp.sport, dst, tcp.dport)
        if self.sizes[key] >= _MAX_STREAM_BYTES:
            return
        self.segments[key].append((int(tcp.seq), payload))
        self.sizes[key] += len(payload)
        self.meta.setdefault(key, {"ts": float(pkt.time)})

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        seen_hashes: set = set()
        seen_yara: set = set()

        store = _load_store()
        from packetiq.detection import yara_scan
        yara_on = yara_scan.available()

        for key, segs in self.segments.items():
            stream = _reassemble(segs)
            if len(stream) < _MIN_FILE_BYTES:
                continue
            src, sport, dst, dport = key

            # ── YARA over the reassembled stream (first 512 KB) ─────────────
            if yara_on:
                for hit in yara_scan.scan_bytes(stream[:512 * 1024]):
                    k = (src, dst, hit["rule"])
                    if k in seen_yara:
                        continue
                    seen_yara.add(k)
                    try:
                        sev = Severity[hit["severity"]]
                    except KeyError:
                        sev = Severity.HIGH
                    events.append(_event(
                        sev, dst, src, sport,
                        f"YARA rule '{hit['rule']}' matched traffic from {src} — {hit['description']}",
                        {"yara_rule": hit["rule"], "description": hit["description"],
                         "tags": hit["tags"], "server": src},
                        self.meta.get(key, {}).get("ts", 0.0),
                    ))

            is_http = sport in _HTTP_PORTS
            body = _http_body(stream) if is_http else stream
            if not body or len(body) < _MIN_FILE_BYTES:
                continue

            ftype, is_exe = _identify(body)
            if ftype is None:
                continue

            sha = hashlib.sha256(body).hexdigest()
            if sha in seen_hashes:
                continue
            seen_hashes.add(sha)

            rep = store.lookup_hash(sha) if store else None
            client = dst   # server is src here (download direction)
            if rep:
                events.append(_event(
                    Severity.CRITICAL, client, src, sport,
                    f"Known-malicious file downloaded from {src} — {rep.label} "
                    f"({ftype}, {len(body):,} bytes)",
                    {"sha256": sha, "file_type": ftype, "size": len(body),
                     "source": rep.source, "label": rep.label, "server": src},
                    self.meta.get(key, {}).get("ts", 0.0),
                ))
            elif is_exe and not is_private_ip(src):
                events.append(_event(
                    Severity.MEDIUM, client, src, sport,
                    f"Executable file transfer over cleartext from {src} "
                    f"({ftype}, {len(body):,} bytes) — review SHA-256",
                    {"sha256": sha, "file_type": ftype, "size": len(body), "server": src},
                    self.meta.get(key, {}).get("ts", 0.0),
                ))

        return events


def analyze(pcap_path: str) -> list[DetectionEvent]:
    acc = FileCarverAccumulator()
    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                acc.feed(pkt)
    except Exception:
        return []
    return acc.finalize()


def _load_store():
    try:
        from packetiq.enrichment.feeds import load_store
        return load_store()
    except Exception:
        return None


def _reassemble(segs: list) -> bytes:
    """Order TCP segments by sequence number and concatenate (best-effort)."""
    segs.sort(key=lambda s: s[0])
    out = bytearray()
    last_seq = None
    for seq, payload in segs:
        if last_seq is None:
            out += payload
            last_seq = seq + len(payload)
            continue
        if seq == last_seq:
            out += payload
            last_seq = seq + len(payload)
        elif seq > last_seq:
            out += payload          # gap (missing segment) — append anyway
            last_seq = seq + len(payload)
        else:
            # overlap / retransmit: append only the new tail
            overlap = last_seq - seq
            if overlap < len(payload):
                out += payload[overlap:]
                last_seq = seq + len(payload)
    return bytes(out)


def _http_body(stream: bytes) -> Optional[bytes]:
    """Return the body of the first HTTP response in the stream."""
    if not stream.startswith(b"HTTP/"):
        return None
    sep = stream.find(b"\r\n\r\n")
    if sep == -1:
        return None
    headers = stream[:sep].lower()
    body = stream[sep + 4:]
    # honor Content-Length if present
    idx = headers.find(b"content-length:")
    if idx != -1:
        try:
            clen = int(headers[idx + 15:].split(b"\r\n", 1)[0].strip())
            body = body[:clen]
        except (ValueError, IndexError):
            pass
    return body


def _identify(body: bytes):
    for magic, ftype, is_exe in _MAGIC:
        if body.startswith(magic):
            return ftype, is_exe
    return None, False


def _event(sev, src_ip, dst_ip, dport, desc, evidence, ts) -> DetectionEvent:
    return DetectionEvent(
        event_type   = EventType.MALICIOUS_FILE,
        severity     = sev,
        src_ip       = src_ip,
        dst_ip       = dst_ip,
        dst_port     = dport,
        protocol     = "HTTP",
        timestamp    = ts,
        packet_count = 1,
        confidence   = 0.95 if sev == Severity.CRITICAL else 0.6,
        description  = desc,
        evidence     = evidence,
    )
