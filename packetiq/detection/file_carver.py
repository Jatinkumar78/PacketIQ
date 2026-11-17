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

from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.utils.helpers import is_private_ip

_HTTP_PORTS = {80, 8080, 8000, 8888}
_FTP_DATA_PORTS = {20}
_MAX_STREAM_BYTES = 8 * 1024 * 1024     # cap reassembly per flow (8 MB)
# Distinct flows tracked at once. Each accumulator already caps the bytes it
# reassembles *per flow*, but nothing capped the number of flows, and the
# per-flow bookkeeping is the amplifier: measured at 740 bytes per flow with
# minimal payloads, so a ~100 MB capture of a million tiny packets on these
# ports cost ~705 MB before any payload was stored. Capping the flow count
# bounds that; new flows past the cap are ignored and counted in
# `skipped_flows`, flows already being reassembled are unaffected.
#
# Set high enough that reaching it is already an extraordinary capture, so this
# is a backstop against exhaustion rather than a routine truncation.
_MAX_FLOWS = 200_000
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
        self.skipped_flows = 0

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
        if key not in self.segments and len(self.segments) >= _MAX_FLOWS:
            self.skipped_flows += 1
            return
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
    """Order TCP segments by sequence number and concatenate (best-effort).

    Sequence numbers are compared as 32-bit serial numbers (RFC 1982), not as
    plain integers. A TCP initial sequence number is random, so a stream whose
    ISN sits near 2**32 wraps through zero within a few kilobytes — well inside
    the 8 MB this carver collects. Sorting the raw values then placed the
    wrapped tail of the file first: the reassembled bytes came out scrambled, so
    the magic was no longer at offset 0, `_identify` returned None, and the
    download was never hashed, reputation-checked or YARA-scanned. A server
    picks its own ISN, so that was an evasion rather than a rare mis-assembly —
    a cleartext PE/EXE transfer went from detected to invisible purely by
    choosing where the sequence space wrapped.

    Offsets are signed distances from the first segment *as captured*, which
    also keeps a late-arriving earlier segment ahead of its successors instead
    of 4 GB behind them.
    """
    base = segs[0][0] if segs else 0

    def _offset(seq: int) -> int:
        return ((seq - base + 2 ** 31) % 2 ** 32) - 2 ** 31

    ordered = sorted(((_offset(seq), payload) for seq, payload in segs),
                     key=lambda s: s[0])
    out = bytearray()
    last_end = None
    for start, payload in ordered:
        if last_end is None:
            out += payload
            last_end = start + len(payload)
            continue
        if start == last_end:
            out += payload
            last_end = start + len(payload)
        elif start > last_end:
            out += payload          # gap (missing segment) — append anyway
            last_end = start + len(payload)
        else:
            # overlap / retransmit: append only the new tail
            overlap = last_end - start
            if overlap < len(payload):
                out += payload[overlap:]
                last_end = start + len(payload)
    return bytes(out)


def _http_body(stream: bytes) -> bytes | None:
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
