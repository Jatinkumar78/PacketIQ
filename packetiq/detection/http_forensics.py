"""
HTTP deep inspection — the request and response, read in full.

The flow-level HTTP detector (`http_inspect.py`) sees a request line and a few
headers, which is enough to spot an attack in a URL but not enough to answer what
a SOC actually asks: what was POSTed, which credentials crossed the wire, what
session cookie leaked, what a custom header carried, what file was uploaded, and
what a gzip'd response body was hiding. Those live in the full HTTP payload, so
this reassembles the TCP stream and parses the messages whole.

It recovers, from the reassembled client and server streams:

  * **POST parameters** (urlencoded form bodies), with the username/password pair
    pulled out as a cleartext credential when both are present.
  * **HTTP Basic / Bearer authentication** decoded from the `Authorization`
    header, which is cleartext even when the body is not.
  * **Cookies**, with the session-bearing ones (session id, auth, token, jwt)
    called out as the thing an attacker would replay.
  * **Custom `X-*` headers**, which carry API keys, internal routing and CSRF
    tokens, and the **User-Agent**.
  * **multipart/form-data uploads**, by field name and filename.
  * **Decompressed response bodies**: gzip and deflate are decompressed before
    the body is scanned, so a flag or secret stuffed into a compressed response
    is recovered rather than skipped as binary.

Every reassembled body is run through the shared artifact decoder, so an encoded
or compressed payload anywhere in the exchange is decoded the same way it is in
any other stream. All of it is emitted as structured evidence for the copilot.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import re
import urllib.parse
import zlib
from collections import defaultdict
from dataclasses import dataclass, field

from packetiq.detection.models import DetectionEvent, EventType, Severity

_HTTP_PORTS = frozenset({80, 8080, 8000, 8888, 8081, 3000, 5000})
_MAX_STREAM_BYTES = 2 * 1024 * 1024
_MAX_FLOWS = 50_000
_MAX_MESSAGES = 64        # HTTP messages parsed per reassembled stream
_MAX_BODY = 512 * 1024    # per-body cap before decode/scan

MITRE_CLEARTEXT_CRED = "T1552.001"
MITRE_WEB = "T1071.001"

_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT")
_USER_KEYS = re.compile(r"^(?:user(?:name)?|login|email|e-mail|uid|acct|account)$", re.I)
_PASS_KEYS = re.compile(r"^(?:pass(?:word|wd)?|pwd|secret|passcode)$", re.I)
_SESSION_COOKIE = re.compile(r"(?:session|sess|sid|auth|token|jwt|csrf|remember|login)", re.I)
_FILENAME_RE = re.compile(rb'filename\*?="?([^"\r\n;]+)"?', re.I)
_FIELDNAME_RE = re.compile(rb'name\*?="?([^"\r\n;]+)"?', re.I)


# ── HTTP message parsing ──────────────────────────────────────────────────────

def _iter_messages(stream: bytes):
    """Yield (start_line, headers, body) for each HTTP message in a stream.

    Pragmatic rather than a full HTTP/1.1 parser: it reads a header block up to
    the blank line and then the Content-Length body, which covers the request
    and response forms a forensic reader needs. A chunked body (no
    Content-Length) yields an empty body, which is honest about what was cheaply
    recoverable rather than mis-parsing it.
    """
    pos = 0
    for _ in range(_MAX_MESSAGES):
        sep = stream.find(b"\r\n\r\n", pos)
        if sep == -1:
            return
        head = stream[pos:sep]
        lines = head.split(b"\r\n")
        start_line = lines[0]
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            if b":" in line:
                key, _, value = line.partition(b":")
                headers[key.strip().lower()] = value.strip()
        body_start = sep + 4
        try:
            clen = min(int(headers.get(b"content-length", b"0")), _MAX_BODY)
        except ValueError:
            clen = 0
        body = stream[body_start:body_start + clen]
        yield start_line, headers, body
        pos = body_start + clen


def _decompress(body: bytes, encoding: bytes) -> bytes:
    """gzip / deflate decompression, with a raw-deflate fallback. A body that is
    not actually valid compressed data comes back empty, never raising."""
    enc = encoding.lower()
    try:
        if b"gzip" in enc:
            return gzip.decompress(body)
        if b"deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError):
        return b""
    return b""


def _post_params(body: bytes, content_type: bytes) -> list[tuple[str, str]]:
    """urlencoded POST parameters as (name, value) pairs."""
    if b"application/x-www-form-urlencoded" not in content_type.lower():
        return []
    text = body.decode("utf-8", "replace")
    return urllib.parse.parse_qsl(text, keep_blank_values=True)


def _multipart_uploads(body: bytes, content_type: bytes) -> list[dict]:
    """Field names and filenames from a multipart/form-data body."""
    low = content_type.lower()
    if b"multipart/form-data" not in low:
        return []
    out: list[dict] = []
    for part in body.split(b"\r\nContent-Disposition:"):
        fn = _FILENAME_RE.search(part)
        if not fn:
            continue
        field_m = _FIELDNAME_RE.search(part)
        out.append({
            "filename": fn.group(1).decode("utf-8", "replace"),
            "field": field_m.group(1).decode("utf-8", "replace") if field_m else "",
        })
    return out


def _basic_auth(headers: dict[bytes, bytes]) -> tuple[str, str] | None:
    """Decode an HTTP Basic Authorization header into (user, password)."""
    auth = headers.get(b"authorization", b"")
    if not auth.lower().startswith(b"basic "):
        return None
    try:
        raw = base64.b64decode(auth.split(b" ", 1)[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    user, _, password = raw.decode("utf-8", "replace").partition(":")
    return user, password


def _bearer_token(headers: dict[bytes, bytes]) -> str:
    auth = headers.get(b"authorization", b"")
    if auth.lower().startswith(b"bearer "):
        return auth.split(b" ", 1)[1].decode("utf-8", "replace")
    return ""


def _cookies(headers: dict[bytes, bytes]) -> list[tuple[str, str]]:
    raw = headers.get(b"cookie", b"")
    out: list[tuple[str, str]] = []
    for pair in raw.split(b";"):
        if b"=" in pair:
            name, _, value = pair.partition(b"=")
            out.append((name.strip().decode("utf-8", "replace"),
                        value.strip().decode("utf-8", "replace")))
    return out


def _custom_headers(headers: dict[bytes, bytes]) -> dict[str, str]:
    return {k.decode("ascii", "replace"): v.decode("utf-8", "replace")
            for k, v in headers.items() if k.startswith(b"x-")}


# ── the accumulator ───────────────────────────────────────────────────────────

@dataclass
class _Txn:
    host: str = ""
    method: str = ""
    path: str = ""
    params: list = field(default_factory=list)
    cookies: list = field(default_factory=list)
    custom_headers: dict = field(default_factory=dict)
    user_agent: str = ""
    uploads: list = field(default_factory=list)


class HTTPForensicsAccumulator:
    """Reassembles HTTP streams and reads the requests and responses whole.

    `feed(pkt)` filters internally, so this shares the engine's one scapy pass.
    """

    def __init__(self) -> None:
        self.segments: dict[tuple, list[tuple[int, bytes]]] = defaultdict(list)
        self.sizes: dict[tuple, int] = defaultdict(int)
        self.credentials: list[dict] = []
        self.cookies: list[dict] = []
        self.custom_headers: dict[str, str] = {}
        self.posts: list[dict] = []
        self.uploads: list[dict] = []
        self.decompressed: list[dict] = []
        self.artifacts: dict = {"flags": [], "secrets": [], "decoded": []}
        self.transactions = 0
        self.skipped = 0

    def feed(self, pkt) -> None:
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return
        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return
        tcp = pkt[TCP]
        if tcp.sport not in _HTTP_PORTS and tcp.dport not in _HTTP_PORTS:
            return
        payload = bytes(tcp.payload)
        if not payload:
            return
        key = (src, int(tcp.sport), dst, int(tcp.dport))
        if key not in self.segments and len(self.segments) >= _MAX_FLOWS:
            self.skipped += 1
            return
        if self.sizes[key] >= _MAX_STREAM_BYTES:
            return
        self.segments[key].append((int(tcp.seq), payload))
        self.sizes[key] += len(payload)

    def finalize(self) -> list[DetectionEvent]:
        for key, segs in self.segments.items():
            stream = _reassemble(segs)
            src, _sport, dst, dport = key
            if dport in _HTTP_PORTS:
                self._read_requests(stream, client=src, server=dst)
            else:
                self._read_responses(stream, server=src, client=dst)
        return self._events()

    def _read_requests(self, stream: bytes, client: str, server: str) -> None:
        for start_line, headers, body in _iter_messages(stream):
            parts = start_line.split(b" ")
            if len(parts) < 2 or parts[0] not in _METHODS:
                continue
            self.transactions += 1
            method = parts[0].decode("ascii", "replace")
            path = parts[1].decode("utf-8", "replace")
            host = headers.get(b"host", b"").decode("utf-8", "replace") or server
            ctype = headers.get(b"content-type", b"")

            self._note_cookies(host, headers)
            self.custom_headers.update(_custom_headers(headers))
            self._note_auth(host, headers)

            params = _post_params(body, ctype)
            if params:
                self.posts.append({"host": host, "path": path,
                                   "params": {k: v for k, v in params}})
                self._note_post_credentials(host, params)
            for up in _multipart_uploads(body, ctype):
                self.uploads.append({"host": host, **up})
            if body:
                self._hunt_body(body, host, "request body")

    def _read_responses(self, stream: bytes, server: str, client: str) -> None:
        for start_line, headers, body in _iter_messages(stream):
            if not start_line.startswith(b"HTTP/"):
                continue
            if not body:
                continue
            encoding = headers.get(b"content-encoding", b"")
            if encoding:
                decoded = _decompress(body, encoding)
                if decoded:
                    self.decompressed.append({
                        "server": server,
                        "encoding": encoding.decode("ascii", "replace"),
                        "bytes": len(decoded),
                    })
                    self._hunt_body(decoded, server, f"{encoding.decode('ascii','replace')} response body")
            else:
                self._hunt_body(body, server, "response body")

    # ── enrichment helpers ────────────────────────────────────────────────────

    def _note_cookies(self, host: str, headers: dict) -> None:
        for name, value in _cookies(headers):
            self.cookies.append({"host": host, "name": name, "value": value,
                                 "session": bool(_SESSION_COOKIE.search(name))})

    def _note_auth(self, host: str, headers: dict) -> None:
        basic = _basic_auth(headers)
        if basic:
            self.credentials.append({"host": host, "username": basic[0],
                                     "password": basic[1], "via": "HTTP Basic auth"})
        token = _bearer_token(headers)
        if token:
            self.credentials.append({"host": host, "username": "", "password": token,
                                     "via": "HTTP Bearer token"})

    def _note_post_credentials(self, host: str, params: list) -> None:
        fields = {k: v for k, v in params}
        user = next((v for k, v in fields.items() if _USER_KEYS.match(k)), "")
        password = next((v for k, v in fields.items() if _PASS_KEYS.match(k)), "")
        if user and password:
            self.credentials.append({"host": host, "username": user,
                                     "password": password, "via": "HTTP POST form"})

    def _hunt_body(self, body: bytes, host: str, where: str) -> None:
        from packetiq.detection import artifact_hunter

        hunt = artifact_hunter.inspect_blob(body[:_MAX_BODY])
        for f in hunt["flags"]:
            if f["value"] not in {x["value"] for x in self.artifacts["flags"]}:
                self.artifacts["flags"].append({**f, "host": host, "where": where})
        for s in hunt["secrets"]:
            ident = (s["kind"], s["value"])
            if ident not in {(x["kind"], x["value"]) for x in self.artifacts["secrets"]}:
                self.artifacts["secrets"].append({**s, "host": host, "where": where})
        for d in hunt["decoded"]:
            if not d["yielded"]:
                self.artifacts["decoded"].append({**d, "host": host, "where": where})

    # ── reporting ─────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        if not (self.credentials or self.cookies or self.custom_headers
                or self.posts or self.uploads or self.decompressed
                or self.artifacts["flags"] or self.artifacts["secrets"]):
            return {}
        session_cookies = [c for c in self.cookies if c["session"]]
        return {
            "transactions": self.transactions,
            "credentials": _dedupe(self.credentials, ("host", "username", "password")),
            "session_cookies": [{"host": c["host"], "name": c["name"], "value": c["value"]}
                                for c in session_cookies],
            "cookie_count": len(self.cookies),
            "custom_headers": self.custom_headers,
            "posts": self.posts,
            "uploads": self.uploads,
            "decompressed": self.decompressed,
            "flags": [{"value": f["value"]} for f in self.artifacts["flags"]],
            "secrets": [{"kind": s["kind"], "value": s["value"], "detail": s["detail"]}
                        for s in self.artifacts["secrets"]],
        }

    def _events(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        for cred in _dedupe(self.credentials, ("host", "username", "password")):
            who = cred["username"] or "(token)"
            events.append(DetectionEvent(
                event_type=EventType.CREDENTIAL_EXPOSURE,
                severity=Severity.CRITICAL,
                src_ip=cred["host"], dst_ip=None, dst_port=80, protocol="HTTP",
                timestamp=0.0, packet_count=1, confidence=1.0,
                description=f"HTTP credential in cleartext ({cred['via']}) — {who} / {cred['password']}",
                evidence={
                    "username": cred["username"],
                    "password": cred["password"],
                    "via": cred["via"],
                    "host": cred["host"],
                    "mitre": MITRE_CLEARTEXT_CRED,
                    "note": "Sent over unencrypted HTTP and read directly off the wire; "
                            "rotate the credential and move the endpoint to HTTPS.",
                },
            ))
        for up in self.uploads:
            events.append(DetectionEvent(
                event_type=EventType.SUSPICIOUS_FILE_TRANSFER,
                severity=Severity.HIGH,
                src_ip="", dst_ip=up["host"], dst_port=80, protocol="HTTP",
                timestamp=0.0, packet_count=1, confidence=0.85,
                description=f"HTTP multipart upload to {up['host']}: {up['filename']}",
                evidence={"filename": up["filename"], "field": up["field"],
                          "host": up["host"], "mitre": "T1105",
                          "note": "A file uploaded over HTTP; retrieve and hash it."},
            ))
        for f in self.artifacts["flags"]:
            events.append(DetectionEvent(
                event_type=EventType.EXTRACTED_SECRET,
                severity=Severity.CRITICAL,
                src_ip=f["host"], dst_ip=None, dst_port=80, protocol="HTTP",
                timestamp=0.0, packet_count=1, confidence=1.0,
                description=f"CTF flag recovered from an HTTP {f['where']}: {f['value']}",
                evidence={"value": f["value"], "where": f["where"], "mitre": "T1140",
                          "note": "Read from the HTTP body, after any decompression shown."},
            ))
        for s in self.artifacts["secrets"]:
            events.append(DetectionEvent(
                event_type=EventType.EXTRACTED_SECRET,
                severity=Severity.HIGH,
                src_ip=s["host"], dst_ip=None, dst_port=80, protocol="HTTP",
                timestamp=0.0, packet_count=1, confidence=0.95,
                description=f"{s['detail']} recovered from an HTTP {s['where']}: {s['value']}",
                evidence={"kind": s["kind"], "value": s["value"], "where": s["where"],
                          "mitre": MITRE_CLEARTEXT_CRED,
                          "note": "Carried in an HTTP body; treat as compromised."},
            ))
        for d in self.artifacts["decoded"]:
            events.append(DetectionEvent(
                event_type=EventType.ENCODED_PAYLOAD,
                severity=Severity.HIGH,
                src_ip=d["host"], dst_ip=None, dst_port=80, protocol="HTTP",
                timestamp=0.0, packet_count=1, confidence=0.85,
                description=f"Obfuscated payload in an HTTP {d['where']} ({d['chain']}): {d['preview']}",
                evidence={"transform_chain": d["chain"], "decoded_preview": d["preview"],
                          "where": d["where"], "mitre": "T1140 / T1132",
                          "note": "Decoded from an HTTP body."},
            ))
        return events


# ── module helpers ────────────────────────────────────────────────────────────

def _reassemble(segs: list[tuple[int, bytes]]) -> bytes:
    seen: set[int] = set()
    out = bytearray()
    for seq, payload in sorted(segs, key=lambda sp: sp[0]):
        if seq in seen:
            continue
        seen.add(seq)
        out += payload
    return bytes(out)


def _dedupe(rows: list[dict], keys: tuple) -> list[dict]:
    seen: set = set()
    out: list[dict] = []
    for row in rows:
        ident = tuple(row.get(k) for k in keys)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(row)
    return out


def _endpoints(pkt) -> tuple[str | None, str | None]:
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    return None, None
