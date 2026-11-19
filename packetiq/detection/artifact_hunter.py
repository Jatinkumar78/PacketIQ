"""
Deep artifact hunter — reading what a payload tried not to be read.

Why this module exists
----------------------
A great many captures, and almost every CTF, hide the one thing that matters
under a layer of encoding: a flag base64'd into a comment, a C2 command gzip'd
and then base64'd again, a reverse-shell one-liner XOR'd with a single byte so a
naive grep slides past it. A tool that reassembles the stream but reads only its
surface answers "there was some traffic" when the stream is holding the answer
one transform away.

This hunts the reassembled TCP/UDP streams for three things:

  * **Obfuscated payloads.** It peels encodings recursively, up to four layers:
    gzip and zlib, Base64, Base32, hex, URL-encoding and ROT13, in any order
    they were stacked. Each layer is only accepted when it unwraps to something
    that actually looks like content (a known file magic, a crib, or readable
    text), so a run of random text is not "decoded" into noise. The exact
    transform chain is recorded, because `base64 -> gzip -> rot13` is itself the
    finding.

  * **Single-byte XOR.** High-entropy payloads that are not valid text are run
    against every key from 0x01 to 0xFF, looking for a known-plaintext crib
    (`THM{`, `<?php`, `/dev/tcp/`, an HTTP verb, a PE header). This is how the
    cheap obfuscation that real droppers use gets undone.

  * **High-value secrets.** CTF flags (including reversed and hex-encoded), JWTs,
    PEM/OpenSSH private keys, AWS/Slack/Google API keys, PowerShell
    `-EncodedCommand` blobs and bash `/dev/tcp` reverse shells, pulled out of the
    cleartext stream and out of everything the two steps above decoded.

Everything surfaced here is emitted as a DetectionEvent, so the grounding filter
lets the copilot cite it: the value of a flag, the transform chain that revealed
a command, the fingerprint of a key. A private key is reported by its type and a
SHA-256 fingerprint rather than by reproducing the key body, the same way the
file carver reports a carved file: the indicator, not the payload.
"""

from __future__ import annotations

import base64
import codecs
import contextlib
import gzip
import hashlib
import math
import re
import urllib.parse
import zlib
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable

from packetiq.detection.models import DetectionEvent, EventType, Severity

# How much of a reassembled stream to reason over, and how many flows to track.
# Generous enough for a CTF capture or a dropped script, bounded so a bulk
# transfer or a flood of tiny flows cannot exhaust memory.
_MAX_STREAM_BYTES = 512 * 1024
_MAX_FLOWS = 50_000
_MIN_BYTES = 4

# Recursive decode depth, and the ceiling on XOR brute-forcing. 255 keys over a
# payload this size is cheap; the cap keeps it cheap on a pathological stream.
_MAX_PASSES = 4
_MAX_XOR_BYTES = 64 * 1024
_MIN_XOR_ENTROPY = 3.0
_MAX_BLOBS = 24

MITRE_DEOBFUSCATE = "T1140"      # Deobfuscate/Decode Files or Information
MITRE_DATA_ENCODING = "T1132"    # Data Encoding
MITRE_UNSECURED_CREDS = "T1552"  # Unsecured Credentials

# ── cribs and magics ──────────────────────────────────────────────────────────

# Lower-cased substrings that mark a byte string as meaningful content. Used both
# to accept a decode layer and as known plaintext for the XOR solver.
_CRIBS = (
    b"thm{", b"flag{", b"ctf{", b"http/", b"<?php", b"powershell",
    b"/dev/tcp/", b"-----begin", b"cmd.exe", b"/bin/sh", b"/bin/bash",
    b"this program", b"invoke-", b"function ",
)

# Byte prefixes that identify a decoded layer as a real file / compressed blob,
# so an intermediate layer (base64 -> gzip bytes) is accepted and unwrapped.
_MAGICS = (
    b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"\x78\xda",
    b"MZ", b"PK\x03\x04", b"\x7fELF", b"%PDF", b"\xff\xd8\xff", b"\x89PNG",
)

_PRINTABLE = set(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}

# ── low-level predicates ──────────────────────────────────────────────────────


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(b in _PRINTABLE for b in data) / len(data)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _has_crib(data: bytes) -> bool:
    low = data.lower()
    return any(c in low for c in _CRIBS)


def _looks_meaningful(data: bytes) -> bool:
    """True if `data` is worth keeping: a crib, a file magic, or readable text.

    This is the gate that stops the recursive decoder from "unlocking" random
    bytes into more random bytes. A layer is only accepted when what falls out
    of it is recognisably content.
    """
    if len(data) < 4:
        return False
    if _has_crib(data):
        return True
    if data.startswith(_MAGICS):
        return True
    return _printable_ratio(data) >= 0.85


# ── single-layer decoders ─────────────────────────────────────────────────────
#
# Each returns (name, decoded) when it both applies and unwraps to something
# meaningful, otherwise None. The driver tries them in order and takes the first.

_B64_RE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_B32_RE = re.compile(rb"[A-Z2-7]+={0,6}")
_HEX_RE = re.compile(rb"[0-9a-fA-F]+")


def _d_gzip(data: bytes) -> tuple[str, bytes] | None:
    if data[:2] != b"\x1f\x8b":
        return None
    try:
        return ("gzip", gzip.decompress(data))
    except (OSError, EOFError, zlib.error):
        return None


def _d_zlib(data: bytes) -> tuple[str, bytes] | None:
    if len(data) < 2 or data[0] != 0x78 or data[1] not in (0x01, 0x9c, 0xda):
        return None
    try:
        return ("zlib", zlib.decompress(data))
    except zlib.error:
        return None


def _d_base64(data: bytes) -> tuple[str, bytes] | None:
    s = data.strip()
    if len(s) < 16 or len(s) % 4 != 0 or not _B64_RE.fullmatch(s):
        return None
    out = base64.b64decode(s, validate=True)
    return ("base64", out) if _looks_meaningful(out) else None


def _d_base32(data: bytes) -> tuple[str, bytes] | None:
    s = data.strip().upper()
    if len(s) < 16 or len(s) % 8 != 0 or not _B32_RE.fullmatch(s):
        return None
    try:
        out = base64.b32decode(s)
    except ValueError:        # binascii.Error (a ValueError) on bad padding
        return None
    return ("base32", out) if _looks_meaningful(out) else None


def _d_hex(data: bytes) -> tuple[str, bytes] | None:
    s = data.strip()
    if len(s) < 16 or len(s) % 2 != 0 or not _HEX_RE.fullmatch(s):
        return None
    out = bytes.fromhex(s.decode("ascii"))
    return ("hex", out) if _looks_meaningful(out) else None


def _d_url(data: bytes) -> tuple[str, bytes] | None:
    if b"%" not in data:
        return None
    out = urllib.parse.unquote_to_bytes(data)
    if out == data or not _looks_meaningful(out):
        return None
    return ("url", out)


def _d_rot13(data: bytes) -> tuple[str, bytes] | None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    rot = codecs.encode(text, "rot13").encode("ascii")
    # Only accept ROT13 when it reveals a crib the original did not have —
    # otherwise rotating arbitrary text just yields more arbitrary text.
    if _has_crib(rot) and not _has_crib(data):
        return ("rot13", rot)
    return None


_DECODERS: tuple[Callable[[bytes], tuple[str, bytes] | None], ...] = (
    _d_gzip, _d_zlib, _d_base64, _d_base32, _d_hex, _d_url, _d_rot13,
)


def _decode_one(data: bytes) -> tuple[str, bytes] | None:
    for decoder in _DECODERS:
        result = decoder(data)
        if result is not None:
            return result
    return None


def decode_chain(blob: bytes, max_passes: int = _MAX_PASSES) -> tuple[list[str], bytes]:
    """Peel encodings recursively and return (transform chain, final bytes).

    Stops when no decoder applies, when a crib appears (the content is reached),
    or after `max_passes` layers.
    """
    chain: list[str] = []
    cur = blob
    for _ in range(max_passes):
        step = _decode_one(cur)
        if step is None:
            break
        name, cur = step
        chain.append(name)
        if _has_crib(cur):
            break
    return chain, cur


# ── XOR solver ────────────────────────────────────────────────────────────────


def xor_single_byte(data: bytes, cribs: Iterable[bytes] = _CRIBS) -> tuple[int, bytes] | None:
    """Brute-force single-byte XOR, returning (key, plaintext) on a crib hit."""
    crib_list = tuple(cribs)
    for key in range(1, 256):
        dec = bytes(b ^ key for b in data)
        low = dec.lower()
        if any(c in low for c in crib_list):
            return key, dec
    return None


# ── secret / flag extraction ──────────────────────────────────────────────────

_FLAG_RE = re.compile(rb"(?:THM|FLAG|CTF)\{[^}\r\n]{1,120}\}", re.IGNORECASE)
_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
_PEM_BEGIN_RE = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----")
_PEM_END_RE = re.compile(rb"-----END (?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----")
_AWS_RE = re.compile(rb"AKIA[0-9A-Z]{16}")
_SLACK_RE = re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}")
_GOOGLE_RE = re.compile(rb"AIza[0-9A-Za-z_\-]{35}")
_DEVTCP_RE = re.compile(
    rb"(?:bash|sh|nc|ncat)\b[^\r\n]{0,80}?/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}")
_PS_ENC_RE = re.compile(
    rb"(?:powershell|pwsh)(?:\.exe)?[^\r\n]{0,60}?-[eE](?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE)

_PEM_MAX = 8 * 1024


def find_flags(data: bytes) -> list[dict]:
    """CTF flags found forward, and reversed (a `}...{MHT` written backwards)."""
    found: list[dict] = []
    for m in _FLAG_RE.finditer(data):
        found.append({"value": m.group(0).decode("ascii", "replace"), "orientation": "forward"})
    for m in _FLAG_RE.finditer(data[::-1]):
        found.append({"value": m.group(0).decode("ascii", "replace"), "orientation": "reversed"})
    return found


def find_secrets(data: bytes) -> list[dict]:
    """High-value secrets carved from a (decoded) stream."""
    out: list[dict] = []

    for m in _JWT_RE.finditer(data):
        out.append({"kind": "jwt", "value": m.group(0).decode("ascii", "replace"),
                    "detail": "JSON Web Token on the wire"})

    begin = _PEM_BEGIN_RE.search(data)
    if begin:
        end = _PEM_END_RE.search(data, begin.end())
        block = data[begin.start():end.end()] if end else data[begin.start():begin.start() + _PEM_MAX]
        fingerprint = hashlib.sha256(block).hexdigest()[:32]
        out.append({"kind": "private_key",
                    "value": f"SHA-256:{fingerprint}",
                    "detail": begin.group(0).decode("ascii", "replace")})

    for m in _AWS_RE.finditer(data):
        out.append({"kind": "aws_access_key", "value": m.group(0).decode("ascii", "replace"),
                    "detail": "AWS access key id"})
    for m in _SLACK_RE.finditer(data):
        out.append({"kind": "slack_token", "value": m.group(0).decode("ascii", "replace"),
                    "detail": "Slack API token"})
    for m in _GOOGLE_RE.finditer(data):
        out.append({"kind": "google_api_key", "value": m.group(0).decode("ascii", "replace"),
                    "detail": "Google API key"})
    for m in _DEVTCP_RE.finditer(data):
        out.append({"kind": "reverse_shell", "value": m.group(0).decode("ascii", "replace").strip(),
                    "detail": "bash /dev/tcp reverse shell one-liner"})
    for m in _PS_ENC_RE.finditer(data):
        raw = _b64_relaxed(m.group(1))
        # PowerShell -EncodedCommand is UTF-16LE; fall back cleanly otherwise.
        cmd = raw.decode("utf-16-le", "replace").strip() or raw.decode("utf-8", "replace").strip()
        out.append({"kind": "powershell_encoded_command", "value": cmd[:300],
                    "detail": "decoded from PowerShell -EncodedCommand"})

    return out


_B64_CLEAN = re.compile(rb"[^A-Za-z0-9+/]")


def _b64_relaxed(s: bytes) -> bytes:
    """Decode base64 that may carry stray padding, truncating to a clean length.

    Stripping non-alphabet characters and cutting to a multiple of four means the
    decode is total: it never raises on odd padding, so the caller needs no guard.
    """
    s = _B64_CLEAN.sub(b"", s)
    return base64.b64decode(s[: len(s) - (len(s) % 4)])


# ── candidate blob extraction ─────────────────────────────────────────────────

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
_B32_RUN = re.compile(rb"[A-Z2-7]{16,}={0,6}")
_HEX_RUN = re.compile(rb"[0-9a-fA-F]{16,}")
_URLENC_RE = re.compile(rb"%[0-9A-Fa-f]{2}")


def _candidate_blobs(data: bytes) -> list[bytes]:
    """Runs of encoded characters worth attempting to decode, longest first.

    A raw compressed whole-stream (gzip/zlib on the wire) is included so it is
    unwrapped even though it is not a text run; so is a URL-encoded stream.
    """
    blobs: list[bytes] = []
    if data.startswith((b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"\x78\xda")):
        blobs.append(data)
    for rx in (_B64_RUN, _B32_RUN, _HEX_RUN):
        blobs.extend(m.group(0) for m in rx.finditer(data))
    if _URLENC_RE.search(data):
        blobs.append(data)
    uniq: list[bytes] = []
    seen: set[bytes] = set()
    for b in sorted(blobs, key=len, reverse=True):
        if b in seen:
            continue
        seen.add(b)
        uniq.append(b)
        if len(uniq) >= _MAX_BLOBS:
            break
    return uniq


# ── the reusable hunt over one reconstructed blob ─────────────────────────────


def inspect_blob(data: bytes) -> dict:
    """Hunt a single reconstructed blob for flags, secrets and encoded content.

    This is the stream hunt factored out so a caller that reassembled the bytes
    itself — a DNS exfil channel, an ICMP tunnel, an HTTP body — can run the same
    decode / XOR / flag-and-secret pipeline and get back the same structured facts
    (`{"flags": [...], "secrets": [...], "decoded": [...]}`), where each decoded
    entry carries its transform `chain`, a `preview`, and whether it `yielded` a
    flag or secret.
    """
    flags: list[dict] = list(find_flags(data))
    secrets: list[dict] = list(find_secrets(data))
    decoded: list[dict] = []

    for blob in _candidate_blobs(data):
        chain, out = decode_chain(blob)
        if not chain or out == blob:
            continue
        found_flags = find_flags(out)
        found_secrets = find_secrets(out)
        flags.extend(found_flags)
        secrets.extend(found_secrets)
        # Report a decoded payload only when it is genuinely readable (a command,
        # a config, a script) or a recognised file, AND it was reached through a
        # real decoding step. Two cases were pure noise on live traffic and are
        # now excluded: a URL-decode on its own (HTTP is already readable, not
        # obfuscated), and a decode that comes out mostly-binary with only a
        # stray crib in it (a TLS record, a compressed blob). A flag or secret
        # found inside any decode is still reported separately, above.
        readable = out.startswith(_MAGICS) or _printable_ratio(out) >= 0.85
        real_transform = any(t != "url" for t in chain)
        if readable and real_transform:
            decoded.append({"chain": " -> ".join(chain), "preview": _preview(out),
                            "yielded": bool(found_flags or found_secrets)})

    # Single-byte XOR over a high-entropy, non-text payload.
    if (len(data) <= _MAX_XOR_BYTES and _printable_ratio(data) < 0.85
            and _entropy(data) >= _MIN_XOR_ENTROPY):
        hit = xor_single_byte(data)
        if hit is not None:
            key_byte, plain = hit
            found_flags = find_flags(plain)
            found_secrets = find_secrets(plain)
            flags.extend(found_flags)
            secrets.extend(found_secrets)
            # A crib can surface under XOR inside otherwise-binary data; only
            # report the recovered payload when it is actually readable, so a
            # stray match in a TLS record or a ciphertext is not a finding.
            if plain.startswith(_MAGICS) or _printable_ratio(plain) >= 0.85:
                decoded.append({"chain": f"xor:0x{key_byte:02x}", "preview": _preview(plain),
                                "yielded": bool(found_flags or found_secrets)})

    return {"flags": flags, "secrets": secrets, "decoded": decoded}


# ── the accumulator ───────────────────────────────────────────────────────────


class ArtifactHunterAccumulator:
    """Reassembles TCP/UDP streams and hunts them for hidden artifacts.

    `feed(pkt)` filters internally so this shares the engine's one scapy pass.
    """

    def __init__(self) -> None:
        self.segments: dict[tuple, list[tuple[int, bytes]]] = defaultdict(list)
        self.sizes: dict[tuple, int] = defaultdict(int)
        self.channels: dict[tuple, str] = {}
        # ICMP echo data, keyed per direction (src, dst, id) and ordered by the
        # echo sequence number — this is how an ICMP tunnel (icmptunnel, ptunnel)
        # carries a payload, and reassembling it recovers what was smuggled.
        self.icmp: dict[tuple, list[tuple[int, bytes]]] = defaultdict(list)
        self.icmp_sizes: dict[tuple, int] = defaultdict(int)
        self.icmp_ends: dict[tuple, tuple[str, str]] = {}
        self.flags: list[dict] = []
        self.secrets: list[dict] = []
        self.decoded: list[dict] = []
        self.skipped = 0
        self._order = 0

    # ── collection ────────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.inet import ICMP, TCP, UDP

        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return
        if pkt.haslayer(ICMP):
            self._feed_icmp(pkt, src, dst)
            return
        if pkt.haslayer(TCP):
            layer = pkt[TCP]
            order = int(layer.seq)
            channel = "TCP"
        elif pkt.haslayer(UDP):
            layer = pkt[UDP]
            self._order += 1
            order = self._order
            channel = "UDP"
        else:
            return
        payload = bytes(layer.payload)
        if not payload:
            return
        key = (src, int(layer.sport), dst, int(layer.dport))
        if key not in self.segments and len(self.segments) >= _MAX_FLOWS:
            self.skipped += 1
            return
        if self.sizes[key] >= _MAX_STREAM_BYTES:
            return
        self.segments[key].append((order, payload))
        self.sizes[key] += len(payload)
        self.channels[key] = channel

    def _feed_icmp(self, pkt, src: str, dst: str) -> None:
        from scapy.layers.inet import ICMP

        icmp = pkt[ICMP]
        if int(icmp.type) not in (0, 8):   # echo reply / request only
            return
        payload = bytes(icmp.payload)
        if not payload:
            return
        key = (src, dst, int(icmp.id))
        if key not in self.icmp and len(self.icmp) >= _MAX_FLOWS:
            self.skipped += 1
            return
        if self.icmp_sizes[key] >= _MAX_STREAM_BYTES:
            return
        self.icmp[key].append((int(icmp.seq), payload))
        self.icmp_sizes[key] += len(payload)
        self.icmp_ends.setdefault(key, (src, dst))

    def _reassemble(self, segs: list[tuple[int, bytes]]) -> bytes:
        seen: set[int] = set()
        out = bytearray()
        for order, payload in sorted(segs, key=lambda sp: sp[0]):
            if order in seen:
                continue
            seen.add(order)
            out += payload
        return bytes(out)

    # ── the hunt ──────────────────────────────────────────────────────────────

    def finalize(self) -> list[DetectionEvent]:
        for key, segs in self.segments.items():
            stream = self._reassemble(segs)
            if len(stream) < _MIN_BYTES:
                continue
            self._hunt(stream, key[0], key[2], self.channels.get(key, "TCP"))
        for key, segs in self.icmp.items():
            stream = self._reassemble(segs)
            if len(stream) < _MIN_BYTES:
                continue
            src, dst = self.icmp_ends[key]
            self._hunt(stream, src, dst, "ICMP")
        return self._events()

    def _hunt(self, stream: bytes, src: str, dst: str, channel: str = "TCP") -> None:
        result = inspect_blob(stream)
        self._record(result["flags"], result["secrets"], src, dst, channel)
        for entry in result["decoded"]:
            self.decoded.append({**entry, "from": src, "to": dst, "channel": channel})

    def _record(self, flags: list[dict], secrets: list[dict],
                src: str, dst: str, channel: str) -> None:
        for f in flags:
            f = {**f, "from": src, "to": dst, "channel": channel}
            if f["value"] not in {x["value"] for x in self.flags}:
                self.flags.append(f)
        for s in secrets:
            s = {**s, "from": src, "to": dst, "channel": channel}
            if (s["kind"], s["value"]) not in {(x["kind"], x["value"]) for x in self.secrets}:
                self.secrets.append(s)

    # ── reporting ─────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        if not (self.flags or self.secrets or self.decoded):
            return {}
        payloads = _dedupe_decoded(self.decoded)
        return {
            "flags": [{"value": f["value"], "orientation": f["orientation"]} for f in self.flags],
            "secrets": [{"kind": s["kind"], "value": s["value"], "detail": s["detail"]}
                        for s in self.secrets],
            "decoded_payloads": [{"chain": d["chain"], "preview": d["preview"],
                                  "channel": d.get("channel", "TCP"),
                                  "from": d["from"], "to": d["to"]} for d in payloads],
            "counts": {"flags": len(self.flags), "secrets": len(self.secrets),
                       "decoded": len(payloads)},
        }

    def _events(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        for f in self.flags:
            channel = f.get("channel", "TCP")
            events.append(DetectionEvent(
                event_type=EventType.EXTRACTED_SECRET,
                severity=Severity.CRITICAL,
                src_ip=f["from"], dst_ip=f["to"], dst_port=None, protocol=channel,
                timestamp=0.0, packet_count=1, confidence=1.0,
                description=(
                    f"CTF flag recovered from the {channel} stream: {f['value']}"
                    + (" (written reversed)" if f["orientation"] == "reversed" else "")
                ),
                evidence={
                    "value": f["value"],
                    "orientation": f["orientation"],
                    "channel": channel,
                    "mitre": MITRE_DEOBFUSCATE,
                    "note": "Read directly from the reassembled stream, after any "
                            "decoding shown. This is the literal flag string on the wire.",
                },
            ))
        for s in self.secrets:
            channel = s.get("channel", "TCP")
            events.append(DetectionEvent(
                event_type=EventType.EXTRACTED_SECRET,
                severity=_SECRET_SEVERITY.get(s["kind"], Severity.HIGH),
                src_ip=s["from"], dst_ip=s["to"], dst_port=None, protocol=channel,
                timestamp=0.0, packet_count=1, confidence=0.95,
                description=f"{s['detail']} recovered: {s['value']}",
                evidence={
                    "kind": s["kind"],
                    "value": s["value"],
                    "channel": channel,
                    "mitre": MITRE_UNSECURED_CREDS,
                    "note": "Carried in clear text or trivially decoded off the wire. "
                            "A private key is reported by fingerprint, not reproduced; "
                            "treat every secret here as compromised and rotate it.",
                },
            ))
        for d in _dedupe_decoded(self.decoded):
            if d["yielded"]:
                continue  # the flag/secret it revealed is the finding, not the wrapper
            channel = d.get("channel", "TCP")
            events.append(DetectionEvent(
                event_type=EventType.ENCODED_PAYLOAD,
                severity=Severity.HIGH,
                src_ip=d["from"], dst_ip=d["to"], dst_port=None, protocol=channel,
                timestamp=0.0, packet_count=1, confidence=0.85,
                description=f"Obfuscated payload decoded over {channel} ({d['chain']}): {d['preview']}",
                evidence={
                    "transform_chain": d["chain"],
                    "decoded_preview": d["preview"],
                    "channel": channel,
                    "mitre": f"{MITRE_DEOBFUSCATE} / {MITRE_DATA_ENCODING}",
                    "note": "The payload was stacked under the encodings shown and "
                            "decoded back to the content previewed here.",
                },
            ))
        return events


_SECRET_SEVERITY = {
    "private_key": Severity.CRITICAL,
    "jwt": Severity.MEDIUM,
}


# ── module helpers ────────────────────────────────────────────────────────────


def _preview(data: bytes, limit: int = 200) -> str:
    text = re.sub(r"\s+", " ", data.decode("utf-8", "replace"))
    # Keep only printable ASCII so a decoded blob can never carry control bytes or
    # replacement characters into the report or the copilot context.
    text = "".join(ch for ch in text if " " <= ch <= "~").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _dedupe_decoded(decoded: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for d in decoded:
        ident = (d["chain"], d["preview"])
        if ident in seen:
            continue
        seen.add(ident)
        out.append(d)
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
