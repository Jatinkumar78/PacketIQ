"""
Credential Exposure Detector — plaintext only, no decryption.

Performs a targeted second pass over the PCAP scanning raw TCP/UDP payloads
for credentials transmitted in cleartext over:

  • HTTP  — POST body key=value pairs, Basic Auth header
  • FTP   — USER / PASS commands
  • SMTP  — AUTH PLAIN / AUTH LOGIN (base64 decoded)
  • IMAP  — LOGIN command
  • POP3  — PASS command
  • TELNET — text login/password prompts
"""

import base64
import re
from collections.abc import Generator
from typing import Optional

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.parser.pcap_parser import RawPacketRecord

# ── Credential field patterns (case-insensitive) ──────────────────────────────

# HTTP POST body: password=<value>, passwd=<value>, etc.
HTTP_CRED_RE = re.compile(
    rb"(?:password|passwd|pass|pwd|secret|token|api_?key)"
    rb"\s*=\s*([^\s&\r\n]{1,128})",
    re.IGNORECASE,
)

# HTTP Authorization: Basic <base64>
HTTP_BASIC_AUTH_RE = re.compile(
    rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]{4,})",
    re.IGNORECASE,
)

# FTP USER / PASS
FTP_USER_RE = re.compile(rb"^USER\s+(\S+)", re.IGNORECASE | re.MULTILINE)
FTP_PASS_RE = re.compile(rb"^PASS\s+(\S+)", re.IGNORECASE | re.MULTILINE)

# SMTP AUTH PLAIN / LOGIN (base64 payload on next line)
SMTP_AUTH_RE = re.compile(
    rb"AUTH\s+(PLAIN|LOGIN)\s*([A-Za-z0-9+/=]*)",
    re.IGNORECASE,
)

# IMAP LOGIN
IMAP_LOGIN_RE = re.compile(
    rb"\w+\s+LOGIN\s+\"?(\S+?)\"?\s+\"?(\S+?)\"?(?:\r?\n|$)",
    re.IGNORECASE,
)

# POP3 PASS
POP3_PASS_RE = re.compile(rb"^PASS\s+(\S+)", re.IGNORECASE | re.MULTILINE)

# Ports that carry application-layer credentials
CRED_PORTS = {
    21:  "FTP",
    23:  "TELNET",
    25:  "SMTP",
    80:  "HTTP",
    110: "POP3",
    143: "IMAP",
    587: "SMTP",
    8080: "HTTP",
}


def detect_from_stream(packet_stream: Generator[RawPacketRecord, None, None]) -> list[DetectionEvent]:
    """
    Stream packets from a PCAPParser and flag any that contain plaintext credentials.
    Call this as a second pass after the extractor has already run.
    """
    events: list[DetectionEvent] = []
    # Deduplicate: (src, dst, port, credential_type) → already flagged
    seen: set[tuple] = set()

    for record in packet_stream:
        if not record.raw_payload or len(record.raw_payload) < 4:
            continue

        src = record.src_ip or ""
        dst = record.dst_ip or ""

        # Determine which protocol handler to use based on destination port
        dport = record.dst_port or 0
        sport = record.src_port or 0

        # ── HTTP ──────────────────────────────────────────────────────────
        if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
            _check_http(record, src, dst, dport, seen, events)

        # ── FTP ───────────────────────────────────────────────────────────
        if dport == 21 or sport == 21:
            _check_ftp(record, src, dst, seen, events)

        # ── SMTP ──────────────────────────────────────────────────────────
        if dport in (25, 587) or sport in (25, 587):
            _check_smtp(record, src, dst, seen, events)

        # ── IMAP ──────────────────────────────────────────────────────────
        if dport == 143 or sport == 143:
            _check_imap(record, src, dst, seen, events)

        # ── POP3 ──────────────────────────────────────────────────────────
        if dport == 110 or sport == 110:
            _check_pop3(record, src, dst, seen, events)

        # ── TELNET (generic printable payload over port 23) ────────────────
        if dport == 23 or sport == 23:
            _check_telnet(record, src, dst, seen, events)

    return events


# ── Per-protocol handlers ─────────────────────────────────────────────────────

def _check_http(record, src, dst, dport, seen, events):
    payload = record.raw_payload

    # POST body credentials
    for m in HTTP_CRED_RE.finditer(payload):
        value = m.group(1)
        field = m.group(0).split(b"=")[0].decode("utf-8", errors="replace")
        key = (src, dst, dport, "HTTP_POST", field.lower())
        if key in seen:
            continue
        seen.add(key)
        events.append(_make_event(
            src, dst, dport, "HTTP",
            f"Plaintext credential in HTTP POST body — field: {field!r}",
            record.timestamp,
            evidence={
                "protocol":   "HTTP",
                "field_name": field,
                "direction":  f"{src} → {dst}:{dport}",
                "note":       "Value redacted from event; visible in raw PCAP",
            },
            severity=Severity.HIGH,
        ))

    # Basic Auth header
    for m in HTTP_BASIC_AUTH_RE.finditer(payload):
        b64 = m.group(1)
        key = (src, dst, dport, "HTTP_BASIC")
        if key in seen:
            continue
        seen.add(key)
        decoded = _safe_b64(b64)
        events.append(_make_event(
            src, dst, dport, "HTTP",
            "HTTP Basic Auth credential exposed (base64 decoded in plaintext)",
            record.timestamp,
            evidence={
                "protocol":      "HTTP",
                "auth_type":     "Basic",
                "decoded_creds": decoded if decoded else "(decode failed)",
                "direction":     f"{src} → {dst}:{dport}",
            },
            severity=Severity.CRITICAL,
        ))


def _check_ftp(record, src, dst, seen, events):
    payload = record.raw_payload

    for m in FTP_USER_RE.finditer(payload):
        username = m.group(1).decode("utf-8", errors="replace")
        key = (src, dst, 21, "FTP_USER", username)
        if key not in seen:
            seen.add(key)
            events.append(_make_event(
                src, dst, 21, "FTP",
                f"FTP username transmitted in plaintext: {username!r}",
                record.timestamp,
                evidence={"protocol": "FTP", "username": username},
                severity=Severity.HIGH,
            ))

    for m in FTP_PASS_RE.finditer(payload):
        key = (src, dst, 21, "FTP_PASS")
        if key not in seen:
            seen.add(key)
            events.append(_make_event(
                src, dst, 21, "FTP",
                "FTP password transmitted in plaintext",
                record.timestamp,
                evidence={
                    "protocol": "FTP",
                    "note":     "Password value redacted; visible in raw PCAP",
                },
                severity=Severity.CRITICAL,
            ))


def _check_smtp(record, src, dst, seen, events):
    for m in SMTP_AUTH_RE.finditer(record.raw_payload):
        auth_type = m.group(1).decode("utf-8", errors="replace").upper()
        b64_payload = m.group(2)
        key = (src, dst, record.dst_port, "SMTP_AUTH")
        if key in seen:
            continue
        seen.add(key)
        decoded = _safe_b64(b64_payload) if b64_payload else None
        events.append(_make_event(
            src, dst, record.dst_port or 25, "SMTP",
            f"SMTP AUTH {auth_type} credential transmitted in plaintext",
            record.timestamp,
            evidence={
                "protocol":      "SMTP",
                "auth_mechanism": auth_type,
                "decoded_creds": decoded or "(inline payload — check raw capture)",
            },
            severity=Severity.CRITICAL,
        ))


def _check_imap(record, src, dst, seen, events):
    for m in IMAP_LOGIN_RE.finditer(record.raw_payload):
        username = m.group(1).decode("utf-8", errors="replace")
        key = (src, dst, 143, "IMAP_LOGIN", username)
        if key in seen:
            continue
        seen.add(key)
        events.append(_make_event(
            src, dst, 143, "IMAP",
            f"IMAP LOGIN credential in plaintext — user: {username!r}",
            record.timestamp,
            evidence={"protocol": "IMAP", "username": username},
            severity=Severity.CRITICAL,
        ))


def _check_pop3(record, src, dst, seen, events):
    for m in POP3_PASS_RE.finditer(record.raw_payload):
        key = (src, dst, 110, "POP3_PASS")
        if key in seen:
            continue
        seen.add(key)
        events.append(_make_event(
            src, dst, 110, "POP3",
            "POP3 password transmitted in plaintext",
            record.timestamp,
            evidence={
                "protocol": "POP3",
                "note":     "Password value redacted; visible in raw PCAP",
            },
            severity=Severity.CRITICAL,
        ))


def _check_telnet(record, src, dst, seen, events):
    """
    Telnet sends all keystrokes in plaintext. Flag any active Telnet session.
    We don't try to reconstruct the interactive session — just alert on the
    protocol itself being used, since all credentials are inherently exposed.
    """
    if len(record.raw_payload) < 2:
        return
    # Check for printable ASCII (actual Telnet session data, not option negotiation)
    printable = sum(1 for b in record.raw_payload if 0x20 <= b <= 0x7E)
    if printable / max(len(record.raw_payload), 1) < 0.5:
        return  # mostly option negotiation bytes, not user data

    key = (src, dst, 23, "TELNET_SESSION")
    if key in seen:
        return
    seen.add(key)
    events.append(_make_event(
        src, dst, 23, "TELNET",
        "Telnet session detected — all credentials transmitted in plaintext",
        record.timestamp,
        evidence={
            "protocol": "TELNET",
            "note":     "Telnet provides zero confidentiality; switch to SSH",
        },
        severity=Severity.CRITICAL,
    ))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(
    src, dst, dport, protocol, description, timestamp,
    evidence=None, severity=Severity.HIGH,
) -> DetectionEvent:
    return DetectionEvent(
        event_type   = EventType.CREDENTIAL_EXPOSURE,
        severity     = severity,
        src_ip       = src,
        dst_ip       = dst,
        dst_port     = dport,
        protocol     = protocol,
        description  = description,
        timestamp    = timestamp,
        packet_count = 1,
        confidence   = 0.95,
        evidence     = evidence or {},
    )


def _safe_b64(data: bytes) -> Optional[str]:
    """Decode base64 bytes → UTF-8 string, return None on failure."""
    try:
        if isinstance(data, bytes):
            decoded = base64.b64decode(data + b"==")  # padding-safe
        else:
            decoded = base64.b64decode(str(data) + "==")
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None
