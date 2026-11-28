"""NetSupport RAT detection — a Remote Access Trojan that names itself on the wire.

Why this module exists
----------------------
A SOC alerts on "NetSupport RAT" and the first questions an analyst must answer
for the incident report are *when did it start* and *which host is infected*.
PacketIQ saw the command-and-control only as an anonymous external IP on port
443, because the traffic is **plain HTTP on 443, not TLS**, and the HTTP
forensics pass only inspects the usual web ports. Nothing told the copilot a RAT
was present, so it answered "not present in this capture" to every question
about it.

What the traffic says about itself
----------------------------------
NetSupport Manager is a legitimate remote-control product; criminals deploy the
same client as a RAT. It does not hide what it is. The infected host's check-in
carries ``User-Agent: NetSupport Manager/<ver>`` and the controller answers with
``Server: NetSupport Gateway/<ver>``; the bodies are the NetSupport command
protocol (``CMD=POLL``, ``CMD=ENCD``, …). Those self-identifying strings are the
signature this module reads — the product literally prints its own name in the
header, so a match is the RAT, not an inference from a port being open.

Nothing here is fabricated: the C2 address, the start time, the client/gateway
versions and the command verbs are all read straight out of the packets, and the
command *payloads* (``DATA=…``) are NetSupport-encrypted, which the module says
rather than pretending to have decoded them.
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from packetiq.detection.models import DetectionEvent, EventType, Severity

# ── Signature ────────────────────────────────────────────────────────────────
# The two self-identifying strings. The client (the infected host) announces the
# first in its request User-Agent; the controller announces the second in its
# response Server header. Either one proves the channel is NetSupport.
_CLIENT_SIG  = b"NetSupport Manager"
_GATEWAY_SIG = b"NetSupport Gateway"
_ANY_SIG     = b"NetSupport"

# The NetSupport command verb that heads each body: ``CMD=POLL\n``, ``CMD=ENCD\n``.
_CMD_RE = re.compile(rb"CMD=([A-Za-z]{2,10})")
# The header value after ``User-Agent:`` / ``Server:``, read from the HTTP head.
_AGENT_RE  = re.compile(r"User-Agent:\s*(NetSupport Manager[^\r\n]*)", re.IGNORECASE)
_SERVER_RE = re.compile(r"Server:\s*(NetSupport Gateway[^\r\n]*)", re.IGNORECASE)
# The request line, e.g. ``POST http://host/fakeurl.htm HTTP/1.1`` or ``POST /x``.
_REQLINE_RE = re.compile(r"^(?:GET|POST|HEAD|PUT)\s+(\S+)", re.IGNORECASE)

MITRE_RAT = "T1219"   # Remote Access Software


@dataclass
class _Channel:
    """One NetSupport C2 channel, folded from both directions of one connection."""

    client_ip:  str = ""
    server_ip:  str = ""
    server_port: int = 0
    first_ts:   float = 0.0
    last_ts:    float = 0.0
    client_agent: str = ""
    gateway:    str = ""
    uri:        str = ""
    commands:   list[str] = field(default_factory=list)
    request_count: int = 0

    @property
    def identified(self) -> bool:
        """True once we have seen a side name itself (client UA or gateway Server)."""
        return bool(self.client_agent or self.gateway)


def _conv_key(a_ip: str, a_port: int, b_ip: str, b_port: int) -> tuple:
    """A direction-independent key for the TCP conversation the packet belongs to."""
    return tuple(sorted(((a_ip, a_port), (b_ip, b_port))))


def _head_text(payload: bytes) -> str:
    """The HTTP head as text, up to the blank line, decoded leniently.

    NetSupport uses bare ``\\n`` line endings, not ``\\r\\n``, so the usual
    ``\\r\\n\\r\\n`` split would never find the header block; both are handled.
    """
    cut = payload.find(b"\r\n\r\n")
    if cut == -1:
        cut = payload.find(b"\n\n")
    head = payload if cut == -1 else payload[:cut]
    return head.decode("latin-1", "replace")


class NetSupportAccumulator:
    """Collects NetSupport RAT C2 over one PCAP pass, then reports the channels.

    ``feed(pkt)`` filters internally so this can ride the engine's existing
    raw-packet loop rather than reading the capture again.
    """

    def __init__(self) -> None:
        self.channels: dict[tuple, _Channel] = {}

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return

        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return
        sport, dport = int(tcp.sport), int(tcp.dport)
        key = _conv_key(src, sport, dst, dport)

        has_sig = _ANY_SIG in payload
        chan = self.channels.get(key)
        # A packet with no signature only counts if it belongs to a connection we
        # have already identified as NetSupport — that is where the bare ``CMD=``
        # bodies (which never repeat the product name) are folded in.
        if chan is None and not has_sig:
            return
        if chan is None:
            chan = self.channels[key] = _Channel()

        ts = float(pkt.time)
        chan.first_ts = chan.first_ts or ts
        chan.last_ts = ts
        chan.request_count += 1

        head = _head_text(payload)
        agent = _AGENT_RE.search(head)
        if agent:
            # The sender of a NetSupport-Manager User-Agent is the infected client.
            chan.client_ip = chan.client_ip or src
            chan.server_ip = chan.server_ip or dst
            chan.server_port = chan.server_port or dport
            chan.client_agent = chan.client_agent or agent.group(1).strip()
            req = _REQLINE_RE.match(head)
            if req and not chan.uri:
                chan.uri = req.group(1)
        server = _SERVER_RE.search(head)
        if server:
            # The sender of a NetSupport-Gateway Server header is the controller.
            chan.server_ip = chan.server_ip or src
            chan.server_port = chan.server_port or sport
            chan.client_ip = chan.client_ip or dst
            chan.gateway = chan.gateway or server.group(1).strip()

        for verb in _CMD_RE.findall(payload):
            cmd = verb.decode("latin-1").upper()
            if cmd not in chan.commands:
                chan.commands.append(cmd)

    # ── reporting ───────────────────────────────────────────────────────────

    def _ordered(self) -> list[_Channel]:
        return sorted(
            (c for c in self.channels.values() if c.identified),
            key=lambda c: c.first_ts,
        )

    def summary(self) -> dict:
        """Structured RAT facts for the report, the UI and the copilot.

        Empty when no NetSupport channel was seen, which is itself the answer to
        "is the alerted RAT actually in this capture?".
        """
        chans = self._ordered()
        if not chans:
            return {}
        return {
            "family": "NetSupport RAT (NetSupport Manager)",
            "detected": True,
            "channels": [
                {
                    "client": c.client_ip,
                    "server": c.server_ip,
                    "port": c.server_port,
                    "c2": f"{c.server_ip}:{c.server_port}",
                    "first_seen": c.first_ts,
                    "first_seen_utc": _utc(c.first_ts),
                    "client_agent": c.client_agent,
                    "gateway": c.gateway,
                    "uri": c.uri,
                    "commands": list(c.commands),
                    "request_count": c.request_count,
                }
                for c in chans
            ],
        }

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        for c in self._ordered():
            events.append(DetectionEvent(
                event_type=EventType.RAT_C2,
                severity=Severity.CRITICAL,
                src_ip=c.client_ip, dst_ip=c.server_ip, dst_port=c.server_port,
                protocol="HTTP",
                timestamp=c.first_ts,
                packet_count=c.request_count,
                confidence=0.97,
                description=(
                    f"NetSupport RAT command-and-control — {c.client_ip} is running "
                    f"the NetSupport Manager client as a RAT and beaconing to "
                    f"{c.server_ip}:{c.server_port}"
                ),
                evidence={
                    "malware_family": "NetSupport RAT (NetSupport Manager)",
                    "c2": f"{c.server_ip}:{c.server_port}",
                    "first_seen_utc": _utc(c.first_ts),
                    "client_agent": c.client_agent or "—",
                    "gateway": c.gateway or "—",
                    "http_uri": c.uri or "—",
                    "commands_observed": ", ".join(c.commands) or "—",
                    "request_count": c.request_count,
                    "mitre": MITRE_RAT,
                    "note": "NetSupport Manager is a legitimate remote-control tool "
                            "abused here as a RAT. The channel is plain HTTP on port "
                            f"{c.server_port} (not TLS) and names itself in its "
                            "headers; the command payloads (DATA=…) are "
                            "NetSupport-encrypted and are not decoded here.",
                },
            ))
        return events


def _utc(ts: float) -> str:
    """A capture timestamp as ``YYYY-MM-DD HH:MM:SS UTC`` — the form a report wants."""
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _endpoints(pkt) -> tuple[str | None, str | None]:
    """Source and destination addresses, IPv4 or IPv6."""
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    return None, None
