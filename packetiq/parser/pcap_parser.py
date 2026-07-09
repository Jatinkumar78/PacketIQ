"""
PCAP Parser — Layer 1 of PacketIQ.

Reads a PCAP/PCAPNG file using Scapy and yields structured raw packet records.
Keeps parsing logic separate from detection and extraction logic.
"""

import os
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import PcapReader
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from packetiq.utils.helpers import get_protocol_name, get_service_name


@dataclass
class RawPacketRecord:
    """Normalized packet record — one per packet in the PCAP."""
    index: int
    timestamp: float
    size: int                       # total frame size in bytes

    # Network layer
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: int = 4
    ttl: Optional[int] = None
    ip_proto: Optional[int] = None  # numeric (6=TCP, 17=UDP, 1=ICMP …)
    protocol: str = "UNKNOWN"       # human-readable

    # Transport layer
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    service: Optional[str] = None   # well-known port service name
    tcp_flags: Optional[str] = None # e.g. "SA", "F", "R"
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    payload_size: int = 0

    # Application hints
    has_dns: bool = False
    has_http: bool = False
    dns_qname: Optional[str] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None
    http_server: Optional[str] = None

    # Raw payload reference (kept small — only first 512 bytes)
    raw_payload: bytes = field(default_factory=bytes, repr=False)


class PCAPParser:
    """
    Reads a PCAP file and yields RawPacketRecord objects.

    Usage:
        parser = PCAPParser("file.pcap")
        for record in parser.stream():
            ...
        summary = parser.file_summary()
    """

    def __init__(self, filepath: str):
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")
        self.filepath = filepath
        self.filesize = os.path.getsize(filepath)
        self._packet_count = 0

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def stream(self) -> Generator[RawPacketRecord, None, None]:
        """
        Lazy generator — parses one packet at a time to avoid loading
        multi-GB captures fully into memory.
        """
        index = 0
        with PcapReader(self.filepath) as reader:
            for pkt in reader:
                record = self._parse_packet(pkt, index)
                if record:
                    yield record
                    index += 1
        self._packet_count = index

    def load_all(self) -> list[RawPacketRecord]:
        """Load entire PCAP into memory. Use only for smaller files."""
        return list(self.stream())

    def file_summary(self) -> dict:
        """High-level metadata about the PCAP file."""
        return {
            "filepath":     self.filepath,
            "filename":     os.path.basename(self.filepath),
            "filesize":     self.filesize,
            "packet_count": self._packet_count,
        }

    # ------------------------------------------------------------------ #
    #  Internal parsing                                                    #
    # ------------------------------------------------------------------ #

    def _parse_packet(self, pkt: Packet, index: int) -> Optional[RawPacketRecord]:
        """Extract a normalized record from a raw Scapy packet."""
        try:
            record = RawPacketRecord(
                index=index,
                timestamp=float(pkt.time),
                size=len(pkt),
            )

            # ── Network layer ──────────────────────────────────────────
            if pkt.haslayer(IP):
                ip = pkt[IP]
                record.src_ip    = ip.src
                record.dst_ip    = ip.dst
                record.ip_version = 4
                record.ttl       = ip.ttl
                record.ip_proto  = ip.proto
                record.protocol  = get_protocol_name(ip.proto)

            elif pkt.haslayer(IPv6):
                ip6 = pkt[IPv6]
                record.src_ip    = ip6.src
                record.dst_ip    = ip6.dst
                record.ip_version = 6
                record.ttl       = ip6.hlim
                record.ip_proto  = ip6.nh
                record.protocol  = get_protocol_name(ip6.nh)

            else:
                # ARP, 802.11, etc. — keep at Ethernet level
                record.protocol = pkt.name if hasattr(pkt, "name") else "OTHER"

            # ── Transport layer ────────────────────────────────────────
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.src_port  = tcp.sport
                record.dst_port  = tcp.dport
                record.tcp_flags = self._decode_tcp_flags(tcp.flags)
                record.tcp_seq   = tcp.seq
                record.tcp_ack   = tcp.ack
                record.protocol  = "TCP"
                record.service   = self._infer_service(tcp.sport, tcp.dport)
                pl = bytes(tcp.payload)          # build once, not twice
                record.payload_size = len(pl)
                record.raw_payload  = pl[:512]

            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.src_port  = udp.sport
                record.dst_port  = udp.dport
                record.protocol  = "UDP"
                record.service   = self._infer_service(udp.sport, udp.dport)
                pl = bytes(udp.payload)          # build once, not twice
                record.payload_size = len(pl)
                record.raw_payload  = pl[:512]

            elif pkt.haslayer(ICMP):
                record.protocol = "ICMP"

            # ── Application layer ──────────────────────────────────────
            if pkt.haslayer(DNS):
                record.has_dns = True
                dns = pkt[DNS]
                if dns.qd:
                    try:
                        record.dns_qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                    except Exception:
                        pass

            if pkt.haslayer(HTTPRequest):
                record.has_http = True
                req = pkt[HTTPRequest]
                record.http_method = self._safe_decode(req.Method)
                record.http_host   = self._safe_decode(req.Host)
                record.http_path   = self._safe_decode(req.Path)
                record.http_user_agent = self._safe_decode(getattr(req, "User_Agent", None))

            elif pkt.haslayer(HTTPResponse):
                record.has_http = True
                resp = pkt[HTTPResponse]
                try:
                    record.http_status = int(resp.Status_Code)
                except Exception:
                    pass
                # The Server header names the server software/version — the most
                # CVE-relevant fingerprint we can read from plaintext HTTP.
                record.http_server = self._safe_decode(getattr(resp, "Server", None))

            return record

        except Exception:
            # Malformed or unsupported packet — skip silently
            return None

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _decode_tcp_flags(flags) -> str:
        """Convert Scapy TCP flags field to readable string like 'SYN', 'SA', 'F'."""
        flag_map = {
            "F": "FIN",
            "S": "SYN",
            "R": "RST",
            "P": "PSH",
            "A": "ACK",
            "U": "URG",
            "E": "ECE",
            "C": "CWR",
        }
        raw = str(flags)
        return "".join(flag_map.get(c, c) for c in raw if c in flag_map) or raw

    @staticmethod
    def _infer_service(sport: int, dport: int) -> str:
        """Prefer the lower/well-known port for service identification."""
        svc_dst = get_service_name(dport)
        svc_src = get_service_name(sport)
        # If destination port is well-known, use it; otherwise check source
        if svc_dst != str(dport):
            return svc_dst
        if svc_src != str(sport):
            return svc_src
        return str(dport)

    @staticmethod
    def _safe_decode(field) -> Optional[str]:
        """Safely decode Scapy bytes fields."""
        if field is None:
            return None
        try:
            return field.decode("utf-8", errors="replace") if isinstance(field, bytes) else str(field)
        except Exception:
            return None
