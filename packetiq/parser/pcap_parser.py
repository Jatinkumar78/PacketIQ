"""
PCAP Parser — Layer 1 of PacketIQ.

Reads a PCAP/PCAPNG file using Scapy and yields structured raw packet records.
Keeps parsing logic separate from detection and extraction logic.
"""

import contextlib
import os
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import PcapReader
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, LLC, SNAP, STP
from scapy.packet import Packet

from packetiq.utils.helpers import get_protocol_name, get_service_name


@dataclass
class RawPacketRecord:
    """Normalized packet record — one per packet in the PCAP."""
    index: int
    timestamp: float
    size: int                       # total frame size in bytes

    # Link layer (Ethernet/802.3) — identifies the physical NIC that sent the
    # frame, so the device inventory can tell real hosts apart from probed-but-
    # nonexistent IPs and merge a host's IPv4 + IPv6 addresses into one device.
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None

    # Network layer
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip_version: int = 4
    ttl: Optional[int] = None
    ip_proto: Optional[int] = None  # numeric (6=TCP, 17=UDP, 1=ICMP …)
    protocol: str = "UNKNOWN"       # transport/network class for detector logic (TCP/UDP/ICMP/ARP…)
    display_protocol: Optional[str] = None  # most-specific protocol for composition (STP, DHCP, mDNS…)

    # Transport layer
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    service: Optional[str] = None   # well-known port service name
    tcp_flags: Optional[str] = None # e.g. "SA", "F", "R"
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    payload_size: int = 0

    # Layer-2 ARP (host discovery / spoofing signals — populated only for ARP)
    is_arp: bool = False
    arp_op: Optional[int] = None        # 1 = request (who-has), 2 = reply (is-at)
    arp_src_mac: Optional[str] = None   # sender hardware address
    arp_src_ip: Optional[str] = None    # sender protocol (IPv4) address
    arp_dst_mac: Optional[str] = None   # target hardware address
    arp_dst_ip: Optional[str] = None    # target protocol (IPv4) address

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

            # ── Link layer (frame source/destination MAC) ──────────────
            # Works for both Ethernet II and 802.3/LLC frames (STP, CDP, DTP…).
            l2 = pkt.getlayer("Ether") or pkt.getlayer("Dot3")
            if l2 is not None:
                record.eth_src = self._norm_mac(getattr(l2, "src", None))
                record.eth_dst = self._norm_mac(getattr(l2, "dst", None))

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

            elif pkt.haslayer(ARP):
                # ARP carries the layer-2 host-discovery and cache-poisoning
                # signals we must not discard (a scanner/MITM lives here, not in IP).
                arp = pkt[ARP]
                record.is_arp      = True
                record.protocol    = "ARP"
                try:
                    record.arp_op = int(arp.op)
                except Exception:
                    record.arp_op = None
                record.arp_src_mac = self._norm_mac(arp.hwsrc)
                record.arp_src_ip  = arp.psrc
                record.arp_dst_mac = self._norm_mac(arp.hwdst)
                record.arp_dst_ip  = arp.pdst

            else:
                # 802.3/LLC (STP, CDP, DTP), 802.11, etc. — keep at link level
                record.protocol = str(getattr(pkt, "name", None) or "OTHER")

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
                    with contextlib.suppress(Exception):
                        record.dns_qname = dns.qd.qname.decode("utf-8", errors="replace").rstrip(".")

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
                with contextlib.suppress(Exception):
                    record.http_status = int(resp.Status_Code)
                # The Server header names the server software/version — the most
                # CVE-relevant fingerprint we can read from plaintext HTTP.
                record.http_server = self._safe_decode(getattr(resp, "Server", None))

            # ── Most-specific protocol name (Wireshark-style composition) ──
            record.display_protocol = self._display_proto(pkt, record)

            return record

        except Exception:
            # Malformed or unsupported packet — skip silently
            return None

    # ------------------------------------------------------------------ #
    #  Protocol identification for accurate composition                    #
    # ------------------------------------------------------------------ #

    # Cisco SNAP protocol IDs (OUI 00:00:0c) → link-layer control protocols.
    _SNAP_CODE = {0x2000: "CDP", 0x2004: "DTP", 0x2003: "VTP", 0x010b: "PVST"}
    # UDP/TCP well-known application protocols surfaced in the composition.
    _UDP_APP = {67: "DHCP", 68: "DHCP", 546: "DHCPv6", 547: "DHCPv6", 69: "TFTP",
                123: "NTP", 137: "NBNS", 138: "NBT-DGM", 161: "SNMP", 162: "SNMP",
                500: "ISAKMP", 514: "SYSLOG", 520: "RIP", 1900: "SSDP", 5353: "mDNS",
                5355: "LLMNR", 4789: "VXLAN"}
    _TCP_APP = {21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 110: "POP", 143: "IMAP",
                139: "NBSS", 445: "SMB", 389: "LDAP", 3389: "RDP", 5900: "VNC"}

    def _display_proto(self, pkt, record: "RawPacketRecord") -> str:
        """Return the most-specific protocol name for the composition table.

        Wireshark shows the highest dissected layer (STP, DHCP, mDNS…); PacketIQ
        used to collapse these into '802.3'/'Ethernet'/'UDP'. This restores that
        granularity for the composition WITHOUT changing ``record.protocol``
        (kept as TCP/UDP/ICMP/ARP for the detectors' flow logic).
        """
        with contextlib.suppress(Exception):
            if record.is_arp:
                return "ARP"
            # ── Application layer over UDP/TCP ──
            if record.has_dns:
                port = record.dst_port or record.src_port or 0
                return "mDNS" if port == 5353 else ("LLMNR" if port == 5355 else "DNS")
            if pkt.haslayer("DHCP") or pkt.haslayer("BOOTP"):
                return "DHCP"
            if pkt.haslayer("NBTDatagram"):
                return "NBT-DGM"
            if record.has_http:
                return "HTTP"
            if record.protocol == "UDP":
                port = (record.dst_port if (record.dst_port or 0) < 49152 else record.src_port) or 0
                return self._UDP_APP.get(port, "UDP")
            if record.protocol == "TCP":
                for p in (record.dst_port, record.src_port):
                    if p in self._TCP_APP:
                        return self._TCP_APP[p]
                if record.dst_port == 443 or record.src_port == 443:
                    return "TLS" if record.payload_size > 0 else "TCP"
                if record.dst_port == 80 or record.src_port == 80:
                    return "HTTP" if record.payload_size > 0 else "TCP"
                return "TCP"
            if record.protocol == "ICMP":
                return "ICMP"
            if record.ip_proto == 2:
                return "IGMP"
            if record.ip_version == 6 and record.protocol not in ("TCP", "UDP"):
                return record.protocol or "IPv6"
            # ── Link-layer control (non-IP frames) ──
            if pkt.haslayer(STP):
                return "STP"
            if pkt.haslayer(SNAP):
                return self._SNAP_CODE.get(int(getattr(pkt[SNAP], "code", 0)), "SNAP")
            eth = pkt.getlayer("Ether")
            if eth is not None and int(getattr(eth, "type", 0)) == 0x9000:
                return "LOOP"          # Ethernet Configuration Test / loopback
            if pkt.haslayer(LLC):
                return "LLC"
        return record.protocol if record.protocol not in (None, "UNKNOWN") else (
            pkt.name if hasattr(pkt, "name") else "OTHER")

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
    def _norm_mac(mac) -> Optional[str]:
        """Normalise a MAC to lowercase colon form; None for empty values."""
        if not mac:
            return None
        return str(mac).strip().lower() or None

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
