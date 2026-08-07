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

from packetiq.utils.helpers import (
    dns_first_question,
    get_protocol_name,
    get_service_name,
)


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
        # TCP flows proven to carry HTTP — see _HTTP_FLOW_CAP.
        self._http_flows: set = set()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def stream(self) -> Generator[RawPacketRecord, None, None]:
        """
        Lazy generator — parses one packet at a time to avoid loading
        multi-GB captures fully into memory.
        """
        index = 0
        self._http_flows.clear()   # each pass starts with no flow history
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
            # Full TCP payload, kept past record.raw_payload's 512-byte cap so
            # the HTTP header scan below can still see a long header block.
            tcp_payload = b""

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
                tcp_payload = pl

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
                q = dns_first_question(dns)
                if q is not None:
                    with contextlib.suppress(Exception):
                        record.dns_qname = q.qname.decode("utf-8", errors="replace").rstrip(".")

            # Read the start line off the wire first. Scapy binds its HTTP
            # dissector to TCP 80/8080 only, so trusting it alone left HTTP
            # invisible on every other port, and its Path field truncates at the
            # first space — dropping exactly the payload an injection carries.
            if tcp_payload:
                self._sniff_http(tcp_payload, record)

            # Scapy's dissected layer then fills anything still unset.
            if pkt.haslayer(HTTPRequest):
                record.has_http = True
                req = pkt[HTTPRequest]
                if record.http_method is None:
                    record.http_method = self._safe_decode(req.Method)
                if record.http_host is None:
                    record.http_host = self._safe_decode(req.Host)
                if record.http_path is None:
                    record.http_path = self._safe_decode(req.Path)
                if record.http_user_agent is None:
                    record.http_user_agent = self._safe_decode(getattr(req, "User_Agent", None))

            elif pkt.haslayer(HTTPResponse):
                record.has_http = True
                resp = pkt[HTTPResponse]
                if record.http_status is None:
                    with contextlib.suppress(Exception):
                        record.http_status = int(resp.Status_Code)
                # The Server header names the server software/version — the most
                # CVE-relevant fingerprint we can read from plaintext HTTP.
                if record.http_server is None:
                    record.http_server = self._safe_decode(getattr(resp, "Server", None))

            if record.has_http:
                self._remember_http_flow(record)

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
                # A stream proven to carry HTTP keeps its name, as in Wireshark.
                # Segments continuing an HTTP message have no start line of their
                # own, so the port table below would name them by port instead —
                # calling the continuation of a malware HTTP session on 3389
                # "RDP" while only its header packets read "HTTP".
                # Same rule the port-80 branch below uses: data segments are the
                # protocol, a bare ACK is just TCP.
                if self._flow_key(record) in self._http_flows:
                    return "HTTP" if record.payload_size > 0 else "TCP"
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
    #  HTTP recovered from payload bytes (port-independent)                #
    # ------------------------------------------------------------------ #
    #
    # Scapy binds its HTTP dissector to TCP 80 and 8080 and nothing else, so
    # byte-identical HTTP served on 8000 / 8888 / 3128 / 81 used to arrive as
    # anonymous TCP: no `has_http`, no method / Host / User-Agent / Server, and
    # therefore no HTTP inspection, no HTTP beaconing evidence and no server
    # banner for CVE matching — on exactly the ports C2 traffic prefers.
    #
    # These read the request/status line off the wire instead of trusting the
    # port number, so a message is only called HTTP when it actually is one.

    # RFC 9110 methods plus PATCH (RFC 5789). "PRI" is deliberately absent: it
    # opens the HTTP/2 connection preface, which is not an HTTP/1 request.
    _HTTP_METHODS = frozenset((
        b"GET", b"POST", b"HEAD", b"PUT", b"DELETE",
        b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT",
    ))
    # First byte of every method above, and of "HTTP/1." itself. One integer
    # comparison rejects almost all non-HTTP payloads before any splitting.
    _HTTP_LEAD = b"GPHDOTC"
    # Past this, a first line is not a header block worth parsing.
    _MAX_START_LINE = 8192

    def _sniff_http(self, payload: bytes, record: "RawPacketRecord") -> None:
        """Populate the HTTP fields from a raw TCP payload, whatever the port.

        Sets nothing unless the payload genuinely opens with an HTTP/1.x request
        line or status line, so a non-HTTP service that happens to sit on a
        web-ish port is never relabelled on a port guess.
        """
        if not payload or payload[0] not in self._HTTP_LEAD:
            return
        line_end = payload.find(b"\r\n")
        if line_end < 0 or line_end > self._MAX_START_LINE:
            return
        start = payload[:line_end]

        # Status line: HTTP/1.x SP 3DIGIT [SP reason-phrase]
        if start.startswith(b"HTTP/1."):
            parts = start.split(b" ", 2)
            if len(parts) < 2 or len(parts[1]) != 3 or not parts[1].isdigit():
                return
            record.has_http = True
            record.http_status = int(parts[1])
            # Names the server software/version — our best plaintext CVE hint.
            record.http_server = self._header_value(payload, b"server")
            return

        # Request line: METHOD SP request-target SP HTTP/1.x
        # Take the method from the first field and the version from the last, so
        # a crude scanner that leaves spaces unencoded inside the target keeps
        # its full request-target — that text is the attack evidence.
        parts = start.split(b" ")
        if len(parts) < 3 or parts[0] not in self._HTTP_METHODS:
            return
        if not parts[-1].startswith(b"HTTP/1."):
            return
        record.has_http = True
        record.http_method = parts[0].decode("ascii")
        record.http_path = self._safe_decode(b" ".join(parts[1:-1]))
        record.http_host = self._header_value(payload, b"host")
        record.http_user_agent = self._header_value(payload, b"user-agent")

    # A capture of many short-lived flows must not grow this without bound. Past
    # the cap we simply stop learning new flows; the ones already known keep
    # their label and everything else falls back to the port table.
    _HTTP_FLOW_CAP = 50_000

    @staticmethod
    def _flow_key(record: "RawPacketRecord") -> tuple:
        """Direction-independent TCP flow identity, so a reply matches its request."""
        a = (record.src_ip or "", record.src_port or 0)
        b = (record.dst_ip or "", record.dst_port or 0)
        return (a, b) if a <= b else (b, a)

    def _remember_http_flow(self, record: "RawPacketRecord") -> None:
        """Record that this TCP flow carries HTTP, for its later segments."""
        if record.protocol != "TCP" or not record.src_ip or not record.dst_ip:
            return
        if len(self._http_flows) < self._HTTP_FLOW_CAP:
            self._http_flows.add(self._flow_key(record))

    @staticmethod
    def _header_value(payload: bytes, name: bytes) -> Optional[str]:
        """Return one header's value, matched case-insensitively.

        ``name`` must already be lowercase. Stops at the blank line ending the
        header block, so a body that happens to contain "Host:" is not read as
        a header. Headers split across TCP segments simply come back None.
        """
        end = payload.find(b"\r\n\r\n")
        block = payload if end < 0 else payload[:end]
        prefix = name + b":"
        n = len(prefix)
        for line in block.split(b"\r\n")[1:]:
            if line[:n].lower() == prefix:
                return line[n:].strip().decode("utf-8", errors="replace") or None
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
