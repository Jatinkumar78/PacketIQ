"""
Utility helpers — formatting, protocol mapping, conversions.
"""

import ipaddress
import socket
import struct
from datetime import datetime

# IANA-based protocol number to name map (common subset)
PROTOCOL_MAP = {
    1:   "ICMP",
    2:   "IGMP",
    6:   "TCP",
    17:  "UDP",
    41:  "IPv6",
    47:  "GRE",
    50:  "ESP",
    51:  "AH",
    58:  "ICMPv6",
    89:  "OSPF",
    132: "SCTP",
}

# Well-known port → service name
PORT_SERVICE_MAP = {
    20:   "FTP-DATA",
    21:   "FTP",
    22:   "SSH",
    23:   "TELNET",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    119:  "NNTP",
    123:  "NTP",
    135:  "MSRPC",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-TRAP",
    179:  "BGP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    514:  "SYSLOG",
    515:  "LPD",
    587:  "SMTP-SUB",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "ORACLE",
    2049: "NFS",
    3306: "MYSQL",
    3389: "RDP",
    4444: "METERPRETER",
    5432: "POSTGRESQL",
    5900: "VNC",
    6379: "REDIS",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    8888: "HTTP-DEV",
    27017: "MONGODB",
}


def get_protocol_name(proto_num: int) -> str:
    return PROTOCOL_MAP.get(proto_num, f"PROTO-{proto_num}")


def get_service_name(port: int) -> str:
    return PORT_SERVICE_MAP.get(port, str(port))


def format_bytes(size: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def format_duration(seconds: float) -> str:
    """Human-readable duration from seconds."""
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s"


def ip_to_int(ip: str) -> int:
    """Convert dotted IPv4 to integer for range comparisons."""
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def ts_to_str(timestamp: float) -> str:
    """Convert UNIX timestamp to human-readable string."""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return str(timestamp)


def is_private_ip(ip: str) -> bool:
    """
    Return True for any IP that should NOT be treated as a routable internet address:
      - RFC1918 private (10/8, 172.16/12, 192.168/16)
      - Loopback (127/8, ::1)
      - Link-local (169.254/16, fe80::/10)
      - Multicast (224/4, ff00::/8)  — includes mDNS 224.0.0.251 and ff02::fb
      - Unspecified (0.0.0.0, ::)
    """
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_multicast or
            addr.is_unspecified
        )
    except ValueError:
        return False
