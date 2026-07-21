"""
Utility helpers — formatting, protocol mapping, conversions.
"""

import ipaddress
import socket
import struct
from datetime import datetime

# ── IANA IP-protocol numbers → name (Internet & transport layers) ──────────────
# Covers the core Internet Protocol Suite transport/internet-layer protocols.
PROTOCOL_MAP = {
    0:   "HOPOPT",       # IPv6 hop-by-hop option
    1:   "ICMP",
    2:   "IGMP",
    3:   "GGP",
    4:   "IP-in-IP",     # IPv4 encapsulation
    6:   "TCP",
    8:   "EGP",
    9:   "IGP",
    17:  "UDP",
    27:  "RDP",          # Reliable Datagram Protocol
    33:  "DCCP",
    41:  "IPv6",         # IPv6 encapsulation (6in4)
    43:  "IPv6-Route",
    44:  "IPv6-Frag",
    46:  "RSVP",
    47:  "GRE",
    50:  "ESP",          # IPsec
    51:  "AH",           # IPsec
    58:  "ICMPv6",
    59:  "IPv6-NoNxt",
    60:  "IPv6-Opts",
    88:  "EIGRP",
    89:  "OSPF",
    94:  "IPIP",
    97:  "ETHERIP",
    103: "PIM",
    112: "VRRP",
    115: "L2TP",
    124: "ISIS",
    132: "SCTP",
    133: "FC",           # Fibre Channel
    136: "UDPLite",
    137: "MPLS-in-IP",
}

# ── Well-known TCP/UDP port → service name (application layer) ──────────────────
# Broad, security-relevant coverage of the IP suite's application protocols so
# the composition, service table and the threat-prediction engine can reason
# about exposed attack surface. Not exhaustive of all 65k ports by design.
PORT_SERVICE_MAP = {
    7:    "ECHO",
    9:    "DISCARD",
    11:   "SYSTAT",
    13:   "DAYTIME",
    17:   "QOTD",
    19:   "CHARGEN",
    20:   "FTP-DATA",
    21:   "FTP",
    22:   "SSH",
    23:   "TELNET",
    25:   "SMTP",
    37:   "TIME",
    42:   "WINS",
    43:   "WHOIS",
    49:   "TACACS",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    69:   "TFTP",
    79:   "FINGER",
    80:   "HTTP",
    88:   "KERBEROS",
    102:  "S7COMM",       # Siemens SCADA
    110:  "POP3",
    111:  "RPCBIND",
    113:  "IDENT",
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
    194:  "IRC",
    389:  "LDAP",
    427:  "SLP",
    443:  "HTTPS",
    445:  "SMB",
    464:  "KPASSWD",
    465:  "SMTPS",
    500:  "ISAKMP",       # IKE / IPsec
    502:  "MODBUS",       # ICS/SCADA
    512:  "REXEC",
    513:  "RLOGIN",
    514:  "SYSLOG",
    515:  "LPD",
    520:  "RIP",
    523:  "DB2",
    540:  "UUCP",
    546:  "DHCPv6",
    547:  "DHCPv6",
    548:  "AFP",
    554:  "RTSP",
    587:  "SMTP-SUB",
    593:  "MS-RPC-HTTP",
    623:  "IPMI",         # BMC / out-of-band mgmt
    631:  "IPP",
    636:  "LDAPS",
    873:  "RSYNC",
    902:  "VMWARE",
    903:  "VMWARE",
    989:  "FTPS-DATA",
    990:  "FTPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS",
    1194: "OPENVPN",
    1433: "MSSQL",
    1434: "MSSQL-M",
    1521: "ORACLE",
    1604: "CITRIX",
    1701: "L2TP",
    1723: "PPTP",
    1883: "MQTT",
    1900: "SSDP",
    2049: "NFS",
    2181: "ZOOKEEPER",
    2222: "SSH-ALT",
    2375: "DOCKER",
    2376: "DOCKER-TLS",
    3128: "SQUID",
    3268: "GC-LDAP",
    3269: "GC-LDAPS",
    3306: "MYSQL",
    3389: "RDP",
    3690: "SVN",
    4444: "METERPRETER",
    4505: "SALT",
    4506: "SALT",
    4786: "CISCO-SMI",
    5000: "UPNP",
    5060: "SIP",
    5061: "SIP-TLS",
    5222: "XMPP",
    5353: "MDNS",
    5355: "LLMNR",
    5432: "POSTGRESQL",
    5555: "ADB",
    5601: "KIBANA",
    5672: "AMQP",
    5683: "CoAP",
    5900: "VNC",
    5938: "TEAMVIEWER",
    5984: "COUCHDB",
    5985: "WINRM",
    5986: "WINRM-SSL",
    6000: "X11",
    6379: "REDIS",
    6443: "KUBE-API",
    6667: "IRC",
    7001: "WEBLOGIC",
    8000: "HTTP-ALT",
    8006: "PROXMOX",
    8080: "HTTP-ALT",
    8086: "INFLUXDB",
    8088: "HADOOP",
    8161: "ACTIVEMQ",
    8443: "HTTPS-ALT",
    8500: "CONSUL",
    8888: "HTTP-DEV",
    9000: "SONARQUBE",
    9042: "CASSANDRA",
    9092: "KAFKA",
    9200: "ELASTICSEARCH",
    9300: "ELASTICSEARCH",
    9418: "GIT",
    10000: "WEBMIN",
    11211: "MEMCACHED",
    15672: "RABBITMQ-MGMT",
    27017: "MONGODB",
    27018: "MONGODB",
    50070: "HADOOP-NN",
    61616: "ACTIVEMQ",
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


def same_org_network(ip_a: str, ip_b: str, prefix: int = 16) -> bool:
    """
    Return True when two IPs plausibly belong to the *same organisation's network*,
    so traffic between them is intra-LAN rather than crossing the internet:

      - both are local (private / loopback / link-local), OR
      - both are public and share the same /prefix block (default /16) — this covers
        public-IP LANs such as a university's own /16 (e.g. Stratosphere CTU's
        147.32.0.0/16), where intra-campus SMB/RDP/FTP is *not* internet-facing.

    A private↔public pair returns False (that IS a genuine network-boundary
    crossing). Used by the SMB, cleartext-protocol, and C2-beacon detectors, whose
    "to an external / internet host" logic must not fire on same-network traffic.
    Non-IP inputs (e.g. an HTTP Host header) return False (cannot be judged).
    """
    if not ip_a or not ip_b:
        return False
    try:
        a = ipaddress.ip_address(ip_a)
        b = ipaddress.ip_address(ip_b)
    except ValueError:
        return False
    if a.version != b.version:
        return False
    a_local = a.is_private or a.is_loopback or a.is_link_local
    b_local = b.is_private or b.is_loopback or b.is_link_local
    if a_local and b_local:
        return True
    if a_local != b_local:
        return False  # one local, one public → genuine boundary crossing
    # both public → same organisation only if they share the same prefix block
    same_prefix = prefix if a.version == 4 else 48
    return b in ipaddress.ip_network(f"{ip_a}/{same_prefix}", strict=False)
