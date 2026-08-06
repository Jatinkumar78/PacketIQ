"""
Utility helpers — formatting, protocol mapping, conversions.
"""

import ipaddress
import socket
import struct
from datetime import datetime
from typing import Optional

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


def format_bytes(size: float) -> str:
    """Human-readable byte size."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


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


def _ip_network_key(ip: str) -> Optional[str]:
    """The L2-segment-sized network an address belongs to (/24 v4, /64 v6)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def monitored_network(result) -> set:
    """The set of IPs the capture gives evidence sit on the network being watched.

    This exists because RFC1918 addressing is only a *proxy* for "internal". A
    university or hosting LAN can be publicly addressed (e.g. CTU's
    147.32.0.0/16); treating those hosts as internet peers produces false
    positives, and treating a web server we merely browsed as "ours" produces
    the opposite kind. Evidence is applied strongest-first:

    1. **Router elimination.** A host on the segment sends frames from its own
       NIC, so its IP pairs with its own MAC. Hosts reached *through* a router
       all share the router's MAC, so a MAC carrying addresses from two or more
       different networks is a router and none of its addresses are local.
    2. **One segment, one subnet.** What survives should be a single broadcast
       domain. If it still spans several networks we keep the dominant one —
       most distinct NICs first, private addressing as the tie-break — plus any
       private and IPv6 link-local addresses, which cannot be routed in.
    3. **Fallback.** With no link-layer data at all (NetFlow, Zeek, cooked
       captures) fall back to RFC1918. If even that yields nothing we return an
       empty set, and callers must not claim to know where the boundary is.
    """
    ip_to_mac: dict = getattr(result, "ip_to_mac", None) or {}
    if ip_to_mac:
        # Group per address family: one dual-stack host legitimately owns an
        # IPv4 /24 *and* an IPv6 /64, which must not read as "spans two
        # networks, therefore a router".
        mac_nets: dict = {}
        for ip, mac in ip_to_mac.items():
            net = _ip_network_key(ip)
            if net:
                family = 6 if ":" in ip else 4
                mac_nets.setdefault((mac, family), set()).add(net)
        router_macs = {mac for (mac, _fam), nets in mac_nets.items() if len(nets) >= 2}
        survivors = {ip for ip, mac in ip_to_mac.items() if ip and mac not in router_macs}

        by_net: dict = {}
        for ip in survivors:
            net = _ip_network_key(ip)
            if net:
                by_net.setdefault(net, set()).add(ip_to_mac.get(ip))
        if len(by_net) > 1:
            def _score(item):
                net, macs = item
                private = net.split("/")[0].startswith(("10.", "192.168.", "172."))
                return (len(macs), private)
            best = max(by_net.items(), key=_score)[0]
            survivors = {
                ip for ip in survivors
                if _ip_network_key(ip) == best
                or is_private_ip(ip)
                or ip.lower().startswith("fe80:")
            }
        if survivors:
            return survivors

    return {ip for ip in (getattr(result, "transmitted_ips", None) or set())
            if ip and is_private_ip(ip)}


# ── MAC OUI → vendor (partial, curated) ───────────────────────────────────────
# A best-effort identification of a NIC's manufacturer from the first 3 octets
# (the IEEE OUI). Deliberately partial — a curated set of the vendors commonly
# seen in enterprise/lab captures — and returns "" when unknown rather than
# guessing, so the device inventory never shows a fabricated vendor.
_OUI_VENDOR = {
    "00:1b:d4": "Cisco", "00:00:0c": "Cisco", "00:1a:a1": "Cisco", "00:1e:14": "Cisco",
    "00:1e:4a": "Cisco", "00:24:14": "Cisco", "cc:46:d6": "Cisco", "00:0c:29": "VMware",
    "00:05:69": "VMware", "00:50:56": "VMware", "00:1c:14": "VMware", "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM", "00:16:3e": "Xen", "00:15:5d": "Microsoft Hyper-V",
    "00:e0:4c": "Realtek", "52:54:ab": "Realtek", "00:1a:4b": "Hewlett-Packard",
    "08:62:66": "Hewlett-Packard", "00:21:5a": "Hewlett-Packard", "3c:d9:2b": "Hewlett-Packard",
    "00:1b:78": "Hewlett-Packard", "00:0e:7f": "Hewlett-Packard", "00:26:55": "Hewlett-Packard",
    "00:1c:c4": "Hewlett-Packard", "00:14:22": "Dell", "00:21:9b": "Dell", "18:03:73": "Dell",
    "b8:2a:72": "Dell", "00:1e:c9": "Dell", "f8:bc:12": "Dell", "00:1b:21": "Intel",
    "00:1c:c0": "Intel", "00:15:17": "Intel", "3c:97:0e": "Intel", "a0:88:b4": "Intel",
    "00:aa:00": "Intel", "8c:16:45": "Intel", "00:03:93": "Apple", "00:1e:c2": "Apple",
    "00:25:00": "Apple", "3c:07:54": "Apple", "a4:5e:60": "Apple", "f0:18:98": "Apple",
    "ac:bc:32": "Apple", "00:1d:4f": "Apple", "d0:23:db": "Apple", "00:26:bb": "Apple",
    "00:09:0f": "Fortinet", "00:0d:b9": "PC Engines", "00:90:a9": "Western Digital",
    "b0:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "00:1f:29": "Hewlett-Packard", "00:24:e8": "Dell", "00:12:3f": "Dell",
    "00:07:e9": "Intel", "00:13:72": "Dell", "00:0f:1f": "Dell", "d4:be:d9": "Dell",
    "00:50:ba": "D-Link", "00:1c:f0": "D-Link", "00:26:5a": "D-Link", "c8:be:19": "D-Link",
    "00:1d:7e": "Cisco-Linksys", "00:23:69": "Cisco-Linksys", "00:25:9c": "Cisco-Linksys",
    "00:14:bf": "Cisco-Linksys", "00:18:39": "Cisco-Linksys", "00:1e:e5": "Cisco-Linksys",
    "00:90:4c": "Epson", "b4:2e:99": "GIGA-BYTE", "1c:1b:0d": "GIGA-BYTE",
    "00:24:1d": "GIGA-BYTE", "00:1f:d0": "GIGA-BYTE", "40:8d:5c": "GIGA-BYTE",
    "00:0d:88": "D-Link", "00:19:e0": "TP-Link", "00:27:19": "TP-Link", "50:c7:bf": "TP-Link",
    "14:cc:20": "TP-Link", "a4:2b:b0": "TP-Link", "00:1d:0f": "TP-Link",
    "00:04:96": "Extreme", "00:1f:45": "Enterasys", "00:e0:1e": "Cisco",
    "00:60:2f": "Cisco", "00:d0:58": "Cisco", "00:0a:41": "Cisco", "00:11:20": "Cisco",
}


def oui_vendor(mac: str) -> str:
    """Best-effort NIC-manufacturer name from a MAC's OUI, or "" when unknown.
    Locally-administered / multicast MACs (bit 0x2 of the first octet set) carry
    no real OUI, so no vendor is claimed for them."""
    if not mac or len(mac) < 8:
        return ""
    mac = mac.strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        return ""
    try:
        first = int(parts[0], 16)
    except ValueError:
        return ""
    if first & 0x2:                       # locally-administered / randomised MAC
        return ""
    return _OUI_VENDOR.get(":".join(parts[:3]), "")
