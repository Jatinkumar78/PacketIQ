"""
Packet inspection — turn a raw scapy packet into a friendly, structured view:
a one-line summary, a layer/field tree (Wireshark-style), and a hex dump.

Used by the web "Packets" browser and the AI "explain this packet" feature.
"""

from __future__ import annotations

import re

from packetiq.utils.helpers import get_service_name


def _ips(pkt):
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    try:
        from scapy.layers.l2 import Ether
        if pkt.haslayer(Ether):
            return pkt[Ether].src, pkt[Ether].dst
    except Exception:
        pass
    return "", ""


def _proto_and_ports(pkt):
    """Return (proto_label, sport, dport)."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, TCP, UDP
    sport = dport = None
    proto = pkt.name or "frame"
    if pkt.haslayer(TCP):
        t = pkt["TCP"]; sport, dport = int(t.sport), int(t.dport)
        proto = "TCP"
    elif pkt.haslayer(UDP):
        u = pkt["UDP"]; sport, dport = int(u.sport), int(u.dport)
        proto = "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
    elif pkt.haslayer("ARP"):
        proto = "ARP"
    if pkt.haslayer(DNS):
        proto = "DNS"
    elif pkt.haslayer("TLS") or dport in (443, 8443) or sport in (443, 8443):
        if proto == "TCP":
            proto = "TLS" if (pkt.haslayer("TLS")) else "TCP/443"
    elif dport in (80, 8080) or sport in (80, 8080):
        if proto == "TCP":
            proto = "HTTP"
    return proto, sport, dport


# Well-known ports → protocol token, so search finds e.g. TLS on a 443 SYN.
_PORT_PROTOCOLS = {
    443: ("tls", "https"), 8443: ("tls", "https"), 80: ("http",), 8080: ("http",),
    53: ("dns",), 22: ("ssh",), 21: ("ftp",), 23: ("telnet",), 25: ("smtp",),
    110: ("pop3",), 143: ("imap",), 389: ("ldap",), 445: ("smb",), 139: ("smb",),
    3389: ("rdp",), 123: ("ntp",), 67: ("dhcp",), 68: ("dhcp",), 161: ("snmp",),
    1883: ("mqtt",), 5060: ("sip",), 3306: ("mysql",), 5432: ("postgres",),
}


def _protocol_tokens(pkt, proto, sport, dport, svc) -> list:
    """All protocol tokens a packet belongs to — used for precise search
    (e.g. 'http' must not match 'https', and 'tls' finds port-443 traffic)."""
    toks: set = set()
    for t in re.split(r"[/\s]+", (proto or "").lower()):
        if t and not t.isdigit():
            toks.add(t)
    try:
        from scapy.layers.inet import TCP, UDP
        if pkt.haslayer(TCP):
            toks.add("tcp")
        if pkt.haslayer(UDP):
            toks.add("udp")
    except Exception:
        pass
    for port in (sport, dport):
        toks.update(_PORT_PROTOCOLS.get(port, ()))
    if svc:
        toks.add(svc.lower())
    return sorted(toks)


def summarize(pkt, index: int) -> dict:
    """One-line summary row for the packet list."""
    from packetiq.utils.helpers import ts_to_str
    src, dst = _ips(pkt)
    proto, sport, dport = _proto_and_ports(pkt)
    svc = ""
    if dport:
        s = get_service_name(dport)
        svc = s if s != str(dport) else ""
    try:
        info = pkt.summary()
    except Exception:
        info = proto
    ts = float(getattr(pkt, "time", 0.0) or 0.0)
    return {
        "no": index,
        "time": ts,
        "ts_str": ts_to_str(ts) if ts else "",
        "src": f"{src}:{sport}" if (src and sport) else src,
        "dst": f"{dst}:{dport}" if (dst and dport) else dst,
        "proto": proto,
        "service": svc,
        "length": len(pkt),
        "info": info[:160],
        "protocols": _protocol_tokens(pkt, proto, sport, dport, svc),
    }


def _hexdump(data: bytes, width: int = 16) -> list:
    rows = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append({"offset": f"{off:04x}", "hex": hexs, "ascii": asci})
    return rows


def _field_value(layer, fd) -> str:
    try:
        val = layer.getfieldval(fd.name)
        disp = layer.get_field(fd.name).i2repr(layer, val)
    except Exception:
        try:
            disp = repr(layer.getfieldval(fd.name))
        except Exception:
            disp = ""
    disp = str(disp)
    return disp if len(disp) <= 300 else disp[:300] + "…"


def dissect(pkt, index: int = 0) -> dict:
    """Full structured view: summary + layer/field tree + hex dump."""
    from scapy.packet import NoPayload
    layers = []
    layer = pkt
    guard = 0
    while layer is not None and not isinstance(layer, NoPayload) and guard < 64:
        guard += 1
        fields = []
        for fd in getattr(layer, "fields_desc", []) or []:
            fields.append({"name": fd.name, "value": _field_value(layer, fd)})
        layers.append({"name": layer.name, "fields": fields})
        layer = layer.payload
    try:
        raw = bytes(pkt)
    except Exception:
        raw = b""
    return {
        "summary": summarize(pkt, index),
        "layers": layers,
        "hex": _hexdump(raw),
        "length": len(raw),
    }


# Tokens treated as protocol filters (exact, not substring) so 'http' ≠ 'https'.
_PROTO_KEYWORDS = {
    "http", "https", "tls", "ssl", "dns", "tcp", "udp", "icmp", "arp", "ssh", "ftp",
    "telnet", "smtp", "pop3", "imap", "ldap", "smb", "rdp", "ntp", "dhcp", "snmp",
    "mqtt", "sip", "mysql", "postgres", "quic",
}
_TLS_GROUP = {"tls", "ssl", "https"}


def matches(summary: dict, q: str) -> bool:
    """
    Search a packet summary. Multi-token, case-insensitive, AND semantics.
    Protocol keywords (http, tls, dns…) are matched *exactly* against the
    packet's protocol set — so 'http' matches HTTP but not HTTPS, and 'tls'
    finds port-443 traffic. Anything else is a substring match over the
    addresses / info text.
    """
    if not q or not q.strip():
        return True
    protos = set(summary.get("protocols") or [])
    hay = " ".join(str(summary.get(k, "")) for k in
                   ("src", "dst", "proto", "service", "info")).lower()
    for tok in q.lower().split():
        if tok in _PROTO_KEYWORDS:
            want = _TLS_GROUP if tok in _TLS_GROUP else {tok}
            if not (want & protos):
                return False
        elif tok not in hay:
            return False
    return True
