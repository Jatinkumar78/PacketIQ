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


# HTTP request methods (with trailing space) and the response prefix — used to
# recognise a segment that actually *carries* an HTTP message, the way Wireshark
# does, rather than labelling every packet on port 80 as "HTTP".
_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                 b"PATCH ", b"TRACE ", b"CONNECT ", b"PROPFIND ", b"MKCOL ")
_TLS_VERSIONS = {0x00: "SSL 3.0", 0x01: "TLS 1.0", 0x02: "TLS 1.1",
                 0x03: "TLS 1.2", 0x04: "TLS 1.3"}
_TLS_RECORD_TYPES = {0x14: "Change Cipher Spec", 0x15: "Alert",
                     0x16: "Handshake", 0x17: "Application Data"}
_TLS_HANDSHAKE_TYPES = {
    1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
    11: "Certificate", 12: "Server Key Exchange", 13: "Certificate Request",
    14: "Server Hello Done", 15: "Certificate Verify", 16: "Client Key Exchange",
    20: "Finished",
}


def _tcp_payload(pkt) -> bytes:
    """First bytes of the TCP payload (empty for handshake/ACK-only segments)."""
    try:
        from scapy.layers.inet import TCP
        if pkt.haslayer(TCP):
            return bytes(pkt["TCP"].payload)[:64]
    except Exception:
        pass
    return b""


def _looks_http(payload: bytes) -> bool:
    """True when a TCP segment begins with an HTTP request line or response."""
    return bool(payload) and (payload.startswith(_HTTP_METHODS) or payload[:5] == b"HTTP/")


def _looks_tls(payload: bytes) -> bool:
    """True when a TCP segment begins with a plausible TLS/SSL record header:
    content-type 20-23, legacy version 0x03 0x00-0x04, and a sane record length.
    This mirrors Wireshark's heuristic so port is irrelevant (TLS on any port is
    detected, and a bare SYN/ACK on :443 is *not* mislabelled as TLS)."""
    if len(payload) < 5:
        return False
    ctype, vmaj, vmin = payload[0], payload[1], payload[2]
    if ctype not in _TLS_RECORD_TYPES or vmaj != 0x03 or vmin > 0x04:
        return False
    rec_len = (payload[3] << 8) | payload[4]
    return 0 < rec_len <= 0x4800   # max TLS record ≈ 2^14 + expansion


def _proto_and_ports(pkt):
    """Return (proto_label, sport, dport).

    The protocol label matches what Wireshark shows in its Protocol column: the
    *highest layer actually present in this packet*. A TCP segment is only called
    "HTTP" or "TLS" when its payload really carries that protocol — handshake,
    ACK and keep-alive segments stay "TCP" (regardless of port), and TLS/HTTP on
    non-standard ports is still detected.
    """
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
    elif proto == "TCP":
        payload = _tcp_payload(pkt)
        if _looks_http(payload):
            proto = "HTTP"
        elif _looks_tls(payload) or pkt.haslayer("TLS"):
            proto = "TLS"
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


def _tcp_flag_str(pkt) -> str:
    """Wireshark-style flag list for a TCP segment, e.g. 'SYN, ACK'."""
    try:
        raw = str(pkt["TCP"].flags)
    except Exception:
        return ""
    names = {"S": "SYN", "A": "ACK", "F": "FIN", "R": "RST",
             "P": "PSH", "U": "URG", "E": "ECE", "C": "CWR"}
    return ", ".join(names[c] for c in raw if c in names)


def _tls_info(payload: bytes) -> str:
    """Describe a TLS record like Wireshark: 'TLS 1.2 Client Hello'."""
    ver = _TLS_VERSIONS.get(payload[2], "TLS")
    rec = _TLS_RECORD_TYPES.get(payload[0], "Record")
    if payload[0] == 0x16 and len(payload) >= 6:               # Handshake
        return f"{ver} {_TLS_HANDSHAKE_TYPES.get(payload[5], rec)}"
    return f"{ver} {rec}"


_DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
               16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}


def _dns_info(pkt) -> str:
    """Wireshark-like DNS line: 'Standard query 0x1a2b A example.com'."""
    from scapy.layers.dns import DNS
    d = pkt[DNS]
    kind = "Standard query response" if int(getattr(d, "qr", 0)) else "Standard query"
    parts = [kind, f"0x{int(getattr(d, 'id', 0)):04x}"]
    if getattr(d, "qd", None):
        try:
            qtype = _DNS_QTYPES.get(int(d.qd.qtype), str(int(d.qd.qtype)))
            qname = d.qd.qname.decode("latin-1", "replace").rstrip(".")
            parts.append(f"{qtype} {qname}")
        except Exception:
            pass
    return " ".join(parts)[:120]


def _wireshark_info(pkt, proto, sport, dport) -> str:
    """A concise, Wireshark-like Info string for the packet list."""
    try:
        if proto == "DNS":
            return _dns_info(pkt)
        if proto in ("HTTP", "TLS"):
            payload = _tcp_payload(pkt)
            if proto == "HTTP" and payload:                    # request/status line
                return payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120]
            if proto == "TLS" and payload:
                return _tls_info(payload)
        if proto == "TCP" and sport is not None:
            t = pkt["TCP"]
            flags = _tcp_flag_str(pkt)
            plen = len(bytes(t.payload))
            bits = [f"{sport} → {dport}"]
            if flags:
                bits.append(f"[{flags}]")
            bits.append(f"Seq={t.seq}")
            if "A" in str(t.flags):
                bits.append(f"Ack={t.ack}")
            bits.append(f"Win={t.window} Len={plen}")
            return " ".join(bits)[:120]
    except Exception:
        pass
    try:
        return pkt.summary()[:160]
    except Exception:
        return proto


def summarize(pkt, index: int) -> dict:
    """One-line summary row for the packet list."""
    from packetiq.utils.helpers import ts_to_str
    src, dst = _ips(pkt)
    proto, sport, dport = _proto_and_ports(pkt)
    svc = ""
    if dport:
        s = get_service_name(dport)
        svc = s if s != str(dport) else ""
    info = _wireshark_info(pkt, proto, sport, dport)
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
