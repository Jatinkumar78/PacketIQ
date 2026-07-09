"""
Packet inspection — turn a raw scapy packet into a friendly, structured view:
a one-line summary, a layer/field tree (Wireshark-style), and a hex dump.

Used by the web "Packets" browser and the AI "explain this packet" feature.
"""

from __future__ import annotations

import math
import re

from packetiq.utils.helpers import get_service_name, is_private_ip


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


# ──────────────────────────────────────────────────────────────────────────────
# Analyst brief — a professional, security-oriented view of a single packet,
# fed to the AI "explain this packet" feature. It surfaces the things a SOC
# analyst actually reads a packet for (host roles, TTL/OS fingerprint, port
# direction, payload entropy, decoded app-layer) as clean grounded facts, so the
# model reasons over analysis instead of re-describing raw scapy field names
# (which render ports as obscure service aliases like "ifsf_hb_port").
# ──────────────────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    """Shannon entropy (bits/byte, 0–8). High (>7.2) ⇒ encrypted/compressed/random."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are printable ASCII (text vs binary heuristic)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def _ttl_analysis(ttl: int):
    """Map an observed TTL to a likely initial TTL, hop count and OS family.
    Standard stack defaults: 64 (Linux/Unix/macOS/BSD/Android), 128 (Windows),
    255 (network gear / some Unix), 32 (legacy/embedded). Phrased as 'consistent
    with' — TTL is a hint, not proof."""
    for initial, os_family in ((64, "Linux / Unix / macOS / BSD / Android"),
                               (128, "Windows"),
                               (255, "a network device (router/firewall) or some Unix"),
                               (32, "a legacy or embedded stack")):
        if 0 < ttl <= initial:
            return initial, initial - ttl, os_family
    return ttl, 0, "an unusual stack"


def _ip_role(ip: str) -> str:
    if not ip:
        return ""
    try:
        return "private / internal (RFC1918)" if is_private_ip(ip) else "public / external"
    except Exception:
        return ""


def _port_role(port: int) -> str:
    """Describe a port the way an analyst reads it — a named service, or the
    IANA range it falls in — instead of scapy's obscure service aliases."""
    if port is None:
        return ""
    svc = get_service_name(port)
    if svc and svc != str(port):
        return f"{port} ({svc})"
    if port < 1024:
        return f"{port} (system/well-known, unassigned here)"
    if port >= 49152:
        return f"{port} (dynamic/ephemeral range — typical client source port)"
    return f"{port} (registered range, no common service)"


def _direction_hint(sport, dport) -> str:
    """Guess client→server direction from which side holds the well-known port."""
    def _serverish(p):
        if p is None:
            return False
        svc = get_service_name(p)
        return p < 1024 or (svc and svc != str(p))
    s_srv, d_srv = _serverish(sport), _serverish(dport)
    if d_srv and not s_srv:
        return "client → server (destination holds the service port)"
    if s_srv and not d_srv:
        return "server → client (source holds the service port)"
    return "direction unclear from ports alone"


def _tls_sni(payload: bytes) -> str:
    """Best-effort SNI (server name) extraction from a TLS ClientHello. Returns
    '' on any malformed/partial record — never raises."""
    try:
        if len(payload) < 45 or payload[0] != 0x16 or payload[5] != 0x01:
            return ""                                   # not a handshake ClientHello
        pos = 43                                        # after record(5)+hs hdr(4)+ver(2)+random(32)
        sid_len = payload[pos]; pos += 1 + sid_len      # session id
        cs_len = (payload[pos] << 8) | payload[pos + 1]; pos += 2 + cs_len   # cipher suites
        comp_len = payload[pos]; pos += 1 + comp_len    # compression methods
        if pos + 2 > len(payload):
            return ""
        ext_total = (payload[pos] << 8) | payload[pos + 1]; pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            etype = (payload[pos] << 8) | payload[pos + 1]
            elen = (payload[pos + 2] << 8) | payload[pos + 3]
            pos += 4
            if etype == 0x0000 and pos + 5 <= len(payload):        # server_name
                name_len = (payload[pos + 3] << 8) | payload[pos + 4]
                start = pos + 5
                return payload[start:start + name_len].decode("latin-1", "replace")
            pos += elen
    except Exception:
        return ""
    return ""


def _full_tcp_payload(pkt) -> bytes:
    try:
        from scapy.layers.inet import TCP
        if pkt.haslayer(TCP):
            return bytes(pkt["TCP"].payload)
    except Exception:
        pass
    return b""


def _int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def analyst_brief(pkt, index: int = 0) -> str:
    """A clean, security-oriented fact sheet for one packet, for the AI explainer.
    All facts are read straight from the packet — no interpretation, no invention."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6

    # Rebuild through bytes so scapy fills computed fields (length, ihl, checksums)
    # — captured packets have them, freshly-built ones don't. Harmless if it fails.
    try:
        pkt = pkt.__class__(bytes(pkt))
    except Exception:
        pass

    proto, sport, dport = _proto_and_ports(pkt)
    src, dst = _ips(pkt)
    lines = [
        f"PACKET #{index}",
        f"Wireshark protocol: {proto}",
        f"Info: {_wireshark_info(pkt, proto, sport, dport)}",
        f"Frame length: {len(pkt)} bytes",
        "",
    ]

    # ── Link layer ───────────────────────────────────────────────────────────
    try:
        from scapy.layers.l2 import Ether
        if pkt.haslayer(Ether):
            e = pkt[Ether]
            lines += ["ETHERNET",
                      f"  Source MAC: {e.src}",
                      f"  Dest MAC:   {e.dst}", ""]
    except Exception:
        pass

    # ── Network layer ────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        i_ttl, hops, os_family = _ttl_analysis(_int(ip.ttl))
        lines += [
            "NETWORK (IPv4)",
            f"  Source IP:      {ip.src}  [{_ip_role(ip.src)}]",
            f"  Destination IP: {ip.dst}  [{_ip_role(ip.dst)}]",
            f"  TTL:            {_int(ip.ttl)}  (likely initial {i_ttl}, ~{hops} hops away; "
            f"consistent with {os_family})",
            f"  Total length:   {_int(ip.len)} bytes, header {_int(ip.ihl, 5) * 4} bytes",
            f"  IP ID:          {_int(ip.id)}   Flags: {ip.flags}   Frag offset: {_int(ip.frag)}",
            "",
        ]
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        lines += ["NETWORK (IPv6)",
                  f"  Source IP:      {ip6.src}  [{_ip_role(ip6.src)}]",
                  f"  Destination IP: {ip6.dst}  [{_ip_role(ip6.dst)}]",
                  f"  Hop limit:      {_int(ip6.hlim)}", ""]

    # ── Transport layer ──────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        lines += [
            "TRANSPORT (TCP)",
            f"  Source port:      {_port_role(sport)}",
            f"  Destination port: {_port_role(dport)}",
            f"  Likely role:      {_direction_hint(sport, dport)}",
            f"  Flags:            {_tcp_flag_str(pkt) or str(t.flags)}",
            f"  Seq: {_int(t.seq)}   Ack: {_int(t.ack)}   Window: {_int(t.window)}",
            "",
        ]
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        lines += [
            "TRANSPORT (UDP)",
            f"  Source port:      {_port_role(sport)}",
            f"  Destination port: {_port_role(dport)}",
            f"  Likely role:      {_direction_hint(sport, dport)}",
            f"  Length:           {_int(u.len)} bytes",
            "",
        ]
    elif pkt.haslayer(ICMP):
        ic = pkt[ICMP]
        lines += ["TRANSPORT (ICMP)",
                  f"  Type: {_int(ic.type)}   Code: {_int(ic.code)}", ""]

    # ── Application layer ────────────────────────────────────────────────────
    app = []
    if proto == "DNS":
        app.append(f"  Decoded: {_dns_info(pkt)}")
    elif proto in ("HTTP", "TLS"):
        head = _tcp_payload(pkt)
        if proto == "HTTP":
            req_line = head.split(b"\r", 1)[0].decode("latin-1", "replace")[:120]
            app.append(f"  Decoded: HTTP — {req_line}")
        else:
            app.append(f"  Decoded: {_tls_info(head)}")
            sni = _tls_sni(_full_tcp_payload(pkt))
            if sni:
                app.append(f"  TLS SNI (server name requested): {sni}")
    if app:
        lines += ["APPLICATION", *app, ""]

    # ── Payload character (entropy tells encrypted/compressed vs text) ────────
    body = _full_tcp_payload(pkt)
    if not body:
        try:
            from scapy.packet import Raw
            if pkt.haslayer(Raw):
                body = bytes(pkt[Raw].load)
        except Exception:
            body = b""
    if body:
        ent = _entropy(body[:2048])
        pr = _printable_ratio(body[:2048])
        if ent >= 7.2:
            ent_note = "high — consistent with encrypted, compressed or random data"
        elif ent >= 5.0:
            ent_note = "medium — mixed binary/text"
        else:
            ent_note = "low — looks like text or structured/repetitive data"
        head_hex = " ".join(f"{b:02x}" for b in body[:24])
        ascii_prev = "".join(chr(b) if 32 <= b < 127 else "." for b in body[:48])
        lines += [
            "PAYLOAD",
            f"  Size: {len(body)} bytes",
            f"  Printable ASCII: {pr * 100:.0f}%",
            f"  Shannon entropy: {ent:.2f} / 8.00  ({ent_note})",
            f"  First bytes (hex): {head_hex}",
            f"  ASCII preview: {ascii_prev}",
            "",
        ]
    else:
        lines += ["PAYLOAD", "  No transport payload (control segment — e.g. TCP handshake/ACK).", ""]

    return "\n".join(lines)[:4000]


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
