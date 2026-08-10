"""
NetFlow / IPFIX ingestion.

Parses exported flow records — Cisco **NetFlow v5**, **NetFlow v9**, and **IPFIX
(v10)** — into a PacketIQ ``ExtractionResult``, so the flow-based detectors
(port/host scan, brute force, beaconing, ICMP volume, SMB / cleartext misuse) and
IOC enrichment run on flow telemetry at collector scale, with no raw PCAP.

Input is a binary file holding one or more export datagrams, as written by a
collector or captured from the export UDP stream. The datagrams self-delimit:
v5 by the header record count, IPFIX by the header length field, and v9 by its
flowsets' own length fields. Payload-dependent detectors (credentials, JA3/TLS,
DNS/HTTP content) need packet bytes and are simply absent for flow input — the
detection engine degrades gracefully.

Field decoding follows the IANA IPFIX Information Elements; NetFlow v9 shares the
same field-type IDs for the common 5-tuple, byte/packet counters, and timestamps.
"""

import ipaddress
import struct

from packetiq.extractor.data_extractor import ExtractionResult, FlowKey, FlowStats

# IP protocol number → PacketIQ protocol label
_IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6"}

# IANA IPFIX IE / NetFlow v9 field type IDs we consume.
_F_OCTETS   = 1     # octetDeltaCount (bytes)
_F_PACKETS  = 2     # packetDeltaCount
_F_PROTO    = 4     # protocolIdentifier
_F_SRCPORT  = 7     # sourceTransportPort
_F_SRCIP4   = 8     # sourceIPv4Address
_F_DSTPORT  = 11    # destinationTransportPort
_F_DSTIP4   = 12    # destinationIPv4Address
_F_LAST_SU  = 21    # flowEndSysUpTime      (ms since device boot)
_F_FIRST_SU = 22    # flowStartSysUpTime    (ms since device boot)
_F_SRCIP6   = 27    # sourceIPv6Address
_F_DSTIP6   = 28    # destinationIPv6Address
_F_START_SEC = 150  # flowStartSeconds      (absolute)
_F_END_SEC   = 151  # flowEndSeconds
_F_START_MS  = 152  # flowStartMilliseconds (absolute)
_F_END_MS    = 153  # flowEndMilliseconds


class NetFlowError(ValueError):
    """Raised when the input is not a recognisable NetFlow/IPFIX stream."""


def _int(b: bytes) -> int:
    return int.from_bytes(b, "big") if b else 0


def _ip(b: bytes):
    """Decode a 4- or 16-byte address field to a string, else None.

    Any 4 bytes are a valid packed IPv4 address and any 16 a valid IPv6 one, so
    the width check is the whole validation — the ValueError handler that used
    to wrap this could never fire on the packed slices the decoder passes in.
    """
    if len(b) == 4:
        return str(ipaddress.IPv4Address(b))
    if len(b) == 16:
        return str(ipaddress.IPv6Address(b))
    return None


class _Decoder:
    """Accumulates parsed flow records across every datagram in a file.

    Keeps the v9/IPFIX template cache (template_id → [(field_type, length), …])
    and the current export-time context (unix seconds + device sys-uptime) so
    sys-uptime-relative timestamps can be converted to absolute epoch seconds.
    """

    def __init__(self) -> None:
        self.templates: dict = {}
        self.records: list = []       # normalised flow dicts
        self.export_secs = 0.0
        self.export_uptime_ms = 0

    # ── absolute-time helper ────────────────────────────────────────────────
    def _abs(self, fields: dict) -> tuple:
        """Return (first_seen, last_seen) epoch seconds from whichever timestamp
        fields the template carried, falling back to the datagram export time."""
        if _F_START_MS in fields:
            first = fields[_F_START_MS] / 1000.0
            last = fields.get(_F_END_MS, fields[_F_START_MS]) / 1000.0
        elif _F_START_SEC in fields:
            first = float(fields[_F_START_SEC])
            last = float(fields.get(_F_END_SEC, fields[_F_START_SEC]))
        elif _F_FIRST_SU in fields:
            base = self.export_secs - self.export_uptime_ms / 1000.0
            first = base + fields[_F_FIRST_SU] / 1000.0
            last = base + fields.get(_F_LAST_SU, fields[_F_FIRST_SU]) / 1000.0
        else:
            first = last = self.export_secs
        return first, max(first, last)

    def _emit(self, fields: dict) -> None:
        src = fields.get(_F_SRCIP4) or fields.get(_F_SRCIP6)
        dst = fields.get(_F_DSTIP4) or fields.get(_F_DSTIP6)
        if not src or not dst:
            return
        first, last = self._abs(fields)
        self.records.append({
            "src": src, "dst": dst,
            "sport": fields.get(_F_SRCPORT, 0), "dport": fields.get(_F_DSTPORT, 0),
            "proto": _IP_PROTO.get(fields.get(_F_PROTO, 0), "OTHER"),
            "packets": fields.get(_F_PACKETS, 0) or 1,
            "bytes": fields.get(_F_OCTETS, 0),
            "first": first, "last": last,
        })

    # ── NetFlow v5 (fixed 48-byte records) ──────────────────────────────────
    def parse_v5(self, data: bytes, off: int) -> int:
        if off + 24 > len(data):
            raise NetFlowError("truncated v5 header")
        _, count, uptime, secs, _nsecs, _seq, _et, _eid, _si = \
            struct.unpack_from("!HHIIIIBBH", data, off)
        self.export_secs, self.export_uptime_ms = float(secs), uptime
        pos = off + 24
        for _ in range(count):
            if pos + 48 > len(data):
                break
            (saddr, daddr, _nh, _in, _out, dpkts, doct, first, last,
             sport, dport, _p1, _flags, prot, *_rest) = \
                struct.unpack_from("!IIIHHIIIIHHBBBBHHBBH", data, pos)
            fields = {
                _F_SRCIP4: str(ipaddress.IPv4Address(saddr)),
                _F_DSTIP4: str(ipaddress.IPv4Address(daddr)),
                _F_SRCPORT: sport, _F_DSTPORT: dport, _F_PROTO: prot,
                _F_PACKETS: dpkts, _F_OCTETS: doct,
                _F_FIRST_SU: first, _F_LAST_SU: last,
            }
            self._emit(fields)
            pos += 48
        return off + 24 + count * 48

    # ── template decoding shared by v9 / IPFIX ──────────────────────────────
    def _read_template_set(self, payload: bytes, ipfix: bool) -> None:
        p = 0
        while p + 4 <= len(payload):
            tid, field_count = struct.unpack_from("!HH", payload, p)
            p += 4
            if tid == 0:
                break
            fields = []
            for _ in range(field_count):
                if p + 4 > len(payload):
                    break
                ftype, flen = struct.unpack_from("!HH", payload, p)
                p += 4
                # IPFIX enterprise fields carry a 4-byte PEN we skip over.
                if ipfix and (ftype & 0x8000):
                    p += 4
                    ftype &= 0x7FFF
                fields.append((ftype, flen))
            self.templates[tid] = fields

    def _read_data_set(self, tid: int, payload: bytes) -> None:
        template = self.templates.get(tid)
        if not template:
            return  # data before its template — cannot decode, skip
        rec_len = sum(flen for _t, flen in template if flen != 0xFFFF)
        has_var = any(flen == 0xFFFF for _t, flen in template)
        p = 0
        while p < len(payload):
            if not has_var and (len(payload) - p) < rec_len:
                break
            fields: dict = {}
            start = p
            ok = True
            for ftype, flen in template:
                if flen == 0xFFFF:                       # RFC 7011 variable length
                    if p >= len(payload):
                        ok = False; break
                    ln = payload[p]; p += 1
                    if ln == 255:
                        if p + 2 > len(payload):
                            ok = False; break
                        ln = struct.unpack_from("!H", payload, p)[0]; p += 2
                    flen = ln
                if p + flen > len(payload):
                    ok = False; break
                raw = payload[p:p + flen]; p += flen
                if ftype in (_F_SRCIP4, _F_DSTIP4, _F_SRCIP6, _F_DSTIP6):
                    fields[ftype] = _ip(raw)
                else:
                    fields[ftype] = _int(raw)
            if not ok or p == start:
                break
            self._emit(fields)

    # ── NetFlow v9 (flowsets self-delimit by their length field) ────────────
    def parse_v9(self, data: bytes, off: int) -> int:
        if off + 20 > len(data):
            raise NetFlowError("truncated v9 header")
        _, _count, uptime, secs, _seq, _src_id = struct.unpack_from("!HHIIII", data, off)
        self.export_secs, self.export_uptime_ms = float(secs), uptime
        pos = off + 20
        while pos + 4 <= len(data):
            fsid, fslen = struct.unpack_from("!HH", data, pos)
            # A flowset id is 0 (template), 1 (options), or ≥256 (data). Anything
            # else (e.g. a version number) means we've reached the next datagram.
            if fslen < 4 or (fsid not in (0, 1) and fsid < 256):
                break
            payload = data[pos + 4: pos + fslen]
            if fsid == 0:
                self._read_template_set(payload, ipfix=False)
            elif fsid >= 256:
                self._read_data_set(fsid, payload)
            pos += fslen
        return pos

    # ── IPFIX / v10 (header carries total length) ───────────────────────────
    def parse_ipfix(self, data: bytes, off: int) -> int:
        if off + 16 > len(data):
            raise NetFlowError("truncated IPFIX header")
        _, length, secs, _seq, _domain = struct.unpack_from("!HHIII", data, off)
        if length < 16:
            raise NetFlowError("invalid IPFIX length")
        self.export_secs, self.export_uptime_ms = float(secs), 0
        end = min(off + length, len(data))
        pos = off + 16
        while pos + 4 <= end:
            setid, setlen = struct.unpack_from("!HH", data, pos)
            if setlen < 4:
                break
            payload = data[pos + 4: pos + setlen]
            if setid == 2:
                self._read_template_set(payload, ipfix=True)
            elif setid >= 256:
                self._read_data_set(setid, payload)
            pos += setlen
        return off + length


def parse_netflow(data: bytes) -> list:
    """Parse a binary NetFlow/IPFIX byte stream into normalised flow-record dicts."""
    dec = _Decoder()
    off = 0
    n = len(data)
    parsed_any = False
    while off + 2 <= n:
        version = struct.unpack_from("!H", data, off)[0]
        if version == 5:
            off = dec.parse_v5(data, off)
        elif version == 9:
            off = dec.parse_v9(data, off)
        elif version == 10:
            off = dec.parse_ipfix(data, off)
        else:
            # Anything else is either padding a collector appended after a good
            # datagram, or a file that was never an export in the first place.
            if parsed_any:
                break
            raise NetFlowError(f"unrecognised export version {version}")
        parsed_any = True
    return dec.records


def load_netflow(path: str) -> ExtractionResult:
    """Parse a NetFlow v5 / v9 / IPFIX export file into an ExtractionResult."""
    from packetiq.utils.helpers import is_private_ip

    with open(path, "rb") as fh:
        records = parse_netflow(fh.read())

    r = ExtractionResult()
    proto_counts: dict = {}
    dst_ports: dict = {}
    src_ports: dict = {}
    ip_src: dict = {}
    ip_dst: dict = {}
    flows: dict = {}
    syn_map: dict = {}
    first_ts = last_ts = None

    for rec in records:
        src, dst = rec["src"], rec["dst"]
        sport, dport, proto = rec["sport"], rec["dport"], rec["proto"]
        pkts, nbytes = rec["packets"], rec["bytes"]
        ts, end = rec["first"], rec["last"]

        r.total_packets += pkts
        r.total_bytes += nbytes
        if ts:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            last_ts = end if last_ts is None else max(last_ts, end)

        proto_counts[proto] = proto_counts.get(proto, 0) + pkts
        ip_src[src] = ip_src.get(src, 0) + pkts
        ip_dst[dst] = ip_dst.get(dst, 0) + pkts
        r.unique_src_ips.add(src)
        r.unique_dst_ips.add(dst)
        if not is_private_ip(src):
            r.external_ips.add(src)
        if not is_private_ip(dst):
            r.external_ips.add(dst)
        if dport:
            dst_ports[dport] = dst_ports.get(dport, 0) + pkts
        if sport:
            src_ports[sport] = src_ports.get(sport, 0) + pkts

        fk = FlowKey(src, dst, sport, dport, proto).canonical()
        fs = flows.get(fk)
        if fs is None:
            fs = FlowStats(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                           protocol=proto, service="", first_seen=ts, last_seen=end)
            flows[fk] = fs
        fs.packets += pkts
        fs.bytes_total += nbytes
        fs.first_seen = min(fs.first_seen, ts) if fs.first_seen else ts
        fs.last_seen = max(fs.last_seen, end)

        if proto == "TCP":
            syn_map.setdefault((src, dst, dport), []).append(ts)

    r.protocol_counts = proto_counts
    r.dst_port_counts = dst_ports
    r.src_port_counts = src_ports
    r.ip_src_counts = ip_src
    r.ip_dst_counts = ip_dst
    r.flows = flows
    r.tcp_syn_pairs = syn_map
    r.capture_start = first_ts or 0.0
    r.capture_end = last_ts or 0.0
    return r
