"""
Zeek conn.log ingestion.

Builds a PacketIQ ExtractionResult directly from a Zeek `conn.log` (TSV or
JSON-lines), so flow-based detectors (port/host scan, brute force, beaconing,
ICMP volume) and IOC enrichment can run on flow logs at enterprise scale
without a raw PCAP.

Payload-based detectors (credential exposure, JA3/TLS) require packet contents
and are skipped for log input — the engine handles their absence gracefully.
"""

import json
from typing import Optional

from packetiq.extractor.data_extractor import ExtractionResult, FlowKey, FlowStats

_PROTO_MAP = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP"}


def _to_float(v, default=0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _to_int(v, default=0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _iter_records(path: str):
    """Yield dict records from a Zeek conn.log in TSV or JSON-lines format."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
        fh.seek(0)
        stripped = first.lstrip()
        if stripped.startswith("{"):
            # JSON-lines
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
            return

        # TSV with Zeek '#fields' header
        fields: Optional[list] = None
        for line in fh:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                continue
            values = line.rstrip("\n").split("\t")
            yield dict(zip(fields, values))


def load_conn_log(path: str) -> ExtractionResult:
    """Parse a Zeek conn.log into an ExtractionResult."""
    r = ExtractionResult()
    from packetiq.utils.helpers import is_private_ip

    proto_counts: dict = {}
    dst_ports: dict = {}
    src_ports: dict = {}
    ip_src: dict = {}
    ip_dst: dict = {}
    flows: dict = {}
    syn_map: dict = {}
    first_ts = last_ts = None

    for rec in _iter_records(path):
        src = rec.get("id.orig_h") or rec.get("orig_h")
        dst = rec.get("id.resp_h") or rec.get("resp_h")
        if not src or not dst:
            continue
        sport = _to_int(rec.get("id.orig_p") or rec.get("orig_p"))
        dport = _to_int(rec.get("id.resp_p") or rec.get("resp_p"))
        proto = _PROTO_MAP.get(str(rec.get("proto", "")).lower(), "OTHER")
        ts = _to_float(rec.get("ts"))
        duration = _to_float(rec.get("duration"))
        orig_bytes = _to_int(rec.get("orig_bytes"))
        resp_bytes = _to_int(rec.get("resp_bytes"))
        orig_pkts = _to_int(rec.get("orig_pkts"))
        resp_pkts = _to_int(rec.get("resp_pkts"))
        pkts = (orig_pkts + resp_pkts) or 1
        nbytes = orig_bytes + resp_bytes

        # totals
        r.total_packets += pkts
        r.total_bytes += nbytes
        if ts:
            first_ts = ts if first_ts is None else min(first_ts, ts)
            end = ts + max(duration, 0.0)
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

        # flow (bidirectional canonical key)
        fk = FlowKey(src, dst, sport, dport, proto).canonical()
        fs = flows.get(fk)
        if fs is None:
            fs = FlowStats(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
                           protocol=proto, service="", first_seen=ts, last_seen=ts + duration)
            flows[fk] = fs
        fs.packets += pkts
        fs.bytes_total += nbytes
        fs.first_seen = min(fs.first_seen, ts) if fs.first_seen else ts
        fs.last_seen = max(fs.last_seen, ts + duration)

        # one "SYN" timestamp per TCP connection record (enables brute force + beacon)
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
