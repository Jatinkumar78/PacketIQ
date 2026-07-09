"""Tests for NetFlow v5 / v9 / IPFIX ingestion (packetiq.inputs.netflow)."""
import ipaddress
import struct

import pytest

from packetiq.detection.engine import DetectionEngine
from packetiq.inputs.netflow import NetFlowError, load_netflow, parse_netflow

UNIX = 1_700_000_000
UPTIME = 100_000  # device sys-uptime (ms) at export


def _ip(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


# ── NetFlow v5 (fixed 48-byte records) ──────────────────────────────────────
def _v5(records: list) -> bytes:
    """records: list of (src, dst, sport, dport, proto, pkts, octets)."""
    hdr = struct.pack("!HHIIIIBBH", 5, len(records), UPTIME, UNIX, 0, 0, 0, 0, 0)
    body = b""
    for i, (src, dst, sp, dp, proto, pkts, octets) in enumerate(records):
        first = UPTIME - 5000 + i          # ms since boot
        last = first + 10
        body += struct.pack(
            "!IIIHHIIIIHHBBBBHHBBH",
            _ip(src), _ip(dst), 0, 0, 0, pkts, octets, first, last,
            sp, dp, 0, 0, proto, 0, 0, 0, 0, 0, 0,
        )
    return hdr + body


def test_v5_parses_flows_and_fields():
    data = _v5([("203.0.113.9", "192.168.1.10", 44000, 443, 6, 5, 4000),
                ("8.8.8.8", "192.168.1.10", 53, 55000, 17, 2, 300)])
    recs = parse_netflow(data)
    assert len(recs) == 2
    tcp = next(r for r in recs if r["proto"] == "TCP")
    assert tcp["src"] == "203.0.113.9" and tcp["dst"] == "192.168.1.10"
    assert tcp["dport"] == 443 and tcp["packets"] == 5 and tcp["bytes"] == 4000
    # absolute timestamp reconstructed from sys-uptime + export epoch
    assert abs(tcp["first"] - (UNIX - 5.0)) < 1.0
    assert any(r["proto"] == "UDP" for r in recs)


def test_v5_vertical_scan_triggers_detection(tmp_path):
    # one source hitting 25 distinct ports on one host → vertical PORT_SCAN
    recs = [("203.0.113.9", "192.168.1.10", 50000 + p, 20 + p, 6, 1, 40)
            for p in range(25)]
    f = tmp_path / "scan.nflow"
    f.write_bytes(_v5(recs))
    result = load_netflow(str(f))
    assert len(result.flows) == 25
    assert result.total_packets == 25
    events, risk, _ = DetectionEngine().run(result, str(f))
    assert any(e.event_type.value == "PORT_SCAN" for e in events)
    assert risk.score > 0


# ── NetFlow v9 / IPFIX (template + data) ────────────────────────────────────
# 7-field template: SRCIP4(8), DSTIP4(12), SRCPORT(7), DSTPORT(11), PROTO(4),
# PKTS(2), OCTETS(1).
_TMPL_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4)]
_REC_LEN = sum(ln for _t, ln in _TMPL_FIELDS)  # 21


def _data_record(src, dst, sp, dp, proto, pkts, octets) -> bytes:
    return (struct.pack("!II", _ip(src), _ip(dst))
            + struct.pack("!HHB", sp, dp, proto)
            + struct.pack("!II", pkts, octets))


def _v9(records: list, tid: int = 256) -> bytes:
    tmpl = struct.pack("!HH", tid, len(_TMPL_FIELDS))
    for ft, fl in _TMPL_FIELDS:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_fs = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    body = b"".join(_data_record(*r) for r in records)
    pad = (-len(body)) % 4
    data_fs = struct.pack("!HH", tid, 4 + len(body) + pad) + body + b"\x00" * pad
    hdr = struct.pack("!HHIIII", 9, len(records), UPTIME, UNIX, 0, 1)
    return hdr + tmpl_fs + data_fs


def _ipfix(records: list, tid: int = 256) -> bytes:
    tmpl = struct.pack("!HH", tid, len(_TMPL_FIELDS))
    for ft, fl in _TMPL_FIELDS:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl
    body = b"".join(_data_record(*r) for r in records)
    data_set = struct.pack("!HH", tid, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)
    hdr = struct.pack("!HHIII", 10, total, UNIX, 0, 0)
    return hdr + tmpl_set + data_set


def test_v9_template_and_data():
    data = _v9([("10.0.0.5", "93.184.216.34", 40000, 443, 6, 10, 8000),
                ("10.0.0.5", "1.1.1.1", 40001, 53, 17, 1, 90)])
    recs = parse_netflow(data)
    assert len(recs) == 2
    r0 = recs[0]
    assert r0["src"] == "10.0.0.5" and r0["dst"] == "93.184.216.34"
    assert r0["dport"] == 443 and r0["proto"] == "TCP" and r0["bytes"] == 8000
    assert recs[1]["proto"] == "UDP" and recs[1]["dport"] == 53


def test_ipfix_template_and_data(tmp_path):
    data = _ipfix([("172.16.0.9", "45.33.32.156", 51000, 445, 6, 3, 500)])
    f = tmp_path / "flows.ipfix"
    f.write_bytes(data)
    result = load_netflow(str(f))
    assert len(result.flows) == 1
    fs = next(iter(result.flows.values()))
    assert fs.dst_port == 445 and fs.protocol == "TCP" and fs.bytes_total == 500
    # SMB (445) crossing private→public must trip PROTOCOL_MISUSE
    events, _risk, _ = DetectionEngine().run(result, str(f))
    assert any(e.event_type.value == "PROTOCOL_MISUSE" for e in events)


def test_multiple_v5_datagrams_concatenated():
    data = _v5([("10.0.0.1", "10.0.0.2", 1, 2, 6, 1, 10)]) \
        + _v5([("10.0.0.3", "10.0.0.4", 3, 4, 17, 1, 10)])
    recs = parse_netflow(data)
    assert len(recs) == 2
    assert {r["src"] for r in recs} == {"10.0.0.1", "10.0.0.3"}


def test_unrecognised_stream_raises():
    with pytest.raises(NetFlowError):
        parse_netflow(b"\x00\x63not a netflow datagram at all")


def test_data_before_template_is_skipped_not_crash():
    # a v9 datagram whose data flowset references an unknown template → no records,
    # no exception (graceful degradation)
    body = _data_record("10.0.0.1", "10.0.0.2", 1, 2, 6, 1, 10)
    data_fs = struct.pack("!HH", 999, 4 + len(body)) + body
    hdr = struct.pack("!HHIIII", 9, 1, UPTIME, UNIX, 0, 1)
    recs = parse_netflow(hdr + data_fs)
    assert recs == []


# ── Web-app wiring (parity with the CLI `netflow` command) ──────────────────
def test_webapp_ingests_netflow_export(tmp_path, monkeypatch):
    """A raw NetFlow export analyses end-to-end through the web API — the same
    upload → detect → results path a PCAP takes, routed by extension."""
    from fastapi.testclient import TestClient

    from packetiq.webapp import create_app

    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "nf.db"))
    # one source hitting 25 distinct ports on one host → vertical PORT_SCAN
    data = _v5([("203.0.113.9", "192.168.1.10", 50000 + p, 20 + p, 6, 1, 40) for p in range(25)])
    with TestClient(create_app()) as client:
        r = client.post("/api/analyze",
                        files={"file": ("scan.netflow", data, "application/octet-stream")})
        assert r.status_code == 200, r.text
        res = r.json()
        assert res["meta"]["unique_flows"] == 25
        assert any(e["event_type"] == "PORT_SCAN" for e in res["events"])


def test_webapp_detects_netflow_by_magic_bytes(tmp_path, monkeypatch):
    """Even with an unfamiliar extension, a flow export is recognised by its
    NetFlow version word (first two bytes) rather than misparsed as a PCAP."""
    from fastapi.testclient import TestClient

    from packetiq.webapp import create_app

    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "nf2.db"))
    data = _v5([("203.0.113.9", "192.168.1.10", 50000 + p, 20 + p, 6, 1, 40) for p in range(25)])
    with TestClient(create_app()) as client:
        r = client.post("/api/analyze",
                        files={"file": ("export.bin", data, "application/octet-stream")})
        assert r.status_code == 200, r.text
        assert r.json()["meta"]["unique_flows"] == 25
