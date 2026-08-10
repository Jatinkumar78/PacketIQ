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


# ── Malformed and unusual exports ───────────────────────────────────────────
#
# Flow exports arrive over UDP from third-party network gear. Truncation,
# padding and vendor quirks are normal, and every one of these paths decides
# between "decode what we can" and "raise on the whole datagram".

@pytest.mark.parametrize("header,expect", [
    (struct.pack("!HH", 5, 1), "truncated v5 header"),
    (struct.pack("!HHIIII", 9, 1, UPTIME, UNIX, 0, 1)[:12], "truncated v9 header"),
    (struct.pack("!HHIII", 10, 40, UNIX, 0, 0)[:10], "truncated IPFIX header"),
])
def test_a_truncated_header_is_rejected_with_a_specific_reason(header, expect):
    with pytest.raises(NetFlowError, match=expect):
        parse_netflow(header)


def test_an_ipfix_datagram_claiming_an_impossible_length_is_rejected():
    """The length field covers the header itself, so anything under 16 is a lie."""
    with pytest.raises(NetFlowError, match="invalid IPFIX length"):
        parse_netflow(struct.pack("!HHIII", 10, 4, UNIX, 0, 0))


def test_a_v5_datagram_that_ends_mid_record_yields_the_whole_records():
    """A UDP export cut short by MTU still carries usable flows."""
    data = _v5([("10.0.0.1", "10.0.0.2", 1, 2, 6, 1, 10),
                ("10.0.0.3", "10.0.0.4", 3, 4, 6, 1, 10)])
    recs = parse_netflow(data[:-20])          # second record clipped

    assert len(recs) == 1
    assert recs[0]["src"] == "10.0.0.1"


def test_trailing_bytes_after_a_valid_datagram_are_ignored():
    """Some collectors pad the file; the flows already decoded must survive."""
    recs = parse_netflow(_v5([("10.0.0.1", "10.0.0.2", 1, 2, 6, 1, 10)]) + b"\xff\xff\x00\x00")
    assert len(recs) == 1


def test_a_v9_flowset_with_an_impossible_length_stops_the_walk():
    hdr = struct.pack("!HHIIII", 9, 1, UPTIME, UNIX, 0, 1)
    recs = parse_netflow(hdr + struct.pack("!HH", 256, 2))     # length < 4
    assert recs == []


def test_an_ipfix_set_with_an_impossible_length_stops_the_walk():
    body = struct.pack("!HH", 256, 2)
    total = 16 + len(body)
    hdr = struct.pack("!HHIII", 10, total, UNIX, 0, 0)
    assert parse_netflow(hdr + body) == []


def test_a_v9_flowset_with_a_reserved_id_stops_the_walk():
    """v9 flowset ids are 0 (template), 1 (options) or 256 and up (data).

    2..255 is reserved, so reading one means the walk has left the datagram —
    usually into the header of the next one, whose first field is a version
    number. Length alone does not catch that: this set declares a perfectly
    legal length.
    """
    hdr = struct.pack("!HHIIII", 9, 1, UPTIME, UNIX, 0, 1)
    assert parse_netflow(hdr + struct.pack("!HH", 2, 8) + b"\x00" * 4) == []


def test_a_template_whose_fields_have_no_width_cannot_spin_forever():
    """A declared field length of 0 consumes nothing.

    A record built only from such fields would leave the read position exactly
    where it started, and the enclosing `while p < len(payload)` would then read
    the same bytes for as long as the process lived. The decoder stops on a
    record that made no progress, which is the guard's second half — the first
    only fires on a record that ran off the end.
    """
    tmpl = struct.pack("!HH", 256, 1) + struct.pack("!HH", 8, 0)   # srcaddr, 0 bytes
    tmpl_fs = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    data_fs = struct.pack("!HH", 256, 8) + b"\x00" * 4
    hdr = struct.pack("!HHIIII", 9, 1, UPTIME, UNIX, 0, 1)

    assert parse_netflow(hdr + tmpl_fs + data_fs) == []


def test_a_template_terminated_by_a_zero_id_stops_parsing_it():
    tmpl = struct.pack("!HH", 0, 0)                            # tid 0 ends the set
    tmpl_fs = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    hdr = struct.pack("!HHIIII", 9, 0, UPTIME, UNIX, 0, 1)

    assert parse_netflow(hdr + tmpl_fs) == []


def test_a_template_declaring_more_fields_than_it_carries_is_truncated_safely():
    tmpl = struct.pack("!HH", 256, 7) + struct.pack("!HH", 8, 4)   # claims 7, carries 1
    tmpl_fs = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl
    hdr = struct.pack("!HHIIII", 9, 0, UPTIME, UNIX, 0, 1)

    assert parse_netflow(hdr + tmpl_fs) == []


def test_an_ipfix_enterprise_field_is_skipped_over_not_misread():
    """Enterprise-specific fields carry a 4-byte private enterprise number.

    Not skipping it shifts every subsequent field, which silently corrupts the
    addresses and ports of every flow in the export.
    """
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4)]
    tmpl = struct.pack("!HH", 256, len(fields) + 1)
    tmpl += struct.pack("!HHI", 0x8000 | 99, 4, 12345)          # enterprise field
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = b"\x00" * 4 + _data_record("10.0.0.5", "93.184.216.34", 40000, 443, 6, 10, 8000)
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)
    data = struct.pack("!HHIII", 10, total, UNIX, 0, 0) + tmpl_set + data_set

    recs = parse_netflow(data)
    assert len(recs) == 1
    assert recs[0]["src"] == "10.0.0.5" and recs[0]["dport"] == 443


def test_a_variable_length_field_is_decoded_at_both_length_encodings():
    """RFC 7011 encodes a length under 255 in one byte and longer ones in three."""
    short_name = b"eth0"
    long_name = b"x" * 300

    for name in (short_name, long_name):
        fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4), (82, 0xFFFF)]
        tmpl = struct.pack("!HH", 256, len(fields))
        for ft, fl in fields:
            tmpl += struct.pack("!HH", ft, fl)
        tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

        if len(name) < 255:
            encoded = bytes([len(name)]) + name
        else:
            encoded = b"\xff" + struct.pack("!H", len(name)) + name
        body = _data_record("10.0.0.5", "93.184.216.34", 40000, 443, 6, 10, 8000) + encoded
        data_set = struct.pack("!HH", 256, 4 + len(body)) + body
        total = 16 + len(tmpl_set) + len(data_set)
        data = struct.pack("!HHIII", 10, total, UNIX, 0, 0) + tmpl_set + data_set

        recs = parse_netflow(data)
        assert len(recs) == 1, f"variable-length name of {len(name)} bytes"
        assert recs[0]["src"] == "10.0.0.5"


def test_a_variable_length_field_running_past_the_set_stops_decoding():
    fields = [(8, 4), (12, 4), (82, 0xFFFF)]
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = struct.pack("!II", _ip("10.0.0.5"), _ip("10.0.0.6")) + b"\x40"   # claims 64, has 0
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    assert parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set) == []


def test_a_flow_missing_an_endpoint_is_not_emitted():
    """A template with no address fields decodes cleanly but describes nothing."""
    fields = [(7, 2), (11, 2), (4, 1)]
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = struct.pack("!HHB", 40000, 443, 6)
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    assert parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set) == []


def test_an_ipv6_flow_is_decoded():
    """IPv6 addresses arrive in the 16-byte fields, not the 4-byte ones."""
    fields = [(27, 16), (28, 16), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4)]
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = (ipaddress.IPv6Address("2606:4700::1111").packed
            + ipaddress.IPv6Address("fd00::50").packed
            + struct.pack("!HHB", 443, 51000, 6)
            + struct.pack("!II", 10, 8000))
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    recs = parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set)
    assert len(recs) == 1
    assert recs[0]["src"] == "2606:4700::1111"
    assert recs[0]["dst"] == "fd00::50"


def test_absolute_flow_timestamps_are_used_when_the_exporter_sends_them():
    """v9/IPFIX exporters may send wall-clock start/end instead of sys-uptime
    deltas; using the uptime path there would date every flow to 1970."""
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4),
              (152, 8), (153, 8)]          # flowStart/EndMilliseconds
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    start_ms, end_ms = UNIX * 1000, (UNIX + 30) * 1000
    body = (_data_record("10.0.0.5", "93.184.216.34", 40000, 443, 6, 10, 8000)
            + struct.pack("!QQ", start_ms, end_ms))
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    recs = parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set)
    assert recs[0]["first"] == float(UNIX)
    assert recs[0]["last"] == float(UNIX + 30)


def test_absolute_second_precision_timestamps_are_also_understood():
    fields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (2, 4), (1, 4),
              (150, 4), (151, 4)]          # flowStart/EndSeconds
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = (_data_record("10.0.0.5", "93.184.216.34", 40000, 443, 6, 10, 8000)
            + struct.pack("!II", UNIX, UNIX + 45))
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    recs = parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set)
    assert recs[0]["first"] == float(UNIX)
    assert recs[0]["last"] == float(UNIX + 45)


def test_an_address_field_of_an_impossible_width_decodes_to_nothing():
    from packetiq.inputs.netflow import _ip as decode_ip

    assert decode_ip(b"\x01\x02\x03") is None
    assert decode_ip(b"") is None


def test_external_addresses_are_collected_from_both_directions(tmp_path):
    """`external_ips` drives the threat-intel lookup, so a listed IP appearing
    only as a flow source must still be enriched."""
    data = _v5([("185.199.108.153", "192.168.1.10", 44000, 443, 6, 5, 4000),
                ("192.168.1.10", "193.122.6.168", 51000, 21, 6, 3, 300)])
    f = tmp_path / "flows.netflow"
    f.write_bytes(data)

    result = load_netflow(str(f))
    assert result.external_ips == {"185.199.108.153", "193.122.6.168"}


def test_a_record_ending_exactly_where_a_variable_length_field_starts_is_dropped():
    """The set boundary lands on the length byte itself — there is no field to read."""
    fields = [(8, 4), (12, 4), (82, 0xFFFF)]
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = struct.pack("!II", _ip("10.0.0.5"), _ip("10.0.0.6"))    # no length byte
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    assert parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set) == []


def test_a_three_byte_length_prefix_cut_short_is_dropped():
    """0xFF introduces a 2-byte length; a set that ends there cannot be trusted."""
    fields = [(8, 4), (12, 4), (82, 0xFFFF)]
    tmpl = struct.pack("!HH", 256, len(fields))
    for ft, fl in fields:
        tmpl += struct.pack("!HH", ft, fl)
    tmpl_set = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl

    body = struct.pack("!II", _ip("10.0.0.5"), _ip("10.0.0.6")) + b"\xff"
    data_set = struct.pack("!HH", 256, 4 + len(body)) + body
    total = 16 + len(tmpl_set) + len(data_set)

    assert parse_netflow(struct.pack("!HHIII", 10, total, UNIX, 0, 0)
                         + tmpl_set + data_set) == []
