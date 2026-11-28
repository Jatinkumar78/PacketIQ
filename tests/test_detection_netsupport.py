"""Tests for NetSupport RAT detection (`packetiq.detection.netsupport`).

The detector reads the self-identifying strings a NetSupport channel prints in its
plain-HTTP headers, so these feed TCP packets carrying those exact bytes — the same
POST/200 exchange a real capture holds.
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetiq.detection import netsupport as ns
from packetiq.detection.models import EventType, Severity

CLIENT = "10.11.10.147"
C2 = "93.152.209.36"

REQ = (b"POST http://93.152.209.36/fakeurl.htm HTTP/1.1\n"
       b"User-Agent: NetSupport Manager/1.3\n"
       b"Content-Type: application/x-www-form-urlencoded\n"
       b"Content-Length: 22\nHost: 93.152.209.36\nConnection: Keep-Alive\n\n"
       b"CMD=POLL\nINFO=1\nACK=1\n")
RESP = (b"HTTP/1.1 200 OK\n"
        b"Server: NetSupport Gateway/1.92 (Windows NT)\n"
        b"Content-Type: application/x-www-form-urlencoded\n"
        b"Content-Length: 69\nConnection: Keep-Alive\n\n"
        b"CMD=ENCD\nES=1\nDATA=deadbeef\n")
BARE_CMD = b"CMD=ENCD\nES=1\nDATA=cafef00d\n"      # a body with no NetSupport header


def _pkt(payload, *, src=CLIENT, dst=C2, sport=51487, dport=443, ts=1794334927.7):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload)
    pkt.time = ts
    return pkt


def _run(packets):
    acc = ns.NetSupportAccumulator()
    for p in packets:
        acc.feed(p)
    return acc


# ── detection ─────────────────────────────────────────────────────────────────

def test_detects_the_channel_from_both_directions():
    acc = _run([_pkt(REQ, ts=1794334927.5),
                _pkt(RESP, src=C2, dst=CLIENT, sport=443, dport=51487, ts=1794334927.7)])
    summ = acc.summary()
    assert summ["family"] == "NetSupport RAT (NetSupport Manager)"
    chan = summ["channels"][0]
    assert chan["client"] == CLIENT
    assert chan["server"] == C2
    assert chan["port"] == 443
    assert chan["c2"] == "93.152.209.36:443"
    assert chan["client_agent"] == "NetSupport Manager/1.3"
    assert chan["gateway"] == "NetSupport Gateway/1.92 (Windows NT)"
    assert chan["uri"] == "http://93.152.209.36/fakeurl.htm"
    assert chan["commands"] == ["POLL", "ENCD"]
    assert chan["first_seen_utc"] == "2026-11-10 18:22:07 UTC"


def test_bare_command_body_folds_into_an_identified_channel():
    acc = _run([_pkt(REQ, ts=10.0), _pkt(BARE_CMD, ts=11.0)])
    chan = acc.summary()["channels"][0]
    assert chan["request_count"] == 2          # the bare body counted
    assert chan["commands"] == ["POLL", "ENCD"]


def test_client_request_alone_still_identifies_the_channel():
    chan = _run([_pkt(REQ)]).summary()["channels"][0]
    assert chan["client_agent"] == "NetSupport Manager/1.3"
    assert chan["gateway"] == ""


def test_finalize_emits_one_critical_rat_event():
    events = _run([_pkt(REQ, ts=1794334927.5),
                   _pkt(RESP, src=C2, dst=CLIENT, sport=443, dport=51487)]).finalize()
    assert len(events) == 1
    ev = events[0]
    assert ev.event_type is EventType.RAT_C2
    assert ev.severity is Severity.CRITICAL
    assert ev.src_ip == CLIENT and ev.dst_ip == C2 and ev.dst_port == 443
    assert ev.evidence["c2"] == "93.152.209.36:443"
    assert ev.evidence["mitre"] == "T1219"
    assert "NetSupport" in ev.evidence["malware_family"]
    assert ev.evidence["first_seen_utc"] == "2026-11-10 18:22:07 UTC"


# ── non-matching traffic is ignored ───────────────────────────────────────────

def test_ignores_unrelated_and_degenerate_packets():
    acc = ns.NetSupportAccumulator()
    acc.feed(Ether() / IP(src=CLIENT, dst=C2) / UDP() / Raw(load=b"NetSupport?"))   # not TCP
    acc.feed(_pkt(b""))                                                             # empty payload
    acc.feed(Ether() / TCP() / Raw(load=b"NetSupport Manager/1.3"))                 # no IP layer
    acc.feed(_pkt(b"GET / HTTP/1.1\nUser-Agent: curl/8\n\n"))                       # not NetSupport
    assert acc.summary() == {}
    assert acc.finalize() == []


def test_ipv6_endpoints_are_read():
    pkt = Ether() / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=5, dport=443) / Raw(load=REQ)
    pkt.time = 1794334927.5
    chan = _run([pkt]).summary()["channels"][0]
    assert chan["client"] == "fe80::1"


# ── small helpers ─────────────────────────────────────────────────────────────

def test_head_text_handles_both_line_endings_and_no_blank_line():
    assert ns._head_text(b"A: 1\r\n\r\nbody").strip() == "A: 1"
    assert ns._head_text(b"A: 1\n\nbody").strip() == "A: 1"
    assert ns._head_text(b"no blank line here") == "no blank line here"


def test_endpoints_returns_none_without_an_ip_layer():
    assert ns._endpoints(Ether() / TCP()) == (None, None)


def test_utc_formats_a_timestamp():
    assert ns._utc(1794334927.5) == "2026-11-10 18:22:07 UTC"
