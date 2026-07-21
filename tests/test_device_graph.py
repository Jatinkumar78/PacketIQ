"""The network graph must show only devices that ACTUALLY EXIST.

Regression tests for the "phantom host" bug: an ARP sweep probes dozens of
addresses that never answer, and a real host owns both an IPv4 and an IPv6
link-local address. The old graph drew one node per probed IP (inventing hosts)
and a separate node for each IPv6 address (double-counting real ones). The
device inventory fixes both: a node exists only with evidence it transmitted,
and a host's addresses collapse to a single physical-device node.
"""

from packetiq.detection.engine import DetectionEngine
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.webapp.app import _build_graph

MAC_A = "00:e0:4c:36:14:02"   # the attacker NIC (.200 + an IPv6 link-local)
MAC_B = "00:e0:4c:68:01:74"   # a live host  (.202 + an IPv6 link-local)


def _lab_like_pcap(path: str) -> None:
    """Attacker .200 ARP-sweeps 25 dead addresses, one host (.202) replies, and
    both real hosts also speak IPv6 mDNS from a link-local address."""
    from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Ether, IPv6, wrpcap
    pkts = []
    t = 1700000000.0
    # ARP who-has sweep to 25 addresses that never respond → probed, not alive
    for i in range(10, 35):
        p = (Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff")
             / ARP(op=1, hwsrc=MAC_A, psrc="192.168.1.200", pdst=f"192.168.1.{i}"))
        p.time = t; t += 0.01
        pkts.append(p)
    # attacker also probes .202, which answers → .202 is a probed *and* live host
    probe = (Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff")
             / ARP(op=1, hwsrc=MAC_A, psrc="192.168.1.200", pdst="192.168.1.202"))
    probe.time = t; t += 0.01
    pkts.append(probe)
    reply = (Ether(src=MAC_B, dst=MAC_A)
             / ARP(op=2, hwsrc=MAC_B, psrc="192.168.1.202", hwdst=MAC_A, pdst="192.168.1.200"))
    reply.time = t; t += 0.01
    pkts.append(reply)
    # both real hosts also emit IPv6 mDNS from a link-local address (same NIC)
    for mac, v6 in ((MAC_A, "fe80::aaaa"), (MAC_B, "fe80::bbbb")):
        p = (Ether(src=mac) / IPv6(src=v6, dst="ff02::fb")
             / UDP(sport=5353, dport=5353) / DNS(qd=DNSQR(qname="_x._tcp.local")))
        p.time = t; t += 0.01
        pkts.append(p)
    # a unicast TCP SYN from attacker to the live host
    syn = (Ether(src=MAC_A, dst=MAC_B) / IP(src="192.168.1.200", dst="192.168.1.202")
           / TCP(sport=44444, dport=80, flags="S"))
    syn.time = t
    pkts.append(syn)
    wrpcap(path, pkts)


def _analyze(path: str):
    ex = DataExtractor()
    for r in PCAPParser(path).stream():
        ex.feed(r)
    result = ex.finalize()
    events, _risk, _fp = DetectionEngine().run(result, path)
    return result, events


def test_ipv6_and_ipv4_collapse_to_one_device(tmp_path):
    p = str(tmp_path / "lab.pcap")
    _lab_like_pcap(p)
    result, _ = _analyze(p)
    # each host's IPv6 link-local is folded onto its IPv4 identity
    assert result.ip_to_device["fe80::aaaa"] == "192.168.1.200"
    assert result.ip_to_device["fe80::bbbb"] == "192.168.1.202"
    # the two real transmitting NICs are recognised as endpoints
    endpoints = {d["id"] for d in result.devices if d["kind"] == "endpoint"}
    assert {"192.168.1.200", "192.168.1.202"} <= endpoints


def test_probed_but_silent_ips_are_not_devices(tmp_path):
    p = str(tmp_path / "lab.pcap")
    _lab_like_pcap(p)
    result, _ = _analyze(p)
    # 25 addresses were probed but never answered → none are real devices
    for i in range(10, 35):
        assert f"192.168.1.{i}" not in result.transmitted_ips


def test_graph_shows_only_real_devices_no_phantoms(tmp_path):
    p = str(tmp_path / "lab.pcap")
    _lab_like_pcap(p)
    result, events = _analyze(p)
    g = _build_graph(result, events)
    ids = {n["id"] for n in g["nodes"]}
    # exactly the two real hosts — no probed IPs, no separate IPv6 nodes
    assert ids == {"192.168.1.200", "192.168.1.202"}
    assert not any(":" in i for i in ids)                 # IPv6 dupes merged away
    assert all(n["packets"] > 0 for n in g["nodes"])      # every node really transmitted


def test_attacker_fanout_is_a_count_not_phantom_nodes(tmp_path):
    p = str(tmp_path / "lab.pcap")
    _lab_like_pcap(p)
    result, events = _analyze(p)
    g = _build_graph(result, events)
    attacker = next(n for n in g["nodes"] if n["role"] == "attacker")
    assert attacker["id"] == "192.168.1.200"
    # the sweep breadth is carried as a count on the attacker, not drawn as dots
    assert attacker["scanned"] >= 25
    assert attacker["alive"] >= 1
    assert len(g["nodes"]) == 2
