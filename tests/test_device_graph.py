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
from packetiq.webapp.app import _build_graph, _devices_payload

MAC_A = "00:e0:4c:36:14:02"   # the attacker NIC (.200 + an IPv6 link-local)
MAC_B = "00:e0:4c:68:01:74"   # a live host  (.202 + an IPv6 link-local)
MAC_SW = "00:1b:d4:c7:4b:89"  # a Cisco switch (broadcasts STP, no IP)


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


def _pcap_with_switch(path: str) -> None:
    """Same lab, plus a Cisco switch broadcasting STP (a real device with no IP)."""
    from scapy.all import ARP, LLC, STP, Dot3, Ether, wrpcap
    pkts = []
    t = 1700000000.0
    # a live host so there's an IP endpoint to attach the switch to
    for _ in range(2):
        pk = (Ether(src=MAC_B, dst="ff:ff:ff:ff:ff:ff")
              / ARP(op=1, hwsrc=MAC_B, psrc="192.168.1.202", pdst="192.168.1.1"))
        pk.time = t; t += 0.01
        pkts.append(pk)
    # the switch: STP BPDUs (802.3 + LLC), no IP layer at all
    for _ in range(5):
        bpdu = Dot3(src=MAC_SW, dst="01:80:c2:00:00:00") / LLC() / STP()
        bpdu.time = t; t += 0.01
        pkts.append(bpdu)
    wrpcap(path, pkts)


def test_switch_appears_as_infrastructure_device(tmp_path):
    p = str(tmp_path / "sw.pcap")
    _pcap_with_switch(p)
    result, _ = _analyze(p)
    kinds = {d["id"]: d["kind"] for d in result.devices}
    assert kinds.get(MAC_SW) == "infrastructure"       # STP-only NIC = switch
    # it is surfaced in the device inventory payload with a vendor from its OUI
    payload = {d["mac"]: d for d in _devices_payload(result)}
    assert payload[MAC_SW]["vendor"] == "Cisco"
    assert payload[MAC_SW]["ips"] == []                # a switch has no IP here


def test_graph_draws_switch_node_and_l2_segment_edges(tmp_path):
    p = str(tmp_path / "sw.pcap")
    _pcap_with_switch(p)
    result, events = _analyze(p)
    g = _build_graph(result, events)
    infra = [n for n in g["nodes"] if n["role"] == "infrastructure"]
    assert len(infra) == 1 and infra[0]["id"] == MAC_SW
    # the single switch is linked to the host by an L2-segment edge (topology),
    # which is a membership, not a conversation/attack
    seg = [e for e in g["edges"] if e["kind"] == "segment"]
    assert seg and all(e["source"] == MAC_SW for e in seg)
