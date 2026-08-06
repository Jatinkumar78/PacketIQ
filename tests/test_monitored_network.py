"""Where is the boundary of the network being monitored?

Almost every "is this internal or external?" decision in PacketIQ depends on
this — the threat forecast, the C2-beacon detector, the connection graph, the
report's host table, and the evidence handed to the AI copilot. RFC1918 is only
a *proxy* for the answer and gets it wrong in both directions:

  * a university or hosting LAN is publicly addressed, so its own hosts look
    like internet peers (this produced a phantom "C2 beacon" on an inbound RDP
    session, and a benign capture flagged as an incident);
  * an external web server we merely browsed is not ours, however it is
    addressed.

`monitored_network()` answers from link-layer evidence instead: hosts on the
segment send frames from their own NIC, while everything behind a router shares
the router's MAC.
"""

from packetiq.extractor.data_extractor import DataExtractor, ExtractionResult
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.utils.helpers import monitored_network

MAC_A = "00:e0:4c:36:14:02"
MAC_B = "00:e0:4c:68:01:74"
MAC_ROUTER = "00:1b:d4:c7:4b:89"


def _analyse(path: str):
    parser = PCAPParser(path)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    return extractor.finalize()


def _write(path, pkts):
    from scapy.all import wrpcap
    t = 1700000000.0
    for p in pkts:
        p.time = t
        t += 0.01
    wrpcap(path, pkts)


def test_routed_hosts_are_outside_the_boundary(tmp_path):
    """Two remote servers reached through one router must both land outside,
    while the local client lands inside."""
    from scapy.all import IP, TCP, Ether
    pkts = []
    for remote in ("93.184.216.34", "23.45.67.89"):
        pkts += [
            (Ether(src=MAC_A, dst=MAC_ROUTER) / IP(src="192.168.1.50", dst=remote)
             / TCP(sport=40000, dport=443, flags="S")),
            (Ether(src=MAC_ROUTER, dst=MAC_A) / IP(src=remote, dst="192.168.1.50")
             / TCP(sport=443, dport=40000, flags="SA")),
        ]
    path = str(tmp_path / "routed.pcap")
    _write(path, pkts)

    scope = monitored_network(_analyse(path))
    assert "192.168.1.50" in scope
    assert "93.184.216.34" not in scope
    assert "23.45.67.89" not in scope


def test_dual_stack_host_is_not_mistaken_for_a_router(tmp_path):
    """A host owning both an IPv4 address and an IPv6 link-local spans two
    networks, but per address family it spans one each — it is an ordinary
    host, not a router, and dropping it emptied the local network entirely."""
    from scapy.all import IP, TCP, Ether, ICMPv6EchoRequest, IPv6
    pkts = [
        (Ether(src=MAC_A, dst=MAC_B) / IP(src="192.168.1.200", dst="192.168.1.202")
         / TCP(sport=40000, dport=445, flags="S")),
        (Ether(src=MAC_B, dst=MAC_A) / IP(src="192.168.1.202", dst="192.168.1.200")
         / TCP(sport=445, dport=40000, flags="SA")),
        (Ether(src=MAC_A, dst=MAC_B) / IPv6(src="fe80::aaaa", dst="fe80::bbbb")
         / ICMPv6EchoRequest()),
        (Ether(src=MAC_B, dst=MAC_A) / IPv6(src="fe80::bbbb", dst="fe80::aaaa")
         / ICMPv6EchoRequest()),
    ]
    path = str(tmp_path / "dualstack.pcap")
    _write(path, pkts)

    scope = monitored_network(_analyse(path))
    assert "192.168.1.200" in scope
    assert "192.168.1.202" in scope


def test_publicly_addressed_lan_is_still_internal(tmp_path):
    """A LAN on public addresses (as universities and hosting providers run) is
    still the monitored network — the hosts have their own NICs on the segment."""
    from scapy.all import IP, TCP, Ether
    pkts = [
        (Ether(src=MAC_A, dst=MAC_B) / IP(src="147.32.84.165", dst="147.32.84.171")
         / TCP(sport=40000, dport=139, flags="S")),
        (Ether(src=MAC_B, dst=MAC_A) / IP(src="147.32.84.171", dst="147.32.84.165")
         / TCP(sport=139, dport=40000, flags="SA")),
        # something genuinely remote, behind the router
        (Ether(src=MAC_A, dst=MAC_ROUTER) / IP(src="147.32.84.165", dst="8.8.8.8")
         / TCP(sport=40001, dport=443, flags="S")),
        (Ether(src=MAC_ROUTER, dst=MAC_A) / IP(src="8.8.8.8", dst="147.32.84.165")
         / TCP(sport=443, dport=40001, flags="SA")),
    ]
    path = str(tmp_path / "publiclan.pcap")
    _write(path, pkts)

    scope = monitored_network(_analyse(path))
    assert "147.32.84.165" in scope
    assert "147.32.84.171" in scope
    assert "8.8.8.8" not in scope


def test_no_link_layer_data_falls_back_to_rfc1918():
    """NetFlow / Zeek / cooked captures carry no MACs — fall back honestly."""
    r = ExtractionResult()
    r.transmitted_ips = {"10.1.2.3", "192.168.9.9", "8.8.8.8"}
    scope = monitored_network(r)
    assert scope == {"10.1.2.3", "192.168.9.9"}


def test_no_evidence_at_all_returns_empty():
    """With nothing to go on we must not guess a boundary."""
    assert monitored_network(ExtractionResult()) == set()
