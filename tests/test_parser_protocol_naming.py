"""Packet parsing: protocol naming, ARP fields, and HTTP recovered from bytes.

`display_protocol` is what the traffic-composition table shows, so a wrong name
here is a wrong chart in every report. The branches covered are the ones a
typical HTTP/TLS capture never reaches — link-layer control frames, NetBIOS,
IGMP, and the scapy-dissected HTTP path that only runs when the hand-rolled
byte sniffer did not already fill the fields.
"""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, LLC, SNAP, Dot3, Ether
from scapy.utils import wrpcap

from packetiq.parser.pcap_parser import PCAPParser

TS = 1700000000.0


def _parse(pkt, index=0):
    """Run one packet through the parser without going near a file."""
    parser = object.__new__(PCAPParser)
    parser._http_flows = set()
    pkt.time = TS
    return parser._parse_packet(pkt, index)


def _parse_all(*pkts):
    """Parse a sequence through one parser so flow state carries across packets."""
    parser = object.__new__(PCAPParser)
    parser._http_flows = set()
    out = []
    for i, pkt in enumerate(pkts):
        pkt.time = TS + i
        out.append(parser._parse_packet(pkt, i))
    return out


# ── Whole-file loading ───────────────────────────────────────────────────────

def test_load_all_returns_the_same_records_as_streaming(tmp_path):
    """`load_all` is the convenience wrapper the CLI's smaller commands use."""
    pkts = []
    for i in range(5):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000 + i, dport=443)
        p.time = TS + i
        pkts.append(p)
    path = tmp_path / "small.pcap"
    wrpcap(str(path), pkts)

    streamed = list(PCAPParser(str(path)).stream())
    loaded = PCAPParser(str(path)).load_all()

    assert len(loaded) == len(streamed) == 5
    assert [r.src_port for r in loaded] == [r.src_port for r in streamed]


# ── ARP ──────────────────────────────────────────────────────────────────────

def test_an_arp_request_records_both_endpoints():
    rec = _parse(Ether() / ARP(op=1, hwsrc="aa:bb:cc:dd:ee:01", psrc="192.168.1.99",
                               hwdst="00:00:00:00:00:00", pdst="192.168.1.50"))

    assert rec.is_arp and rec.protocol == "ARP"
    assert rec.arp_op == 1
    assert rec.arp_src_ip == "192.168.1.99" and rec.arp_dst_ip == "192.168.1.50"
    assert rec.display_protocol == "ARP"


# ── Link-layer control frames ────────────────────────────────────────────────

def test_a_snap_frame_is_named_from_its_protocol_code():
    """Cisco control traffic (CDP/DTP) rides SNAP; naming it 'LLC' would hide
    the presence of a switch on the segment."""
    pkt = Dot3(dst="01:00:0c:cc:cc:cc", src="aa:bb:cc:dd:ee:01") / LLC() / SNAP(code=0x2000)
    rec = _parse(pkt)

    assert rec.display_protocol in ("CDP", "SNAP")


def test_a_plain_llc_frame_is_named_llc():
    pkt = Dot3(dst="01:80:c2:00:00:00", src="aa:bb:cc:dd:ee:01") / LLC(dsap=0x42, ssap=0x42)
    rec = _parse(pkt)

    assert rec.display_protocol in ("LLC", "STP")


def test_an_ethernet_loopback_test_frame_is_named():
    pkt = Ether(type=0x9000, src="aa:bb:cc:dd:ee:01") / (b"\x00" * 40)
    assert _parse(pkt).display_protocol == "LOOP"


# ── IP-layer protocols ───────────────────────────────────────────────────────

def test_igmp_is_named_rather_than_left_as_ip():
    """Multicast group membership is normal LAN traffic; showing it as unknown
    IP in the composition chart makes a clean capture look odd."""
    pkt = Ether() / IP(src="192.168.1.50", dst="224.0.0.22", proto=2) / (b"\x22\x00" + b"\x00" * 6)
    assert _parse(pkt).display_protocol == "IGMP"


def test_icmp_is_named():
    assert _parse(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()).display_protocol == "ICMP"


def test_an_ipv6_control_protocol_keeps_its_own_name():
    from scapy.layers.inet6 import ICMPv6EchoRequest

    rec = _parse(Ether() / IPv6(src="fd00::1", dst="fd00::2") / ICMPv6EchoRequest())
    assert rec.display_protocol not in (None, "", "TCP", "UDP")


# ── UDP application naming ───────────────────────────────────────────────────

def test_a_netbios_datagram_is_named():
    pkt = (Ether() / IP(src="192.168.1.50", dst="192.168.1.255")
           / UDP(sport=138, dport=138) / (b"\x11" + b"\x00" * 60))
    assert _parse(pkt).display_protocol in ("NBT-DGM", "NBDS")


def test_an_ephemeral_source_port_does_not_name_the_protocol():
    """Naming by the client's random high port would label NTP traffic '51000'.

    The server-side port is the one that identifies the service, so the low
    port wins regardless of direction.
    """
    to_server = (Ether() / IP(src="192.168.1.50", dst="216.239.35.0")
                 / UDP(sport=51000, dport=123) / (b"\x1b" + b"\x00" * 47))
    from_server = (Ether() / IP(src="216.239.35.0", dst="192.168.1.50")
                   / UDP(sport=123, dport=51000) / (b"\x1c" + b"\x00" * 47))

    assert _parse(to_server).display_protocol == _parse(from_server).display_protocol


def test_udp_on_an_unknown_port_stays_udp():
    pkt = (Ether() / IP(src="192.168.1.50", dst="192.168.1.60")
           / UDP(sport=40000, dport=40001) / b"payload")
    assert _parse(pkt).display_protocol == "UDP"


def test_mdns_and_llmnr_are_distinguished_from_unicast_dns():
    mdns = (Ether() / IP(src="192.168.1.50", dst="224.0.0.251") / UDP(sport=5353, dport=5353)
            / DNS(rd=0, qd=DNSQR(qname="printer.local")))
    llmnr = (Ether() / IP(src="192.168.1.50", dst="224.0.0.252") / UDP(sport=5355, dport=5355)
             / DNS(rd=0, qd=DNSQR(qname="wpad")))
    dns = (Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=51000, dport=53)
           / DNS(rd=1, qd=DNSQR(qname="example.com")))

    assert _parse(mdns).display_protocol == "mDNS"
    assert _parse(llmnr).display_protocol == "LLMNR"
    assert _parse(dns).display_protocol == "DNS"


# ── HTTP via scapy's dissector ───────────────────────────────────────────────

def test_a_scapy_dissected_request_fills_the_fields_the_byte_sniffer_missed():
    """The hand-rolled sniffer only reads a request that starts in this packet.

    When scapy has already reassembled one, its fields are the fallback — and
    they are what supplies the User-Agent used for CVE lookup.
    """
    pkt = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=8888, flags="PA")
           / HTTP() / HTTPRequest(Method=b"GET", Host=b"example.com", Path=b"/index.html",
                                  User_Agent=b"curl/8.5.0"))
    rec = _parse(pkt)

    assert rec.has_http
    assert rec.http_method == "GET"
    assert rec.http_host == "example.com"
    assert rec.http_path == "/index.html"
    assert rec.http_user_agent == "curl/8.5.0"


def test_a_scapy_dissected_response_yields_the_status_and_server_banner():
    """The Server header is the single most CVE-relevant string in plaintext HTTP."""
    pkt = (Ether() / IP(src="93.184.216.34", dst="192.168.1.50")
           / TCP(sport=8888, dport=51000, flags="PA")
           / HTTP() / HTTPResponse(Status_Code=b"200", Server=b"Apache/2.4.49 (Unix)"))
    rec = _parse(pkt)

    assert rec.has_http
    assert rec.http_status == 200
    assert rec.http_server == "Apache/2.4.49 (Unix)"


def test_a_response_with_an_unparseable_status_is_not_fatal():
    pkt = (Ether() / IP(src="93.184.216.34", dst="192.168.1.50")
           / TCP(sport=8888, dport=51000, flags="PA")
           / HTTP() / HTTPResponse(Status_Code=b"nonsense", Server=b"nginx/1.18.0"))
    rec = _parse(pkt)

    assert rec.http_status is None
    assert rec.http_server == "nginx/1.18.0"


# ── HTTP recovered from raw bytes ────────────────────────────────────────────

def _raw_http(payload, sport=51000, dport=8888):
    return (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
            / TCP(sport=sport, dport=dport, flags="PA") / payload)


def test_a_request_target_containing_spaces_is_kept_whole():
    """A crude scanner leaves spaces unencoded. That text *is* the attack
    evidence, so splitting on the first space would truncate the finding."""
    rec = _parse(_raw_http(b"GET /search?q=1 OR 1=1 HTTP/1.1\r\nHost: victim\r\n\r\n"))

    assert rec.has_http
    assert rec.http_method == "GET"
    assert rec.http_path == "/search?q=1 OR 1=1"


def test_a_start_line_that_is_not_http_is_ignored():
    assert _parse(_raw_http(b"SSH-2.0-OpenSSH_9.6\r\n")).has_http is False


def test_a_request_line_with_no_version_is_ignored():
    """Without `HTTP/1.x` this is not a request; guessing would invent a finding."""
    assert _parse(_raw_http(b"GET /index.html\r\nHost: victim\r\n\r\n")).has_http is False


def test_a_request_with_an_unknown_method_is_ignored():
    assert _parse(_raw_http(b"FROB /x HTTP/1.1\r\nHost: victim\r\n\r\n")).has_http is False


def test_later_segments_of_a_known_http_flow_keep_the_http_label():
    """Wireshark does the same. Without it, the continuation of a malware HTTP
    session on port 3389 would be labelled RDP.
    """
    start = _raw_http(b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\n\r\n",
                      dport=3389)
    body = _raw_http(b"MZ" + b"\x90" * 200, dport=3389)
    ack = (Ether() / IP(src="192.168.1.50", dst="93.184.216.34")
           / TCP(sport=51000, dport=3389, flags="A"))

    first, second, third = _parse_all(start, body, ack)

    assert first.display_protocol == "HTTP"
    assert second.display_protocol == "HTTP", "the body segment belongs to the same flow"
    assert third.display_protocol == "TCP", "a bare ACK carries no protocol data"


def test_the_learned_flow_table_is_capped(monkeypatch):
    """A capture of a million short flows must not grow this without bound."""
    parser = object.__new__(PCAPParser)
    parser._http_flows = set()
    monkeypatch.setattr(PCAPParser, "_HTTP_FLOW_CAP", 2)

    for i in range(5):
        pkt = _raw_http(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", sport=51000 + i)
        pkt.time = TS
        parser._parse_packet(pkt, i)

    assert len(parser._http_flows) == 2


def test_a_flow_with_no_addresses_is_not_learned():
    parser = object.__new__(PCAPParser)
    parser._http_flows = set()

    class Bare:
        protocol = "TCP"
        src_ip = None
        dst_ip = "10.0.0.2"

    parser._remember_http_flow(Bare())
    assert parser._http_flows == set()


# ── Field decoding ───────────────────────────────────────────────────────────

def test_scapy_byte_fields_decode_to_text():
    assert PCAPParser._safe_decode(b"Apache/2.4.49") == "Apache/2.4.49"
    assert PCAPParser._safe_decode(None) is None
    assert PCAPParser._safe_decode(200) == "200"


def test_a_field_that_cannot_be_decoded_yields_none():
    class Hostile:
        def __str__(self):
            raise UnicodeError("undecodable")

    assert PCAPParser._safe_decode(Hostile()) is None


def test_invalid_utf8_in_a_header_is_replaced_not_dropped():
    """Attacker-controlled headers are not valid UTF-8 often enough to matter;
    the bytes still have to reach the report."""
    assert "�" in PCAPParser._safe_decode(b"Apache/2.4.49 \xff\xfe")


# ── Malformed packets ────────────────────────────────────────────────────────

def test_a_packet_the_parser_cannot_read_yields_nothing():
    """A malformed frame is skipped, not allowed to abort the whole capture."""
    class NotAPacket:
        time = TS

    assert _parse_all(NotAPacket())[0] is None
