"""Per-packet inspection: the analyst facts the AI packet card is grounded on.

`analyst_facts` exists so the model reasons over decoded analysis instead of raw
scapy field names. That makes every helper here a grounding surface: a wrong TTL
bucket, port role or direction hint becomes a confident wrong sentence in the UI.

The paths covered are the ones a clean HTTP/TLS capture never reaches —
malformed records, absent layers, and the unusual values real captures carry.
"""

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from packetiq import inspect as insp

TS = 1700000000.0


def _p(pkt):
    pkt.time = TS
    return pkt


# ── Address extraction ───────────────────────────────────────────────────────

def test_ipv4_addresses_are_read_from_the_ip_layer():
    assert insp._ips(_p(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP())) == (
        "10.0.0.1", "10.0.0.2")


def test_ipv6_addresses_are_read_from_the_ipv6_layer():
    assert insp._ips(_p(Ether() / IPv6(src="fd00::1", dst="fd00::2") / TCP())) == (
        "fd00::1", "fd00::2")


def test_a_frame_with_no_ip_layer_falls_back_to_its_macs():
    """A pure layer-2 frame still has endpoints worth showing in the packet list."""
    src, dst = insp._ips(_p(Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP()))
    assert src == "aa:bb:cc:dd:ee:01"
    assert dst == "ff:ff:ff:ff:ff:ff"


def test_something_with_no_layers_at_all_yields_empty_endpoints():
    class Bare:
        def haslayer(self, layer):
            return False

    assert insp._ips(Bare()) == ("", "")


# ── Payload extraction ───────────────────────────────────────────────────────

def test_a_packet_with_no_tcp_layer_has_no_tcp_payload():
    assert insp._tcp_payload(_p(Ether() / IP() / UDP())) == b""
    assert insp._full_tcp_payload(_p(Ether() / IP() / UDP())) == b""


def test_a_udp_payload_is_used_when_there_is_no_tcp():
    body = insp._payload_bytes(_p(Ether() / IP() / UDP(sport=5000, dport=5001) / b"hello"))
    assert body == b"hello"


def test_a_bare_raw_layer_is_the_last_resort_payload():
    """Some link-layer frames carry data with no transport layer at all."""
    pkt = _p(Ether(type=0x9000) / Raw(load=b"loopback test data"))
    assert insp._payload_bytes(pkt) == b"loopback test data"


def test_a_packet_with_no_payload_anywhere_yields_nothing():
    assert insp._payload_bytes(_p(Ether() / ARP())) == b""


# ── TLS record heuristics ────────────────────────────────────────────────────

def test_a_record_too_short_to_have_a_header_is_not_tls():
    assert insp._looks_tls(b"\x16\x03") is False
    assert insp._looks_tls(b"") is False


@pytest.mark.parametrize("payload,why", [
    (b"\x99\x03\x03\x00\x10" + b"x" * 16, "content type is not a TLS record type"),
    (b"\x16\x02\x03\x00\x10" + b"x" * 16, "major version is not 3"),
    (b"\x16\x03\x09\x00\x10" + b"x" * 16, "minor version is past TLS 1.3"),
    (b"\x16\x03\x03\x00\x00", "zero-length record"),
    (b"\x16\x03\x03\xff\xff", "record longer than TLS allows"),
])
def test_bytes_that_only_look_like_tls_are_rejected(payload, why):
    """Port is irrelevant to the check, so the record header has to carry it —
    otherwise a bare SYN-ACK on :443 gets labelled TLS."""
    assert insp._looks_tls(payload) is False, why


def test_a_plausible_tls_record_is_recognised():
    assert insp._looks_tls(b"\x16\x03\x03\x00\x10" + b"x" * 16) is True


@pytest.mark.parametrize("payload,expect", [
    (b"\x16\x03\x03\x00\x10\x01" + b"x" * 16, "TLS 1.2 Client Hello"),
    (b"\x16\x03\x03\x00\x10\x02" + b"x" * 16, "TLS 1.2 Server Hello"),
    (b"\x17\x03\x03\x00\x10" + b"x" * 16, "TLS 1.2 Application Data"),
    (b"\x15\x03\x01\x00\x02\x02", "TLS 1.0 Alert"),
])
def test_a_tls_record_is_described_the_way_wireshark_does(payload, expect):
    assert insp._tls_info(payload) == expect


# ── SNI extraction ───────────────────────────────────────────────────────────

def _client_hello_with_sni(host: str) -> bytes:
    import struct

    name = host.encode()
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_ext = struct.pack("!HHH", 0x0000, len(sni_entry) + 2, len(sni_entry)) + sni_entry
    body = (b"\x03\x03" + b"\x00" * 32          # version + random
            + b"\x00"                            # session id length
            + struct.pack("!H", 2) + b"\x13\x01"  # cipher suites
            + b"\x01\x00"                        # compression methods
            + struct.pack("!H", len(sni_ext)) + sni_ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_the_server_name_is_read_out_of_a_client_hello():
    """SNI is the only host name visible in an otherwise encrypted session."""
    assert insp._tls_sni(_client_hello_with_sni("evil.example.xyz")) == "evil.example.xyz"


@pytest.mark.parametrize("payload", [
    b"",
    b"\x16\x03\x01\x00\x05" + b"\x00" * 40,          # handshake type is not ClientHello
    b"\x17\x03\x03\x00\x10" + b"\x00" * 40,          # application data
    b"\x16\x03\x01\x00\xff\x01" + b"\xff" * 60,      # lengths run past the buffer
])
def test_anything_that_is_not_a_readable_client_hello_yields_no_sni(payload):
    """A partial record must produce an empty string, never an exception — this
    runs over attacker-controlled bytes on every inspected packet."""
    assert insp._tls_sni(payload) == ""


def test_a_client_hello_truncated_before_its_extensions_yields_no_sni():
    full = _client_hello_with_sni("example.com")
    assert insp._tls_sni(full[:46]) == ""


# ── TCP flags ────────────────────────────────────────────────────────────────

def test_tcp_flags_render_as_wireshark_names():
    assert insp._tcp_flag_str(_p(Ether() / IP() / TCP(flags="SA"))) == "SYN, ACK"
    assert insp._tcp_flag_str(_p(Ether() / IP() / TCP(flags="FPU"))) == "FIN, PSH, URG"


def test_a_packet_with_no_tcp_layer_has_no_flags():
    assert insp._tcp_flag_str(_p(Ether() / IP() / UDP())) == ""


# ── Info column ──────────────────────────────────────────────────────────────

def test_a_protocol_with_no_special_handling_falls_back_to_the_scapy_summary():
    info = insp._wireshark_info(_p(Ether() / IP() / ICMP()), "ICMP", None, None)
    assert info and "ICMP" in info.upper()


def test_the_info_column_degrades_to_the_protocol_name_when_nothing_renders():
    class Unsummarisable:
        def haslayer(self, layer):
            return False

        def summary(self):
            raise ValueError("cannot render")

    assert insp._wireshark_info(Unsummarisable(), "MYSTERY", None, None) == "MYSTERY"


# ── Field rendering ──────────────────────────────────────────────────────────

def test_a_field_that_cannot_be_rendered_falls_back_to_its_repr():
    class Field:
        name = "odd"

    class Layer:
        def getfieldval(self, name):
            return {"raw": b"\x00"}

        def get_field(self, name):
            raise KeyError(name)

    assert insp._field_value(Layer(), Field()) == "{'raw': b'\\x00'}"


def test_a_field_that_cannot_even_be_repr_ed_renders_empty():
    class Field:
        name = "hostile"

    class Layer:
        def getfieldval(self, name):
            raise RuntimeError("unreadable")

        def get_field(self, name):
            raise RuntimeError("unreadable")

    assert insp._field_value(Layer(), Field()) == ""


def test_a_very_long_field_value_is_truncated():
    class Field:
        name = "long"

    class Layer:
        def getfieldval(self, name):
            return "x" * 500

        def get_field(self, name):
            raise KeyError(name)

    out = insp._field_value(Layer(), Field())
    assert len(out) == 301 and out.endswith("…")


# ── Dissection ───────────────────────────────────────────────────────────────

def test_a_packet_is_dissected_into_layers_fields_and_hex():
    out = insp.dissect(_p(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
                          / TCP(sport=51000, dport=443)), 0)

    assert [layer["name"] for layer in out["layers"]][:2] == ["Ethernet", "IP"]
    assert out["hex"], "the hex dump is what an analyst checks the decode against"
    assert out["summary"]["src"] == "10.0.0.1:51000"


def test_a_packet_whose_bytes_cannot_be_rebuilt_still_dissects(monkeypatch):
    """A frame from a truncated capture can fail to re-serialise. The layer tree
    and the summary row are still worth showing — only the hex dump is lost.

    The packet list renders every row through `summarize`, so one such frame must
    not take the whole list down with it.
    """
    def unbuildable(self):
        raise ValueError("cannot rebuild this frame")

    monkeypatch.setattr(Ether, "__bytes__", unbuildable)

    pkt = _p(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=51000, dport=443))
    out = insp.dissect(pkt, 0)

    assert out["hex"] == []
    assert [layer["name"] for layer in out["layers"]][:2] == ["Ethernet", "IP"]
    assert out["summary"]["length"] == 0
    assert out["summary"]["src"] == "10.0.0.1:51000"


# ── Statistical helpers ──────────────────────────────────────────────────────

def test_the_entropy_of_nothing_is_zero():
    assert insp._entropy(b"") == 0.0
    assert insp._printable_ratio(b"") == 0.0


def test_entropy_separates_random_bytes_from_repetitive_text():
    import os

    assert insp._entropy(b"A" * 500) == 0.0
    assert insp._entropy(os.urandom(4096)) > 7.2


@pytest.mark.parametrize("entropy,expect", [
    (7.9, "high"), (7.2, "high"), (6.0, "medium"), (5.0, "medium"), (2.0, "low"),
])
def test_entropy_is_described_in_words_for_the_packet_card(entropy, expect):
    assert insp._entropy_note(entropy).startswith(expect)


def test_the_printable_ratio_separates_text_from_binary():
    assert insp._printable_ratio(b"GET / HTTP/1.1\r\n") == 1.0
    assert insp._printable_ratio(bytes(range(0, 32))) < 0.2


# ── TTL analysis ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ttl,initial,hops,family", [
    (64, 64, 0, "Linux"),
    (57, 64, 7, "Linux"),
    (128, 128, 0, "Windows"),
    (120, 128, 8, "Windows"),
    (255, 255, 0, "network device"),
    (250, 255, 5, "network device"),
])
def test_a_ttl_maps_to_an_initial_value_hop_count_and_os_family(ttl, initial, hops, family):
    got_initial, got_hops, got_family = insp._ttl_analysis(ttl)
    assert (got_initial, got_hops) == (initial, hops)
    assert family.lower() in got_family.lower()


def test_a_ttl_past_every_standard_default_is_called_unusual():
    """Nothing standard exceeds 255. Guessing an OS there would be a fabricated
    fact in the packet card."""
    initial, hops, family = insp._ttl_analysis(300)
    assert (initial, hops) == (300, 0)
    assert "unusual" in family


def test_a_zero_ttl_is_also_unusual():
    assert "unusual" in insp._ttl_analysis(0)[2]


# ── Roles and direction ──────────────────────────────────────────────────────

def test_an_address_is_described_as_internal_or_external():
    assert "internal" in insp._ip_role("192.168.1.50")
    assert "external" in insp._ip_role("185.199.108.153")


def test_an_absent_address_has_no_role():
    assert insp._ip_role("") == ""


def test_an_unparseable_address_is_not_claimed_to_be_internal():
    """`is_private_ip` answers False for anything it cannot parse, so the safe
    reading is 'not known to be ours' — never 'internal'."""
    assert insp._ip_role("not-an-address") == "public / external"


@pytest.mark.parametrize("port,expect", [
    (443, "https"),
    (22, "ssh"),
    (60000, "dynamic/ephemeral"),
    (30000, "registered range"),
])
def test_a_port_is_described_by_service_or_by_range(port, expect):
    assert expect in insp._port_role(port).lower()


def test_an_unassigned_well_known_port_is_still_flagged_as_system_range():
    """A service on a low unassigned port is unusual and worth naming as such."""
    role = insp._port_role(1023)
    assert "1023" in role and "system/well-known" in role


def test_no_port_has_no_description():
    assert insp._port_role(None) == ""


def test_direction_is_inferred_from_which_side_holds_the_service_port():
    assert "client → server" in insp._direction_hint(51000, 443)
    assert "server → client" in insp._direction_hint(443, 51000)


@pytest.mark.parametrize("sport,dport", [(51000, 52000), (80, 443)])
def test_direction_is_left_unclear_rather_than_guessed(sport, dport):
    """Two ephemeral ports, or two service ports, genuinely do not say which end
    is the client. Asserting one would be a fabricated fact."""
    assert insp._direction_hint(sport, dport) == "direction unclear from ports alone"


# ── Integer coercion ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expect", [(42, 42), ("42", 42), (None, 0), ("x", 0)])
def test_packet_fields_coerce_to_integers_with_a_fallback(value, expect):
    assert insp._int(value) == expect


def test_the_integer_fallback_is_configurable():
    assert insp._int(None, default=5) == 5


# ── Analyst facts end to end ─────────────────────────────────────────────────

def test_an_ipv6_packet_reports_its_hop_limit_rather_than_a_ttl():
    facts = insp.analyst_facts(
        _p(Ether() / IPv6(src="2606:4700::1111", dst="fd00::50", hlim=58)
           / TCP(sport=443, dport=51000)), 0)

    assert facts["ip_version"] == "IPv6"
    assert facts["hop_limit"] == 58
    assert facts["src"] == "2606:4700::1111"
    assert "ttl" not in facts


def test_an_ipv4_packet_reports_its_ttl_analysis_and_roles():
    facts = insp.analyst_facts(
        _p(Ether(src="aa:bb:cc:dd:ee:01") / IP(src="192.168.1.50",
                                               dst="185.199.108.153", ttl=57)
           / TCP(sport=51000, dport=443)), 0)

    assert facts["ip_version"] == "IPv4"
    assert facts["ttl"] == 57 and facts["ttl_initial"] == 64 and facts["hops"] == 7
    assert "internal" in facts["src_role"] and "external" in facts["dst_role"]
    assert facts["eth_src"] == "aa:bb:cc:dd:ee:01"
    assert "client → server" in facts["direction"]


def test_a_dns_query_is_decoded_into_the_facts():
    facts = insp.analyst_facts(
        _p(Ether() / IP(src="192.168.1.50", dst="8.8.8.8")
           / UDP(sport=51000, dport=53)
           / DNS(rd=1, qd=DNSQR(qname="example.com"))), 0)

    assert facts["transport"] == "UDP"
    assert "example.com" in str(facts)


def test_the_brief_is_plain_prose_with_no_markdown():
    """It renders into a card in the web UI, so stray markdown shows as literal
    asterisks rather than formatting."""
    brief = insp.analyst_brief(
        _p(Ether() / IP(src="192.168.1.50", dst="185.199.108.153", ttl=57)
           / TCP(sport=51000, dport=443)), 0)

    assert brief
    assert "**" not in brief
    assert "```" not in brief
