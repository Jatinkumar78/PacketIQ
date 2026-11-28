"""Tests for host-name extraction (`packetiq.detection.host_names`): the computer
name and OS a host announces for itself over NetBIOS Browser and DHCP.

The Browser announcement rides in an SMB mailslot scapy exposes only as an opaque
buffer, so the detector hand-parses the fixed-layout body; these build that body by
hand (the same bytes a capture holds) and feed DHCP as live objects.
"""

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetiq.detection import host_names as hn

MARK = b"\\MAILSLOT\\BROWSE\x00"
CLIENT = "10.11.10.147"
MAC = "00:12:f0:e5:17:43"


def _browse_body(name=b"DESKTOP-5OMVI3L", opcode=0x01, osmaj=10, osmin=0, stype=0x00001003):
    body = bytes([opcode, 0])                  # OpCode, UpdateCount
    body += (240000).to_bytes(4, "little")     # Periodicity
    body += name.ljust(16, b"\x00")[:16]       # ServerName (16, NUL-padded)
    body += bytes([osmaj & 0xFF, osmin & 0xFF])
    body += stype.to_bytes(4, "little")        # ServerType
    body += b"\x0f\x01\x55\xaa"                 # config version + signature
    return body


def _browse_pkt(body=None, *, src=CLIENT, mac=MAC, dport=138):
    payload = b"\x11\x02\x00\x00nbt-header" + MARK + (body if body is not None else _browse_body())
    eth = Ether(src=mac) if mac else Ether()
    return eth / IP(src=src, dst="10.11.10.255") / UDP(sport=138, dport=dport) / Raw(load=payload)


def _dhcp_pkt(options, *, src=CLIENT, mac=MAC, with_ether=True):
    base = Ether(src=mac) if with_ether else IP(src=src)
    if with_ether:
        base = base / IP(src=src)
    return base / UDP(sport=68, dport=67) / BOOTP() / DHCP(options=options)


def _run(packets):
    acc = hn.HostNameAccumulator()
    for p in packets:
        acc.feed(p)
    return acc


# ── NetBIOS Browser ───────────────────────────────────────────────────────────

def test_browser_host_announcement_gives_name_os_and_role():
    rec = _run([_browse_pkt()]).summary()["by_ip"][CLIENT]
    assert rec["name"] == "DESKTOP-5OMVI3L"
    assert rec["os"] == "Windows 10/11 or Server 2016+"
    assert "workstation" in rec["role"] and "server" in rec["role"]
    assert rec["mac"] == MAC
    assert rec["sources"] == ["NetBIOS Browser"]


def test_browser_local_master_announcement_is_also_read():
    rec = _run([_browse_pkt(_browse_body(opcode=0x0F))]).summary()["by_ip"][CLIENT]
    assert rec["name"] == "DESKTOP-5OMVI3L"


def test_browser_ignores_other_opcodes_short_bodies_and_empty_names():
    acc = _run([
        _browse_pkt(_browse_body(opcode=0x0C)),          # domain announcement — not a host
        _browse_pkt(b"\x01\x00short"),                    # body shorter than the fixed layout
        _browse_pkt(_browse_body(name=b"")),              # no server name
    ])
    assert acc.summary() == {}


def test_browser_ignores_non_138_and_markerless_and_non_udp():
    acc = _run([
        # A browse announcement on a non-datagram-service conversation (neither side 138).
        Ether(src=MAC) / IP(src=CLIENT) / UDP(sport=137, dport=137) / Raw(load=MARK + _browse_body()),
        Ether(src=MAC) / IP(src=CLIENT) / UDP(sport=138, dport=138) / Raw(load=b"no marker here"),
        Ether(src=MAC) / IP(src=CLIENT),                  # no UDP at all
    ])
    assert acc.summary() == {}


# ── DHCP ──────────────────────────────────────────────────────────────────────

def test_dhcp_hostname_and_fqdn_recorded_by_ip():
    rec = _run([_dhcp_pkt([("hostname", b"DESKTOP-5OMVI3L"),
                           ("client_FQDN", b"\x00\x00\x00DESKTOP-5OMVI3L.theluckyturkey.com"),
                           "end"])]).summary()["by_ip"][CLIENT]
    assert rec["name"] == "DESKTOP-5OMVI3L"
    assert rec["fqdn"] == "DESKTOP-5OMVI3L.theluckyturkey.com"
    assert rec["sources"] == ["DHCP"]


def test_dhcp_from_an_unconfigured_client_is_keyed_by_mac():
    rec = _run([_dhcp_pkt([("hostname", b"DESKTOP-5OMVI3L"), "end"],
                          src="0.0.0.0")]).summary()["by_mac"][MAC]
    assert rec["name"] == "DESKTOP-5OMVI3L"


def test_dhcp_without_a_name_or_a_flags_only_fqdn_records_nothing():
    acc = _run([_dhcp_pkt([("client_FQDN", b"\x00\xff\xff"), "end"])])    # flags-only, no name
    assert acc.summary() == {}


def test_a_name_with_no_resolvable_key_is_dropped():
    # DHCP from 0.0.0.0 with no Ethernet layer: no IP and no MAC to key on.
    acc = _run([_dhcp_pkt([("hostname", b"X"), "end"], src="0.0.0.0", with_ether=False)])
    assert acc.summary() == {}


def test_non_dhcp_packet_is_ignored():
    acc = _run([Ether(src=MAC) / IP(src=CLIENT) / UDP(sport=5, dport=5) / Raw(load=b"x")])
    assert acc.summary() == {}


# ── helpers ───────────────────────────────────────────────────────────────────

def test_text_decoding():
    assert hn._text(b"NAME\x00\x00") == "NAME"
    assert hn._text("already") == "already"


def test_fqdn_strips_control_bytes_and_rejects_noise():
    assert hn._fqdn(b"\x00\x00\x00host.example.com") == "host.example.com"
    assert hn._fqdn(b"\x00\xff\xff") == ""              # flags only, high bytes dropped
    assert hn._fqdn("plain.name") == "plain.name"


def test_os_label_and_role_decoding():
    assert hn._os_label(10, 0) == "Windows 10/11 or Server 2016+"
    assert hn._os_label(7, 7) == ""
    assert hn._os_label(None, None) == ""
    assert "domain controller" in hn._role(0x00000008)
    assert hn._role("not-an-int") == ""


def test_eth_and_ip_src_helpers():
    assert hn._eth_src(Ether(src=MAC) / IP(src=CLIENT)) == MAC
    assert hn._eth_src(IP(src=CLIENT)) == ""
    assert hn._ip_src(IP(src=CLIENT)) == CLIENT
    assert hn._ip_src(IPv6(src="fe80::1")) == "fe80::1"
    assert hn._ip_src(Ether(src=MAC)) == ""
