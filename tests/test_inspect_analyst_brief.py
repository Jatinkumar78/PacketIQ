"""The AI 'explain this packet' fact sheet must read like a professional analyst
view — ports as numbers + service (never scapy's obscure aliases), host roles,
TTL/OS fingerprint, direction, payload entropy, and decoded app-layer — all
grounded in the packet.
"""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from packetiq.inspect import (
    _entropy,
    _port_role,
    _tls_sni,
    _ttl_analysis,
    analyst_brief,
)

_MAC_A = "aa:bb:cc:00:11:22"
_MAC_B = "aa:bb:cc:33:44:55"


def _tls_client_hello(sni: bytes) -> bytes:
    entry = b"\x00" + len(sni).to_bytes(2, "big") + sni
    name_list = len(entry).to_bytes(2, "big") + entry
    ext = b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f"
            + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(hs).to_bytes(2, "big") + hs


def test_ports_shown_as_numbers_with_service_not_aliases():
    pkt = (Ether(src=_MAC_A, dst=_MAC_B)
           / IP(src="17.252.60.221", dst="172.20.10.3", ttl=50)
           / UDP(sport=443, dport=16393))
    brief = analyst_brief(pkt, 42)
    assert "443 (HTTPS)" in brief
    assert "16393" in brief
    # scapy's alias for 3062 etc. must never leak into the analyst view
    assert "ifsf" not in brief.lower()
    assert "_port" not in brief


def test_host_roles_and_ttl_fingerprint():
    pkt = (Ether(src=_MAC_A, dst=_MAC_B)
           / IP(src="17.252.60.221", dst="172.20.10.3", ttl=50)
           / UDP(sport=443, dport=16393))
    brief = analyst_brief(pkt, 1)
    assert "public / external" in brief          # the Apple-owned public IP
    assert "RFC1918" in brief                     # the local host
    assert "TTL" in brief and "hops" in brief
    assert "consistent with" in brief             # honest, hedged language


def test_direction_and_flags_for_tcp():
    pkt = (Ether(src=_MAC_A, dst=_MAC_B)
           / IP(src="10.0.0.5", dst="93.184.216.34", ttl=64)
           / TCP(sport=51000, dport=443, flags="S"))
    brief = analyst_brief(pkt, 2)
    assert "client → server" in brief             # dst holds the service port
    assert "SYN" in brief
    assert "ephemeral" in brief                    # 51000 is a client source port


def test_tls_sni_is_decoded():
    ch = _tls_client_hello(b"example.com")
    pkt = (Ether(src=_MAC_A, dst=_MAC_B)
           / IP(src="10.0.0.5", dst="93.184.216.34", ttl=64)
           / TCP(sport=51000, dport=443, flags="PA") / ch)
    brief = analyst_brief(pkt, 3)
    assert "TLS" in brief
    assert "example.com" in brief                  # SNI extracted


def test_entropy_flags_encrypted_payload():
    high = _entropy(bytes(range(256)) * 4)
    low = _entropy(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assert high > 7.5
    assert low < 5.0


def test_control_segment_has_no_payload_section():
    pkt = (Ether(src=_MAC_A, dst=_MAC_B)
           / IP(src="10.0.0.5", dst="10.0.0.9", ttl=128)
           / TCP(sport=51000, dport=445, flags="S"))
    brief = analyst_brief(pkt, 4)
    assert "No transport payload" in brief
    assert "consistent with Windows" in brief      # TTL 128 → Windows


def test_helpers_direct():
    assert _port_role(53).startswith("53 (")
    assert "ephemeral" in _port_role(51000)
    init, hops, osf = _ttl_analysis(50)
    assert init == 64 and hops == 14 and "Linux" in osf
    assert _tls_sni(b"not-a-tls-record") == ""      # never raises
