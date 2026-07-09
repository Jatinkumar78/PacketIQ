"""The per-packet AI triage note must arrive as clean, labelled sections — never
raw Markdown — and the UI's evidence panel must come from deterministic packet
facts, not from the model.
"""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from packetiq.inspect import analyst_facts
from packetiq.webapp import app as webapp

_CLEAN = """VERDICT: Benign
SUMMARY: A TLS 1.2 Application Data record on an established HTTPS session.
ORIGIN: Internal 10.0.0.5 (client, port 51000) to external 93.184.216.34 on port 443.
ASSESSMENT: Port matches protocol and the payload is encrypted. Nothing stands out.
ACTION: No action — normal traffic. Follow the TCP stream to confirm the cipher."""

# A model that ignores the "no Markdown" rule — the parser must still clean it.
_MESSY = """**VERDICT:** Suspicious
**SUMMARY:** High-entropy label in a DNS query.
* **ORIGIN:** Internal host to the local resolver on port 53.
- ASSESSMENT: Entropy is **consistent with** encoded data in the query name.
**ACTION:** Pivot on the querying host."""


def test_prompt_forbids_markdown_and_names_the_sections():
    p = webapp._PACKET_EXPLAIN_SYSTEM
    assert "Do NOT use Markdown" in p
    for label in ("VERDICT:", "SUMMARY:", "ORIGIN:", "ASSESSMENT:", "ACTION:"):
        assert label in p


def test_parses_clean_labelled_sections():
    s = webapp._parse_explanation(_CLEAN)
    assert s["verdict"] == "Benign"
    assert s["verdict_key"] == "benign"
    assert s["summary"].startswith("A TLS 1.2 Application Data record")
    assert "93.184.216.34" in s["origin"]
    assert "encrypted" in s["assessment"]
    assert s["action"].startswith("No action")


def test_strips_markdown_the_model_leaked():
    s = webapp._parse_explanation(_MESSY)
    assert s["verdict"] == "Suspicious"
    assert s["verdict_key"] == "suspicious"
    blob = " ".join(s.values())
    assert "*" not in blob and "_" not in blob and "#" not in blob
    assert "consistent with" in s["assessment"]     # content survives the strip


def test_verdict_maps_to_badge_class():
    assert webapp._verdict_key("Benign") == "benign"
    assert webapp._verdict_key("Informational") == "informational"
    assert webapp._verdict_key("Worth a look") == "review"
    assert webapp._verdict_key("Suspicious") == "suspicious"
    assert webapp._verdict_key("Malicious") == "suspicious"
    assert webapp._verdict_key("weird thing") == "informational"


def test_unlabelled_prose_yields_no_sections():
    # Falls back to cleaned prose in the UI rather than rendering nothing.
    assert webapp._parse_explanation("Let's break down this packet. It is a UDP packet.") == {}
    assert webapp._parse_explanation("") == {}


def test_analyst_facts_are_deterministic_and_structured():
    pkt = (Ether(src="aa:bb:cc:00:11:22", dst="aa:bb:cc:33:44:55")
           / IP(src="10.0.0.5", dst="93.184.216.34", ttl=64)
           / TCP(sport=51000, dport=443, flags="PA") / (b"\x17\x03\x03\x00\x10" + b"\x00" * 16))
    f = analyst_facts(pkt, 7)
    assert f["index"] == 7
    assert f["protocol"] == "TLS"
    assert f["src"] == "10.0.0.5" and "RFC1918" in f["src_role"]
    assert f["dst"] == "93.184.216.34" and "public" in f["dst_role"]
    assert f["dport_desc"] == "443 (HTTPS)"
    assert "client → server" in f["direction"]
    assert f["ttl"] == 64 and f["ttl_initial"] == 64 and f["hops"] == 0
    assert "Linux" in f["os_hint"]
    assert f["tcp_flags"] == "PSH, ACK"
    assert f["app_decoded"].startswith("TLS 1.2")
    assert f["payload_size"] > 0 and 0 <= f["entropy"] <= 8


def test_analyst_facts_control_segment_has_no_payload():
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9", ttl=128) / TCP(sport=51000, dport=445, flags="S")
    f = analyst_facts(pkt, 0)
    assert f["payload_size"] == 0
    assert "Windows" in f["os_hint"]
    assert "entropy" not in f          # no payload → no entropy claim


def test_analyst_facts_decodes_dns_query():
    pkt = (Ether() / IP(src="10.0.0.5", dst="8.8.8.8", ttl=64)
           / UDP(sport=51515, dport=53) / DNS(rd=1, qd=DNSQR(qname="evil.example.com")))
    f = analyst_facts(pkt, 1)
    assert f["protocol"] == "DNS"
    assert "evil.example.com" in f["app_decoded"]
    assert f["dport_desc"] == "53 (DNS)"
