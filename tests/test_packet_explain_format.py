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


_BULLETED = """VERDICT: Worth a look - long encoded URI over cleartext HTTP
SUMMARY: An HTTP GET from an internal host to an external server on port 80.
ORIGIN: Internal 172.20.10.3 (client) to public 52.84.112.57 on port 80.
KEY POINTS:
- Host roles: internal client to external server
- Ports: 50219 (ephemeral) to 80 (HTTP)
- Payload: 5.74/8.00 entropy, consistent with encoded text
ASSESSMENT: Not proof of compromise, but worth a second look.
ACTION: Follow the TCP stream and decode the URI."""

# Old/alternate headings a model may drift to, including a bare heading with no colon.
_ALIASED = """Verdict — Worth a look: long encoded URI
What this packet is — An HTTP GET to an external server.
Key fields that matter
- TTL: 64 is consistent with Linux
- Destination port: 80, an HTTP service
Indicators & context — The URI looks encoded.
Recommended next step — Follow the TCP stream."""


def test_prompt_forbids_markdown_and_names_the_sections():
    p = webapp._PACKET_EXPLAIN_SYSTEM
    assert "Do NOT use Markdown" in p
    for label in ("VERDICT:", "SUMMARY:", "ORIGIN:", "KEY POINTS:", "ASSESSMENT:", "ACTION:"):
        assert label in p


def test_key_points_parse_into_a_list():
    s = webapp._parse_explanation(_BULLETED)
    assert isinstance(s["key_points"], list)
    assert len(s["key_points"]) == 3
    assert s["key_points"][0] == "Host roles: internal client to external server"
    assert not any(p.startswith("-") for p in s["key_points"])


def test_verdict_reason_is_split_from_the_label():
    s = webapp._parse_explanation(_BULLETED)
    assert s["verdict"] == "Worth a look"          # clean badge text
    assert s["verdict_key"] == "review"
    assert s["verdict_reason"] == "long encoded URI over cleartext HTTP"


def test_alias_headings_and_bare_heading_are_understood():
    s = webapp._parse_explanation(_ALIASED)
    assert s["verdict"] == "Worth a look"
    assert s["summary"].startswith("An HTTP GET")
    assert len(s["key_points"]) == 2               # bare "Key fields that matter" heading
    assert "encoded" in s["assessment"]
    assert s["action"].startswith("Follow the TCP stream")


def test_verdict_alone_is_not_a_structured_answer():
    # Nothing substantive → caller renders the prose fallback instead of a bare badge.
    assert webapp._parse_explanation("VERDICT: Benign") == {}


def test_overlong_verdict_reason_becomes_the_summary():
    # A model that ran its whole answer onto the verdict line must not stretch the badge.
    long_tail = "This is a very long trailing explanation that clearly belongs in the summary " \
                "rather than beside the verdict badge, since it runs well past the limit."
    s = webapp._parse_explanation("VERDICT: Benign - " + long_tail)
    assert "verdict_reason" not in s
    assert s["summary"] == long_tail
    assert s["verdict"] == "Benign"


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
