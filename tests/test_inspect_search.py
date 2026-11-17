"""Packet inspector search — protocol-aware filtering (http ≠ https, tls finds 443)."""

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether

from packetiq.inspect import matches, summarize


def _sum(pkt):
    return summarize(pkt, 0)


def test_protocol_tokens_present():
    s = _sum(Ether() / IP(dst="1.1.1.1") / TCP(dport=443, flags="S"))
    assert "tls" in s["protocols"] and "https" in s["protocols"] and "tcp" in s["protocols"]
    assert "http" not in s["protocols"]


def test_http_does_not_match_https():
    http = _sum(Ether() / IP() / TCP(sport=5001, dport=80, flags="PA") / b"GET / HTTP/1.1\r\n")
    https = _sum(Ether() / IP() / TCP(sport=5002, dport=443, flags="PA") / b"\x16\x03\x01")
    assert matches(http, "http") and not matches(https, "http")     # the original bug
    assert matches(https, "https") and not matches(http, "https")


def test_tls_finds_443():
    https = _sum(Ether() / IP() / TCP(sport=5002, dport=443, flags="S"))
    assert matches(https, "tls")          # previously returned nothing
    assert matches(https, "ssl")


def test_protocol_exact_keywords():
    dns = _sum(Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="x.com")))
    icmp = _sum(Ether() / IP(dst="8.8.8.8") / ICMP())
    arp = _sum(Ether() / ARP(pdst="10.0.0.1"))
    assert matches(dns, "dns") and matches(dns, "udp") and not matches(dns, "tcp")
    assert matches(icmp, "icmp") and not matches(icmp, "dns")
    assert matches(arp, "arp")


def test_multi_token_and_semantics():
    http = _sum(Ether() / IP(src="10.0.0.2", dst="93.184.216.34") / TCP(dport=80, flags="PA") / b"GET /")
    assert matches(http, "http 10.0.0.2")        # protocol AND ip
    assert not matches(http, "http 9.9.9.9")     # ip not present
    assert not matches(http, "https 10.0.0.2")   # wrong protocol


def test_substring_and_empty():
    p = _sum(Ether() / IP(src="10.0.0.2", dst="8.8.8.8") / UDP(dport=53) / DNS())
    assert matches(p, "8.8.8.8")     # ip substring
    assert matches(p, "")            # empty query matches everything
    assert not matches(p, "9.9.9.9")


def test_a_very_long_search_query_is_bounded():
    """Search cost is tokens x packets, and up to 200,000 packets are scanned.

    An unbounded query was a free way to burn server CPU through
    `/api/packets?q=`: measured 0.4us/packet for a single token but
    644us/packet for 50,000 — roughly 129 seconds of work for one request, and
    a URL carries that many single-character tokens comfortably. Capping the
    token count alone was not enough, because `q.lower().split()` ran once per
    packet and is itself proportional to the query length; slicing the string
    first makes the cost flat (~2us/packet even for a 1 MB query).

    The trade-off is deliberate: tokens past the 32nd are ignored. Under AND
    semantics a 33-term search already matches nothing, so no useful query is
    affected — and this is asserted rather than timed so it holds on any runner.
    """
    summary = {"src": "10.0.0.9", "dst": "45.33.32.156", "proto": "TCP",
               "service": "HTTP", "info": "GET /index.html",
               "protocols": ["tcp", "http"]}

    # Within the cap, one non-matching token still rejects the packet.
    assert matches(summary, " ".join(["0"] * 5 + ["definitelynotpresent"])) is False

    # Past the cap the tail is never consulted, so the packet still matches.
    assert matches(summary, " ".join(["0"] * 32 + ["definitelynotpresent"])) is True

    # A megabyte of query is accepted and answered, not refused or hung on.
    assert matches(summary, "0 " * 500_000) is True


def test_bounding_the_query_leaves_ordinary_searches_alone():
    """The cap must not change what a real search means."""
    summary = {"src": "10.0.0.9", "dst": "45.33.32.156", "proto": "TCP",
               "service": "HTTP", "info": "GET /index.html",
               "protocols": ["tcp", "http"]}

    assert matches(summary, "http") is True
    assert matches(summary, "https") is False, "protocol keywords stay exact"
    assert matches(summary, "10.0.0.9 http") is True
    assert matches(summary, "nomatch") is False
    assert matches(summary, "") is True
