"""DNS anomaly detection: the DGA scorer, the resolver guards, and the helpers.

The synthetic fixture queries `<random>.exfil.example-evil.xyz`, whose SLD is
`example-evil` — a hyphenated compound, which the DGA arm deliberately skips. So
the entire DGA finding path had never executed, and neither had four of the five
guards that stop the rogue-resolver check firing on ordinary multicast traffic.
"""

import pytest

from packetiq.detection import dns_anomaly
from packetiq.detection.models import EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# 16 distinct characters → Shannon entropy exactly 4.0 bits/char, above the 3.8
# threshold, with no hyphens to trip the compound-word guard.
DGA_SLD = "x7k2m9q4v6z1n8p3"


def _q(qname, src="192.168.1.50", dst="8.8.8.8", ts=1.0):
    return {"ts": ts, "src": src, "dst": dst, "qname": qname}


def _res(*queries):
    r = ExtractionResult()
    r.dns_queries = list(queries)
    return r


# ── DGA scoring ──────────────────────────────────────────────────────────────

def test_a_high_entropy_domain_is_flagged_as_dga():
    events = dns_anomaly._dga_detection(_res(_q(f"{DGA_SLD}.com")))

    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == EventType.DNS_ANOMALY
    assert ev.severity == Severity.HIGH
    assert ev.evidence["sld"] == DGA_SLD
    assert ev.evidence["entropy"] >= dns_anomaly.DGA_ENTROPY_THRESHOLD


def test_the_same_generated_name_under_two_tlds_is_flagged_once():
    """Fast-flux rotates the TLD; the registered label is what identifies it."""
    events = dns_anomaly._dga_detection(_res(
        _q(f"{DGA_SLD}.com"),
        _q(f"www.{DGA_SLD}.net"),
    ))
    assert len(events) == 1


def test_an_empty_query_name_is_skipped():
    """Malformed or truncated DNS shows up as an empty qname, not an exception."""
    assert dns_anomaly._dga_detection(_res(_q(""))) == []


def test_a_short_label_is_never_dga():
    """`kqxvz` has high entropy per character but is too short to be generated."""
    assert dns_anomaly._dga_detection(_res(_q("kqxvz.com"))) == []


def test_a_trusted_cdn_domain_is_never_scored():
    assert dns_anomaly._dga_detection(_res(_q("d1a2b3c4e5f6g7.cloudfront.net"))) == []


def test_a_hyphenated_compound_name_is_not_dga():
    """`kqxv-zmbr-twnj-p3y7` scores 4.0 bits — above the threshold — but its
    hyphen structure is how human-chosen names look, not generated ones."""
    assert dns_anomaly._dga_detection(_res(_q("kqxv-zmbr-twnj-p3y7.com"))) == []


@pytest.mark.parametrize("sld,expect", [
    ("googleanalytics", False),          # no hyphen at all
    ("google-analytics", True),          # two readable parts
    ("amazon-cloud-front", True),        # three
    ("kqxv-zmbr-twnj-p3y7", True),       # four is still allowed
    ("a-b-c", False),                    # parts too short
    ("kq-xv-zm-br-tw", False),           # five parts is past the limit
])
def test_the_compound_word_heuristic(sld, expect):
    assert dns_anomaly._looks_like_compound_word(sld) is expect


# ── Tunneling ────────────────────────────────────────────────────────────────

def test_one_tunneling_source_is_reported_once():
    """A tunnel emits thousands of oversized names; the host is the finding."""
    long_names = [_q("f" * 60 + f".{i}.exfil.example.com", ts=float(i)) for i in range(5)]
    events = dns_anomaly._tunneling_detection(_res(*long_names))

    assert len(events) == 1


def test_two_tunneling_sources_are_reported_separately():
    events = dns_anomaly._tunneling_detection(_res(
        _q("f" * 60 + ".exfil.example.com", src="192.168.1.50"),
        _q("g" * 60 + ".exfil.example.com", src="192.168.1.51"),
    ))
    assert len({e.src_ip for e in events}) == 2


def test_a_long_trusted_cdn_name_is_not_tunneling():
    """Signed CDN URLs routinely exceed the length threshold."""
    long_cdn = "a" * 60 + ".cloudfront.net"
    assert dns_anomaly._tunneling_detection(_res(_q(long_cdn))) == []


# ── Excessive-query context ──────────────────────────────────────────────────

def test_a_heavily_polled_name_is_informational_only():
    """This is a caching artifact, not an attack.

    It is emitted at LOW precisely so it stays below the alerting threshold —
    treating it as a threat was the dominant false-positive source on real
    benign traffic.
    """
    queries = [_q("telemetry.example.com", ts=float(i)) for i in range(30)]
    events = dns_anomaly._excessive_queries(_res(*queries))

    assert len(events) == 1
    assert events[0].severity == Severity.LOW
    assert events[0].packet_count == 30
    assert "informational" in events[0].description.lower()


def test_a_heavily_polled_trusted_domain_is_not_even_informational():
    queries = [_q("www.cloudflare.com", ts=float(i)) for i in range(30)]
    assert dns_anomaly._excessive_queries(_res(*queries)) == []


def test_a_name_queried_a_few_times_is_not_reported():
    queries = [_q("example.com", ts=float(i)) for i in range(5)]
    assert dns_anomaly._excessive_queries(_res(*queries)) == []


def test_one_name_polled_by_several_hosts_names_the_count_not_a_host():
    queries = [_q("telemetry.example.com", src=f"192.168.1.{50 + i % 3}", ts=float(i))
               for i in range(30)]
    ev = dns_anomaly._excessive_queries(_res(*queries))[0]
    assert ev.src_ip == "3 sources"


# ── Rogue-resolver guards ────────────────────────────────────────────────────

def test_a_query_with_no_destination_is_skipped():
    assert dns_anomaly._non_standard_resolver(_res(_q("example.com", dst=""))) == []


@pytest.mark.parametrize("resolver", ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
def test_well_known_public_resolvers_are_not_rogue(resolver):
    assert dns_anomaly._non_standard_resolver(_res(_q("example.com", dst=resolver))) == []


@pytest.mark.parametrize("addr", ["224.0.0.251", "ff02::fb", "224.0.0.252", "ff02::1:3"])
def test_mdns_and_llmnr_multicast_is_not_a_resolver(addr):
    """Bonjour and LLMNR are always link-local. Flagging them would put a MEDIUM
    finding in every capture taken on a normal office LAN."""
    assert dns_anomaly._non_standard_resolver(_res(_q("printer.local", dst=addr))) == []


def test_multicast_with_a_port_suffix_is_still_multicast():
    """The address arrives as `224.0.0.251:53` from some sources; the port is
    stripped before the comparison rather than the guard being missed."""
    assert dns_anomaly._non_standard_resolver(_res(_q("printer.local", dst="224.0.0.251:53"))) == []


@pytest.mark.parametrize("addr", ["239.255.255.250", "ff05::1:3"])
def test_other_multicast_ranges_are_not_resolvers(addr):
    assert dns_anomaly._non_standard_resolver(_res(_q("upnp.local", dst=addr))) == []


def test_the_local_dns_server_is_not_rogue():
    assert dns_anomaly._non_standard_resolver(_res(_q("intranet", dst="192.168.1.1"))) == []


def test_a_campus_resolver_on_a_public_address_is_not_rogue():
    """Both endpoints inside 147.32.0.0/16 — the organisation runs that resolver.

    RFC1918 alone would call this rogue, which is wrong for every publicly
    addressed campus network.
    """
    r = _res(_q("example.com", src="147.32.84.10", dst="147.32.80.1"))
    assert dns_anomaly._non_standard_resolver(r) == []


def test_an_off_network_public_resolver_is_reported_once():
    r = _res(
        _q("example.com", src="192.168.1.50", dst="185.199.108.153", ts=1.0),
        _q("other.com", src="192.168.1.50", dst="185.199.108.153", ts=2.0),
    )
    events = dns_anomaly._non_standard_resolver(r)

    assert len(events) == 1, "one client/resolver pair is one finding"
    assert events[0].severity == Severity.MEDIUM


# ── Helpers ──────────────────────────────────────────────────────────────────

def test_the_entropy_of_nothing_is_zero():
    assert dns_anomaly._shannon_entropy("") == 0.0


def test_entropy_rises_with_character_diversity():
    assert dns_anomaly._shannon_entropy("aaaaaaaa") == 0.0
    assert dns_anomaly._shannon_entropy("abcdefgh") == pytest.approx(3.0)
    assert dns_anomaly._shannon_entropy(DGA_SLD) == pytest.approx(4.0)


@pytest.mark.parametrize("fqdn,sld", [
    ("www.google.com", "google"),
    ("google.com", "google"),
    ("deep.sub.example.co", "example"),
    ("example.com.", "example"),          # trailing root dot
    ("localhost", "localhost"),           # single label, no dot to split on
    ("", ""),
])
def test_second_level_label_extraction(fqdn, sld):
    assert dns_anomaly._extract_sld(fqdn) == sld


def test_the_sliding_window_of_nothing_is_zero():
    assert dns_anomaly._max_window_count([], 60.0) == 0


def test_the_sliding_window_finds_the_densest_burst():
    """Three queries in the first second, then a long quiet spell, then two.

    The window has to slide past the gap rather than counting the whole capture.
    """
    ts = [0.0, 0.2, 0.4, 500.0, 500.5]
    assert dns_anomaly._max_window_count(ts, 60.0) == 3


def test_the_sliding_window_counts_everything_inside_one_window():
    assert dns_anomaly._max_window_count([float(i) for i in range(10)], 60.0) == 10
