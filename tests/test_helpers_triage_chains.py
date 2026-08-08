"""Shared helpers, allow-list triage, and attack-chain merging.

Helpers here are called from every renderer and detector, so a wrong answer
travels everywhere at once. Triage decides what a user never sees — the one
place where a bug removes a real finding silently rather than adding a noisy
one — so both the suppression and the refusal-to-suppress are pinned down.
"""

import ipaddress

import pytest

from packetiq import triage
from packetiq.correlation.models import AttackChain, MitreTechnique
from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.utils import helpers

TS = 1700000000.0


def _event(etype=EventType.PORT_SCAN, severity=Severity.HIGH, src="45.33.32.156",
           dst="192.168.1.50", confidence=0.9, evidence=None, ts=TS):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description="finding", dst_ip=dst, dst_port=445,
                          protocol="TCP", timestamp=ts, packet_count=10,
                          confidence=confidence, evidence=evidence or {})


# ── Formatting helpers ───────────────────────────────────────────────────────

@pytest.mark.parametrize("size,expect", [
    (512, "512.0 B"),
    (1536, "1.5 KB"),
    (5 * 1024 ** 2, "5.0 MB"),
    (3 * 1024 ** 3, "3.0 GB"),
    (2 * 1024 ** 4, "2.0 TB"),
    (7 * 1024 ** 5, "7.0 PB"),
])
def test_byte_sizes_scale_all_the_way_to_petabytes(size, expect):
    """The PB rung is the loop's fall-through; a multi-TB capture index hits it."""
    assert helpers.format_bytes(size) == expect


@pytest.mark.parametrize("secs,expect", [
    (0.25, "250.0ms"),
    (12.5, "12.50s"),
    (90, "1m 30s"),
    (3725, "1h 2m 5s"),
    (90000, "25h 0m 0s"),
])
def test_durations_scale_from_milliseconds_to_hours(secs, expect):
    assert helpers.format_duration(secs) == expect


def test_an_ipv4_address_converts_to_an_integer_for_range_maths():
    assert helpers.ip_to_int("0.0.0.1") == 1
    assert helpers.ip_to_int("255.255.255.255") == 4294967295


@pytest.mark.parametrize("value", ["not-an-ip", "", "2606:4700::1111", None])
def test_anything_that_is_not_an_ipv4_address_converts_to_zero(value):
    """Callers use this for ordering, so it must return a number, not raise."""
    assert helpers.ip_to_int(value) == 0


def test_a_timestamp_renders_to_millisecond_precision():
    assert helpers.ts_to_str(TS).count(":") == 2
    assert "." in helpers.ts_to_str(TS)


@pytest.mark.parametrize("value", ["not-a-timestamp", 1e30, float("nan")])
def test_an_unrenderable_timestamp_falls_back_to_its_own_text(value):
    """A corrupt packet time must not take the whole report down."""
    assert helpers.ts_to_str(value) == str(value)


# ── Same-organisation reasoning ──────────────────────────────────────────────

def test_two_private_addresses_are_the_same_organisation():
    assert helpers.same_org_network("192.168.1.10", "10.0.0.5") is True


def test_two_public_addresses_in_one_block_are_the_same_organisation():
    assert helpers.same_org_network("147.32.84.10", "147.32.200.1") is True


def test_two_public_addresses_in_different_blocks_are_not():
    assert helpers.same_org_network("147.32.84.10", "185.199.108.153") is False


def test_a_private_to_public_pair_is_a_genuine_boundary_crossing():
    """This is the case the SMB and cleartext detectors exist to catch."""
    assert helpers.same_org_network("192.168.1.10", "185.199.108.153") is False


def test_mixed_address_families_are_never_the_same_network():
    assert helpers.same_org_network("192.168.1.10", "fd00::1") is False


@pytest.mark.parametrize("a,b", [
    ("", "10.0.0.1"), ("10.0.0.1", ""),
    ("example.com", "10.0.0.1"),        # an HTTP Host header, not an address
])
def test_inputs_that_are_not_addresses_cannot_be_judged(a, b):
    assert helpers.same_org_network(a, b) is False


def test_an_ipv6_pair_is_compared_on_its_slash_48_routing_prefix():
    """IPv6 uses /48, not the IPv4 /16 — that is the block an organisation is
    actually delegated, so the two families need different prefix lengths."""
    assert helpers.same_org_network("2606:4700:0:1::1", "2606:4700:0:2::9") is True
    assert helpers.same_org_network("2606:4700:0:1::1", "2606:4701:0:1::9") is False


# ── Segment keys and OUI vendors ─────────────────────────────────────────────

def test_a_segment_key_is_a_slash_24_for_ipv4_and_a_slash_64_for_ipv6():
    assert helpers._ip_network_key("192.168.1.50") == "192.168.1.0/24"
    assert helpers._ip_network_key("2606:4700::1111").endswith("/64")


def test_something_that_is_not_an_address_has_no_segment():
    assert helpers._ip_network_key("not-an-ip") is None


def test_a_locally_administered_mac_is_never_given_a_vendor():
    """Randomised MACs (the 0x2 bit) carry no real OUI. Naming a vendor there
    would attribute a phone's privacy address to whoever owns that prefix."""
    assert helpers.oui_vendor("02:11:22:33:44:55") == ""
    assert helpers.oui_vendor("aa:bb:cc:dd:ee:ff") == ""      # 0xaa has 0x2 set


@pytest.mark.parametrize("mac", ["", "aa:bb", "not:a:mac:at:all:xx", "zz:11:22:33:44:55"])
def test_an_unparseable_mac_yields_no_vendor(mac):
    assert helpers.oui_vendor(mac) == ""


# ── Triage: evidence rendering ───────────────────────────────────────────────

def test_empty_evidence_fields_are_dropped_from_the_explanation():
    """A finding card full of `Foo: ` lines reads as broken, not as thorough."""
    points = triage._evidence_points({"attempts": 40, "note": "", "targets": [],
                                      "extra": None, "detail": {}})
    assert points == ["Attempts: 40"]


def test_a_list_valued_evidence_field_is_rendered_inline_and_capped():
    points = triage._evidence_points({"ports": list(range(20))})
    assert points[0].startswith("Ports: 0, 1, 2")
    assert "9," not in points[0].split("Ports: ")[1].split(", ")[-1]


def test_the_number_of_evidence_points_is_capped():
    points = triage._evidence_points({f"field_{i}": i + 1 for i in range(30)})
    assert len(points) == 12


# ── Triage: the allow-list ───────────────────────────────────────────────────

def _allowlist(**kw):
    al = triage.Allowlist()
    al.ips = set(kw.get("ips", []))
    al.cidrs = [ipaddress.ip_network(c, strict=False) for c in kw.get("cidrs", [])]
    al.domains = set(kw.get("domains", []))
    al.ja3 = set(kw.get("ja3", []))
    return al


def test_an_allow_listed_address_suppresses_the_finding_with_a_reason():
    hit, reason = triage.is_allowlisted(_event(src="45.33.32.156"),
                                        _allowlist(ips=["45.33.32.156"]))
    assert hit is True
    assert "45.33.32.156" in reason and "allow-list" in reason


def test_an_address_inside_an_allow_listed_network_is_suppressed():
    """A vulnerability scanner lives on one subnet; allow-listing it by CIDR is
    how an operator stops it filling every report."""
    hit, reason = triage.is_allowlisted(_event(src="10.10.5.7"),
                                        _allowlist(cidrs=["10.10.0.0/16"]))
    assert hit is True
    assert "allow-listed network" in reason


def test_an_address_outside_the_allow_listed_network_is_kept():
    hit, _ = triage.is_allowlisted(_event(src="192.168.1.9"),
                                   _allowlist(cidrs=["10.10.0.0/16"]))
    assert hit is False


def test_a_non_address_is_never_matched_against_a_cidr():
    assert triage._ip_in_cidrs("not-an-ip", [ipaddress.ip_network("10.0.0.0/8")]) is False
    assert triage._ip_in_cidrs("", [ipaddress.ip_network("10.0.0.0/8")]) is False
    assert triage._ip_in_cidrs("10.0.0.1", []) is False


@pytest.mark.parametrize("key", ["domain", "qname", "indicator", "host"])
def test_an_allow_listed_domain_suppresses_whichever_field_carried_it(key):
    """Detectors name the domain differently; the allow-list has to match all of them."""
    event = _event(EventType.DNS_ANOMALY, evidence={key: "Telemetry.Example.COM."})
    hit, reason = triage.is_allowlisted(event, _allowlist(domains=["telemetry.example.com"]))

    assert hit is True
    assert "telemetry.example.com" in reason


def test_an_allow_listed_ja3_fingerprint_suppresses_the_finding():
    event = _event(EventType.JA3_ANOMALY, evidence={"ja3": "A" * 32})
    hit, reason = triage.is_allowlisted(event, _allowlist(ja3=["a" * 32]))

    assert hit is True
    assert "JA3" in reason


def test_no_allow_list_means_nothing_is_suppressed():
    assert triage.is_allowlisted(_event(), None) == (False, "")
    assert triage.is_allowlisted(_event(), triage.Allowlist()) == (False, "")


def test_a_malformed_cidr_in_the_config_is_skipped_not_fatal(tmp_path, monkeypatch):
    """A typo in packetiq.toml must not stop the whole allow-list loading."""
    from packetiq import config
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text('[allowlist]\ncidrs = ["10.0.0.0/8", "not-a-cidr", "192.168.0.0/16"]\n',
                   encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        al = triage.load_allowlist()
        assert len(al.cidrs) == 2
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


# ── Triage: suppression pass ─────────────────────────────────────────────────

def test_the_default_configuration_suppresses_nothing(tmp_path, monkeypatch):
    """This is the promise the module documents: recall is unchanged out of the box."""
    from packetiq import config
    monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
    config.reload()

    events = [_event(confidence=c) for c in (0.1, 0.5, 0.9)]
    kept, suppressed = triage.apply_suppression(events)

    assert len(kept) == 3 and suppressed == []


def test_an_allow_listed_finding_is_suppressed_with_its_reason(tmp_path, monkeypatch):
    from packetiq import config
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text('[allowlist]\nips = ["45.33.32.156"]\n', encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        kept, suppressed = triage.apply_suppression([_event(src="45.33.32.156"),
                                                     _event(src="203.0.113.9")])
        assert len(kept) == 1
        assert len(suppressed) == 1
        assert "allow-list" in suppressed[0][1]
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


def test_a_confidence_floor_suppresses_weak_findings_and_says_so():
    kept, suppressed = triage.apply_suppression(
        [_event(confidence=0.2), _event(confidence=0.95, src="203.0.113.9")],
        min_confidence=0.5)

    assert len(kept) == 1 and kept[0].confidence == 0.95
    assert "below confidence floor" in suppressed[0][1]


# ── MITRE technique identity ─────────────────────────────────────────────────

def test_a_technique_renders_its_id_name_and_tactic():
    t = MitreTechnique("TA0043", "Reconnaissance", "T1046", "Network Service Discovery")
    text = str(t)

    assert "T1046" in text and "Network Service Discovery" in text and "Reconnaissance" in text


def test_techniques_are_identified_by_id_alone():
    """Two rules can label the same technique differently; deduplicating on the
    whole record would list T1046 twice in one chain."""
    a = MitreTechnique("TA0043", "Reconnaissance", "T1046", "Network Service Discovery")
    b = MitreTechnique("TA0007", "Discovery", "T1046", "Service Scanning")

    assert a == b
    assert len({a, b}) == 1


def test_a_technique_is_not_equal_to_something_else_entirely():
    t = MitreTechnique("TA0043", "Reconnaissance", "T1046", "Network Service Discovery")
    assert t != "T1046"


# ── Attack chain merging ─────────────────────────────────────────────────────

def _chain(chain_id, events, techniques=(), phases=(), attackers=("45.33.32.156",)):
    return AttackChain(chain_id=chain_id, name="chain", description="d",
                       attacker_ips=set(attackers), target_ips={"192.168.1.50"},
                       events=list(events), severity=Severity.HIGH, confidence=0.8,
                       first_seen=TS, last_seen=TS + 100,
                       mitre_techniques=list(techniques),
                       kill_chain_phases=list(phases))


def test_a_chain_reports_its_size_and_span():
    chain = _chain("AAAA", [_event(ts=TS + i) for i in range(3)])
    assert chain.event_count == 3
    assert chain.duration == 100.0


def test_a_chain_with_inverted_timestamps_reports_zero_duration():
    chain = AttackChain(first_seen=TS + 500, last_seen=TS)
    assert chain.duration == 0.0


def test_a_chain_lists_its_tactics_in_the_order_they_appear():
    """Ordering is the kill-chain narrative; a set would scramble it."""
    chain = _chain("AAAA", [], techniques=[
        MitreTechnique("TA0043", "Reconnaissance", "T1046", "Discovery"),
        MitreTechnique("TA0006", "Credential Access", "T1110", "Brute Force"),
        MitreTechnique("TA0043", "Reconnaissance", "T1595", "Active Scanning"),
    ])

    assert chain.unique_tactics == ["Reconnaissance", "Credential Access"]
    assert sorted(chain.unique_technique_ids) == ["T1046", "T1110", "T1595"]


def test_absorbing_a_chain_merges_events_intel_and_span_without_duplicating():
    a_events = [_event(ts=TS + i) for i in range(3)]
    b_events = a_events[1:] + [_event(ts=TS + 900, src="203.0.113.9")]

    a = _chain("AAAA", a_events,
               techniques=[MitreTechnique("TA0043", "Reconnaissance", "T1046", "Discovery")],
               phases=["Reconnaissance"])
    b = _chain("BBBB", b_events,
               techniques=[MitreTechnique("TA0043", "Reconnaissance", "T1046", "Discovery"),
                           MitreTechnique("TA0006", "Credential Access", "T1110", "Brute Force")],
               phases=["Reconnaissance", "Credential Access"],
               attackers=("203.0.113.9",))

    a.absorb(b)

    assert a.event_count == 4, "shared events must not be counted twice"
    assert a.attacker_ips == {"45.33.32.156", "203.0.113.9"}
    assert sorted(a.unique_technique_ids) == ["T1046", "T1110"]
    assert a.kill_chain_phases == ["Reconnaissance", "Credential Access"]
    assert a.first_seen == TS and a.last_seen == TS + 900
