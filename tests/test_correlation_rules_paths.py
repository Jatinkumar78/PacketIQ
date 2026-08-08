"""Correlation rules: the thresholds that decide whether findings become a chain.

A chain is the strongest claim PacketIQ makes — "these separate findings are one
intrusion". Every rule here has a minimum-evidence bar, and the tests pin both
sides of it: the case that clears the bar and the case that must not.
"""


from packetiq.correlation import rules
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, EventType, Severity

TS = 1700000000.0


def _event(etype, severity=Severity.HIGH, src="45.33.32.156", dst="192.168.1.50",
           port=445, ts=TS, description="finding", evidence=None):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=port,
                          protocol="TCP", timestamp=ts, packet_count=10,
                          evidence=evidence or {})


# ── Time ordering ────────────────────────────────────────────────────────────

def test_events_within_the_window_are_correlatable():
    assert rules._time_order(_event(EventType.PORT_SCAN, ts=TS),
                             _event(EventType.BRUTE_FORCE, ts=TS + 600)) is True


def test_an_event_that_precedes_its_supposed_cause_is_not_correlatable():
    """Brute force *before* the scan that found the host is not that chain."""
    assert rules._time_order(_event(EventType.PORT_SCAN, ts=TS + 600),
                             _event(EventType.BRUTE_FORCE, ts=TS)) is False


def test_events_an_hour_apart_are_not_correlatable():
    assert rules._time_order(_event(EventType.PORT_SCAN, ts=TS),
                             _event(EventType.BRUTE_FORCE, ts=TS + 7200)) is False


def test_an_event_with_no_timestamp_is_not_excluded_on_timing():
    """Some detectors report a finding without a first-occurrence time; refusing
    to correlate those would break the chain for a whole class of findings."""
    assert rules._time_order(_event(EventType.PORT_SCAN, ts=0.0),
                             _event(EventType.BRUTE_FORCE, ts=TS)) is True


# ── Recon → initial access ───────────────────────────────────────────────────

def test_a_scan_and_a_brute_force_against_the_same_host_form_a_chain():
    chains = rules.recon_to_initial_access([
        _event(EventType.PORT_SCAN, ts=TS),
        _event(EventType.BRUTE_FORCE, ts=TS + 300, port=22),
    ])

    assert len(chains) == 1
    assert chains[0].attacker_ips == {"45.33.32.156"}


def test_a_scan_and_a_brute_force_against_different_hosts_do_not_chain():
    """Same attacker, unrelated targets, and a narrow scan — correlating those
    would invent a campaign out of two independent findings."""
    chains = rules.recon_to_initial_access([
        _event(EventType.PORT_SCAN, dst="192.168.1.50", ts=TS),
        _event(EventType.BRUTE_FORCE, dst="10.9.9.9", ts=TS + 300, port=22),
    ])

    assert chains == []


def test_a_broad_host_scan_chains_to_a_brute_force_on_any_host_it_swept():
    chains = rules.recon_to_initial_access([
        _event(EventType.HOST_SCAN, dst="192.168.1.99", ts=TS),
        _event(EventType.BRUTE_FORCE, dst="192.168.1.50", ts=TS + 300, port=22),
    ])

    assert len(chains) == 1


# ── C2 channel ───────────────────────────────────────────────────────────────

def test_a_single_c2_indicator_is_not_a_channel():
    """One beacon is a finding. Calling it an established C2 channel overstates
    what the packets show."""
    assert rules.c2_channel_detection([_event(EventType.C2_BEACON, src="192.168.1.50")]) == []


def test_two_c2_indicators_from_one_host_are_a_channel():
    # DNS tunnelling plus an ICMP covert channel: two independent ways of
    # reaching the same operator, which is what "established channel" means.
    chains = rules.c2_channel_detection([
        _event(EventType.DNS_TUNNELING, src="192.168.1.50", ts=TS),
        _event(EventType.ICMP_TUNNELING, src="192.168.1.50", ts=TS + 60),
    ])

    assert len(chains) == 1
    assert chains[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_a_dga_finding_counts_as_a_c2_indicator():
    chains = rules.c2_channel_detection([
        _event(EventType.DNS_ANOMALY, src="192.168.1.50", ts=TS,
               description="Potential DGA domain queried: x7k2m9q4v6z1n8p3.com"),
        _event(EventType.ICMP_TUNNELING, src="192.168.1.50", ts=TS + 60),
    ])

    assert len(chains) == 1


# ── Covert exfiltration ──────────────────────────────────────────────────────

def test_a_host_with_no_tunnel_findings_is_not_exfiltrating():
    assert rules.covert_exfiltration([_event(EventType.C2_BEACON, src="192.168.1.50")]) == []


def test_both_tunnel_channels_at_once_is_escalated():
    chains = rules.covert_exfiltration([
        _event(EventType.ICMP_TUNNELING, src="192.168.1.50", ts=TS,
               evidence={"bytes": 130000}),
        _event(EventType.DNS_TUNNELING, src="192.168.1.50", ts=TS + 60,
               evidence={"bytes": 4000}),
    ])

    assert len(chains) == 1
    assert chains[0].severity == Severity.CRITICAL


def test_one_tunnel_channel_is_still_reported():
    chains = rules.covert_exfiltration([
        _event(EventType.DNS_TUNNELING, src="192.168.1.50", evidence={"bytes": 4000}),
    ])
    assert len(chains) == 1


# ── DGA cluster ──────────────────────────────────────────────────────────────

def test_a_single_generated_domain_is_not_a_cluster():
    assert rules.dga_c2_cluster([
        _event(EventType.DNS_ANOMALY, src="192.168.1.50",
               description="Potential DGA domain queried: aaa.com",
               evidence={"domain": "aaa.com"}),
    ]) == []


def test_several_generated_domains_from_one_host_are_a_cluster():
    """Domain rotation is the signature. The chain has to name the domains, or
    a responder cannot go and block them."""
    events = [
        _event(EventType.DNS_ANOMALY, src="192.168.1.50", ts=TS + i,
               description=f"Potential DGA domain queried: gen{i}.example.xyz",
               evidence={"domain": f"gen{i}.example.xyz"})
        for i in range(4)
    ]
    chains = rules.dga_c2_cluster(events)

    assert len(chains) == 1
    assert "4" in chains[0].description
    assert chains[0].attacker_ips == {"192.168.1.50"}


# ── Credential spray ─────────────────────────────────────────────────────────

def test_too_few_brute_force_findings_are_not_a_spray():
    events = [_event(EventType.BRUTE_FORCE, dst=f"192.168.1.{50 + i}", port=22)
              for i in range(2)]
    assert rules.credential_spray(events) == []


def test_brute_force_concentrated_on_one_host_is_not_a_spray():
    """Depth, not breadth — that is rule 1's chain, not this one. Reporting it
    twice would double-count the same intrusion."""
    events = [_event(EventType.BRUTE_FORCE, dst="192.168.1.50", port=22, ts=TS + i)
              for i in range(5)]
    assert rules.credential_spray(events) == []


def test_brute_force_spread_across_many_hosts_on_one_service_is_a_spray():
    events = [_event(EventType.BRUTE_FORCE, dst=f"192.168.1.{50 + i}", port=22,
                     ts=TS + i) for i in range(5)]
    chains = rules.credential_spray(events)

    assert len(chains) == 1
    assert "SSH" in chains[0].name
    assert "5 " in chains[0].description
    assert chains[0].severity == Severity.HIGH


def test_a_wide_enough_spray_is_critical():
    events = [_event(EventType.BRUTE_FORCE, dst=f"192.168.1.{50 + i}", port=3389,
                     ts=TS + i) for i in range(12)]
    chains = rules.credential_spray(events)

    assert len(chains) == 1
    assert chains[0].severity == Severity.CRITICAL


def test_sprays_against_two_services_are_reported_separately():
    """A single chain covering both would lose which service to lock down."""
    events = ([_event(EventType.BRUTE_FORCE, dst=f"192.168.1.{50 + i}", port=22,
                      ts=TS + i) for i in range(4)]
              + [_event(EventType.BRUTE_FORCE, dst=f"192.168.1.{60 + i}", port=3389,
                        ts=TS + i) for i in range(4)])
    chains = rules.credential_spray(events)

    assert len(chains) == 2
    assert {c.name.split(" — ")[1].split(":")[0] for c in chains} == {"SSH", "RDP"}


def test_a_spray_on_a_port_with_no_known_service_still_names_the_port():
    events = [_event(EventType.BRUTE_FORCE, dst=f"192.168.1.{50 + i}", port=9999,
                     ts=TS + i) for i in range(4)]
    chains = rules.credential_spray(events)

    assert len(chains) == 1
    assert "9999" in chains[0].name


# ── Chain result assembly ────────────────────────────────────────────────────

def test_a_chain_absorbed_by_another_is_not_lost_from_the_result():
    """The merge pass collects anything that was absorbed *into* but not yet
    emitted; dropping it would silently delete a real chain from the report."""
    from packetiq.correlation.engine import CorrelationEngine

    shared = [_event(EventType.PORT_SCAN, ts=TS + i) for i in range(6)]

    def chain(cid, evs):
        return AttackChain(chain_id=cid, name=f"chain {cid}", description="d",
                           attacker_ips={"45.33.32.156"}, target_ips={"192.168.1.50"},
                           events=list(evs), severity=Severity.HIGH, confidence=0.8,
                           first_seen=TS, last_seen=TS + 300)

    merged = CorrelationEngine()._merge([chain("AAAA", shared[:2]),
                                         chain("BBBB", shared),
                                         chain("CCCC", shared[3:])])

    assert merged, "the merge must never return an empty set for real chains"
    assert all(isinstance(c, AttackChain) for c in merged)


# ── Attribution scoring guards ───────────────────────────────────────────────

def test_an_actor_profile_with_no_weights_is_skipped(monkeypatch):
    """A malformed profile would divide by zero when scoring."""
    from packetiq.attribution import engine as attr

    monkeypatch.setattr(attr, "THREAT_ACTORS", [
        {"name": "Empty Profile", "aliases": [], "origin": "?", "motivation": "?",
         "ttp_weights": {}, "phases": set(), "description": "", "references": []},
    ])

    assert attr.AttributionEngine().attribute(
        [_event(EventType.PORT_SCAN), _event(EventType.BRUTE_FORCE)], []) == []


def test_a_thin_overlap_is_rejected_even_when_the_ttps_match(monkeypatch):
    """Two matched TTPs out of twenty is coincidence, not attribution."""
    from packetiq.attribution import engine as attr

    monkeypatch.setattr(attr, "THREAT_ACTORS", [
        {"name": "Broad Profile", "aliases": [], "origin": "?", "motivation": "?",
         "ttp_weights": {t: 1.0 for t in EventType},
         "phases": set(), "description": "", "references": []},
    ])

    matches = attr.AttributionEngine().attribute(
        [_event(EventType.PORT_SCAN), _event(EventType.BRUTE_FORCE)], [])

    assert matches == [], "a 2-of-many overlap must not produce an attribution"
