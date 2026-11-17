"""
Tests for the intelligence layer: SIGMA generation, JA3 feed loading, and
the (honestly-framed) threat-actor TTP-overlap engine.
"""

import pytest
import yaml

from packetiq.attribution.engine import DISCLAIMER, MIN_MATCHED_TTPS, AttributionEngine
from packetiq.detection import ja3
from packetiq.sigma.generator import SigmaGenerator


def test_sigma_rules_are_valid_yaml(pipeline):
    rules = SigmaGenerator().generate(pipeline["events"], pipeline["chains"])
    assert rules, "should generate at least one SIGMA rule"
    for r in rules:
        doc = yaml.safe_load(r.raw_yaml)   # raises if invalid YAML
        assert doc["title"]
        assert "detection" in doc
        assert doc["level"] in ("low", "medium", "high", "critical")
        # date must be a real value, not the old 'auto' placeholder
        assert doc["date"] != "auto"


def test_ja3_blocklist_is_real_data():
    """The bundled JA3 feed must load and contain only valid md5 fingerprints."""
    bl = ja3.load_blocklist()
    assert len(bl) > 50, "bundled abuse.ch JA3 feed should have many entries"
    for md5 in bl:
        assert len(md5) == 32 and all(c in "0123456789abcdef" for c in md5)


def test_ja3_no_feed_means_no_findings(tmp_path):
    """With an empty feed, the detector must produce nothing (never fabricate)."""
    empty = tmp_path / "empty.csv"
    empty.write_text("# no entries\n", encoding="utf-8")
    ja3.load_blocklist.cache_clear()
    bl = ja3.load_blocklist(str(empty))
    assert bl == {}
    ja3.load_blocklist.cache_clear()


def test_attribution_is_labelled_as_overlap(pipeline):
    matches = AttributionEngine().attribute(pipeline["events"], pipeline["chains"])
    # The attack capture has many TTPs, so several profiles will overlap.
    assert matches, "expected at least one TTP-overlap match"
    for m in matches:
        # Honesty guarantees: every match carries the not-attribution disclaimer
        assert m.disclaimer == DISCLAIMER
        # and only surfaces with enough overlapping TTPs
        assert len(m.matched_ttps) >= MIN_MATCHED_TTPS


def test_attribution_skips_trivial_capture():
    """A single port scan must not 'match' any threat actor profile."""
    from packetiq.detection.models import DetectionEvent, EventType, Severity
    ev = [DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.MEDIUM,
                         src_ip="45.33.32.156", description="scan")]
    matches = AttributionEngine().attribute(ev, [])
    assert matches == []


# ── SIGMA rules are templated, so capture text must not reach YAML structure ──

def _dns_rule_for(domain: str):
    from packetiq.detection.models import DetectionEvent, EventType, Severity
    event = DetectionEvent(
        event_type=EventType.DNS_ANOMALY, severity=Severity.HIGH,
        src_ip="10.0.0.9", dst_ip="10.0.0.1", dst_port=53,
        description="dga", evidence={"domain": domain},
    )
    rules = SigmaGenerator().generate([event], [])
    assert rules, "a DNS anomaly must still produce a rule"
    return rules[0].raw_yaml


@pytest.mark.parametrize("domain", [
    "evil'.com",                                 # ends the single-quoted scalar
    "evil.com\nlevel: informational",            # starts a new top-level key
    "a' or x\n    x:\n        foo: 1\n    condition: x #",   # rewrites the logic
    "'''''.com",
    "evil\r\nstatus: stable.com",
])
def test_a_crafted_domain_cannot_break_the_generated_sigma_yaml(domain):
    """The rules are built from f-string templates, not a YAML dumper.

    A DNS label is a length-prefixed byte string, so a query name may legally
    contain a quote or a newline — verified end to end: a crafted packet's name
    reaches `result.dns_queries[].qname` verbatim. Interpolated into
    `dns.question.name|contains: '{domain}'`, a single quote ended the scalar
    and `yaml.safe_load` raised ParserError. SIGMA export exists to hand rules
    to a SIEM, so a rule that will not load is the feature failing on exactly
    the capture that provoked it.
    """
    doc = yaml.safe_load(_dns_rule_for(domain))   # raises if injection succeeded

    assert doc["level"] == "high", "severity must come from the event, not the capture"
    assert doc["detection"]["condition"] == "selection"
    assert set(doc["detection"]) == {"selection", "condition"}, (
        "no extra detection block may be injected"
    )


def test_a_crafted_domain_still_round_trips_as_data():
    """Escaping must preserve the value, not mangle it — the quote is evidence."""
    doc = yaml.safe_load(_dns_rule_for("evil'quote.com"))

    assert doc["detection"]["selection"]["dns.question.name|contains"] == "evil'quote.com"
