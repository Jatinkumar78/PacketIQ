"""
Tests for the intelligence layer: SIGMA generation, JA3 feed loading, and
the (honestly-framed) threat-actor TTP-overlap engine.
"""

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
