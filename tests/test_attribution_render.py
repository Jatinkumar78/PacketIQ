"""
Regression tests for the `fuse` command's threat-actor TTP-overlap rows.

These exist because a field (`icon`) was removed from AttributionMatch while
`cli.py` still read it, and nothing executed that render path — so the CLI
raised AttributeError for every capture that produced an attribution match.
The rule these tests encode: the renderer may only touch fields the dataclass
actually declares, and it must survive the real engine's output.
"""

import dataclasses

from packetiq.attribution.engine import AttributionEngine, AttributionMatch
from packetiq.cli import _attribution_line
from packetiq.detection.models import DetectionEvent, EventType, Severity


def _campaign_events():
    """Enough distinct TTPs across kill-chain phases to clear MIN_MATCHED_TTPS."""
    return [
        DetectionEvent(event_type=EventType.PORT_SCAN, severity=Severity.MEDIUM,
                       src_ip="10.0.0.9", dst_ip="10.0.0.20", description="scan"),
        DetectionEvent(event_type=EventType.BRUTE_FORCE, severity=Severity.HIGH,
                       src_ip="10.0.0.9", dst_ip="10.0.0.20", description="brute force"),
        DetectionEvent(event_type=EventType.C2_BEACON, severity=Severity.CRITICAL,
                       src_ip="10.0.0.20", dst_ip="203.0.113.7", description="beacon"),
        DetectionEvent(event_type=EventType.DNS_TUNNELING, severity=Severity.HIGH,
                       src_ip="10.0.0.20", description="dns tunnel"),
        DetectionEvent(event_type=EventType.CREDENTIAL_EXPOSURE, severity=Severity.HIGH,
                       src_ip="10.0.0.20", description="cleartext creds"),
        DetectionEvent(event_type=EventType.IOC_MATCH, severity=Severity.CRITICAL,
                       src_ip="10.0.0.20", dst_ip="203.0.113.7", description="known C2"),
    ]


def test_renders_every_match_the_real_engine_produces():
    """The exact path `fuse` takes: engine output straight into the renderer."""
    matches = AttributionEngine().attribute(_campaign_events(), [])
    assert matches, "campaign TTPs should overlap at least one actor profile"

    for m in matches:
        line = _attribution_line(m)
        assert m.actor_name in line
        assert f"{int(m.confidence * 100):3d}%" in line
        assert m.origin in line


def test_renderer_touches_only_declared_fields():
    """A field dropped from the dataclass must not survive in the renderer.

    Constructing the match from the declared field list means any future
    removal makes this fail here rather than at a user's terminal.
    """
    names = {f.name for f in dataclasses.fields(AttributionMatch)}
    assert {"actor_name", "confidence", "origin", "color"} <= names

    match = AttributionMatch(
        actor_name="Test Actor", aliases=["TA-1"], origin="Unknown",
        motivation="testing", confidence=0.75, matched_ttps=["PORT_SCAN"],
        phases={"Reconnaissance"}, description="synthetic",
        color="red", mitre_group="G0000", target_sectors=["research"],
    )
    line = _attribution_line(match)
    assert "Test Actor" in line
    assert " 75%" in line


def test_confidence_bar_stays_twenty_cells_at_the_extremes():
    """Off-by-one in the bar maths would corrupt the aligned table."""
    for confidence in (0.0, 0.5, 1.0):
        match = AttributionMatch(
            actor_name="Edge", aliases=[], origin="Unknown", motivation="testing",
            confidence=confidence, matched_ttps=[], phases=set(), description="",
            color="red", mitre_group="G0000", target_sectors=[],
        )
        line = _attribution_line(match)
        assert line.count("█") + line.count("░") == 20
