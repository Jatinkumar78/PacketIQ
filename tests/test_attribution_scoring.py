"""
Regression tests for the TTP-overlap *score* itself.

These exist because the score saturated. Coverage alone — matched profile
weight over total profile weight — is a recall measure, so every actor whose
documented profile is a subset of what a capture produced scored exactly 1.0;
the kill-chain phase bonus was then added and clamped with `min(x, 1.0)`,
which pulled the near-misses up onto the same ceiling. On the synthetic attack
capture seven of the eight profiles reported an identical 1.000, including one
whose true coverage was 0.824. A ranking in which everything ties tells an
analyst nothing on exactly the captures they care about, and "100%" printed
beside a state-sponsored group reads as a certainty that no disclaimer undoes.

The rules these tests encode:
  - no profile may reach 1.0 unless the detected TTP set is *exactly* its
    profile (the one case where "100% overlap" is a checkable set statement),
  - the phase bonus may never be the thing that reaches the ceiling,
  - breadth counts: a wide profile fully matched beats a narrow one fully
    matched, and the same profile is worth less in a capture full of other
    behaviour than in one that shows nothing else,
  - the two components are reported, so the headline number can be audited.
"""

import re

import pytest

from packetiq.attribution import engine as attr
from packetiq.attribution.engine import (
    MIN_MATCHED_TTPS,
    SPECIFICITY_FLOOR,
    AttributionEngine,
)
from packetiq.correlation.mitre import EVENT_TYPE_KILL_CHAIN
from packetiq.detection.models import DetectionEvent, EventType, Severity

TS = 1700000000.0


def _events(types):
    return [DetectionEvent(event_type=t, severity=Severity.HIGH, src_ip="10.0.0.1",
                           description="x", timestamp=TS) for t in types]


def _profile(name, types, phases=frozenset()):
    """A synthetic actor whose every TTP carries equal weight.

    Equal weights keep the arithmetic exact, so the assertions below are about
    the formula rather than about the hand-tuned weights in actors.py.
    """
    return {"name": name, "aliases": [], "origin": "?", "motivation": "?",
            "ttp_weights": {t: 1.0 for t in types}, "phases": set(phases),
            "description": "", "references": [], "color": "red",
            "mitre_group": "G0000", "target_sectors": []}


def test_no_profile_saturates_the_scale_on_the_attack_capture(pipeline):
    """The shipped defect: 7 of 8 actors reported exactly 1.000."""
    matches = AttributionEngine().attribute(pipeline["events"], pipeline["chains"])
    assert matches, "the attack capture must still overlap several profiles"

    assert all(m.confidence < 1.0 for m in matches), (
        "a capture that also shows behaviour outside a profile cannot be a "
        "100% overlap with it: " + ", ".join(
            f"{m.actor_name}={m.confidence}" for m in matches if m.confidence >= 1.0)
    )
    # And the ranking has to carry information, not just avoid the ceiling.
    assert matches[0].confidence - matches[-1].confidence > 0.1


def test_the_ranking_is_ordered_and_reproducible(pipeline):
    """Ties are broken on coverage then name, so the order is total."""
    first = AttributionEngine().attribute(pipeline["events"], pipeline["chains"])
    again = AttributionEngine().attribute(pipeline["events"], pipeline["chains"])

    assert [m.actor_name for m in first] == [m.actor_name for m in again]
    keys = [(-m.confidence, -m.coverage, m.actor_name) for m in first]
    assert keys == sorted(keys)


def test_only_an_exact_set_match_reaches_a_full_overlap(monkeypatch):
    """1.0 means the detected TTPs are precisely this profile — nothing else."""
    wide = [EventType.PORT_SCAN, EventType.BRUTE_FORCE, EventType.C2_BEACON,
            EventType.DNS_TUNNELING, EventType.CREDENTIAL_EXPOSURE,
            EventType.PROTOCOL_MISUSE]
    monkeypatch.setattr(attr, "THREAT_ACTORS", [
        _profile("Exact", wide),
        _profile("Subset", wide[:3]),
    ])

    matches = {m.actor_name: m for m in
               AttributionEngine().attribute(_events(wide), [])}

    # Detected == Exact's profile, so coverage and specificity are both 1.0.
    assert matches["Exact"].confidence == 1.0
    assert matches["Exact"].coverage == 1.0
    assert matches["Exact"].specificity == 1.0

    # Subset covers all of its own (narrower) profile, so the old formula scored
    # it 1.0 too. It explains only half of what was seen, so it must rank below.
    assert matches["Subset"].coverage == 1.0
    assert matches["Subset"].confidence < matches["Exact"].confidence
    assert matches["Subset"].confidence == 0.75   # 1.0 × (0.5 + 0.5 × 0.5)


def test_a_broader_profile_fully_matched_outranks_a_narrow_one(monkeypatch):
    """Five documented TTPs all seen is weaker evidence than twelve all seen."""
    broad = list(EventType)[:8]
    narrow = broad[:MIN_MATCHED_TTPS]
    monkeypatch.setattr(attr, "THREAT_ACTORS", [
        _profile("Narrow", narrow),
        _profile("Broad", broad),
    ])

    ranked = AttributionEngine().attribute(_events(broad), [])

    assert [m.actor_name for m in ranked] == ["Broad", "Narrow"]
    assert ranked[0].coverage == ranked[1].coverage == 1.0, (
        "both profiles are fully covered — only specificity may separate them"
    )


def test_the_same_profile_is_worth_less_in_a_capture_full_of_other_behaviour(
        monkeypatch):
    """Unexplained behaviour discounts a match, and is capped in how far it can."""
    profile = list(EventType)[:4]
    monkeypatch.setattr(attr, "THREAT_ACTORS", [_profile("Fixed", profile)])

    clean = AttributionEngine().attribute(_events(profile), [])[0]
    noisy = AttributionEngine().attribute(_events(list(EventType)), [])[0]

    assert clean.coverage == noisy.coverage == 1.0
    assert noisy.confidence < clean.confidence
    # The floor keeps noise from erasing a fully covered profile outright.
    assert noisy.confidence >= SPECIFICITY_FLOOR * clean.confidence


def test_the_phase_bonus_cannot_reach_the_ceiling_on_a_partial_match(monkeypatch):
    """The old code added the bonus and clamped: 0.8 + 0.3 → a reported 1.000."""
    profile = [EventType.PORT_SCAN, EventType.BRUTE_FORCE, EventType.C2_BEACON,
               EventType.DNS_TUNNELING, EventType.CREDENTIAL_EXPOSURE]
    observed = profile[:4]                      # 4 of 5 → coverage 0.8
    phases = {EVENT_TYPE_KILL_CHAIN[t] for t in observed
              if EVENT_TYPE_KILL_CHAIN.get(t)}
    assert len(phases) >= 2, "fixture needs a real multi-phase overlap"

    monkeypatch.setattr(attr, "THREAT_ACTORS",
                        [_profile("Phased", profile, phases=phases)])

    m = AttributionEngine().attribute(_events(observed), [])[0]

    assert m.coverage == 0.8
    assert m.specificity == 1.0            # every observed TTP is in the profile
    assert m.confidence < 1.0, "a 4-of-5 match must never report a full overlap"
    assert m.confidence > 0.8, "the phase overlap should still raise the score"


def test_the_reported_components_reconstruct_the_score(monkeypatch):
    """The headline number must be auditable from the fields beside it."""
    profile = list(EventType)[:4]
    monkeypatch.setattr(attr, "THREAT_ACTORS", [_profile("Audit", profile)])

    m = AttributionEngine().attribute(_events(list(EventType)[:8]), [])[0]

    assert m.coverage == 1.0
    assert m.specificity == 0.5
    expected = m.coverage * (SPECIFICITY_FLOOR + (1 - SPECIFICITY_FLOOR) * m.specificity)
    assert m.confidence == pytest.approx(round(expected, 3))


def test_the_chat_context_reports_percentages_in_range(pipeline):
    """`_build_chat_context` consumes `_ser_attr` output, already scaled to 0-100.

    Scaling again in that f-string printed "profile coverage 10000%". The
    existing chat-context test builds its attribution dict by hand with no
    coverage key, so the default of 0 hid the bug — only real serialised
    attributions expose it.
    """
    from packetiq.webapp import app as webapp

    attrs = [webapp._ser_attr(a) for a in
             AttributionEngine().attribute(pipeline["events"], pipeline["chains"])]
    assert attrs, "the attack capture must produce attributions to serialise"

    text = webapp._build_chat_context({"attributions": attrs})
    section = text[text.find("THREAT ACTOR ATTRIBUTION"):]
    for pct in re.findall(r"(\d+)%", section):
        assert int(pct) <= 100, f"percentage out of range: {pct}% in\n{section[:400]}"
