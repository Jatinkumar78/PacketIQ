"""
Threat-Actor TTP-Overlap Engine.

IMPORTANT — this is NOT attribution. It computes how much the *behaviour*
observed in a capture (the detected TTPs and kill-chain phases) overlaps
with the documented TTP profile of known threat groups. Generic techniques
like port scanning and brute force are used by countless actors, so a high
overlap score is only an investigative lead — never a confirmed identity.
Real attribution requires correlating concrete infrastructure (IPs,
domains, certificates, malware hashes), which a single PCAP rarely provides.

Scoring algorithm — two measurements, because one is not enough:

  coverage    = matched profile weight / that actor's total profile weight.
                "How much of this actor's documented behaviour did we see?"
  specificity = distinct matched TTPs / distinct TTPs detected in the capture.
                "How much of what we actually saw does this profile explain?"

  score = coverage × (SPECIFICITY_FLOOR + (1 − SPECIFICITY_FLOOR) × specificity)

  Coverage alone is a recall measure, and on its own it saturates: every actor
  whose profile is a subset of the findings scores exactly 1.0. On the synthetic
  attack capture that was literally true — four profiles hit 1.00 and the
  additive phase bonus below pushed three more through the old `min(x, 1.0)`
  clamp, so seven of eight actors reported an identical "100%". A ranking where
  everything ties carries no information on precisely the captures an analyst
  cares about, and "APT28 — 100%" next to a state-sponsored group reads as a
  certainty no disclaimer undoes. Specificity breaks that tie honestly: matching
  all five of a five-TTP profile means less when the capture also showed five
  other techniques than when it showed nothing else. It is damped by
  SPECIFICITY_FLOOR because behaviour outside a profile is expected — other
  tooling, the defender's own scanners, background noise — so it discounts a
  match without being able to erase it.

  The kill-chain phase bonus then takes a share of the *remaining headroom*
  (score += bonus × (1 − score)) instead of being added and clamped. That keeps
  it monotonic and order-preserving while making 1.0 unreachable by addition.
  The score can only reach 1.0 when coverage and specificity are both 1.0 —
  i.e. the set of detected TTPs is exactly this actor's profile, nothing more
  and nothing less, which is the one case where "100% overlap" is a literally
  checkable statement about two sets rather than a claim about an identity.

  To avoid surfacing matches from trivial captures, an actor is only reported
  when BOTH:
    - at least MIN_MATCHED_TTPS distinct detected TTPs overlap its profile, and
    - the overlap score is >= MIN_OVERLAP.
  Results are ranked by overlap score, then by coverage, then by name, so the
  order is total and reproducible rather than dependent on profile order.
"""

from dataclasses import dataclass

from packetiq.attribution.actors import THREAT_ACTORS
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, EventType

MIN_OVERLAP       = 0.45  # minimum normalized overlap to surface a profile
MIN_MATCHED_TTPS  = 3     # need >= 3 distinct overlapping TTPs (avoids trivial matches)
PHASE_BONUS       = 0.10  # per overlapping kill chain phase, applied to remaining headroom
MAX_PHASE_BONUS   = 0.30  # at most 3 phases' worth of bonus
SPECIFICITY_FLOOR = 0.50  # most that unexplained observed behaviour can discount a match

DISCLAIMER = (
    "Behavioural TTP overlap only — an investigative lead, NOT confirmed "
    "attribution. Confirming a threat actor requires infrastructure/IOC "
    "correlation beyond a single capture."
)


@dataclass
class AttributionMatch:
    actor_name:   str
    aliases:      list[str]
    origin:       str
    motivation:   str
    confidence:   float        # 0.0 – 1.0  (TTP-overlap score, NOT attribution confidence)
    matched_ttps: list[str]    # EventType values that matched
    phases:       set[str]
    description:  str
    color:        str
    mitre_group:  str
    target_sectors: list[str]
    disclaimer:   str = DISCLAIMER
    # The two components of `confidence`, carried so a reader can tell a broad
    # profile seen in a noisy capture from a narrow one seen cleanly. New fields
    # go last with defaults: a renderer built from the declared field list has
    # broken on a field change here before (tests/test_attribution_render.py).
    coverage:     float = 0.0  # fraction of this actor's profile weight observed
    specificity:  float = 0.0  # fraction of the capture's TTPs this profile explains


class AttributionEngine:

    def attribute(
        self,
        events: list[DetectionEvent],
        chains: list[AttackChain],
    ) -> list[AttributionMatch]:
        """Score events + chains against all actor TTP profiles, return overlaps."""
        detected_types: set[EventType] = {e.event_type for e in events}

        # Collect kill chain phases from chains
        detected_phases: set[str] = set()
        for ch in chains:
            detected_phases.update(ch.kill_chain_phases)
        # Also from events directly
        from packetiq.correlation.mitre import EVENT_TYPE_KILL_CHAIN
        for et in detected_types:
            ph = EVENT_TYPE_KILL_CHAIN.get(et, "")
            if ph:
                detected_phases.add(ph)

        matches: list[AttributionMatch] = []

        for actor in THREAT_ACTORS:
            weights   = actor["ttp_weights"]
            max_score = sum(weights.values())
            if max_score == 0:
                continue

            matched: dict[EventType, float] = {}
            for et, weight in weights.items():
                if et in detected_types:
                    matched[et] = weight

            # Require enough distinct overlapping TTPs to avoid trivial matches
            # (e.g. a lone port scan should not "match" half the actor database).
            if len(matched) < MIN_MATCHED_TTPS:
                continue

            raw_score = sum(matched.values())
            coverage  = raw_score / max_score

            # How much of what was actually observed does this profile account
            # for? No guard on the divisor is needed or wanted: reaching here
            # means `matched` is non-empty, and `matched` is a subset of
            # `detected_types`, so the denominator is >= 1 by construction. A
            # dead guard would be an unreachable statement under the 100%
            # coverage gate.
            specificity = len(matched) / len(detected_types)
            factor = SPECIFICITY_FLOOR + (1.0 - SPECIFICITY_FLOOR) * specificity
            confidence = coverage * factor

            # Phase overlap bonus, taken from the remaining headroom so it can
            # never saturate (the old `min(confidence + bonus, 1.0)` flattened
            # seven of eight actors onto an identical 1.000).
            phase_overlap = detected_phases & actor["phases"]
            bonus = min(len(phase_overlap) * PHASE_BONUS, MAX_PHASE_BONUS)
            confidence = confidence + bonus * (1.0 - confidence)

            if confidence < MIN_OVERLAP:
                continue

            matches.append(AttributionMatch(
                actor_name   = actor["name"],
                aliases      = actor["aliases"],
                origin       = actor["origin"],
                motivation   = actor["motivation"],
                confidence   = round(confidence, 3),
                matched_ttps = [et.value for et in matched],
                phases       = actor["phases"],
                description  = actor["description"],
                color        = actor["color"],
                mitre_group  = actor["mitre_group"],
                target_sectors = actor["target_sectors"],
                coverage     = round(coverage, 3),
                specificity  = round(specificity, 3),
            ))

        # Total order: score, then how completely the profile was covered, then
        # name. Two profiles of identical shape genuinely tie, and a tie should
        # look like one rather than being broken by actor-table order.
        matches.sort(key=lambda m: (-m.confidence, -m.coverage, m.actor_name))
        return matches
