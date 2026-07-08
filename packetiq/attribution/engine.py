"""
Threat-Actor TTP-Overlap Engine.

IMPORTANT — this is NOT attribution. It computes how much the *behaviour*
observed in a capture (the detected TTPs and kill-chain phases) overlaps
with the documented TTP profile of known threat groups. Generic techniques
like port scanning and brute force are used by countless actors, so a high
overlap score is only an investigative lead — never a confirmed identity.
Real attribution requires correlating concrete infrastructure (IPs,
domains, certificates, malware hashes), which a single PCAP rarely provides.

Scoring algorithm:
  For each actor, sum the profile weights of TTPs that were detected and
  divide by that actor's maximum possible weight → a normalized overlap.
  Add a small kill-chain phase-overlap bonus. To avoid surfacing matches
  from trivial captures, an actor is only reported when BOTH:
    - at least MIN_MATCHED_TTPS distinct detected TTPs overlap its profile, and
    - the overlap score is >= MIN_OVERLAP.
  Results are ranked by overlap score.
"""

from dataclasses import dataclass

from packetiq.attribution.actors import THREAT_ACTORS
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, EventType

MIN_OVERLAP      = 0.45  # minimum normalized overlap to surface a profile
MIN_MATCHED_TTPS = 3     # need >= 3 distinct overlapping TTPs (avoids trivial matches)
PHASE_BONUS      = 0.10  # +10% per overlapping kill chain phase (max 0.30)

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
    icon:         str
    color:        str
    mitre_group:  str
    target_sectors: list[str]
    disclaimer:   str = DISCLAIMER


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
            confidence = raw_score / max_score

            # Phase overlap bonus (capped at 3 phases × 10%)
            phase_overlap = detected_phases & actor["phases"]
            bonus = min(len(phase_overlap) * PHASE_BONUS, 0.30)
            confidence = min(confidence + bonus, 1.0)

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
                icon         = actor["icon"],
                color        = actor["color"],
                mitre_group  = actor["mitre_group"],
                target_sectors = actor["target_sectors"],
            ))

        matches.sort(key=lambda m: -m.confidence)
        return matches
