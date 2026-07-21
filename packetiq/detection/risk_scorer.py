"""
Risk Scorer — computes an overall risk score from a list of DetectionEvents.

Scoring model:
  Each event contributes: severity.score × confidence × weight
  Weights dampen duplicate event types to avoid score inflation.

  CRITICAL = 25 pts base
  HIGH     = 15 pts base
  MEDIUM   =  8 pts base
  LOW      =  3 pts base

Final score is clamped to 0–100 and mapped to a risk tier.
"""

from collections import Counter
from dataclasses import dataclass

from packetiq.detection.models import DetectionEvent

RISK_TIERS = [
    (76, "CRITICAL", "bold red",    "Active compromise indicators. Immediate response required."),
    (51, "HIGH",     "bold yellow", "Multiple attack indicators. Escalate to SOC lead."),
    (26, "MEDIUM",   "bold cyan",   "Suspicious activity detected. Investigate further."),
    (0,  "LOW",      "bold green",  "Low-level anomalies. Monitor and baseline."),
]


@dataclass
class RiskReport:
    score:        int           # 0–100
    tier:         str           # CRITICAL / HIGH / MEDIUM / LOW
    color:        str           # Rich color string
    summary:      str           # Human-readable tier description
    event_count:  int
    by_severity:  dict          # severity → count
    by_type:      dict          # event_type → count
    top_sources:  list[str]     # most active attacker IPs
    top_targets:  list[str]     # most targeted IPs


def score(events: list[DetectionEvent]) -> RiskReport:
    """Compute a risk report from detection events."""
    if not events:
        return RiskReport(
            score=0, tier="LOW", color="bold green",
            summary="No threats detected.",
            event_count=0, by_severity={}, by_type={},
            top_sources=[], top_targets=[],
        )

    raw_score = 0.0

    # Count events per type to apply diminishing returns
    type_counts: Counter = Counter(e.event_type for e in events)

    # Per-event contribution with diminishing returns per event type
    type_seen: Counter = Counter()

    for event in sorted(events, key=lambda e: e.severity.score, reverse=True):
        etype = event.event_type
        type_seen[etype] += 1
        n = type_seen[etype]

        # Diminishing returns: 1st = 100%, 2nd = 60%, 3rd+ = 30%
        multiplier = 1.0 if n == 1 else (0.6 if n == 2 else 0.3)

        raw_score += event.severity.score * event.confidence * multiplier

    final_score = min(100, int(raw_score))

    # Determine tier
    tier_label, tier_color, tier_summary = "LOW", "bold green", ""
    for threshold, label, color, summary in RISK_TIERS:
        if final_score >= threshold:
            tier_label, tier_color, tier_summary = label, color, summary
            break

    # Honest floor: the headline tier must not read *lower* than the worst single
    # finding warrants. The dampened aggregate score can be small (e.g. one recon
    # event), but a capture that contains a HIGH/CRITICAL indicator cannot be
    # summarised as "LOW — no action". The numeric score is left untouched.
    tier_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    severities = {e.severity.value for e in events}
    floor_label = ("HIGH" if "CRITICAL" in severities
                   else "MEDIUM" if "HIGH" in severities
                   else None)
    if floor_label and tier_rank[floor_label] > tier_rank[tier_label]:
        for _threshold, label, color, summary in RISK_TIERS:
            if label == floor_label:
                tier_label, tier_color, tier_summary = label, color, summary
                break

    # Breakdown stats
    by_severity = dict(Counter(e.severity.value for e in events))
    by_type     = dict(Counter(e.event_type.value for e in events))

    src_counter = Counter(e.src_ip for e in events if e.src_ip)
    dst_counter = Counter(e.dst_ip for e in events if e.dst_ip)

    return RiskReport(
        score       = final_score,
        tier        = tier_label,
        color       = tier_color,
        summary     = tier_summary,
        event_count = len(events),
        by_severity = by_severity,
        by_type     = by_type,
        top_sources = [ip for ip, _ in src_counter.most_common(5)],
        top_targets = [ip for ip, _ in dst_counter.most_common(5)],
    )
