"""
Timeline Builder — reconstructs a chronological event sequence from all
PacketIQ analysis layers (extraction, detection, correlation).

Pipeline:
  1. Seed from detection events          (timestamped threat findings)
  2. Inject DNS activity milestones      (first query per domain, suspicious queries)
  3. Inject HTTP activity milestones     (first request per host)
  4. Inject attack chain anchors         (chain start / chain end markers)
  5. Sort chronologically
  6. Detect pivot points                 (kill chain phase transitions)
  7. Detect activity gaps                (silences > GAP_THRESHOLD seconds)
  8. Bucket into phase segments
  9. Build activity density bar
"""

from typing import Optional

from packetiq.correlation import mitre as mitre_db
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.timeline.models import ActivityBar, Category, PhaseSegment, Timeline, TimelineEvent

# ── Thresholds ────────────────────────────────────────────────────────────────
GAP_THRESHOLD_SECS  = 30.0   # silence longer than this → insert a GAP marker
ACTIVITY_BAR_WIDTH  = 60     # number of buckets for the ASCII activity bar


class TimelineBuilder:

    def build(
        self,
        result: ExtractionResult,
        events: list[DetectionEvent],
        chains: list[AttackChain],
    ) -> Timeline:
        """Construct and return a complete Timeline object."""

        raw: list[TimelineEvent] = []

        raw.extend(self._from_detection_events(events))
        raw.extend(self._from_dns_activity(result, events))
        raw.extend(self._from_http_activity(result))
        raw.extend(self._from_chains(chains))

        # Sort chronologically; stable sort preserves insertion order for ties
        raw.sort(key=lambda e: e.timestamp)

        # Remove exact duplicate descriptions at the same timestamp
        raw = self._deduplicate(raw)

        # Annotate each event with its kill chain phase (from MITRE mapping)
        self._annotate_phases(raw, chains)

        # Detect pivots and gaps
        enriched = self._insert_pivots_and_gaps(raw)

        # Group into phase segments
        segments = self._build_segments(enriched)

        # Activity density bar
        activity = self._build_activity_bar(
            [e for e in enriched if e.category not in (Category.GAP, Category.PIVOT)],
            result.capture_start,
            result.capture_end,
        )

        tl = Timeline(
            events         = enriched,
            phase_segments = segments,
            pivot_points   = [e for e in enriched if e.category == Category.PIVOT],
            activity_bar   = activity,
            capture_start  = result.capture_start,
            capture_end    = result.capture_end,
        )
        return tl

    # ── Source: Detection Events ──────────────────────────────────────────────

    def _from_detection_events(self, events: list[DetectionEvent]) -> list[TimelineEvent]:
        result = []
        for e in events:
            if not e.timestamp:
                continue

            # Pull primary MITRE technique ID
            techs   = mitre_db.techniques_for_event(e.event_type)
            mitre_id = techs[0].technique_id if techs else None

            result.append(TimelineEvent(
                timestamp   = e.timestamp,
                category    = Category.THREAT,
                description = e.description,
                src_ip      = e.src_ip,
                dst_ip      = e.dst_ip,
                dst_port    = e.dst_port,
                protocol    = e.protocol,
                severity    = e.severity,
                mitre_id    = mitre_id,
                evidence    = e.evidence,
            ))
        return result

    # ── Source: DNS Activity ──────────────────────────────────────────────────

    def _from_dns_activity(
        self,
        result: ExtractionResult,
        events: list[DetectionEvent],
    ) -> list[TimelineEvent]:
        """
        Include DNS milestones not already captured by detection events:
        - First query to each unique domain
        - Domains associated with detection events (even if seen only once)
        """
        timeline_events = []

        # Domains already flagged by the detection engine → skip (they're in THREAT events)
        flagged_domains = set()
        for e in events:
            d = e.evidence.get("domain", "")
            if d:
                flagged_domains.add(d)

        seen_domains: set[str] = set()

        for q in sorted(result.dns_queries, key=lambda x: x.get("ts", 0)):
            domain = q.get("qname", "") or ""
            ts     = q.get("ts", 0.0)
            src    = q.get("src", "")

            if not domain or not ts:
                continue
            if domain in flagged_domains:
                continue   # already a THREAT event for this domain
            if domain in seen_domains:
                continue   # only show first query per domain

            seen_domains.add(domain)
            timeline_events.append(TimelineEvent(
                timestamp   = ts,
                category    = Category.DNS,
                description = f"DNS query: {domain}",
                src_ip      = src,
                dst_ip      = q.get("dst"),
                dst_port    = 53,
                protocol    = "DNS",
            ))

        return timeline_events

    # ── Source: HTTP Activity ─────────────────────────────────────────────────

    def _from_http_activity(self, result: ExtractionResult) -> list[TimelineEvent]:
        """First HTTP request to each unique host."""
        seen_hosts: set[str] = set()
        timeline_events = []

        for r in sorted(result.http_requests, key=lambda x: x.get("ts", 0)):
            host = r.get("host") or r.get("dst") or ""
            ts   = r.get("ts", 0.0)
            if not ts or host in seen_hosts:
                continue

            seen_hosts.add(host)
            method = r.get("method") or "GET"
            path   = r.get("path")  or "/"
            timeline_events.append(TimelineEvent(
                timestamp   = ts,
                category    = Category.HTTP,
                description = f"HTTP {method} {host}{path}",
                src_ip      = r.get("src"),
                dst_ip      = r.get("dst"),
                dst_port    = 80,
                protocol    = "HTTP",
            ))

        return timeline_events

    # ── Source: Attack Chains ─────────────────────────────────────────────────

    def _from_chains(self, chains: list[AttackChain]) -> list[TimelineEvent]:
        """Chain start and end markers."""
        result = []
        for chain in chains:
            if chain.first_seen:
                result.append(TimelineEvent(
                    timestamp   = chain.first_seen,
                    category    = Category.CHAIN_START,
                    description = f"Chain begins: {chain.name}",
                    severity    = chain.severity,
                    chain_name  = chain.name,
                    src_ip      = next(iter(sorted(chain.attacker_ips)), None),
                ))
            if chain.last_seen and chain.last_seen != chain.first_seen:
                result.append(TimelineEvent(
                    timestamp   = chain.last_seen,
                    category    = Category.CHAIN_END,
                    description = f"Chain ends:   {chain.name}",
                    severity    = chain.severity,
                    chain_name  = chain.name,
                    src_ip      = next(iter(sorted(chain.attacker_ips)), None),
                ))
        return result

    # ── Phase annotation ──────────────────────────────────────────────────────

    def _annotate_phases(self, events: list[TimelineEvent], chains: list[AttackChain]):
        """
        Assign a kill chain phase to each timeline event.
        Priority: chain membership > MITRE event-type mapping > empty
        """
        # Build a mapping: event timestamp+src → phase from chains
        # (approximate — events that appear in a chain inherit its phase)
        chain_phase_map: dict[tuple, str] = {}
        for chain in chains:
            for ce in chain.events:
                key = (round(ce.timestamp, 3), ce.src_ip)
                phase = mitre_db.kill_chain_phase(ce.event_type)
                chain_phase_map[key] = phase

        for ev in events:
            if ev.category == Category.CHAIN_START and ev.chain_name:
                # Find the chain to get its primary phase
                ev.phase = "Exploitation"   # chains span multiple phases; use highest
                continue
            if ev.category in (Category.GAP, Category.PIVOT):
                continue

            # Try chain membership first
            key = (round(ev.timestamp, 3), ev.src_ip)
            if key in chain_phase_map:
                ev.phase = chain_phase_map[key]
                continue

            # Fall back to category-based heuristic
            ev.phase = _category_to_phase(ev.category)

    # ── Pivot and gap injection ───────────────────────────────────────────────

    def _insert_pivots_and_gaps(self, events: list[TimelineEvent]) -> list[TimelineEvent]:
        """
        Walk sorted events and inject:
          - PIVOT markers when the kill chain phase advances
          - GAP markers when there is a silence > GAP_THRESHOLD_SECS
        """
        if not events:
            return events

        result: list[TimelineEvent] = []
        prev_ts    = events[0].timestamp
        prev_phase = ""

        from packetiq.correlation.models import KILL_CHAIN_PHASES
        phase_order = {p: i for i, p in enumerate(KILL_CHAIN_PHASES)}

        for ev in events:
            # Gap detection
            gap = ev.timestamp - prev_ts
            if gap > GAP_THRESHOLD_SECS:
                from packetiq.utils.helpers import format_duration
                result.append(TimelineEvent(
                    timestamp   = prev_ts + gap / 2,
                    category    = Category.GAP,
                    description = f"Activity gap: {format_duration(gap)} silence",
                    phase       = prev_phase,
                ))

            # Pivot detection — only advance, never go backwards
            new_phase = ev.phase
            if (new_phase and new_phase != prev_phase and
                    phase_order.get(new_phase, 0) > phase_order.get(prev_phase, -1)):
                result.append(TimelineEvent(
                    timestamp   = ev.timestamp,
                    category    = Category.PIVOT,
                    description = f"Phase transition: {prev_phase or 'START'} → {new_phase}",
                    phase       = new_phase,
                ))
                prev_phase = new_phase

            result.append(ev)
            prev_ts = ev.timestamp

        return result

    # ── Phase segments ────────────────────────────────────────────────────────

    def _build_segments(self, events: list[TimelineEvent]) -> list[PhaseSegment]:
        """Group consecutive events by phase into PhaseSegment objects."""
        if not events:
            return []

        segments: list[PhaseSegment] = []
        current_phase = ""
        current_events: list[TimelineEvent] = []
        seg_start = events[0].timestamp

        for ev in events:
            phase = ev.phase or current_phase
            if phase != current_phase and ev.category not in (Category.GAP, Category.PIVOT):
                if current_events:
                    segments.append(PhaseSegment(
                        phase    = current_phase,
                        start_ts = seg_start,
                        end_ts   = ev.timestamp,
                        events   = current_events,
                    ))
                current_phase  = phase
                current_events = []
                seg_start      = ev.timestamp

            current_events.append(ev)

        if current_events:
            segments.append(PhaseSegment(
                phase    = current_phase,
                start_ts = seg_start,
                end_ts   = current_events[-1].timestamp,
                events   = current_events,
            ))

        return segments

    # ── Activity bar ──────────────────────────────────────────────────────────

    def _build_activity_bar(
        self,
        events: list[TimelineEvent],
        start_ts: float,
        end_ts: float,
    ) -> Optional[ActivityBar]:
        duration = end_ts - start_ts
        if duration <= 0 or not events:
            return None

        n = ACTIVITY_BAR_WIDTH
        bucket_secs = duration / n
        buckets = [0] * n

        for ev in events:
            idx = min(int((ev.timestamp - start_ts) / bucket_secs), n - 1)
            if 0 <= idx < n:
                buckets[idx] += 1

        return ActivityBar(
            buckets      = buckets,
            bucket_secs  = bucket_secs,
            total_events = len(events),
            start_ts     = start_ts,
            end_ts       = end_ts,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _deduplicate(events: list[TimelineEvent]) -> list[TimelineEvent]:
        seen: set[tuple] = set()
        result = []
        for ev in events:
            key = (round(ev.timestamp, 2), ev.category, ev.description[:60])
            if key not in seen:
                seen.add(key)
                result.append(ev)
        return result


def _category_to_phase(category: str) -> str:
    """Heuristic phase for non-threat categories."""
    return {
        Category.DNS:         "Command & Control",
        Category.HTTP:        "Delivery",
        Category.CHAIN_START: "Exploitation",
        Category.CHAIN_END:   "Actions on Objectives",
        Category.FLOW_SPIKE:  "Delivery",
    }.get(category, "")
