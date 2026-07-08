"""
C2 Beacon Periodicity Detector.

Identifies automated beacon traffic by analysing statistical regularity
of connection inter-arrival times for each (src, dst, port) flow tuple.

Algorithm:
  1. Collect TCP SYN timestamps per (src, dst, dport) from syn_pairs
  2. Collect HTTP request timestamps grouped by (src, host)
  3. Filter intervals: MIN_INTERVAL < delta < MAX_INTERVAL
  4. Coefficient of Variation (CV) = stddev / mean
  5. CV < CV_HIGH  → CRITICAL (highly automated, near-zero jitter)
  6. CV < CV_MED   → HIGH     (automated with small jitter)
"""

import statistics
from collections import defaultdict
from typing import Optional

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.utils.helpers import is_private_ip, same_org_network

MIN_CONNECTIONS    = 12      # need 12+ hits to distinguish beacon from coincidence
MIN_INTERVAL       = 5.0     # seconds — ignore retransmit bursts and TLS keep-alives
MAX_INTERVAL       = 600.0   # 10 min cap — real C2 beacons typically ≤ 10 min;
                              # software update checks (every 15-60 min) are excluded
CV_THRESHOLD_HIGH  = 0.10    # near-perfect regularity → CRITICAL (bot-like precision)
CV_THRESHOLD_MED   = 0.25    # clear regularity → HIGH


class BeaconDetector:

    def detect(self, result: ExtractionResult) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []

        # ── TCP SYN-based beacons ─────────────────────────────────────────
        for (src, dst, dport), ts_list in result.tcp_syn_pairs.items():
            ev = self._analyse(src, dst, dport, ts_list, "TCP")
            if ev:
                events.append(ev)

        # ── HTTP request-based beacons ────────────────────────────────────
        http_groups: dict[tuple, list[float]] = defaultdict(list)
        for req in result.http_requests:
            src  = req.get("src") or ""
            host = req.get("host") or req.get("dst") or ""
            ts   = req.get("ts", 0.0)
            if src and host and ts:
                http_groups[(src, host, 80)].append(ts)

        for (src, host, port), ts_list in http_groups.items():
            ev = self._analyse(src, host, port, ts_list, "HTTP")
            if ev:
                events.append(ev)

        return events

    # ── Core statistics ───────────────────────────────────────────────────

    def _analyse(
        self,
        src: str,
        dst: str,
        dport: int,
        timestamps: list[float],
        proto: str,
    ) -> Optional[DetectionEvent]:
        # C2 beacons phone home to external IPs — internal regular connections
        # are monitoring agents, health checks, sync clients, etc.
        if is_private_ip(dst):
            return None
        # Same-organisation traffic (both endpoints on one LAN, including a
        # public-IP campus /16) is intra-LAN periodicity — idle-RDP keepalives,
        # health checks, sync clients — not C2 phoning home across the internet.
        # A genuine external beacon (a different /16) is still caught.
        if same_org_network(src, dst):
            return None

        from packetiq import config
        min_conn = config.get("beacon", "min_connections", MIN_CONNECTIONS)
        min_int  = config.get("beacon", "min_interval", MIN_INTERVAL)
        max_int  = config.get("beacon", "max_interval", MAX_INTERVAL)

        if len(timestamps) < min_conn:
            return None

        ts_sorted = sorted(timestamps)
        deltas = [
            ts_sorted[i + 1] - ts_sorted[i]
            for i in range(len(ts_sorted) - 1)
            if min_int <= (ts_sorted[i + 1] - ts_sorted[i]) <= max_int
        ]

        if len(deltas) < min_conn - 1:
            return None

        mean_d = statistics.mean(deltas)
        if mean_d < MIN_INTERVAL:
            return None

        try:
            stdev = statistics.stdev(deltas)
        except statistics.StatisticsError:
            return None

        from packetiq import config
        cv_high     = config.get("beacon", "cv_threshold_high", CV_THRESHOLD_HIGH)
        cv_med      = config.get("beacon", "cv_threshold_med", CV_THRESHOLD_MED)
        cv_jitter   = config.get("beacon", "cv_threshold_jittered", 0.50)
        period_ratio = config.get("beacon", "periodicity_ratio", 0.70)

        cv = stdev / mean_d if mean_d > 0 else 1.0

        # Primary signal: low coefficient of variation = highly regular timing.
        # Secondary signal: jitter-tolerant periodicity — even when CV is moderate
        # (deliberate jitter / occasional missed beacons), a beacon still has most
        # intervals clustered around the median. This catches jittered C2 that a
        # pure-CV check would miss.
        median_d = statistics.median(deltas)
        near = sum(1 for d in deltas if median_d and abs(d - median_d) <= 0.30 * median_d)
        periodicity = near / len(deltas) if deltas else 0.0

        is_regular  = cv < cv_med
        is_jittered = (cv_med <= cv < cv_jitter) and (periodicity >= period_ratio)
        if not (is_regular or is_jittered):
            return None

        if cv < cv_high:
            severity = Severity.CRITICAL
        elif is_regular:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM   # jittered/evasive beacon
        jitter_pct = round(cv * 100, 1)
        regularity = round(max(1.0 - cv, periodicity) * 100)

        return DetectionEvent(
            event_type   = EventType.C2_BEACON,
            severity     = severity,
            src_ip       = src,
            dst_ip       = dst,
            dst_port     = dport,
            protocol     = proto,
            timestamp    = ts_sorted[0],
            packet_count = len(timestamps),
            confidence   = regularity / 100,
            description  = (
                f"C2 beacon: {src} → {dst}:{dport} "
                f"every ~{_fmt(mean_d)} (±{jitter_pct}% jitter, {len(timestamps)} hits)"
            ),
            evidence={
                "mean_interval_secs": round(mean_d, 2),
                "median_interval_secs": round(median_d, 2),
                "stdev_secs":         round(stdev, 2),
                "cv":                 round(cv, 4),
                "periodicity_ratio":  round(periodicity, 3),
                "pattern":            "jittered" if is_jittered else "regular",
                "connection_count":   len(timestamps),
                "jitter_pct":         jitter_pct,
                "regularity_score":   regularity,
                "protocol":           proto,
            },
        )


def _fmt(secs: float) -> str:
    if secs < 60:
        return f"{secs:.1f}s"
    if secs < 3600:
        return f"{secs / 60:.1f}min"
    return f"{secs / 3600:.1f}hr"
