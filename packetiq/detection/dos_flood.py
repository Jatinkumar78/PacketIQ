"""
Denial-of-Service flood detector (SYN flood / connection-exhaustion).

Distinct from scanning: a scan sprays SYNs *across many ports/hosts* to map the
network, whereas a flood concentrates a high volume of half-open SYNs on **one
target endpoint** to exhaust its connection state. The scan detectors therefore
miss it (one host, one port ⇒ zero "distinct ports/hosts").

Reads ExtractionResult.tcp_syn_pairs ((src,dst,dport) → SYN timestamps) and the
flow table to tell which SYNs were answered. A single (src → dst:port) with many
*unanswered* SYNs is flagged as a possible flood, tiered by volume and rate.
"""

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# Unanswered SYNs to ONE target endpoint before it counts as a flood. Set well
# above normal TCP SYN retransmission (a stuck client retries ~3–6 times) so a
# genuinely dead service doesn't false-positive.
DOS_SYN_THRESHOLD = 60
DOS_SYN_HIGH      = 300     # very high volume → HIGH
DOS_RATE_HIGH     = 40.0    # SYNs/sec sustained → HIGH


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []

    # Which (src, dst, dport) SYNs actually completed a handshake (got SYN-ACK)?
    answered: set = set()
    for f in result.flows.values():
        flags = f.tcp_flags_seen or set()
        if any("SYNACK" in x or "ACKSYN" in x for x in flags):
            answered.add((f.src_ip, f.dst_ip, f.dst_port))
            answered.add((f.dst_ip, f.src_ip, f.src_port))

    for (src, dst, dport), tss in (result.tcp_syn_pairs or {}).items():
        n = len(tss)
        if n < DOS_SYN_THRESHOLD or (src, dst, dport) in answered:
            continue

        span = (max(tss) - min(tss)) if len(tss) > 1 else 0.0
        rate = (n / span) if span > 0 else float(n)

        severity = (
            Severity.HIGH if (n >= DOS_SYN_HIGH or rate >= DOS_RATE_HIGH)
            else Severity.MEDIUM
        )
        from packetiq.utils.helpers import get_service_name
        service = get_service_name(dport) if dport is not None else "?"
        events.append(DetectionEvent(
            event_type   = EventType.DOS_FLOOD,
            severity     = severity,
            src_ip       = src,
            dst_ip       = dst,
            dst_port     = dport,
            protocol     = "TCP",
            description  = (
                f"Possible SYN flood — {n} unanswered SYNs from {src} to "
                f"{dst}:{dport}/{service}"
                + (f" (~{rate:.0f}/s)" if span > 0 else "")
                + " (connection-exhaustion pattern)"
            ),
            timestamp    = min(tss) if tss else 0.0,
            packet_count = n,
            confidence   = min(1.0, n / float(DOS_SYN_HIGH)),
            evidence     = {
                "unanswered_syns": n,
                "target":          f"{dst}:{dport}",
                "service":         service,
                "duration_s":      round(span, 1),
                "syns_per_s":      round(rate, 1),
                "threshold":       DOS_SYN_THRESHOLD,
                "handshakes_completed": 0,
                "technique":       "T1499.002 Service Exhaustion Flood",
            },
        ))
    return events
