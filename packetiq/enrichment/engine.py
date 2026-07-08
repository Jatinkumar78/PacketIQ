"""
Enrichment engine — matches observed IPs and domains against the IOC store
and emits IOC_MATCH detection events.

This is what turns a behavioural hunch ("this looks like a beacon") into a
concrete, attributable finding ("this destination is a known QakBot C2 per
abuse.ch Feodo Tracker").
"""

from collections import defaultdict
from typing import Optional

from packetiq.detection.models import DetectionEvent, EventType
from packetiq.enrichment.feeds import IOCStore, load_store
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.utils.helpers import is_private_ip


def enrich(result: ExtractionResult, store: Optional[IOCStore] = None) -> list[DetectionEvent]:
    """Cross-reference external IPs and DNS domains against threat-intel feeds."""
    store = store if store is not None else load_store()
    if store.total == 0:
        return []

    events: list[DetectionEvent] = []

    # Map each external IP to the internal host(s) that talked to it (for context)
    peers: dict[str, set] = defaultdict(set)
    last_ts: dict[str, float] = {}
    for fl in result.flows.values():
        if not (fl.src_ip and fl.dst_ip):
            continue
        peers[fl.src_ip].add(fl.dst_ip)
        peers[fl.dst_ip].add(fl.src_ip)
        last_ts[fl.src_ip] = max(last_ts.get(fl.src_ip, 0.0), fl.last_seen)
        last_ts[fl.dst_ip] = max(last_ts.get(fl.dst_ip, 0.0), fl.last_seen)

    # ── IP / CIDR matches ────────────────────────────────────────────────────
    seen_ips: set = set()
    candidate_ips = set(result.external_ips) | {
        ip for ip in (set(result.ip_src_counts) | set(result.ip_dst_counts))
        if not is_private_ip(ip)
    }
    for ip in candidate_ips:
        if ip in seen_ips:
            continue
        hit = store.lookup_ip(ip)
        if not hit:
            continue
        seen_ips.add(ip)
        internal = next((p for p in peers.get(ip, ()) if is_private_ip(p)), None)
        events.append(DetectionEvent(
            event_type   = EventType.IOC_MATCH,
            severity     = hit.severity,
            src_ip       = internal or "(local host)",
            dst_ip       = ip,
            protocol     = "IP",
            timestamp    = last_ts.get(ip, result.capture_start),
            packet_count = result.ip_src_counts.get(ip, 0) + result.ip_dst_counts.get(ip, 0),
            confidence   = 0.95,
            description  = (
                f"Traffic to/from threat-intel-listed IP {ip} — {hit.label}"
            ),
            evidence     = {
                "indicator": ip,
                "kind":      hit.kind,
                "source":    hit.source,
                "label":     hit.label,
                "internal_peers": sorted(p for p in peers.get(ip, ()) if is_private_ip(p))[:5],
            },
        ))

    # ── Domain matches ───────────────────────────────────────────────────────
    seen_domains: set = set()
    for q in result.dns_queries:
        qname = (q.get("qname") or "").rstrip(".").lower()
        if not qname or qname in seen_domains:
            continue
        hit = store.lookup_domain(qname)
        if not hit:
            continue
        seen_domains.add(qname)
        events.append(DetectionEvent(
            event_type   = EventType.IOC_MATCH,
            severity     = hit.severity,
            src_ip       = q.get("src", "") or "(local host)",
            dst_ip       = q.get("dst"),
            dst_port     = 53,
            protocol     = "DNS",
            timestamp    = q.get("ts", 0.0),
            packet_count = sum(1 for x in result.dns_queries if (x.get("qname") or "").rstrip(".").lower() == qname),
            confidence   = 0.95,
            description  = (
                f"DNS query for threat-intel-listed domain {qname} — {hit.label}"
            ),
            evidence     = {
                "indicator": qname,
                "kind":      "domain",
                "source":    hit.source,
                "label":     hit.label,
                "matched_on": hit.indicator,
            },
        ))

    return events
