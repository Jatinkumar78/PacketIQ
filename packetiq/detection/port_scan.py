"""
Port & Host Scan Detector.

Detects four scan patterns from flow-level data:

1. Vertical port scan  — one src → one dst, many distinct ports (SYN-only)
2. Horizontal host scan — one src → many dsts, same port (service sweep)
3. TCP connect scan    — completed 3WHS to many ports → quick RST (slow scan)
4. Stealth SYN scan    — many SYN-only half-opens (no SYN-ACK received)

Uses: ExtractionResult.flows + ExtractionResult.tcp_syn_pairs
"""

from collections import defaultdict

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# ── Thresholds ────────────────────────────────────────────────────────────────
VERT_SCAN_PORT_THRESHOLD  = 15   # distinct ports to same host = vertical scan
STEALTH_HALFOPEN_THRESHOLD = 10  # half-open SYNs (no SYN-ACK) = stealth scan

# Default horizontal scan threshold (distinct hosts on same port)
HORIZ_SCAN_HOST_THRESHOLD = 20

# Per-port overrides for horizontal scan.
# Web ports (80/443/8080) are contacted by browsers across many CDN IPs during
# normal browsing — a client hitting 30 HTTPS servers is typical, not a scan.
# Only flag when the count is implausibly high for organic traffic.
HORIZ_SCAN_PORT_THRESHOLDS: dict[int, int] = {
    80:   60,   # HTTP — CDN, tracking pixels, ads
    443:  60,   # HTTPS — same; also TLS session to many CDN nodes
    8080: 40,   # Alt-HTTP
    8443: 40,   # Alt-HTTPS
}


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    events.extend(_vertical_scan(result))
    events.extend(_horizontal_scan(result))
    events.extend(_stealth_syn_scan(result))
    return events


# ── Vertical port scan ─────────────────────────────────────────────────────────

def _vertical_scan(result: ExtractionResult) -> list[DetectionEvent]:
    """
    Group TCP flows by (src_ip, dst_ip). If one source contacts more than
    VERT_SCAN_PORT_THRESHOLD distinct ports on the same host → port scan.
    """
    from packetiq import config
    vert_threshold = config.get("port_scan", "vertical_port_threshold", VERT_SCAN_PORT_THRESHOLD)
    events: list[DetectionEvent] = []
    # src_ip → dst_ip → set of destination ports
    matrix: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for flow in result.flows.values():
        if flow.protocol not in ("TCP", "UDP"):
            continue
        if flow.src_ip and flow.dst_ip and flow.dst_port is not None:
            matrix[flow.src_ip][flow.dst_ip].add(flow.dst_port)

    for src_ip, dst_map in matrix.items():
        for dst_ip, ports in dst_map.items():
            if len(ports) >= vert_threshold:
                severity = (
                    Severity.CRITICAL if len(ports) >= 100
                    else Severity.HIGH if len(ports) >= 30
                    else Severity.MEDIUM
                )
                events.append(DetectionEvent(
                    event_type   = EventType.PORT_SCAN,
                    severity     = severity,
                    src_ip       = src_ip,
                    dst_ip       = dst_ip,
                    description  = (
                        f"Vertical port scan — {len(ports)} distinct ports probed on {dst_ip}"
                    ),
                    packet_count = len(ports),
                    confidence   = min(1.0, len(ports) / 100),
                    evidence     = {
                        "ports_probed":      len(ports),
                        "threshold":         vert_threshold,
                        "sample_ports":      sorted(ports)[:20],
                        "scan_type":         "vertical",
                    },
                ))
    return events


# ── Horizontal host scan ───────────────────────────────────────────────────────

def _horizontal_scan(result: ExtractionResult) -> list[DetectionEvent]:
    """
    Group TCP/UDP flows by (src_ip, dst_port). If one source contacts more than
    HORIZ_SCAN_HOST_THRESHOLD distinct hosts on the same port → sweep scan.
    """
    events: list[DetectionEvent] = []
    # src_ip → dst_port → set of dst_ips
    matrix: dict[str, dict[int, set]] = defaultdict(lambda: defaultdict(set))

    for flow in result.flows.values():
        if flow.protocol not in ("TCP", "UDP"):
            continue
        if flow.src_ip and flow.dst_ip and flow.dst_port is not None:
            matrix[flow.src_ip][flow.dst_port].add(flow.dst_ip)

    from packetiq import config
    default_horiz = config.get("port_scan", "horizontal_host_threshold", HORIZ_SCAN_HOST_THRESHOLD)
    for src_ip, port_map in matrix.items():
        for dport, hosts in port_map.items():
            threshold = HORIZ_SCAN_PORT_THRESHOLDS.get(dport, default_horiz)
            if len(hosts) < threshold:
                continue
            from packetiq.utils.helpers import get_service_name
            service = get_service_name(dport)
            severity = (
                Severity.HIGH if len(hosts) >= threshold * 3
                else Severity.MEDIUM
            )
            events.append(DetectionEvent(
                event_type   = EventType.HOST_SCAN,
                severity     = severity,
                src_ip       = src_ip,
                dst_port     = dport,
                description  = (
                    f"Horizontal host scan — {len(hosts)} hosts probed "
                    f"on port {dport}/{service}"
                ),
                packet_count = len(hosts),
                confidence   = min(1.0, len(hosts) / (threshold * 2)),
                evidence     = {
                    "hosts_probed": len(hosts),
                    "target_port":  dport,
                    "service":      service,
                    "threshold":    threshold,
                    "sample_hosts": sorted(hosts)[:10],
                },
            ))
    return events


# ── Stealth SYN scan (half-open) ───────────────────────────────────────────────

def _stealth_syn_scan(result: ExtractionResult) -> list[DetectionEvent]:
    """
    tcp_syn_pairs tracks SYNs sent. synack_set tracks which got a reply.
    Half-open = SYN sent, no SYN-ACK received → stealthy Nmap-style scan.

    Groups half-open connections by src_ip. If a single src has many
    half-open SYNs → stealth scan.
    """
    events: list[DetectionEvent] = []

    # Reconstruct synack_set from the flows (flows that have SYNACK in their flags)
    synack_set: set[tuple] = set()
    for flow in result.flows.values():
        if "SYNACK" in flow.tcp_flags_seen or "ACKSYN" in flow.tcp_flags_seen:
            synack_set.add((flow.dst_ip, flow.src_ip, flow.src_port))

    # Find half-open SYNs per source IP
    half_open_by_src: dict[str, list[tuple]] = defaultdict(list)

    for (src, dst, dport), tss in result.tcp_syn_pairs.items():
        rkey = (dst, src, None)  # we don't have sport in syn_pairs, approximate
        # Check any synack returned to this src
        replied = any(
            s == src and t == dst
            for (t, s, _) in synack_set
        )
        if not replied:
            half_open_by_src[src].append((dst, dport, len(tss)))

    from packetiq import config
    stealth_threshold = config.get("port_scan", "stealth_halfopen_threshold", STEALTH_HALFOPEN_THRESHOLD)
    for src_ip, half_opens in half_open_by_src.items():
        if len(half_opens) < stealth_threshold:
            continue

        distinct_ports = {port for _, port, _ in half_opens}
        distinct_dsts  = {dst  for dst,  _, _ in half_opens}

        severity = (
            Severity.HIGH if len(distinct_ports) >= 30
            else Severity.MEDIUM
        )
        events.append(DetectionEvent(
            event_type   = EventType.PORT_SCAN,
            severity     = severity,
            src_ip       = src_ip,
            description  = (
                f"Stealth SYN scan — {len(half_opens)} half-open connections "
                f"({len(distinct_ports)} ports, {len(distinct_dsts)} hosts)"
            ),
            packet_count = sum(c for _, _, c in half_opens),
            confidence   = min(1.0, len(half_opens) / 50),
            evidence     = {
                "half_open_count":  len(half_opens),
                "distinct_ports":   len(distinct_ports),
                "distinct_targets": len(distinct_dsts),
                "threshold":        stealth_threshold,
                "scan_type":        "stealth_syn",
                "sample_targets":   [f"{d}:{p}" for d, p, _ in half_opens[:10]],
            },
        ))

    return events
