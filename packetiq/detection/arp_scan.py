"""
ARP Scan & Spoofing Detector (layer-2 reconnaissance and man-in-the-middle).

Two patterns, both read straight from the ARP evidence the extractor collects:

1. ARP host-discovery sweep — one sender ARP-requests ("who-has") many distinct
   target IPs. This is exactly what ``nmap -sn``, ``arp-scan`` and ``netdiscover``
   do to enumerate live hosts on a local subnet, and it is invisible to IP-layer
   scan detectors because it never sends a single IP packet.  MITRE T1018.

2. ARP cache poisoning / spoofing — a single IPv4 address is announced by more
   than one MAC. That IP→MAC conflict is the fingerprint of an adversary-in-the-
   middle (ettercap / arpspoof / bettercap) redirecting a victim's traffic.
   MITRE T1557.002.

Uses: ExtractionResult.arp_request_targets / arp_request_counts /
      arp_sender_macs / arp_request_window / arp_ip_to_macs
"""

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# ── Thresholds ────────────────────────────────────────────────────────────────
# Distinct target IPs one sender must ARP-request before it counts as a sweep.
# A normal client resolves a handful of peers (gateway + a few hosts); asking
# "who-has" for 20+ distinct addresses is host-discovery behaviour, not usage.
ARP_SCAN_TARGET_THRESHOLD = 20
# HIGH is the honest ceiling: this is reconnaissance (discovery), not a breach.
ARP_SCAN_HIGH_TARGETS     = 50     # broad sweep → HIGH; 20–49 → MEDIUM


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    events.extend(_arp_host_discovery(result))
    events.extend(_arp_spoofing(result))
    return events


# ── ARP host-discovery sweep ────────────────────────────────────────────────────

def _arp_host_discovery(result: ExtractionResult) -> list[DetectionEvent]:
    from packetiq import config
    threshold = config.get("arp_scan", "target_threshold", ARP_SCAN_TARGET_THRESHOLD)

    events: list[DetectionEvent] = []
    for sender_ip, targets in (result.arp_request_targets or {}).items():
        n = len(targets)
        if n < threshold:
            continue

        requests = result.arp_request_counts.get(sender_ip, n)
        macs = sorted(result.arp_sender_macs.get(sender_ip, set()))
        first_ts, last_ts = result.arp_request_window.get(sender_ip, (0.0, 0.0))
        span = max(0.0, (last_ts or 0.0) - (first_ts or 0.0))
        rate = (requests / span) if span > 0 else 0.0

        severity = (
            Severity.HIGH if n >= ARP_SCAN_HIGH_TARGETS
            else Severity.MEDIUM
        )

        events.append(DetectionEvent(
            event_type   = EventType.ARP_SCAN,
            severity     = severity,
            src_ip       = sender_ip,
            protocol     = "ARP",
            description  = (
                f"ARP host-discovery sweep — {sender_ip} ARP-requested "
                f"{n} distinct hosts"
                + (f" in {span:.0f}s" if span > 0 else "")
                + " (layer-2 subnet enumeration)"
            ),
            timestamp    = first_ts or 0.0,
            packet_count = requests,
            confidence   = min(1.0, n / 100.0),
            evidence     = {
                "distinct_targets": n,
                "arp_requests":     requests,
                "sender_mac":       ", ".join(macs) if macs else "",
                "duration_s":       round(span, 1),
                "requests_per_s":   round(rate, 1),
                "sample_targets":   sorted(targets)[:12],
                "threshold":        threshold,
                "technique":        "T1018 Remote System Discovery",
                "scan_type":        "arp_sweep",
            },
        ))
    return events


# ── ARP cache poisoning / spoofing ──────────────────────────────────────────────

def _arp_spoofing(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    for ip, macs in (result.arp_ip_to_macs or {}).items():
        if len(macs) < 2:
            continue

        mac_list = sorted(macs)
        # More conflicting MACs → stronger signal; still framed as "possible"
        # because HA/VRRP failover can legitimately move an IP between NICs.
        events.append(DetectionEvent(
            event_type   = EventType.ARP_SPOOFING,
            severity     = Severity.HIGH,
            src_ip       = ip,
            protocol     = "ARP",
            description  = (
                f"Possible ARP cache poisoning — {ip} was announced by "
                f"{len(mac_list)} different MAC addresses (IP→MAC conflict)"
            ),
            packet_count = len(mac_list),
            confidence   = min(0.9, 0.5 + 0.15 * (len(mac_list) - 1)),
            evidence     = {
                "claimed_ip":      ip,
                "conflicting_macs": ", ".join(mac_list),
                "mac_count":       len(mac_list),
                "technique":       "T1557.002 ARP Cache Poisoning",
            },
        ))
    return events
