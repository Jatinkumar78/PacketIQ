"""
Brute Force Detector.

Strategy:
  - Scans tcp_syn_pairs for high-frequency SYN bursts per authentication port.
  - Uses a sliding time window to find the peak burst rate.

Scope — ONLY authentication-oriented services where repeated SYN bursts are
genuinely suspicious:
  SSH, TELNET, FTP, RDP, VNC

Deliberately excluded to avoid false positives:
  - HTTP/HTTPS (80, 443, 8080, 8443): Normal browsing, REST clients, CDN
    connection pools all produce many SYNs. Use credential detector instead.
  - SMTP/POP3/IMAP (25, 110, 143, 465, 587): Mail servers send batch deliveries
    that look identical to brute force at the SYN level.
  - Databases (MySQL, PostgreSQL, MSSQL, MongoDB, Redis): Connection pools
    reconnect continuously. Normal operation looks like a burst.

Real-world brute force tools (Hydra, Medusa, Ncrack, CrackMapExec) target
SSH, RDP, FTP, VNC, Telnet — that is exactly what we monitor.
"""

from collections import defaultdict

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# ── Global window ────────────────────────────────────────────────────────────
WINDOW_SECS = 60    # sliding window in seconds

# Port → (service label, base severity, SYN threshold in WINDOW_SECS)
#
# Threshold rationale:
#   SSH  (22)  : 20 SYNs/60s — developer reconnecting: 3-6 SYNs. Real brute force: 30-300+/min
#   FTP  (21)  : 15 SYNs/60s — each auth = 1 TCP connection. 15 in 60s is very rapid.
#   TELNET (23): 10 SYNs/60s — deprecated protocol; any burst is extremely suspicious
#   RDP  (3389): 10 SYNs/60s — Windows RDP has built-in lockout; 10 rapid retries = alert
#   VNC  (5900): 10 SYNs/60s — VNC has minimal lockout; any burst is suspicious
MONITORED_PORTS: dict[int, tuple[str, Severity, int]] = {
    22:   ("SSH",    Severity.HIGH,     20),
    21:   ("FTP",    Severity.HIGH,     15),
    23:   ("TELNET", Severity.HIGH,     10),
    3389: ("RDP",    Severity.CRITICAL, 10),
    5900: ("VNC",    Severity.HIGH,     10),
}

# Avg bytes per SYN above this → real sessions, not brute force.
# SSH brute force: ~1-3 KB per failed attempt (banner + key negotiation + fail)
# Legitimate SSH session: 20 KB+ (key exchange + shell + data)
# Using 15 KB as the cutoff is conservative but avoids false positives on
# SSH key-based auth where connections succeed quickly with little data.
LEGITIMATE_SESSION_BYTES = 15_000


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    """
    Scan tcp_syn_pairs for high-frequency SYN bursts on authentication ports.
    Cross-references flow data to filter out legitimate high-volume sessions.

    Thresholds are read from config ([brute_force] in packetiq.toml), falling
    back to the module defaults.
    """
    from packetiq import config
    window = config.get("brute_force", "window_secs", WINDOW_SECS)
    legit_bytes = config.get("brute_force", "legitimate_session_bytes", LEGITIMATE_SESSION_BYTES)
    monitored = {
        22:   ("SSH",    Severity.HIGH,     config.get("brute_force", "ssh_threshold", 20)),
        21:   ("FTP",    Severity.HIGH,     config.get("brute_force", "ftp_threshold", 15)),
        23:   ("TELNET", Severity.HIGH,     config.get("brute_force", "telnet_threshold", 10)),
        3389: ("RDP",    Severity.CRITICAL, config.get("brute_force", "rdp_threshold", 10)),
        5900: ("VNC",    Severity.HIGH,     config.get("brute_force", "vnc_threshold", 10)),
    }
    events: list[DetectionEvent] = []

    # Build index of total bytes exchanged per (src, dst, dport) direction.
    # This lets us determine whether connections are real sessions or rapid-fail attempts.
    flow_bytes: dict[tuple, int] = defaultdict(int)
    flow_count: dict[tuple, int] = defaultdict(int)
    for flow in result.flows.values():
        if flow.src_ip and flow.dst_ip and flow.dst_port:
            k = (flow.src_ip, flow.dst_ip, flow.dst_port)
            flow_bytes[k] += flow.bytes_total
            flow_count[k] += 1

    for (src_ip, dst_ip, dport), timestamps in result.tcp_syn_pairs.items():
        if dport not in monitored:
            continue
        service_label, severity, threshold = monitored[dport]

        if len(timestamps) < threshold:
            continue

        ts_sorted = sorted(timestamps)
        max_in_window = _max_window_count(ts_sorted, window)

        if max_in_window < threshold:
            continue

        # ── Session legitimacy check ─────────────────────────────────────────
        # If avg bytes per connection is high, these are real sessions (not rapid-fail).
        k = (src_ip, dst_ip, dport)
        total_bytes = flow_bytes.get(k, 0)
        n_flows     = flow_count.get(k, 0)
        avg_bytes   = total_bytes / n_flows if n_flows > 0 else 0

        if avg_bytes > legit_bytes:
            continue   # Long-lived sessions → not brute force

        span = ts_sorted[-1] - ts_sorted[0]

        # Escalate if extremely aggressive
        if max_in_window >= 50 and dport in (22, 21):
            severity = Severity.CRITICAL

        rate_per_min = max_in_window  # already per 60s window
        confidence = min(1.0, max_in_window / (threshold * 2))

        events.append(DetectionEvent(
            event_type   = EventType.BRUTE_FORCE,
            severity     = severity,
            src_ip       = src_ip,
            dst_ip       = dst_ip,
            dst_port     = dport,
            protocol     = "TCP",
            description  = (
                f"Brute force on {service_label} — "
                f"{max_in_window} attempts in {window}s "
                f"({rate_per_min}/min rate)"
            ),
            timestamp    = ts_sorted[0],
            packet_count = len(timestamps),
            confidence   = confidence,
            evidence     = {
                "service":         service_label,
                "total_syns":      len(timestamps),
                "max_in_window":   max_in_window,
                "window_secs":     window,
                "burst_span_secs": round(span, 2),
                "threshold":       threshold,
                "avg_bytes_per_conn": round(avg_bytes),
            },
        ))

    return events


def _max_window_count(sorted_ts: list[float], window: float) -> int:
    """Sliding window maximum — O(n) two-pointer scan."""
    if not sorted_ts:
        return 0
    left = 0
    best = 0
    for right in range(len(sorted_ts)):
        while sorted_ts[right] - sorted_ts[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best
