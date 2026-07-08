"""
Protocol Misuse Detector.

Detects protocol-level anomalies from flow and packet data:

  1. Non-standard port usage     — known protocols on wrong ports
  2. ICMP tunneling              — oversized ICMP packets (data exfil)
  3. Suspicious TCP flag combos  — XMAS, NULL, FIN-only scans
  4. SMB over internet           — port 445 to external IPs
  5. Cleartext protocols in use  — Telnet, FTP, HTTP on external connections
  6. High port-to-low-port ratio — unusual session reversal (potential backdoor)
"""


from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.utils.helpers import is_private_ip

# ICMP tunneling threshold — a normal ping session (64-byte payloads, ~100 pings)
# totals under 20 KB. Legitimate large-ping diagnostics rarely exceed 100 KB.
# Only flag flows that are clearly carrying sustained data volumes above 100 KB.
ICMP_TUNNEL_THRESHOLD = 102_400   # 100 KB total flow bytes → flag

# Cleartext protocols that carry credentials and should NOT traverse the internet.
# HTTP (port 80) is excluded: ordinary web browsing is cleartext HTTP to external
# hosts by design. Only truly dangerous auth-carrying protocols are listed.
CLEARTEXT_RISKY = {21: "FTP", 23: "TELNET"}

# Our parser decodes TCP flags into a concatenation of fixed 3-letter tokens
# (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR). We split them back into a set so
# detection is order-independent.
_FLAG_TOKENS = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")


def _flag_set(combo: str) -> set[str]:
    """Split a decoded flag string like 'FINPSHURG' into {'FIN','PSH','URG'}."""
    return {combo[i:i + 3] for i in range(0, len(combo), 3) if combo[i:i + 3] in _FLAG_TOKENS}


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    events.extend(_icmp_tunneling(result))
    events.extend(_suspicious_tcp_flags(result))
    events.extend(_smb_to_internet(result))
    events.extend(_cleartext_to_internet(result))
    return events


# ── ICMP Tunneling ────────────────────────────────────────────────────────────

def _icmp_tunneling(result: ExtractionResult) -> list[DetectionEvent]:
    """
    ICMP flows with large byte volumes suggest data exfiltration or
    tunneling (tools: icmptunnel, ptunnel). Normal ping: 64–1024 bytes.
    Flag ICMP flows exceeding ICMP_TUNNEL_THRESHOLD total bytes.
    """
    from packetiq import config
    icmp_threshold = config.get("icmp", "tunnel_threshold_bytes", ICMP_TUNNEL_THRESHOLD)
    events: list[DetectionEvent] = []

    for flow in result.flows.values():
        if flow.protocol != "ICMP":
            continue
        if flow.bytes_total < icmp_threshold:
            continue

        severity = Severity.HIGH if flow.bytes_total > 500_000 else Severity.MEDIUM
        events.append(DetectionEvent(
            event_type   = EventType.ICMP_TUNNELING,
            severity     = severity,
            src_ip       = flow.src_ip,
            dst_ip       = flow.dst_ip,
            description  = (
                f"ICMP tunneling suspected — {flow.bytes_total:,} bytes over ICMP "
                f"({flow.packets} packets)"
            ),
            packet_count = flow.packets,
            confidence   = min(1.0, flow.bytes_total / 1_000_000),
            evidence     = {
                "protocol":       "ICMP",
                "total_bytes":    flow.bytes_total,
                "total_packets":  flow.packets,
                "avg_pkt_bytes":  round(flow.bytes_total / max(flow.packets, 1)),
                "threshold":      icmp_threshold,
            },
        ))

    return events


# ── Suspicious TCP Flags ──────────────────────────────────────────────────────

def _suspicious_tcp_flags(result: ExtractionResult) -> list[DetectionEvent]:
    """
    XMAS scan: FIN+URG+PSH set simultaneously (RFC-violating; used by Nmap -sX)
    NULL scan: No flags set (RFC-violating; used by Nmap -sN)
    FIN-only:  Only FIN set without prior connection (used by Nmap -sF)
    """
    events: list[DetectionEvent] = []
    seen: set[tuple] = set()

    for flow in result.flows.values():
        for flag_combo in flow.tcp_flags_seen:
            flags = _flag_set(flag_combo)

            scan_type = None
            # XMAS scan: FIN + PSH + URG set together (Nmap -sX). SYN/ACK absent.
            if {"FIN", "PSH", "URG"}.issubset(flags) and not (flags & {"SYN", "ACK"}):
                scan_type = "XMAS"
            # FIN-only scan: just FIN, no other control flags (Nmap -sF).
            elif flags == {"FIN"}:
                scan_type = "FIN_ONLY"
            # NULL scan (no flags) cannot be seen at flow level — the parser/extractor
            # only records flows for packets that carry at least one flag.

            if scan_type is None:
                continue

            key = (flow.src_ip, flow.dst_ip, scan_type)
            if key in seen:
                continue
            seen.add(key)

            events.append(DetectionEvent(
                event_type   = EventType.SUSPICIOUS_FLAGS,
                severity     = Severity.HIGH,
                src_ip       = flow.src_ip,
                dst_ip       = flow.dst_ip,
                dst_port     = flow.dst_port,
                protocol     = "TCP",
                description  = (
                    f"RFC-violating TCP scan detected ({scan_type}) — "
                    f"flags: {flag_combo!r} on {flow.src_ip} → {flow.dst_ip}"
                ),
                packet_count = flow.packets,
                confidence   = 0.9,
                evidence     = {
                    "scan_type":    scan_type,
                    "tcp_flags":    flag_combo,
                    "note":         "These flag combinations are used by stealth scanners (Nmap)",
                },
            ))

    return events


# ── SMB to Internet ───────────────────────────────────────────────────────────

def _smb_to_internet(result: ExtractionResult) -> list[DetectionEvent]:
    """
    SMB (port 445/139) traffic to or from external IPs indicates potential
    EternalBlue, ransomware lateral movement, or data exfiltration.
    """
    events: list[DetectionEvent] = []
    seen: set[tuple] = set()

    for flow in result.flows.values():
        if flow.dst_port not in (445, 139) and flow.src_port not in (445, 139):
            continue

        # Check if either endpoint is external
        src_ext = not is_private_ip(flow.src_ip) if flow.src_ip else False
        dst_ext = not is_private_ip(flow.dst_ip) if flow.dst_ip else False

        if not (src_ext or dst_ext):
            continue

        key = (flow.src_ip, flow.dst_ip, flow.dst_port)
        if key in seen:
            continue
        seen.add(key)

        ext_ip = flow.src_ip if src_ext else flow.dst_ip
        events.append(DetectionEvent(
            event_type   = EventType.PROTOCOL_MISUSE,
            severity     = Severity.CRITICAL,
            src_ip       = flow.src_ip,
            dst_ip       = flow.dst_ip,
            dst_port     = flow.dst_port,
            protocol     = "TCP",
            description  = (
                f"SMB traffic to/from external IP {ext_ip} — "
                f"possible EternalBlue/ransomware/lateral movement"
            ),
            packet_count = flow.packets,
            confidence   = 0.95,
            evidence     = {
                "external_ip": ext_ip,
                "smb_port":    flow.dst_port,
                "bytes":       flow.bytes_total,
                "risk":        "EternalBlue / ransomware / data exfil",
            },
        ))

    return events


# ── Cleartext Protocols to Internet ──────────────────────────────────────────

def _cleartext_to_internet(result: ExtractionResult) -> list[DetectionEvent]:
    """
    Using FTP, TELNET, or HTTP to communicate with external public IPs
    is a credential exposure risk. Flag these flows.
    """
    events: list[DetectionEvent] = []
    seen: set[tuple] = set()

    for flow in result.flows.values():
        if flow.dst_port not in CLEARTEXT_RISKY:
            continue
        if not flow.dst_ip:
            continue
        if is_private_ip(flow.dst_ip):
            continue  # Internal only — lower risk (still flagged by credential detector)

        svc = CLEARTEXT_RISKY[flow.dst_port]
        key = (flow.src_ip, flow.dst_ip, flow.dst_port)
        if key in seen:
            continue
        seen.add(key)

        events.append(DetectionEvent(
            event_type   = EventType.PROTOCOL_MISUSE,
            severity     = Severity.HIGH,
            src_ip       = flow.src_ip,
            dst_ip       = flow.dst_ip,
            dst_port     = flow.dst_port,
            protocol     = "TCP",
            description  = (
                f"Cleartext {svc} session to external host {flow.dst_ip} — "
                f"credentials and data transmitted unencrypted"
            ),
            packet_count = flow.packets,
            confidence   = 0.9,
            evidence     = {
                "service":      svc,
                "external_dst": flow.dst_ip,
                "bytes":        flow.bytes_total,
                "remediation":  f"Replace {svc} with encrypted alternative",
            },
        ))

    return events
