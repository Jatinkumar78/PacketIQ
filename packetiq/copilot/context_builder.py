"""
Context Builder — serializes all PacketIQ analysis data into a structured
text block that Claude can reason over.

Design goals:
  - Deterministic output (same analysis → same context)
  - Token-efficient (no redundant prose, tight formatting)
  - SOC-oriented (emphasizes what matters for incident response)
  - Safe to cache with Anthropic prompt caching
"""

from datetime import datetime

from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.utils.helpers import format_bytes, format_duration, is_private_ip, ts_to_str

# An evidence-rich capture can touch thousands of external IPs. Enumerating all of
# them buries the actual findings (detections, attack chains, MITRE) and overflows
# a local model's context window, so it silently truncates and drops the evidence
# it most needs. We cap every long IP/domain enumeration to the top entries by
# volume and add an "… and N more" line, keeping the context signal-dense.
_MAX_IP_LIST = 30


def build_context(
    file_meta: dict,
    result: ExtractionResult,
    events: list[DetectionEvent],
    chains: list[AttackChain],
    risk_score: int = 0,
    risk_tier: str = "UNKNOWN",
) -> str:
    """
    Build the complete PCAP analysis context string for the AI copilot.
    Returns a structured text block ready to be embedded in the system prompt.
    """
    sections: list[str] = []

    sections.append(_header(file_meta, result, risk_score, risk_tier))
    sections.append(_capture_stats(result))
    sections.append(_protocol_distribution(result))
    sections.append(_network_topology(result))
    sections.append(_port_activity(result))
    sections.append(_detection_events(events))
    sections.append(_attack_chains(chains))
    sections.append(_dns_intelligence(result))
    sections.append(_http_activity(result))
    sections.append(_ioc_summary(result, events, chains))

    return "\n\n".join(s for s in sections if s.strip())


# ── Section builders ──────────────────────────────────────────────────────────

def _header(meta: dict, result: ExtractionResult, score: int, tier: str) -> str:
    duration = max(0.0, result.capture_end - result.capture_start)
    return f"""=== PACKETIQ ANALYSIS CONTEXT ===
File      : {meta.get('filename', 'unknown')}
Size      : {format_bytes(meta.get('filesize', 0))}
Packets   : {result.total_packets:,}
Duration  : {format_duration(duration)}
Start     : {ts_to_str(result.capture_start) if result.capture_start else 'N/A'}
End       : {ts_to_str(result.capture_end)   if result.capture_end   else 'N/A'}
Risk Score: {score}/100 [{tier}]
Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""


def _capture_stats(result: ExtractionResult) -> str:
    lines = [
        "=== CAPTURE STATISTICS ===",
        f"Total Bytes        : {format_bytes(result.total_bytes)}",
        f"Unique Source IPs  : {len(result.unique_src_ips)}",
        f"Unique Dest IPs    : {len(result.unique_dst_ips)}",
        f"External IPs       : {len(result.external_ips)}",
        f"Unique Flows       : {len(result.flows)}",
        f"DNS Queries        : {len(result.dns_queries)}",
        f"HTTP Requests      : {len(result.http_requests)}",
        f"TCP Completed 3WHS : {result.completed_connections}",
        f"TCP Half-Open SYNs : {result.open_connections}",
    ]
    return "\n".join(lines)


def _protocol_distribution(result: ExtractionResult) -> str:
    total = max(result.total_packets, 1)
    lines = ["=== PROTOCOL DISTRIBUTION ==="]
    for proto, cnt in sorted(result.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        pct = cnt / total * 100
        lines.append(f"  {proto:<10} {cnt:>8,} pkts  ({pct:.1f}%)")
    return "\n".join(lines)


def _network_topology(result: ExtractionResult) -> str:
    total = max(result.total_packets, 1)
    lines = ["=== TOP SOURCE IPs (by packet count) ==="]
    top_src = sorted(result.ip_src_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    for ip, cnt in top_src:
        scope = "INTERNAL" if is_private_ip(ip) else "EXTERNAL"
        lines.append(f"  {ip:<20} {cnt:>7,} pkts  [{scope}]")

    lines.append("\n=== TOP DESTINATION IPs (by packet count) ===")
    top_dst = sorted(result.ip_dst_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    for ip, cnt in top_dst:
        scope = "INTERNAL" if is_private_ip(ip) else "EXTERNAL"
        lines.append(f"  {ip:<20} {cnt:>7,} pkts  [{scope}]")

    ext = result.external_ips
    if ext:
        # Rank external contacts by traffic volume and cap the list — the top
        # peers are what an analyst needs; the long tail only buries the findings.
        dst = result.ip_dst_counts
        ranked = sorted(ext, key=lambda ip: dst.get(ip, 0), reverse=True)
        shown = ranked[:_MAX_IP_LIST]
        lines.append(f"\n=== EXTERNAL IP CONTACTS ({len(ext)} total, top {len(shown)} by volume) ===")
        for ip in shown:
            lines.append(f"  {ip:<20} {dst.get(ip, 0):>7,} pkts")
        if len(ext) > len(shown):
            lines.append(f"  … and {len(ext) - len(shown):,} more external IPs")

    return "\n".join(lines)


def _port_activity(result: ExtractionResult) -> str:
    from packetiq.utils.helpers import get_service_name
    lines = ["=== TOP DESTINATION PORTS ==="]
    top_ports = sorted(result.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    for port, cnt in top_ports:
        svc = get_service_name(port)
        lines.append(f"  {port:<6} ({svc:<12}) {cnt:>7,} pkts")
    return "\n".join(lines)


def _detection_events(events: list[DetectionEvent]) -> str:
    if not events:
        return "=== DETECTION EVENTS ===\nNone detected."

    lines = [f"=== DETECTION EVENTS ({len(events)} total) ==="]
    for i, e in enumerate(events, 1):
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        lines.append(
            f"\n[{i}] [{e.severity.value}] {e.event_type.value}\n"
            f"    Source      : {e.src_ip or '—'}\n"
            f"    Destination : {dst}\n"
            f"    Protocol    : {e.protocol or '—'}\n"
            f"    Description : {e.description}\n"
            f"    Confidence  : {e.confidence * 100:.0f}%\n"
            f"    Packets     : {e.packet_count}"
        )
        # Include key evidence fields (skip internal/noisy ones)
        for k, v in e.evidence.items():
            if k in ("note",):
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v[:5])
            lines.append(f"    {k:<16}: {v}")

    return "\n".join(lines)


def _attack_chains(chains: list[AttackChain]) -> str:
    if not chains:
        return "=== ATTACK CHAINS ===\nNo multi-stage chains correlated."

    lines = [f"=== ATTACK CHAINS ({len(chains)} identified) ==="]
    for i, chain in enumerate(chains, 1):
        phases   = " → ".join(chain.kill_chain_phases) if chain.kill_chain_phases else "—"
        attackers = ", ".join(sorted(chain.attacker_ips))
        targets   = ", ".join(sorted(chain.target_ips))
        techs     = "; ".join(f"{t.technique_id} {t.technique_name}"
                              for t in chain.mitre_techniques[:8])
        duration = format_duration(chain.duration)

        lines.append(
            f"\n[CHAIN {i}] {chain.name}\n"
            f"  Severity      : {chain.severity.value}\n"
            f"  Confidence    : {chain.confidence * 100:.0f}%\n"
            f"  Events Linked : {chain.event_count}\n"
            f"  Duration      : {duration}\n"
            f"  Attacker IPs  : {attackers}\n"
            f"  Target IPs    : {targets}\n"
            f"  Kill Chain    : {phases}\n"
            f"  Primary Phase : {chain.primary_phase}\n"
            f"  MITRE ATT&CK  : {techs}\n"
            f"  Description   : {chain.description}"
        )
        if chain.analyst_note:
            lines.append(f"  Analyst Note  : {chain.analyst_note}")

    return "\n".join(lines)


def _dns_intelligence(result: ExtractionResult) -> str:
    if not result.dns_queries:
        return ""

    lines = [f"=== DNS INTELLIGENCE ({len(result.dns_queries)} queries) ==="]

    # Domain frequency
    freq: dict[str, int] = {}
    for q in result.dns_queries:
        domain = q.get("qname", "")
        if domain:
            freq[domain] = freq.get(domain, 0) + 1

    lines.append("Top Queried Domains:")
    for domain, cnt in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]:
        lines.append(f"  {domain:<50} {cnt:>5}x")

    return "\n".join(lines)


def _http_activity(result: ExtractionResult) -> str:
    if not result.http_requests:
        return ""

    lines = [f"=== HTTP ACTIVITY ({len(result.http_requests)} requests) ==="]
    for r in result.http_requests[:30]:
        method = r.get("method", "?") or "?"
        host   = r.get("host",   "?") or "?"
        path   = r.get("path",   "/") or "/"
        src    = r.get("src",    "?") or "?"
        lines.append(f"  {method:<6} {src:<18} → {host}{path}")

    return "\n".join(lines)


def _ioc_summary(
    result: ExtractionResult,
    events: list[DetectionEvent],
    chains: list[AttackChain],
) -> str:
    """Pre-computed IOC list for quick reference."""
    lines = ["=== IOC SUMMARY ==="]

    # Attacker IPs from detection events
    attacker_ips = sorted({
        e.src_ip for e in events
        if e.src_ip and e.severity.value in ("CRITICAL", "HIGH")
    })
    if attacker_ips:
        lines.append(f"Suspected Attacker IPs (HIGH/CRITICAL events) — {len(attacker_ips)}:")
        for ip in attacker_ips[:_MAX_IP_LIST]:
            lines.append(f"  {ip}")
        if len(attacker_ips) > _MAX_IP_LIST:
            lines.append(f"  … and {len(attacker_ips) - _MAX_IP_LIST:,} more")

    # Target IPs
    target_ips = sorted({
        e.dst_ip for e in events
        if e.dst_ip and e.severity.value in ("CRITICAL", "HIGH")
    })
    if target_ips:
        lines.append(f"Targeted IPs — {len(target_ips)}:")
        for ip in target_ips[:_MAX_IP_LIST]:
            lines.append(f"  {ip}")
        if len(target_ips) > _MAX_IP_LIST:
            lines.append(f"  … and {len(target_ips) - _MAX_IP_LIST:,} more")

    # External IPs contacted (top by volume; the full set is a count, not a dump)
    if result.external_ips:
        ext = sorted(result.external_ips,
                     key=lambda ip: result.ip_dst_counts.get(ip, 0), reverse=True)
        shown = ext[:_MAX_IP_LIST]
        lines.append(f"External IPs Contacted ({len(ext)} total, top {len(shown)} by volume):")
        for ip in shown:
            lines.append(f"  {ip}")
        if len(ext) > len(shown):
            lines.append(f"  … and {len(ext) - len(shown):,} more")

    # Suspicious domains
    suspicious_domains = sorted({
        q.get("qname", "")
        for q in result.dns_queries
        if q.get("qname") and (
            len(q["qname"]) > 30 or
            any(q["qname"].endswith(tld) for tld in (".xyz", ".tk", ".ml", ".top", ".pw"))
        )
    })
    if suspicious_domains:
        lines.append("Suspicious Domains:")
        for d in suspicious_domains:
            lines.append(f"  {d}")

    return "\n".join(lines)
