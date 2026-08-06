"""
Correlation Rules — each function takes a list of DetectionEvents and returns
zero or more AttackChain objects.

Rule design principles:
  - Rules are independent and composable — the engine deduplicates later.
  - Each rule names itself with a clear threat narrative.
  - Confidence reflects how certain the correlation is (not just severity).
  - Evidence dict captures the linking logic for analyst review.

Rule catalogue:
  1. recon_to_initial_access      — scan + brute force from same source
  2. brute_credential_chain       — brute force + plaintext cred on same target
  3. c2_channel_detection         — DNS tunneling + beaconing pattern
  4. covert_exfiltration          — ICMP + DNS tunnel from same source
  5. lateral_movement_smb         — SMB external + credential exposure
  6. full_kill_chain              — 3+ kill chain phases from same attacker
  7. dga_c2_cluster               — multiple DGA/suspicious domains from same src
  8. credential_spray             — brute force against many different targets
"""

from collections import defaultdict
from typing import Optional

from packetiq.correlation import mitre as mitre_db
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, EventType, Severity

# ── Shared helpers ────────────────────────────────────────────────────────────

def _chain(
    name: str,
    description: str,
    events: list[DetectionEvent],
    severity: Severity,
    confidence: float,
    analyst_note: str = "",
) -> AttackChain:
    """Factory that auto-fills MITRE and kill chain from the event list."""
    attacker_ips = {e.src_ip for e in events if e.src_ip}
    target_ips   = {e.dst_ip for e in events if e.dst_ip}
    timestamps   = [e.timestamp for e in events if e.timestamp]

    chain = AttackChain(
        name          = name,
        description   = description,
        attacker_ips  = attacker_ips,
        target_ips    = target_ips,
        events        = events,
        severity      = severity,
        confidence    = confidence,
        first_seen    = min(timestamps) if timestamps else 0.0,
        last_seen     = max(timestamps) if timestamps else 0.0,
        mitre_techniques    = mitre_db.techniques_for_events(events),
        kill_chain_phases   = mitre_db.kill_chain_phases_for_events(events),
        analyst_note  = analyst_note,
    )
    chain._update_primary_phase()
    return chain


def _events_by_src(events: list[DetectionEvent]) -> dict[str, list[DetectionEvent]]:
    groups: dict[str, list] = defaultdict(list)
    for e in events:
        if e.src_ip:
            groups[e.src_ip].append(e)
    return groups


def _events_of_type(events: list[DetectionEvent], *types: EventType) -> list[DetectionEvent]:
    return [e for e in events if e.event_type in types]


def _same_target(e1: DetectionEvent, e2: DetectionEvent) -> bool:
    """True if both events share a destination IP."""
    return bool(e1.dst_ip and e2.dst_ip and e1.dst_ip == e2.dst_ip)


def _time_order(earlier: DetectionEvent, later: DetectionEvent, max_gap_secs: float = 3600) -> bool:
    """True if earlier occurred at or before later (within max_gap_secs)."""
    if not earlier.timestamp or not later.timestamp:
        return True
    diff = later.timestamp - earlier.timestamp
    return 0 <= diff <= max_gap_secs


# ── Rule 1: Recon → Initial Access ───────────────────────────────────────────

def recon_to_initial_access(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    Attacker scans a target (PORT_SCAN / HOST_SCAN / SUSPICIOUS_FLAGS),
    then follows up with a brute-force attempt against the same target.
    Represents Lockheed Martin Kill Chain phases 1→3: Recon → Delivery.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    recon_types  = {EventType.PORT_SCAN, EventType.HOST_SCAN, EventType.ARP_SCAN,
                    EventType.SUSPICIOUS_FLAGS}
    attack_types = {EventType.BRUTE_FORCE}

    for src_ip, src_events in by_src.items():
        recon_events  = [e for e in src_events if e.event_type in recon_types]
        attack_events = [e for e in src_events if e.event_type in attack_types]

        if not recon_events or not attack_events:
            continue

        # Correlate: find (scan, brute) pairs on same or related target
        correlated_pairs: list[tuple] = []
        for scan_ev in recon_events:
            for bf_ev in attack_events:
                # Accept if: scan targets same IP as brute force, OR scan was broad
                target_match = (
                    _same_target(scan_ev, bf_ev) or
                    scan_ev.dst_ip is None or
                    scan_ev.event_type == EventType.HOST_SCAN
                )
                if target_match and _time_order(scan_ev, bf_ev):
                    correlated_pairs.append((scan_ev, bf_ev))

        if not correlated_pairs:
            continue

        # Collect unique events across all correlated pairs
        linked_events: list[DetectionEvent] = []
        seen_ids: set[int] = set()
        for s, b in correlated_pairs:
            for e in (s, b):
                if id(e) not in seen_ids:
                    linked_events.append(e)
                    seen_ids.add(id(e))

        targets = {e.dst_ip for e in attack_events if e.dst_ip}
        services = {e.evidence.get("service", "") for e in attack_events}
        confidence = min(0.95, 0.6 + 0.1 * len(correlated_pairs))

        chains.append(_chain(
            name        = f"Targeted Attack: Recon → Brute Force [{src_ip}]",
            description = (
                f"{src_ip} performed network reconnaissance then launched "
                f"brute-force attacks against {len(targets)} target(s) "
                f"({', '.join(filter(None, services))})"
            ),
            events      = linked_events,
            severity    = Severity.CRITICAL if len(correlated_pairs) >= 2 else Severity.HIGH,
            confidence  = confidence,
            analyst_note= (
                f"Scan-then-attack pattern from {src_ip}. "
                f"Investigate whether brute force succeeded — check for subsequent "
                f"credential exposure events or unusual outbound traffic."
            ),
        ))

    return chains


# ── Rule 2: Brute Force + Credential Exposure on Same Target ─────────────────

def brute_credential_chain(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    Brute force against a service on target X, AND plaintext credentials
    observed on the same target or same network. This suggests either a
    successful compromise or parallel credential-harvesting activity.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    for src_ip, src_events in by_src.items():
        bf_events   = _events_of_type(src_events, EventType.BRUTE_FORCE)
        cred_events = _events_of_type(src_events, EventType.CREDENTIAL_EXPOSURE)

        # Also consider credential events from ANY source targeting same host as brute force
        bf_targets = {e.dst_ip for e in bf_events if e.dst_ip}

        # Pull in credential events from any source hitting the same targets
        extra_creds = [
            e for e in events
            if e.event_type == EventType.CREDENTIAL_EXPOSURE
            and e.src_ip != src_ip
            and (e.dst_ip in bf_targets or e.src_ip in bf_targets)
        ]

        all_creds = cred_events + extra_creds

        if not bf_events or not all_creds:
            continue

        linked = list({id(e): e for e in bf_events + all_creds}.values())
        services = {e.evidence.get("service", e.protocol or "") for e in bf_events}

        chains.append(_chain(
            name        = f"Credential Compromise Chain [{src_ip} → {', '.join(bf_targets)}]",
            description = (
                f"Brute force on {', '.join(filter(None, services))} service(s) "
                f"correlated with {len(all_creds)} plaintext credential exposure(s) "
                f"on overlapping targets"
            ),
            events      = linked,
            severity    = Severity.CRITICAL,
            confidence  = min(0.95, 0.7 + 0.05 * len(all_creds)),
            analyst_note= (
                "Brute force + plaintext credentials on same target is a strong "
                "compromise indicator. Check for successful auth events and lateral movement. "
                "Prioritise password resets and session invalidation."
            ),
        ))

    return chains


# ── Rule 3: C2 Channel Detection ─────────────────────────────────────────────

def c2_channel_detection(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    Detects established Command & Control channels:
    - DNS tunneling (data exfil over DNS queries)
    - Combined with high-frequency DNS beaconing to same domain
    - OR ICMP tunneling alongside DNS anomalies

    Multiple C2 indicators from the same source IP = high confidence C2.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    c2_types = {EventType.DNS_TUNNELING, EventType.DNS_ANOMALY, EventType.ICMP_TUNNELING}

    for src_ip, src_events in by_src.items():
        c2_events = [e for e in src_events if e.event_type in c2_types]

        if len(c2_events) < 2:
            continue

        has_tunnel  = any(e.event_type == EventType.DNS_TUNNELING  for e in c2_events)
        has_icmp    = any(e.event_type == EventType.ICMP_TUNNELING  for e in c2_events)
        has_beacon  = any(
            e.event_type == EventType.DNS_ANOMALY and
            e.evidence.get("pattern") == "beaconing"
            for e in c2_events
        )
        has_dga     = any(
            e.event_type == EventType.DNS_ANOMALY and
            "DGA" in e.description.upper()
            for e in c2_events
        )

        indicator_count = sum([has_tunnel, has_icmp, has_beacon, has_dga])
        if indicator_count < 2:
            continue

        confidence = min(0.95, 0.55 + 0.15 * indicator_count)
        indicators = []
        if has_tunnel: indicators.append("DNS tunneling")
        if has_icmp:   indicators.append("ICMP covert channel")
        if has_beacon: indicators.append("DNS beaconing")
        if has_dga:    indicators.append("DGA domain queries")

        chains.append(_chain(
            name        = f"C2 Channel Established [{src_ip}]",
            description = (
                f"Host {src_ip} shows {indicator_count} C2 indicator(s): "
                + ", ".join(indicators)
            ),
            events      = c2_events,
            severity    = Severity.CRITICAL if has_tunnel and has_beacon else Severity.HIGH,
            confidence  = confidence,
            analyst_note= (
                f"Potential malware implant on {src_ip} communicating with C2 infrastructure. "
                "Isolate host, capture memory, and analyse running processes. "
                "Block the identified domains/IPs at DNS and firewall level."
            ),
        ))

    return chains


# ── Rule 4: Covert Exfiltration ───────────────────────────────────────────────

def covert_exfiltration(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    Data exfiltration via covert channels: ICMP tunneling + DNS tunneling
    from the same host strongly suggests active data theft.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    for src_ip, src_events in by_src.items():
        icmp_evs = _events_of_type(src_events, EventType.ICMP_TUNNELING)
        dns_evs  = _events_of_type(src_events, EventType.DNS_TUNNELING)

        if not icmp_evs and not dns_evs:
            continue

        # Need at least one confirmed tunnel (not just anomaly)
        combined = icmp_evs + dns_evs
        if len(combined) < 1:
            continue

        # If both channels are active simultaneously, escalate
        both_active = bool(icmp_evs and dns_evs)

        total_bytes = sum(
            e.evidence.get("total_bytes", 0) for e in icmp_evs
        )

        channels = []
        if icmp_evs: channels.append(f"ICMP ({total_bytes:,} bytes)")
        if dns_evs:  channels.append("DNS")

        chains.append(_chain(
            name        = f"Covert Data Exfiltration [{src_ip}]",
            description = (
                f"Host {src_ip} exfiltrating data via covert channel(s): "
                + ", ".join(channels)
            ),
            events      = combined,
            severity    = Severity.CRITICAL if both_active else Severity.HIGH,
            confidence  = 0.90 if both_active else 0.75,
            analyst_note= (
                "Data is leaving the network via protocol tunneling, bypassing standard "
                "DLP controls. Identify what data may have been exfiltrated by correlating "
                "with filesystem/access logs on the suspected host."
            ),
        ))

    return chains


# ── Rule 5: SMB Lateral Movement ─────────────────────────────────────────────

def lateral_movement_smb(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    External SMB traffic (port 445) combined with credential exposure
    or brute force — hallmarks of worm propagation (WannaCry, EternalBlue)
    or ransomware lateral movement.
    """
    chains: list[AttackChain] = []

    # SMB-to-external events are PROTOCOL_MISUSE with port 445 evidence
    smb_events = [
        e for e in events
        if e.event_type == EventType.PROTOCOL_MISUSE
        and e.dst_port in (445, 139)
        and "EternalBlue" in e.description
    ]

    if not smb_events:
        return chains

    by_src = defaultdict(list)
    for e in smb_events:
        by_src[e.src_ip].append(e)

    for src_ip, src_smb in by_src.items():
        # Find any related brute force or credential events from same subnet
        related = [
            e for e in events
            if e.src_ip and e.src_ip.rsplit(".", 1)[0] == src_ip.rsplit(".", 1)[0]
            and e.event_type in (EventType.BRUTE_FORCE, EventType.CREDENTIAL_EXPOSURE)
        ]

        linked = list({id(e): e for e in src_smb + related}.values())

        chains.append(_chain(
            name        = f"SMB Lateral Movement [{src_ip}]",
            description = (
                f"{src_ip} initiated SMB connections to external IPs "
                + (f"with {len(related)} correlated credential event(s)" if related else
                   "(potential ransomware/EternalBlue propagation)")
            ),
            events      = linked,
            severity    = Severity.CRITICAL,
            confidence  = 0.90 if related else 0.75,
            analyst_note= (
                "External SMB traffic is a critical indicator. Possible scenarios: "
                "EternalBlue exploit, ransomware spreading to external NAS/shares, "
                "or data exfiltration via SMB. Block port 445 outbound immediately."
            ),
        ))

    return chains


# ── Rule 6: Full Kill Chain ───────────────────────────────────────────────────

def full_kill_chain(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    Single attacker IP spanning 3+ distinct kill chain phases.
    This is the highest-confidence indicator of an APT or targeted intrusion.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    from packetiq.correlation.models import KILL_CHAIN_PHASES

    for src_ip, src_events in by_src.items():
        phases = set(mitre_db.kill_chain_phase(e.event_type) for e in src_events)

        # Need at least 3 distinct kill chain phases
        ordered_phases = [p for p in KILL_CHAIN_PHASES if p in phases]
        if len(ordered_phases) < 3:
            continue

        sev_counts: defaultdict = defaultdict(int)
        for e in src_events:
            sev_counts[e.severity.value] += 1

        overall_sev = (
            Severity.CRITICAL if sev_counts["CRITICAL"] > 0
            else Severity.HIGH
        )

        chains.append(_chain(
            name        = f"Full Attack Kill Chain Detected [{src_ip}]",
            description = (
                f"Attacker {src_ip} progressed through {len(ordered_phases)} "
                f"kill chain phases: {' → '.join(ordered_phases)}"
            ),
            events      = src_events,
            severity    = overall_sev,
            confidence  = min(0.98, 0.65 + 0.1 * len(ordered_phases)),
            analyst_note= (
                f"This is a high-confidence APT indicator. {src_ip} shows systematic "
                f"attack progression from {ordered_phases[0]} through to "
                f"{ordered_phases[-1]}. Treat as active intrusion. Initiate IR playbook."
            ),
        ))

    return chains


# ── Rule 6b: Reconnaissance progression (same attacker, multiple recon phases) ─

def reconnaissance_progression(events: list[DetectionEvent]) -> list[AttackChain]:
    """One source performing multiple, distinct reconnaissance actions.

    e.g. an ARP subnet sweep (host discovery) followed by TCP service probing of
    the hosts it found. Two recon phases from one source is a coherent scanning
    campaign even when it never reaches exploitation — exactly what a truncated
    or vantage-limited capture of a pentest looks like.
    """
    recon_types = {EventType.ARP_SCAN, EventType.PORT_SCAN, EventType.HOST_SCAN,
                   EventType.SUSPICIOUS_FLAGS}
    chains: list[AttackChain] = []
    for src_ip, src_events in _events_by_src(events).items():
        recon = [e for e in src_events if e.event_type in recon_types]
        distinct_types = {e.event_type for e in recon}
        if len(recon) < 2 or len(distinct_types) < 2:
            continue
        # Full-kill-chain already covers 3+ *phases*; this focuses on the recon stage.
        type_names = ", ".join(sorted(t.value.replace("_", " ") for t in distinct_types))
        targets = sorted({e.dst_ip for e in recon if e.dst_ip})
        sev = Severity.HIGH if any(e.severity == Severity.HIGH for e in recon) else Severity.MEDIUM
        chains.append(_chain(
            name        = f"Reconnaissance campaign [{src_ip}]",
            description = (
                f"{src_ip} performed multiple reconnaissance actions ({type_names})"
                + (f" against {len(targets)} host(s)" if targets else "")
                + " — systematic host discovery and service enumeration."
            ),
            events      = recon,
            severity    = sev,
            confidence  = 0.85,
            analyst_note= (
                f"{src_ip} is actively mapping the network (discovery → service probing). "
                "This is the reconnaissance stage of an intrusion; identify and isolate the "
                "host, and watch the enumerated services for follow-on exploitation."
            ),
        ))
    return chains


# ── Rule 7: DGA / Malware Domain Cluster ─────────────────────────────────────

def dga_c2_cluster(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    Multiple DGA-like domain queries from the same source IP indicate
    malware performing automated domain generation for C2 resilience.
    One DGA hit is suspicious; multiple confirms the pattern.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    for src_ip, src_events in by_src.items():
        dga_events = [
            e for e in src_events
            if e.event_type == EventType.DNS_ANOMALY
            and "DGA" in e.description.upper()
        ]

        if len(dga_events) < 2:
            continue

        domains = [e.evidence.get("domain", "") for e in dga_events]
        chains.append(_chain(
            name        = f"DGA Malware Domain Cluster [{src_ip}]",
            description = (
                f"{src_ip} queried {len(dga_events)} algorithmically generated "
                f"domains — characteristic of malware C2 with domain rotation"
            ),
            events      = dga_events,
            severity    = Severity.HIGH,
            confidence  = min(0.92, 0.65 + 0.1 * len(dga_events)),
            analyst_note= (
                "DGA domains are used by malware families (Conficker, Mirai, Dridex) to "
                "evade takedown. Block all detected domains at DNS level and initiate "
                "endpoint investigation on the querying host."
            ),
        ))

    return chains


# ── Rule 8: Credential Spray (Brute Force against many targets) ───────────────

def credential_spray(events: list[DetectionEvent]) -> list[AttackChain]:
    """
    A single source bruting the same port/service across many different targets
    (credential stuffing / spray) rather than targeting one host deeply.
    Distinct from rule 1 (recon→attack) — here the attacker goes wide, not deep.
    """
    chains: list[AttackChain] = []
    by_src = _events_by_src(events)

    for src_ip, src_events in by_src.items():
        bf_events = _events_of_type(src_events, EventType.BRUTE_FORCE)
        if len(bf_events) < 3:
            continue

        # Group by destination port (service)
        by_port: dict[Optional[int], list] = defaultdict(list)
        for e in bf_events:
            by_port[e.dst_port].append(e)

        for dport, port_events in by_port.items():
            targets = {e.dst_ip for e in port_events if e.dst_ip}
            if len(targets) < 3:
                continue

            from packetiq.utils.helpers import get_service_name
            service = get_service_name(dport) if dport else "UNKNOWN"

            chains.append(_chain(
                name        = f"Credential Spray — {service}:{dport} [{src_ip}]",
                description = (
                    f"{src_ip} launched credential spray against {len(targets)} "
                    f"hosts on {service} port {dport}"
                ),
                events      = port_events,
                severity    = Severity.CRITICAL if len(targets) >= 10 else Severity.HIGH,
                confidence  = min(0.95, 0.6 + 0.05 * len(targets)),
                analyst_note= (
                    "Credential spray targets many accounts/hosts with few attempts each "
                    "to evade lockout policies. Check for successful authentications across "
                    "all target systems. Review account lockout thresholds."
                ),
            ))

    return chains
