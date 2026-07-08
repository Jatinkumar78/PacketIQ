"""
SIGMA Rule Generator.

Automatically generates deployable SIGMA detection rules from PacketIQ
analysis results. Each detected threat pattern produces one or more
SIGMA rules ready for direct import into SIEM platforms (Splunk, Elastic,
QRadar, Microsoft Sentinel).

Output: YAML-formatted SIGMA rules with full ATT&CK tagging.
Reference: https://github.com/SigmaHQ/sigma
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent, EventType, Severity


@dataclass
class SigmaRule:
    title:       str
    rule_id:     str
    status:      str
    description: str
    level:       str        # informational / low / medium / high / critical
    tags:        list[str]
    logsource:   dict
    detection:   dict
    falsepositives: list[str]
    raw_yaml:    str        # pre-rendered YAML string


_LEVEL_MAP = {
    Severity.CRITICAL: "critical",
    Severity.HIGH:     "high",
    Severity.MEDIUM:   "medium",
    Severity.LOW:      "low",
}


class SigmaGenerator:

    def generate(
        self,
        events: list[DetectionEvent],
        chains: list[AttackChain],
    ) -> list[SigmaRule]:
        """Generate SIGMA rules for all detection findings."""
        rules: list[SigmaRule] = []
        seen_keys: set[str] = set()

        for ev in events:
            key = f"{ev.event_type}:{ev.src_ip}:{ev.dst_ip}:{ev.dst_port}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            rule = self._rule_for_event(ev)
            if rule:
                rules.append(rule)

        for chain in chains:
            rule = self._rule_for_chain(chain)
            if rule:
                rules.append(rule)

        return rules

    # ── Per-event type templates ──────────────────────────────────────────

    def _rule_for_event(self, ev: DetectionEvent) -> Optional[SigmaRule]:
        dispatch = {
            EventType.PORT_SCAN:           self._port_scan,
            EventType.HOST_SCAN:           self._host_scan,
            EventType.BRUTE_FORCE:         self._brute_force,
            EventType.C2_BEACON:           self._c2_beacon,
            EventType.JA3_ANOMALY:         self._ja3_anomaly,
            EventType.DNS_ANOMALY:         self._dns_anomaly,
            EventType.DNS_TUNNELING:       self._dns_tunneling,
            EventType.CREDENTIAL_EXPOSURE: self._credential_exposure,
            EventType.ICMP_TUNNELING:      self._icmp_tunneling,
            EventType.PROTOCOL_MISUSE:     self._protocol_misuse,
            EventType.SUSPICIOUS_FLAGS:    self._suspicious_flags,
        }
        fn = dispatch.get(ev.event_type)
        return fn(ev) if fn else None

    # ── Rule builders ─────────────────────────────────────────────────────

    def _port_scan(self, ev: DetectionEvent) -> SigmaRule:
        ports = ev.evidence.get("ports_probed", ev.evidence.get("distinct_ports", "?"))
        return self._net_rule(
            title       = f"Port Scan from {ev.src_ip}",
            description = (
                f"Port scanning from {ev.src_ip} — {ports} distinct ports probed. "
                "Apply a count(dst_port) by src_ip > 15 within 60s aggregation in your SIEM."
            ),
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.reconnaissance", "attack.t1046"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
    condition: selection""",
            falsepositives = ["Legitimate network scanners", "IT asset discovery tools", "Security auditing"],
        )

    def _host_scan(self, ev: DetectionEvent) -> SigmaRule:
        return self._net_rule(
            title       = f"Host Scan (Horizontal) from {ev.src_ip}",
            description = (
                f"Same-port probe across multiple hosts from {ev.src_ip}, indicative of host discovery. "
                "Apply a count(dst_ip) by src_ip > 10 within 120s aggregation in your SIEM."
            ),
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.reconnaissance", "attack.t1018"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dst_port: {ev.dst_port or 0}
    condition: selection""",
            falsepositives = ["Network monitoring", "Load balancer health checks"],
        )

    def _brute_force(self, ev: DetectionEvent) -> SigmaRule:
        svc = ev.evidence.get("service", ev.protocol or "service")
        return self._auth_rule(
            title       = f"Brute Force Attack on {svc} from {ev.src_ip}",
            description = (
                f"Brute-force {svc} login attempts from {ev.src_ip} — "
                f"{ev.evidence.get('total_syns', '?')} attempts detected. "
                "Apply a count() by src_ip > 6 within 60s aggregation in your SIEM."
            ),
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.credential_access", "attack.t1110", "attack.t1110.001"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dst_port: {ev.dst_port or 22}
        event_type: 'authentication_failure'
    condition: selection""",
            falsepositives = ["Misconfigured automation", "Password reset loops"],
        )

    def _c2_beacon(self, ev: DetectionEvent) -> SigmaRule:
        interval = ev.evidence.get("mean_interval_secs", 60)
        jitter   = ev.evidence.get("jitter_pct", 0)
        return self._net_rule(
            title       = f"C2 Beacon Traffic — {ev.src_ip} to {ev.dst_ip}:{ev.dst_port}",
            description = (
                f"Highly regular outbound connection from {ev.src_ip} to "
                f"{ev.dst_ip}:{ev.dst_port} every ~{interval:.0f}s (±{jitter}% jitter). "
                "Consistent with automated C2 beaconing; correlate repeated connections in your SIEM."
            ),
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.command_and_control", "attack.t1071", "attack.t1071.001", "attack.t1132"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dst_ip: '{ev.dst_ip or "*"}'
        dst_port: {ev.dst_port or 443}
    condition: selection""",
            falsepositives = ["Heartbeat / keepalive traffic", "NTP synchronization", "Update checks"],
        )

    def _ja3_anomaly(self, ev: DetectionEvent) -> SigmaRule:
        malware  = ev.evidence.get("malware", "Unknown malware")
        ja3_hash = ev.evidence.get("ja3_hash", "")
        return self._net_rule(
            title       = f"Malicious TLS Fingerprint ({malware}) from {ev.src_ip}",
            description = f"TLS ClientHello JA3 hash {ja3_hash} matches known {malware} tooling.",
            level       = "critical",
            tags        = ["attack.command_and_control", "attack.t1573", "attack.t1573.002"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        tls.ja3: '{ja3_hash}'
    condition: selection""",
            falsepositives = ["Custom TLS libraries that coincidentally match this hash"],
        )

    def _dns_anomaly(self, ev: DetectionEvent) -> SigmaRule:
        domain = ev.evidence.get("domain", ev.dst_ip or "")
        return self._dns_rule(
            title       = f"Suspicious DNS Query from {ev.src_ip}",
            description = f"High-entropy or DGA-pattern domain queried: {domain}",
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.command_and_control", "attack.t1071.004"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dns.question.name|contains: '{domain[:40]}'
    condition: selection""",
            falsepositives = ["CDN domains", "Tracking pixels", "DNSSEC records"],
        )

    def _dns_tunneling(self, ev: DetectionEvent) -> SigmaRule:
        return self._dns_rule(
            title       = f"DNS Tunneling — {ev.src_ip}",
            description = f"Excessively long DNS queries from {ev.src_ip}, consistent with data exfiltration via DNS.",
            level       = "high",
            tags        = ["attack.exfiltration", "attack.t1048", "attack.t1071.004"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dns.question.name|re: '.{{50,}}'
    condition: selection""",
            falsepositives = ["Legitimate long domain names", "DNSSEC/DANE validation"],
        )

    def _credential_exposure(self, ev: DetectionEvent) -> SigmaRule:
        cred_type = ev.evidence.get("protocol", ev.protocol or "credential")
        return self._net_rule(
            title       = f"Cleartext Credentials ({cred_type}) from {ev.src_ip}",
            description = f"Credential material detected in plaintext {ev.protocol} traffic from {ev.src_ip}.",
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.credential_access", "attack.t1552", "attack.t1552.001"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dst_port: {ev.dst_port or 80}
        protocol: '{(ev.protocol or "HTTP").lower()}'
    filter:
        dst_ip|cidr: '10.0.0.0/8'
    condition: selection and not filter""",
            falsepositives = ["Internal test systems", "Legacy applications without TLS"],
        )

    def _icmp_tunneling(self, ev: DetectionEvent) -> SigmaRule:
        return self._net_rule(
            title       = f"ICMP Tunneling from {ev.src_ip}",
            description = f"High-volume ICMP data flow from {ev.src_ip} — likely covert channel.",
            level       = "high",
            tags        = ["attack.exfiltration", "attack.t1048.003", "attack.t1095"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        protocol: 'ICMP'
    condition: selection""",
            falsepositives = ["Network diagnostic tools", "Ping sweeps"],
        )

    def _protocol_misuse(self, ev: DetectionEvent) -> SigmaRule:
        return self._net_rule(
            title       = f"Protocol Misuse — {ev.src_ip} → {ev.dst_ip}:{ev.dst_port}",
            description = ev.description,
            level       = _LEVEL_MAP[ev.severity],
            tags        = ["attack.lateral_movement", "attack.t1021", "attack.defense_evasion", "attack.t1036"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        dst_port: {ev.dst_port or 445}
    filter:
        dst_ip|cidr: '10.0.0.0/8'
    condition: selection and not filter""",
            falsepositives = ["IT administrative access", "Monitoring tools"],
        )

    def _suspicious_flags(self, ev: DetectionEvent) -> SigmaRule:
        scan_type = ev.evidence.get("scan_type", "XMAS")
        flags     = ev.evidence.get("tcp_flags", scan_type)
        return self._net_rule(
            title       = f"Suspicious TCP Flags ({scan_type}) from {ev.src_ip}",
            description = f"{scan_type} scan detected from {ev.src_ip} (flags: {flags}).",
            level       = "high",
            tags        = ["attack.reconnaissance", "attack.t1046", "attack.defense_evasion"],
            detection_yaml = f"""\
    selection:
        src_ip: '{ev.src_ip}'
        tcp.flags: '{flags}'
    condition: selection""",
            falsepositives = ["Network testing tools", "Buggy TCP stacks"],
        )

    def _rule_for_chain(self, chain: AttackChain) -> SigmaRule:
        technique_tags = [
            f"attack.{t.technique_id.lower()}"
            for t in chain.mitre_techniques[:5]
        ]
        title = f"Attack Chain — {chain.name}"
        attacker = next(iter(sorted(chain.attacker_ips)), "*")
        return self._net_rule(
            title       = title,
            description = (
                f"{chain.description} — Attacker: {attacker}. Confidence: {chain.confidence:.0%}. "
                f"Correlate {len(chain.events)}+ distinct event types from this source in your SIEM."
            ),
            level       = _LEVEL_MAP[chain.severity],
            tags        = ["attack.lateral_movement", *technique_tags],
            detection_yaml = f"""\
    selection:
        src_ip: '{attacker}'
    condition: selection""",
            falsepositives = ["Penetration testing", "Red team exercises"],
        )

    # ── YAML scaffold helpers ─────────────────────────────────────────────

    def _net_rule(self, title, description, level, tags, detection_yaml, falsepositives) -> SigmaRule:
        return self._build(title, description, level, tags,
                           {"category": "network_connection"}, detection_yaml, falsepositives)

    def _auth_rule(self, title, description, level, tags, detection_yaml, falsepositives) -> SigmaRule:
        return self._build(title, description, level, tags,
                           {"category": "authentication"}, detection_yaml, falsepositives)

    def _dns_rule(self, title, description, level, tags, detection_yaml, falsepositives) -> SigmaRule:
        return self._build(title, description, level, tags,
                           {"category": "dns"}, detection_yaml, falsepositives)

    def _build(self, title, description, level, tags, logsource, detection_yaml, falsepositives) -> SigmaRule:
        rule_id  = str(uuid.uuid4())
        tag_list = "\n".join(f"    - {t}" for t in tags)
        fp_list  = "\n".join(f"    - {f}" for f in falsepositives)
        ls_lines = "\n".join(f"    {k}: {v}" for k, v in logsource.items())
        today    = datetime.now().strftime("%Y/%m/%d")
        # Quote the title — names can contain ':' (e.g. "Attack Chain: ...") or
        # other YAML-significant characters that would otherwise break parsing.
        title_yaml = '"' + title.replace("\\", "\\\\").replace('"', '\\"') + '"'

        yaml = f"""\
title: {title_yaml}
id: {rule_id}
status: experimental
description: >
    {description}
    Auto-generated by PacketIQ.
author: PacketIQ
date: {today}
logsource:
{ls_lines}
detection:
{detection_yaml}
falsepositives:
{fp_list}
level: {level}
tags:
{tag_list}
"""
        return SigmaRule(
            title          = title,
            rule_id        = rule_id,
            status         = "experimental",
            description    = description,
            level          = level,
            tags           = tags,
            logsource      = logsource,
            detection      = {},
            falsepositives = falsepositives,
            raw_yaml       = yaml,
        )
