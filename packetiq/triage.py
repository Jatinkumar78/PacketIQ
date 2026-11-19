"""
Triage layer — false-positive reduction and per-finding explainability.

This module does two things, both central to PacketIQ being trustworthy in the
real world:

1. **Explainability.** For every detection it produces a plain-English account of
   *what* was seen, *why* it was flagged, the concrete evidence behind it, the
   MITRE technique, and a recommended response. Nothing here is invented — the
   explanation is generated deterministically from the detector's own evidence.

2. **False-positive reduction.** Each finding is graded for *precision*
   (Confirmed / High / Probable / Tentative) based on whether it rests on
   observed fact (e.g. a real OSINT feed hit, cleartext credentials) or on a
   heuristic. An optional, user-controlled allow-list and confidence floor
   (configured in packetiq.toml) suppress known-good noise — conservatively, so
   genuine attacks are never silently dropped (defaults change nothing).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from packetiq import config
from packetiq.correlation.mitre import kill_chain_phase, techniques_for_event
from packetiq.detection.models import EventType

# ── Plain-English rationale per finding type ─────────────────────────────────
# what: one line on the behaviour · why: why it is suspicious · action: response
_RATIONALE: dict = {
    EventType.BRUTE_FORCE: {
        "what": "Many authentication attempts to a service in a short window.",
        "why": "A high rate of login attempts from one source is the signature of password guessing / credential stuffing.",
        "action": "Verify whether the source is authorised; rate-limit or block it; enforce MFA and check for any successful login after the burst.",
    },
    EventType.PORT_SCAN: {
        "what": "One source touched many ports on a single host.",
        "why": "Sweeping a host's ports is classic service-discovery reconnaissance that precedes targeted exploitation.",
        "action": "Confirm the source isn't an approved scanner (vuln scan/asset mgmt); if not, block it and review what services were exposed.",
    },
    EventType.HOST_SCAN: {
        "what": "One source probed the same port across many hosts.",
        "why": "Horizontal sweeps map which hosts run a given service — reconnaissance or worm-style spread.",
        "action": "Validate the source; if unexpected, isolate it and check the targeted service for exposure.",
    },
    EventType.ARP_SCAN: {
        "what": "One host sent ARP 'who-has' requests for many addresses across the local subnet.",
        "why": "Sweeping the subnet with ARP is layer-2 host discovery — how nmap/arp-scan enumerate live hosts before targeting them. It leaves no IP-layer trace.",
        "action": "Confirm the source isn't an approved asset-management/vuln scanner; if not, locate the device on the switch port and isolate it.",
    },
    EventType.ARP_SPOOFING: {
        "what": "A single IP address was claimed by more than one MAC address on the wire.",
        "why": "An IP→MAC conflict is the signature of ARP cache poisoning — an on-path attacker redirecting a victim's traffic to intercept or alter it (man-in-the-middle).",
        "action": "Identify both MACs; if one is unauthorised, isolate it. Consider dynamic ARP inspection (DAI) and port security on the switch. (Rule out legitimate HA/VRRP failover first.)",
    },
    EventType.DOS_FLOOD: {
        "what": "A large number of unanswered TCP SYNs was aimed at a single host and port.",
        "why": "Concentrating half-open connections on one endpoint exhausts its connection table — the signature of a SYN flood / denial-of-service, distinct from a port scan (which spreads across ports/hosts).",
        "action": "Rate-limit the source and enable SYN cookies upstream; confirm the target's availability and rule out a stuck client repeatedly retrying a dead service.",
    },
    EventType.DNS_ANOMALY: {
        "what": "Unusual DNS behaviour (high-entropy or excessive queries).",
        "why": "Algorithmically generated domains and query floods are associated with malware C2 and data staging.",
        "action": "Review the domains/resolver; if algorithmic, treat the querying host as potentially infected.",
    },
    EventType.DNS_TUNNELING: {
        "what": "Abnormally long/structured DNS labels carrying data.",
        "why": "Encoding payloads inside DNS queries is a covert channel used to exfiltrate data or tunnel C2 past firewalls.",
        "action": "Inspect the resolver and querying host; block the domain; treat as possible exfiltration.",
    },
    EventType.CREDENTIAL_EXPOSURE: {
        "what": "Credentials observed in cleartext on the wire.",
        "why": "Plaintext credentials (HTTP Basic, FTP, Telnet, etc.) can be trivially captured and reused by any on-path attacker.",
        "action": "Rotate the exposed credentials immediately and move the service to an encrypted protocol (HTTPS/SFTP/SSH).",
    },
    EventType.PROTOCOL_MISUSE: {
        "what": "A protocol used in an unexpected or non-standard way.",
        "why": "Protocol misuse often indicates evasion, tunnelling, or a service running on a non-standard port.",
        "action": "Confirm the service is legitimate; investigate the endpoints involved.",
    },
    EventType.ICMP_TUNNELING: {
        "what": "Large or sustained data volume carried over ICMP.",
        "why": "ICMP normally carries tiny control messages; bulk data in ICMP is a covert exfiltration/C2 channel.",
        "action": "Block/limit ICMP payloads at the egress and investigate the host generating them.",
    },
    EventType.SUSPICIOUS_FLAGS: {
        "what": "TCP packets with abnormal flag combinations.",
        "why": "Illegal flag sets (NULL/XMAS/FIN) are used to fingerprint hosts and evade simple filters during scanning.",
        "action": "Correlate with other scan activity from the same source; block if confirmed.",
    },
    EventType.C2_BEACON: {
        "what": "Regular, periodic connections to an external host.",
        "why": "Beaconing at a fixed cadence (even when jittered) is how implants check in with command-and-control infrastructure.",
        "action": "Treat the internal host as potentially compromised; block the destination and triage the endpoint.",
    },
    EventType.JA3_ANOMALY: {
        "what": "A TLS client fingerprint (JA3) matching a known-bad list.",
        "why": "Malware families have distinctive TLS handshakes; a JA3 match to abuse.ch's SSLBL ties the flow to known malicious tooling.",
        "action": "Investigate the internal host's TLS client; block the destination; hunt for the associated malware.",
    },
    EventType.IOC_MATCH: {
        "what": "An observed IP/domain matched a real threat-intel feed.",
        "why": "The indicator appears on a current OSINT blocklist (abuse.ch / Spamhaus / Tor), tying this traffic to known-bad infrastructure.",
        "action": "Block the indicator and investigate every host that communicated with it.",
    },
    EventType.MALICIOUS_FILE: {
        "what": "A carved file's hash matched a known-malware database.",
        "why": "The SHA-256 is listed in MalwareBazaar — the exact sample is confirmed malicious, not merely suspicious.",
        "action": "Quarantine the file, isolate the receiving host, and begin incident response.",
    },
    EventType.HTTP_ATTACK: {
        "what": "An HTTP request containing an exploitation pattern.",
        "why": "Payloads such as SQLi, XSS, path traversal or Log4Shell in the URI/headers indicate active exploitation attempts.",
        "action": "Confirm whether the target responded as exploited; patch/virtual-patch the app; block the source.",
    },
    EventType.TLS_ANOMALY: {
        "what": "A TLS certificate with a risky property.",
        "why": "Self-signed, expired or abnormally long-lived certs are common on C2 and interception infrastructure.",
        "action": "Verify the endpoint's legitimacy; treat unknown self-signed external certs as suspicious.",
    },
    EventType.KERBEROS_USER_ENUM: {
        "what": "One host asked a domain controller about many account names at once.",
        "why": "A KDC answers an unknown principal differently from a real one, so an attacker can sift valid accounts out of a wordlist without ever guessing a password. The accounts named in the evidence were confirmed by the KDC itself.",
        "action": "Treat every confirmed account as targeted. Check whether any of them later authenticated from this source, and review the DC's Kerberos logging for event 4768 from this address.",
    },
    EventType.KERBEROS_BRUTE_FORCE: {
        "what": "Pre-authentication failed for many different accounts from one source.",
        "why": "One password tried across many accounts stays under per-account lockout thresholds, which is precisely why spraying is preferred to brute force. Every account named exists.",
        "action": "Force a reset on any account that subsequently succeeded, and check for a single weak password shared across the named accounts.",
    },
    EventType.KERBEROS_ROASTING: {
        "what": "Ticket material was obtained that can be cracked away from the network.",
        "why": "An AS-REP for an account without pre-authentication, or a service ticket encrypted with RC4, hands over a hash the attacker can attack offline at their own pace with no further traffic and no failed logons.",
        "action": "Rotate the credentials of every account and service principal named. Enable pre-authentication, and set a long random password on service accounts so an offline crack does not finish.",
    },
    EventType.SUSPICIOUS_FILE_TRANSFER: {
        "what": "A file moved over a cleartext protocol, usually FTP, into a web-served directory.",
        "why": "An upload to a directory like /var/www/html is how a web shell or reverse shell gets planted where the server will execute it. The filename and the directory are both read from the FTP control channel in clear text.",
        "action": "Retrieve the named file from the target, hash it, and determine what it does. If it is a web or reverse shell, treat the host as compromised from the moment of upload.",
    },
    EventType.REVERSE_SHELL: {
        "what": "An interactive shell reconstructed from a cleartext TCP stream.",
        "why": "When a reverse or bind shell runs over an unencrypted connection, every command the attacker typed and every line of output is readable on the wire. This is the fullest possible account of what was done on the host: the commands, the privilege escalation, and any tool pulled from the internet.",
        "action": "Treat every command in the transcript as having run. Rotate any credential used, remove any tool or account the attacker added, and investigate anything they downloaded, especially a rootkit or persistence tool.",
    },
    EventType.DCERPC_SUSPECT_BIND: {
        "what": "A bind to a remote-procedure interface that is a known attack tool.",
        "why": "The interface UUID in a DCERPC bind says which service was asked for, in clear text even when the call is encrypted. svcctl creates a service to run a payload (PsExec); atsvc schedules a task; drsuapi replicates password hashes out of the domain (DCSync); spoolss is PrintNightmare. A bind to one of these from a host that is not its normal client is the signal.",
        "action": "Match the client against who should be making this call. For svcctl or atsvc, check the target's service and scheduled-task logs; for drsuapi, treat it as a full domain compromise and begin credential rotation from krbtgt down.",
    },
    EventType.DCERPC_RECON: {
        "what": "RPC endpoint-mapper probing, or binds the server refused.",
        "why": "Asking the endpoint mapper what interfaces are available, or having binds rejected, is how an attacker enumerates a host's RPC surface before choosing a service to abuse. On its own it is reconnaissance, not execution.",
        "action": "Note the source as scanning the RPC surface and watch for a follow-up bind that succeeds.",
    },
    EventType.LDAP_ENUMERATION: {
        "what": "A client read the directory: which domain, which objects, which attributes.",
        "why": "Every intrusion into Active Directory starts by asking what is there, and LDAP is how you ask. A RootDSE query works before you know anything about the domain, which is why it comes first. A search asking for servicePrincipalName is looking for kerberoastable accounts; one asking for userAccountControl is usually looking for accounts with pre-authentication disabled.",
        "action": "Compare the filters in the evidence against what this client has any business asking. Directory reads are also normal administration, so the question is who asked, not whether LDAP was used.",
    },
    EventType.SMB_LATERAL_MOVEMENT: {
        "what": "A connection to an administrative share, or to a named pipe behind one.",
        "why": "ADMIN$, C$ and IPC$ are not browsed by users. Writing to ADMIN$ and then opening the svcctl pipe is how PsExec and its descendants run code on a remote host; atsvc is the scheduled-task equivalent. The share connection and the pipe together are remote code execution.",
        "action": "Treat the destination as compromised. Check Windows event 7045 for a service created in this window, and the scheduled-task log, then look for the file that was written.",
    },
    EventType.SMB_FILE_ACCESS: {
        "what": "Files opened, read or written over SMB.",
        "why": "A write to an administrative share is usually a payload being staged before execution. A large read from a user share may be the data leaving. The filenames are in the evidence because the name is often the whole answer.",
        "action": "Retrieve the named files from the destination and hash them. For reads, work out what the data was and whether it should have left.",
    },
    EventType.WINRM_EXECUTION: {
        "what": "A remote-management session: commands run on the target over WS-Management.",
        "why": "WinRM is how PowerShell Remoting and tools like Evil-WinRM get an interactive shell on a Windows host. The command text is inside SPNEGO session encryption and cannot be recovered from the capture, but the account, the client software and the volume are in clear text. A client that is not Microsoft's own WinRM client did not get there by an administrator's normal workflow.",
        "action": "Treat the target as compromised from the first request. Pull PowerShell operational and WinRM logs on the host for this window, which do hold the command text, and disable the account named until it is cleared.",
    },
    EventType.NTLM_AUTHENTICATION: {
        "what": "An account, domain and workstation name sent in an NTLM handshake.",
        "why": "The NTLM type 3 message names the account in clear text even when the session payload is encrypted. Over plain HTTP the challenge/response travels with it, which is material for an offline crack or a relay. The workstation name is whatever the client chose to send, so it describes the client rather than proving its identity.",
        "action": "Confirm whether this account and workstation pairing is expected. If the workstation name is unfamiliar, treat the account as compromised rather than the machine as unknown.",
    },
    EventType.KERBEROS_ANOMALY: {
        "what": "Kerberos used in a way current Windows clients do not.",
        "why": "Asking only for RC4 when AES is standard is a deliberate downgrade: RC4 ticket material is far cheaper to crack. Genuine domain members negotiate AES.",
        "action": "Identify the client. If it is not a legacy system that genuinely needs RC4, treat the request as tooling rather than a domain member.",
    },
}

# Findings that rest on observed fact (a feed hit / cleartext data), not a
# heuristic threshold — these are graded "Confirmed" regardless of a CV/score.
_EVIDENCE_BACKED = {
    EventType.IOC_MATCH, EventType.MALICIOUS_FILE,
    EventType.CREDENTIAL_EXPOSURE, EventType.JA3_ANOMALY,
}

_PRECISION_STYLE = {
    "Confirmed": "ok", "High": "ok", "Probable": "warn", "Tentative": "muted",
}


def precision(event) -> str:
    """Grade how much to trust a finding (independent of its severity)."""
    if event.event_type in _EVIDENCE_BACKED:
        return "Confirmed"
    conf = float(getattr(event, "confidence", 1.0) or 0.0)
    if conf >= 0.85:
        return "High"
    if conf >= 0.6:
        return "Probable"
    return "Tentative"


def precision_style(label: str) -> str:
    return _PRECISION_STYLE.get(label, "muted")


def _evidence_points(evidence: dict) -> list:
    """Turn the evidence dict into readable 'Label: value' strings."""
    out = []
    for k, v in (evidence or {}).items():
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in list(v)[:8])
        label = k.replace("_", " ").capitalize()
        out.append(f"{label}: {v}")
    return out[:12]


def explain(event) -> dict:
    """Deterministic, grounded explanation of a single finding."""
    et = event.event_type
    r = _RATIONALE.get(et, {"what": event.description, "why": "Flagged by a PacketIQ detector.",
                            "action": "Investigate the endpoints involved."})
    techs = techniques_for_event(et)
    label = precision(event)
    return {
        "what": r["what"],
        "why": r["why"],
        "recommendation": r["action"],
        "evidence_points": _evidence_points(getattr(event, "evidence", {})),
        "mitre": [{"id": t.technique_id, "name": t.technique_name,
                   "tactic": t.tactic_name} for t in techs],
        "kill_chain_phase": kill_chain_phase(et),
        "precision": label,
        "precision_style": precision_style(label),
        "confidence_pct": round(float(getattr(event, "confidence", 1.0) or 0.0) * 100),
    }


# ── Allow-list / suppression (user-controlled false-positive reduction) ──────

@dataclass
class Allowlist:
    ips: set = field(default_factory=set)
    cidrs: list = field(default_factory=list)        # list[ip_network]
    domains: set = field(default_factory=set)
    ja3: set = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.ips or self.cidrs or self.domains or self.ja3)


def load_allowlist() -> Allowlist:
    """Read the optional [allowlist] section from packetiq.toml (all optional)."""
    al = Allowlist()
    al.ips = {str(x).strip() for x in config.get("allowlist", "ips", []) if str(x).strip()}
    for c in config.get("allowlist", "cidrs", []) or []:
        try:
            al.cidrs.append(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            continue
    al.domains = {str(x).strip().lower().rstrip(".") for x in config.get("allowlist", "domains", []) if str(x).strip()}
    al.ja3 = {str(x).strip().lower() for x in config.get("allowlist", "ja3", []) if str(x).strip()}
    return al


def _ip_in_cidrs(ip: str, cidrs: list) -> bool:
    if not ip or not cidrs:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in cidrs)


def is_allowlisted(event, al: Allowlist):
    """Return (suppress: bool, reason: str) for a finding against the allow-list."""
    if not al:
        return False, ""
    for ip in (event.src_ip, event.dst_ip):
        if ip and ip in al.ips:
            return True, f"{ip} is on the allow-list"
        if _ip_in_cidrs(ip, al.cidrs):
            return True, f"{ip} is within an allow-listed network"
    ev = getattr(event, "evidence", {}) or {}
    for key in ("domain", "qname", "indicator", "host"):
        d = str(ev.get(key, "")).lower().rstrip(".")
        if d and d in al.domains:
            return True, f"domain {d} is on the allow-list"
    ja3 = str(ev.get("ja3", "")).lower()
    if ja3 and ja3 in al.ja3:
        return True, "JA3 fingerprint is on the allow-list"
    return False, ""


def apply_suppression(events: list, min_confidence: float | None = None):
    """
    Return (kept, suppressed) where `suppressed` is a list of (event, reason).

    Conservative by design: with the default config (empty allow-list,
    min_confidence = 0) nothing is suppressed, so detection recall is unchanged.
    """
    al = load_allowlist()
    floor = min_confidence if min_confidence is not None else float(config.get("triage", "min_confidence", 0.0) or 0.0)
    kept, suppressed = [], []
    for e in events:
        hit, reason = is_allowlisted(e, al)
        if hit:
            suppressed.append((e, reason))
            continue
        if float(getattr(e, "confidence", 1.0) or 0.0) < floor:
            suppressed.append((e, f"below confidence floor ({floor:.0%})"))
            continue
        kept.append(e)
    return kept, suppressed
