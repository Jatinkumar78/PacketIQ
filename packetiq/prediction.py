"""
Threat Prediction — forward-looking attack forecasting from a capture.

Given the extracted flows/services and the detections already raised, this module
forecasts the attacks a capture is *most exposed to next*. Two grounded sources,
never invented:

1. **Exposed attack surface** — the services actually observed on the wire
   (open/responding where we can tell) mapped to the concrete attacks that target
   them (e.g. SMB → EternalBlue / ransomware lateral movement; FTP/Telnet →
   credential sniffing). Higher likelihood when a scan was seen probing them.

2. **Behavioural trajectory** — where the *detected* activity typically leads in
   the kill chain (e.g. a port scan → targeted exploitation of what it found; an
   ARP sweep → lateral movement / MITM; a C2 beacon → data exfiltration).

Every prediction names the exact evidence it rests on. This is a forecast of
*possible* attacks given what is exposed and observed — not a claim that an attack
occurred, and not a probability of malice. It complements (never replaces) the
evidence-backed detections.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from packetiq.detection.models import EventType
from packetiq.utils.helpers import get_service_name

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_LIK_RANK = {"High": 0, "Medium": 1, "Low": 2}


@dataclass
class ThreatPrediction:
    """A forecast of an attack the capture is exposed to (not a confirmed event)."""
    attack:        str
    category:      str            # kill-chain-ish grouping
    likelihood:    str            # High / Medium / Low
    severity:      str            # potential impact if it occurred
    rationale:     str            # why — plain English, grounded in evidence
    recommendation: str
    evidence:      list = field(default_factory=list)   # concrete observed facts
    mitre:         list = field(default_factory=list)    # ["T1210 Exploitation of Remote Services", ...]
    affected:      list = field(default_factory=list)    # host(s)/service(s)

    def sort_key(self):
        return (_SEV_RANK.get(self.severity, 9), _LIK_RANK.get(self.likelihood, 9))


# ── Service → attacks it exposes ────────────────────────────────────────────────
# Each entry: attack, category, base-severity, mitre[], rationale, recommendation.
# Keyed by the service name produced by helpers.get_service_name().
_SERVICE_THREATS: dict = {
    "FTP": ("Credential theft / brute force on FTP", "Credential Access", "HIGH",
            ["T1110 Brute Force", "T1040 Network Sniffing"],
            "FTP transmits credentials in cleartext and is a common brute-force and anonymous-access target.",
            "Move to FTPS/SFTP, disable anonymous login, and enforce lockout on repeated failures."),
    "TELNET": ("Credential sniffing / remote shell abuse on Telnet", "Credential Access", "HIGH",
               ["T1040 Network Sniffing", "T1110 Brute Force"],
               "Telnet carries credentials and shell traffic in cleartext — trivially captured by any on-path attacker.",
               "Replace Telnet with SSH and block port 23 at the perimeter."),
    "SMB": ("SMB exploitation / ransomware lateral movement", "Lateral Movement", "HIGH",
            ["T1210 Exploitation of Remote Services", "T1021.002 SMB/Windows Admin Shares", "T1570 Lateral Tool Transfer"],
            "Exposed SMB is the classic vector for EternalBlue/SMBGhost, NTLM relay and ransomware spread across a subnet.",
            "Patch MS17-010/SMBGhost, disable SMBv1, require SMB signing, and restrict 445 to management hosts."),
    "NetBIOS-SSN": ("NetBIOS/SMB relay & enumeration", "Lateral Movement", "HIGH",
                    ["T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay", "T1087 Account Discovery"],
                    "Legacy NetBIOS session service enables name-poisoning relay attacks and host/share enumeration.",
                    "Disable NetBIOS over TCP/IP and LLMNR; enforce SMB signing."),
    "MSRPC": ("MSRPC/DCOM abuse & remote code execution", "Execution", "HIGH",
              ["T1210 Exploitation of Remote Services", "T1047 Windows Management Instrumentation"],
              "Exposed Windows RPC endpoints are used for PetitPotam/PrintNightmare-class coercion and remote execution.",
              "Restrict RPC to trusted management ranges and keep Windows fully patched."),
    "RDP": ("RDP brute force / BlueKeep exploitation", "Lateral Movement", "HIGH",
            ["T1021.001 Remote Desktop Protocol", "T1110 Brute Force"],
            "Internet- or subnet-reachable RDP is a top ransomware entry point (brute force, BlueKeep CVE-2019-0708).",
            "Require NLA + MFA, patch BlueKeep, and put RDP behind a VPN/jump host."),
    "VNC": ("Unauthenticated / weak-auth VNC takeover", "Lateral Movement", "HIGH",
            ["T1021.005 VNC"],
            "VNC frequently runs with no or weak authentication, giving full interactive control of the host.",
            "Require strong VNC auth over a tunnel, or disable it in favour of RDP/SSH with MFA."),
    "SSH": ("SSH brute force / credential stuffing", "Credential Access", "MEDIUM",
            ["T1110.001 Password Guessing", "T1021.004 SSH"],
            "Reachable SSH is continuously targeted by password-guessing and key-reuse attacks.",
            "Enforce key-only auth, disable root login, and rate-limit/lock out on failed attempts."),
    "HTTP": ("Web application attack (SQLi / XSS / RCE)", "Initial Access", "MEDIUM",
             ["T1190 Exploit Public-Facing Application"],
             "Plaintext HTTP services are probed for injection, traversal and known-CVE exploitation.",
             "Front with TLS + a WAF, patch the app/framework, and add the missing security headers."),
    "SNMP": ("SNMP community-string abuse / info disclosure", "Discovery", "MEDIUM",
             ["T1046 Network Service Scanning", "T1602 Data from Configuration Repository"],
             "SNMP with default community strings ('public'/'private') leaks device config and can allow writes.",
             "Use SNMPv3 with auth+priv, change/remove default communities, restrict by ACL."),
    "SMTP": ("Mail relay abuse / credential sniffing", "Collection", "MEDIUM",
             ["T1040 Network Sniffing", "T1110 Brute Force"],
             "Cleartext SMTP can leak credentials and, if open-relay, be abused for spam/phishing.",
             "Enforce STARTTLS/AUTH, disable open relay, and require authentication."),
    "POP3": ("Mailbox credential sniffing", "Credential Access", "MEDIUM",
             ["T1040 Network Sniffing"],
             "POP3 without TLS exposes mailbox credentials on the wire.",
             "Require POP3S/IMAPS (TLS) and disable the cleartext ports."),
    "IMAP": ("Mailbox credential sniffing", "Credential Access", "MEDIUM",
             ["T1040 Network Sniffing"],
             "IMAP without TLS exposes mailbox credentials on the wire.",
             "Require IMAPS (TLS) and disable the cleartext port."),
    "LDAP": ("Directory enumeration / anonymous bind", "Discovery", "MEDIUM",
             ["T1087 Account Discovery", "T1069 Permission Groups Discovery"],
             "Anonymous or cleartext LDAP allows enumeration of users, groups and the directory tree.",
             "Disable anonymous bind, require LDAPS, and restrict directory queries."),
    "KERBEROS": ("Kerberoasting / AS-REP roasting", "Credential Access", "HIGH",
                 ["T1558.003 Kerberoasting", "T1558.004 AS-REP Roasting"],
                 "Reachable Kerberos permits offline cracking of service-account and AS-REP-roastable tickets.",
                 "Use long random service-account passwords/gMSA and require pre-auth."),
    "MSSQL": ("Database compromise (auth abuse / xp_cmdshell RCE)", "Initial Access", "HIGH",
              ["T1190 Exploit Public-Facing Application", "T1505 Server Software Component"],
              "Exposed MSSQL is targeted for weak-credential login and xp_cmdshell command execution.",
              "Bind to localhost/mgmt only, enforce strong auth, and disable xp_cmdshell."),
    "MYSQL": ("Database compromise / data theft", "Collection", "HIGH",
              ["T1190 Exploit Public-Facing Application", "T1005 Data from Local System"],
              "Exposed MySQL is targeted for credential brute force and bulk data exfiltration.",
              "Restrict to app hosts, enforce strong auth, and disable remote root."),
    "POSTGRESQL": ("Database compromise / data theft", "Collection", "HIGH",
                   ["T1190 Exploit Public-Facing Application", "T1005 Data from Local System"],
                   "Exposed PostgreSQL is targeted for credential abuse and, via extensions, command execution.",
                   "Restrict pg_hba to trusted hosts and enforce scram-sha-256 auth."),
    "ORACLE": ("Database compromise / data theft", "Collection", "HIGH",
               ["T1190 Exploit Public-Facing Application"],
               "Exposed Oracle TNS is targeted for SID enumeration and default-credential access.",
               "Restrict listener access and remove default accounts."),
    "MONGODB": ("Unauthenticated database access / data theft", "Collection", "HIGH",
                ["T1190 Exploit Public-Facing Application", "T1005 Data from Local System"],
                "MongoDB has historically shipped with no auth, exposing entire databases for theft/ransom.",
                "Enable authentication, bind to localhost, and never expose it to untrusted networks."),
    "REDIS": ("Unauthenticated Redis → RCE / webshell", "Execution", "HIGH",
              ["T1190 Exploit Public-Facing Application"],
              "Unauthenticated Redis allows config abuse to write SSH keys or webshells for code execution.",
              "Require a strong password/ACL, bind to localhost, and enable protected-mode."),
    "ELASTICSEARCH": ("Unauthenticated index access / data theft", "Collection", "HIGH",
                      ["T1190 Exploit Public-Facing Application"],
                      "Open Elasticsearch exposes and allows deletion/ransom of every index.",
                      "Enable security/auth, bind to localhost, and put it behind a proxy."),
    "IPMI": ("BMC compromise (cipher-0 / hash disclosure)", "Initial Access", "HIGH",
             ["T1190 Exploit Public-Facing Application"],
             "IPMI/BMC is exploitable via cipher-0 auth bypass and RAKP hash disclosure for full server control.",
             "Isolate management interfaces on a dedicated network and disable cipher-0."),
    "WINRM": ("Remote command execution / pass-the-hash", "Execution", "HIGH",
              ["T1021.006 Windows Remote Management"],
              "WinRM enables remote PowerShell execution and pass-the-hash lateral movement.",
              "Restrict WinRM to management hosts and require HTTPS + strong auth."),
    "DOCKER": ("Unauthenticated Docker API → host takeover", "Execution", "CRITICAL",
               ["T1610 Deploy Container", "T1190 Exploit Public-Facing Application"],
               "An exposed Docker API (2375) lets anyone launch privileged containers and take over the host.",
               "Never expose the Docker socket/API; require mTLS if remote access is essential."),
    "VMWARE": ("Hypervisor / VM management attack surface", "Initial Access", "MEDIUM",
               ["T1190 Exploit Public-Facing Application"],
               "VMware auth/management services are targeted for known-CVE exploitation and credential attacks.",
               "Patch ESXi/vCenter promptly and restrict management ports to admins."),
    "TFTP": ("Configuration exfiltration via TFTP", "Collection", "MEDIUM",
             ["T1602 Data from Configuration Repository"],
             "TFTP has no authentication and is used to pull device configs and firmware.",
             "Disable TFTP or restrict it to a provisioning VLAN."),
    "CHARGEN": ("UDP amplification DoS (chargen)", "Impact", "MEDIUM",
                ["T1498.001 Direct Network Flood"],
                "The chargen service (19) is a classic UDP-amplification reflector for DDoS.",
                "Disable the legacy simple-TCP/UDP services (echo/discard/daytime/qotd/chargen)."),
    "ECHO": ("Legacy service info leak / amplification", "Impact", "LOW",
             ["T1498.001 Direct Network Flood"],
             "The echo service (7) is an obsolete simple service usable for amplification and fingerprinting.",
             "Disable inetd simple services; they serve no modern purpose."),
    "MODBUS": ("ICS/SCADA manipulation (Modbus)", "Impact", "HIGH",
               ["T0855 Unauthorized Command Message"],
               "Modbus has no authentication; exposure allows reading and altering industrial process values.",
               "Segment OT from IT, and gateway Modbus behind an authenticated protocol break."),
    "S7COMM": ("ICS/SCADA manipulation (S7)", "Impact", "HIGH",
               ["T0855 Unauthorized Command Message"],
               "Siemens S7comm exposure allows PLC read/write and process disruption.",
               "Isolate the OT network and restrict S7 to the engineering station."),
}

# Cleartext protocols whose mere *use* (payloads flowing) implies sniffing risk.
_CLEARTEXT = {"FTP", "TELNET", "HTTP", "SMTP", "POP3", "IMAP", "SNMP", "LDAP", "TFTP"}


def _observed_services(result) -> dict:
    """port → {'service', 'hosts': set, 'responded': bool, 'flows': int}.

    'responded' means we actually saw the port answer (SYN-ACK, or bidirectional
    UDP) — i.e. it is genuinely open, not merely probed by a scan.
    """
    svc: dict = {}
    for f in result.flows.values():
        port = f.dst_port
        if port is None or f.protocol not in ("TCP", "UDP"):
            continue
        rec = svc.setdefault(port, {"service": get_service_name(port),
                                    "hosts": set(), "responded": False, "flows": 0})
        rec["flows"] += 1
        if f.dst_ip:
            rec["hosts"].add(f.dst_ip)
        flags = f.tcp_flags_seen or set()
        if any("SYNACK" in x or "ACKSYN" in x for x in flags):
            rec["responded"] = True
        elif f.protocol == "UDP" and f.packets > 1:
            rec["responded"] = True  # a UDP reply came back
    return svc


def _scanned_ports(events) -> set:
    """Ports that a detected scan actually probed (raises likelihood)."""
    ports: set = set()
    for e in events:
        if e.event_type in (EventType.PORT_SCAN, EventType.HOST_SCAN):
            if e.dst_port:
                ports.add(e.dst_port)
            for p in (e.evidence or {}).get("sample_ports", []) or []:
                ports.add(p)
    return ports


def predict(result, events: list) -> list[ThreatPrediction]:
    """Return grounded attack forecasts, most severe/likely first."""
    preds: list[ThreatPrediction] = []
    services = _observed_services(result)
    scanned = _scanned_ports(events)
    event_types = {e.event_type for e in events}
    scan_seen = bool(event_types & {EventType.PORT_SCAN, EventType.HOST_SCAN,
                                    EventType.ARP_SCAN})

    # ── 1. Exposed-service attack surface ────────────────────────────────────
    for port, info in services.items():
        threat = _SERVICE_THREATS.get(info["service"])
        if not threat:
            continue
        attack, category, severity, mitre, rationale, remediation = threat
        hosts = sorted(info["hosts"])[:8]
        responded = info["responded"]
        was_scanned = port in scanned or (scan_seen and not responded)

        # Likelihood: confirmed-open + actively scanned → High; open → Medium;
        # only probed (not confirmed open) → Low.
        if responded and (was_scanned or port in scanned):
            likelihood = "High"
        elif responded:
            likelihood = "Medium"
        else:
            likelihood = "Low"

        ev = [f"{info['service']} (port {port}) observed on {', '.join(hosts) or 'the network'}"
              f"{' — port responded (open)' if responded else ' — probed'}"]
        if port in scanned:
            ev.append(f"port {port} was included in an observed scan")
        if info["service"] in _CLEARTEXT and responded:
            ev.append(f"{info['service']} is a cleartext protocol — credentials/data are exposed on the wire")

        preds.append(ThreatPrediction(
            attack=attack, category=category, likelihood=likelihood, severity=severity,
            rationale=rationale, recommendation=remediation,
            evidence=ev, mitre=list(mitre), affected=[f"{h}:{port}" for h in hosts] or [f"port {port}"],
        ))

    # ── 2. Behavioural trajectory from detections ────────────────────────────
    def _add(attack, category, likelihood, severity, rationale, recommendation, evidence, mitre, affected):
        preds.append(ThreatPrediction(attack, category, likelihood, severity, rationale,
                                      recommendation, evidence, mitre, affected))

    scan_events = [e for e in events if e.event_type in
                   (EventType.PORT_SCAN, EventType.HOST_SCAN, EventType.ARP_SCAN)]
    if scan_events:
        srcs = sorted({e.src_ip for e in scan_events if e.src_ip})[:6]
        open_svcs = sorted({info["service"] for info in services.values() if info["responded"]})
        _add("Targeted exploitation of discovered services", "Initial Access", "High", "HIGH",
             "Reconnaissance was observed — a scanner is enumerating the network. Attackers follow discovery with "
             "targeted exploitation of the live services they found.",
             "Treat the scanning host as hostile, block it, and prioritise patching the exposed services below.",
             [f"scan/recon from {', '.join(srcs)}"] + ([f"live services found: {', '.join(open_svcs[:10])}"] if open_svcs else []),
             ["T1046 Network Service Scanning", "T1190 Exploit Public-Facing Application"],
             srcs)

    if EventType.ARP_SCAN in event_types or EventType.ARP_SPOOFING in event_types:
        srcs = sorted({e.src_ip for e in events if e.event_type in
                       (EventType.ARP_SCAN, EventType.ARP_SPOOFING) and e.src_ip})[:6]
        _add("Man-in-the-middle / lateral movement staging", "Lateral Movement", "Medium", "HIGH",
             "Layer-2 activity (ARP sweep/poisoning) precedes on-path interception and pivoting between hosts.",
             "Enable dynamic ARP inspection and port security; investigate the source host on the switch.",
             [f"ARP activity from {', '.join(srcs)}"], ["T1557.002 ARP Cache Poisoning", "T1018 Remote System Discovery"], srcs)

    if EventType.BRUTE_FORCE in event_types:
        _add("Account takeover via credential guessing", "Credential Access", "High", "HIGH",
             "A brute-force burst was seen; success yields valid credentials for deeper access.",
             "Lock out/rate-limit the source, enforce MFA, and hunt for any successful login after the burst.",
             ["brute-force detection present"], ["T1110 Brute Force", "T1078 Valid Accounts"], [])

    if EventType.CREDENTIAL_EXPOSURE in event_types:
        _add("Credential reuse across services", "Lateral Movement", "High", "HIGH",
             "Cleartext credentials were captured; attackers reuse them against other services and hosts.",
             "Rotate the exposed credentials now and move the service to an encrypted protocol.",
             ["cleartext credentials observed"], ["T1078 Valid Accounts", "T1552.001 Credentials In Files"], [])

    if event_types & {EventType.C2_BEACON, EventType.DNS_TUNNELING, EventType.JA3_ANOMALY}:
        _add("Command-and-control & data exfiltration", "Exfiltration", "High", "CRITICAL",
             "C2/tunnelling indicators suggest an active implant; the next stage is data exfiltration over the channel.",
             "Isolate the internal host, block the destination, and triage the endpoint for malware.",
             ["C2 / tunnelling indicator present"], ["T1041 Exfiltration Over C2 Channel", "T1071 Application Layer Protocol"], [])

    if EventType.DOS_FLOOD in event_types:
        _add("Service outage from flooding", "Impact", "High", "HIGH",
             "A high-rate half-open/flood pattern was seen, which exhausts server connection state.",
             "Enable SYN cookies/rate-limiting upstream and block the source.",
             ["flood/half-open burst present"], ["T1499.002 Service Exhaustion Flood"], [])

    # ── Dedup (same attack+affected) keeping the strongest, then sort ────────
    best: dict = {}
    for p in preds:
        key = (p.attack, tuple(p.affected))
        cur = best.get(key)
        if cur is None or p.sort_key() < cur.sort_key():
            best[key] = p
    out = sorted(best.values(), key=lambda p: p.sort_key())
    return out
