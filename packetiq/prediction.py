"""
Threat Prediction — forward-looking attack forecasting from a capture.

Given the extracted flows/services and the detections already raised, this module
forecasts the attacks a capture is *most exposed to next*. Two grounded sources,
never invented:

1. **Exposed attack surface** — services the packets *prove* are listening
   (`ExtractionResult.service_exposure` state == "open": a completed TCP
   handshake, or a UDP service that answered) **on a host inside the monitored
   network**, mapped to the concrete attacks that target them (e.g. SMB →
   EternalBlue / ransomware lateral movement; FTP/Telnet → credential sniffing).

2. **Behavioural trajectory** — where the *detected* activity typically leads in
   the kill chain (e.g. a port scan → targeted exploitation of what it found; an
   ARP sweep → lateral movement / MITM; a C2 beacon → data exfiltration). Each
   one quotes the detection it follows from.

Two rules keep this free of the false positives a naive version produces:

* **Proven-open only.** A port that answered a SYN with RST is proven *closed*,
  and a port that never answered is *filtered*. Neither is attack surface, so
  neither is ever forecast. Only "open" counts.
* **Your network only.** A service is only your exposure if the *serving* host is
  on the monitored network. An internal client browsing an external web server
  does not make that server your attack surface.

If a capture is benign — clients talking outward, nothing listening locally —
this module correctly returns **no predictions at all**.

Every prediction names the exact evidence it rests on. This is a forecast of
*possible* attacks given what is exposed and observed — not a claim that an attack
occurred, and not a probability of malice. It complements (never replaces) the
evidence-backed detections.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from packetiq.detection.models import EventType
from packetiq.utils.helpers import monitored_network

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


def _exposed_services(result, local: set) -> dict:
    """service name → aggregated evidence for ports PROVEN open on our hosts.

    Only `state == "open"` is considered. Ports proven closed (answered a SYN
    with RST) and ports that never answered are deliberately excluded — they are
    not attack surface, and forecasting an attack against them is the single
    biggest source of false positives.
    """
    svc: dict = {}
    for (ip, port, proto), info in (result.service_exposure or {}).items():
        if info.get("state") != "open" or ip not in local:
            continue
        rec = svc.setdefault(info["service"], {
            "ports": set(), "hosts": set(), "protos": set(),
            "ext_clients": set(), "client_count": 0,
        })
        rec["ports"].add(port)
        rec["hosts"].add(ip)
        rec["protos"].add(proto)
        clients = info.get("clients") or set()
        rec["client_count"] += len(clients)
        # A client outside the monitored network proves the service is reachable
        # from off-net — a materially higher exposure than LAN-only reachability.
        rec["ext_clients"] |= {c for c in clients if c and c not in local}
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


def _fmt(items, limit: int = 4) -> str:
    """Render a bounded, deterministic list of evidence items."""
    vals = sorted(items, key=str)
    head = ", ".join(str(v) for v in vals[:limit])
    return head + (f" and {len(vals) - limit} more" if len(vals) > limit else "")


def predict(result, events: list) -> list[ThreatPrediction]:
    """Return grounded attack forecasts, most severe/likely first.

    Returns an empty list when the capture shows no exposed service on the
    monitored network and no attack behaviour — which is the correct answer for
    ordinary benign traffic.
    """
    preds: list[ThreatPrediction] = []
    local = monitored_network(result)
    services = _exposed_services(result, local)
    scanned = _scanned_ports(events)
    event_types = {e.event_type for e in events}

    # ── 1. Exposed-service attack surface (proven-open, our hosts only) ──────
    for name, info in services.items():
        threat = _SERVICE_THREATS.get(name)
        if not threat:
            continue
        attack, category, severity, mitre, rationale, remediation = threat
        hosts  = sorted(info["hosts"])
        ports  = sorted(info["ports"])
        proto  = "/".join(sorted(info["protos"]))
        ext    = sorted(info["ext_clients"])
        probed = [p for p in ports if p in scanned]

        # Likelihood is set by what the packets show, not by the service name:
        # actively probed, or reachable from off-net → High; otherwise open but
        # only ever used from inside the monitored network → Medium.
        likelihood = "High" if (probed or ext) else "Medium"

        ev = [f"{name} on {_fmt(f'{h}:{p}' for h in hosts for p in ports)} "
              f"({proto}) is confirmed listening — it completed a handshake with "
              f"{info['client_count']} client connection(s) in this capture"]
        if probed:
            ev.append(f"port {_fmt(probed)} was probed by a scan detected in this capture")
        if ext:
            ev.append(f"reachable from outside the monitored network — connected from {_fmt(ext)}")
        if name in _CLEARTEXT:
            ev.append(f"{name} is a cleartext protocol — credentials and data are readable "
                      f"by anyone on the path")

        preds.append(ThreatPrediction(
            attack=attack, category=category, likelihood=likelihood, severity=severity,
            rationale=rationale, recommendation=remediation,
            evidence=ev, mitre=list(mitre),
            affected=[f"{h}:{p}" for h in hosts[:8] for p in ports[:4]],
        ))

    # ── 2. Behavioural trajectory from detections ────────────────────────────
    def _add(attack, category, likelihood, severity, rationale, recommendation, evidence, mitre, affected):
        preds.append(ThreatPrediction(attack, category, likelihood, severity, rationale,
                                      recommendation, evidence, mitre, affected))

    def _cite(*types) -> tuple:
        """(evidence lines, source IPs) quoted from the matching detections."""
        hits = [e for e in events if e.event_type in types]
        lines = [e.description for e in hits[:3] if e.description]
        srcs = sorted({e.src_ip for e in hits if e.src_ip})[:6]
        return lines, srcs

    scan_events = [e for e in events if e.event_type in
                   (EventType.PORT_SCAN, EventType.HOST_SCAN, EventType.ARP_SCAN)]
    if scan_events:
        lines, srcs = _cite(EventType.PORT_SCAN, EventType.HOST_SCAN, EventType.ARP_SCAN)
        open_svcs = sorted(services)
        ev = list(lines)
        if open_svcs:
            ev.append(f"live services the scan could have found: {_fmt(open_svcs, 10)}")
        else:
            ev.append("no service on the monitored network answered — the scan found nothing open")
        _add("Targeted exploitation of discovered services", "Initial Access",
             "High" if open_svcs else "Low", "HIGH",
             "Reconnaissance was observed — a scanner is enumerating the network. Attackers follow discovery with "
             "targeted exploitation of the live services they found.",
             ("Treat the scanning host as hostile, block it, and prioritise patching the exposed services listed "
              "in the other forecasts." if open_svcs else
              "Treat the scanning host as hostile and block it. Nothing answered this time, so there is no exposure "
              "to patch — but the same sweep against a host with a service running would find it."),
             ev, ["T1046 Network Service Scanning", "T1190 Exploit Public-Facing Application"], srcs)

    if EventType.ARP_SCAN in event_types or EventType.ARP_SPOOFING in event_types:
        lines, srcs = _cite(EventType.ARP_SCAN, EventType.ARP_SPOOFING)
        _add("Man-in-the-middle / lateral movement staging", "Lateral Movement", "Medium", "HIGH",
             "Layer-2 activity (ARP sweep/poisoning) precedes on-path interception and pivoting between hosts.",
             "Enable dynamic ARP inspection and port security; investigate the source host on the switch.",
             lines, ["T1557.002 ARP Cache Poisoning", "T1018 Remote System Discovery"], srcs)

    if EventType.BRUTE_FORCE in event_types:
        lines, srcs = _cite(EventType.BRUTE_FORCE)
        _add("Account takeover via credential guessing", "Credential Access", "High", "HIGH",
             "A brute-force burst was seen; success yields valid credentials for deeper access.",
             "Lock out/rate-limit the source, enforce MFA, and hunt for any successful login after the burst.",
             lines, ["T1110 Brute Force", "T1078 Valid Accounts"], srcs)

    if EventType.CREDENTIAL_EXPOSURE in event_types:
        lines, srcs = _cite(EventType.CREDENTIAL_EXPOSURE)
        _add("Credential reuse across services", "Lateral Movement", "High", "HIGH",
             "Cleartext credentials were captured; attackers reuse them against other services and hosts.",
             "Rotate the exposed credentials now and move the service to an encrypted protocol.",
             lines, ["T1078 Valid Accounts", "T1552.001 Credentials In Files"], srcs)

    if event_types & {EventType.C2_BEACON, EventType.DNS_TUNNELING, EventType.JA3_ANOMALY}:
        lines, srcs = _cite(EventType.C2_BEACON, EventType.DNS_TUNNELING, EventType.JA3_ANOMALY)
        _add("Command-and-control & data exfiltration", "Exfiltration", "High", "CRITICAL",
             "C2/tunnelling indicators suggest an active implant; the next stage is data exfiltration over the channel.",
             "Isolate the internal host, block the destination, and triage the endpoint for malware.",
             lines, ["T1041 Exfiltration Over C2 Channel", "T1071 Application Layer Protocol"], srcs)

    if EventType.DOS_FLOOD in event_types:
        lines, srcs = _cite(EventType.DOS_FLOOD)
        _add("Service outage from flooding", "Impact", "High", "HIGH",
             "A high-rate half-open/flood pattern was seen, which exhausts server connection state.",
             "Enable SYN cookies/rate-limiting upstream and block the source.",
             lines, ["T1499.002 Service Exhaustion Flood"], srcs)

    # ── Dedup (same attack+affected) keeping the strongest, then sort ────────
    best: dict = {}
    for p in preds:
        key = (p.attack, tuple(p.affected))
        cur = best.get(key)
        if cur is None or p.sort_key() < cur.sort_key():
            best[key] = p
    out = sorted(best.values(), key=lambda p: p.sort_key())
    return out
