"""
MITRE ATT&CK mappings for PacketIQ detection event types.

Maps each EventType to one or more MITRE ATT&CK tactics and techniques.
Reference: https://attack.mitre.org/  (Enterprise Matrix)

Kill chain phase assignments align with the Lockheed Martin Cyber Kill Chain.
"""

from packetiq.correlation.models import MitreTechnique
from packetiq.detection.models import EventType

# ── Primary technique per EventType ──────────────────────────────────────────
#
# Format: EventType → list[MitreTechnique]
# Most event types map to one primary technique; some map to multiple.

EVENT_TYPE_TECHNIQUES: dict[str, list[MitreTechnique]] = {

    EventType.PORT_SCAN: [
        MitreTechnique("TA0043", "Reconnaissance",    "T1046",     "Network Service Discovery"),
        MitreTechnique("TA0007", "Discovery",         "T1046",     "Network Service Discovery"),
    ],

    EventType.HOST_SCAN: [
        MitreTechnique("TA0043", "Reconnaissance",    "T1018",     "Remote System Discovery"),
        MitreTechnique("TA0007", "Discovery",         "T1018",     "Remote System Discovery"),
    ],

    EventType.ARP_SCAN: [
        MitreTechnique("TA0007", "Discovery",         "T1018",     "Remote System Discovery"),
        MitreTechnique("TA0043", "Reconnaissance",    "T1595",     "Active Scanning"),
    ],

    EventType.ARP_SPOOFING: [
        MitreTechnique("TA0006", "Credential Access", "T1557",     "Adversary-in-the-Middle"),
        MitreTechnique("TA0006", "Credential Access", "T1557.002", "ARP Cache Poisoning"),
        MitreTechnique("TA0009", "Collection",        "T1557",     "Adversary-in-the-Middle"),
    ],

    EventType.DOS_FLOOD: [
        MitreTechnique("TA0040", "Impact",            "T1499",     "Endpoint Denial of Service"),
        MitreTechnique("TA0040", "Impact",            "T1499.002", "Service Exhaustion Flood"),
    ],

    EventType.BRUTE_FORCE: [
        MitreTechnique("TA0006", "Credential Access", "T1110",     "Brute Force"),
        MitreTechnique("TA0006", "Credential Access", "T1110.001", "Password Guessing"),
        MitreTechnique("TA0001", "Initial Access",    "T1078",     "Valid Accounts"),
    ],

    EventType.CREDENTIAL_EXPOSURE: [
        MitreTechnique("TA0006", "Credential Access", "T1552",     "Unsecured Credentials"),
        MitreTechnique("TA0006", "Credential Access", "T1552.001", "Credentials In Files"),
        MitreTechnique("TA0009", "Collection",        "T1119",     "Automated Collection"),
    ],

    EventType.DNS_ANOMALY: [
        MitreTechnique("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        MitreTechnique("TA0011", "Command and Control", "T1071.004", "DNS"),
        MitreTechnique("TA0043", "Reconnaissance",      "T1590",     "Gather Victim Network Information"),
    ],

    EventType.DNS_TUNNELING: [
        MitreTechnique("TA0011", "Command and Control", "T1071.004", "DNS"),
        MitreTechnique("TA0010", "Exfiltration",        "T1048",     "Exfiltration Over Alternative Protocol"),
        MitreTechnique("TA0010", "Exfiltration",        "T1048.001", "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"),
    ],

    EventType.ICMP_TUNNELING: [
        MitreTechnique("TA0010", "Exfiltration",        "T1048.003", "Exfiltration Over Unencrypted Non-C2 Protocol"),
        MitreTechnique("TA0011", "Command and Control", "T1095",     "Non-Application Layer Protocol"),
    ],

    EventType.PROTOCOL_MISUSE: [
        MitreTechnique("TA0008", "Lateral Movement",   "T1021",     "Remote Services"),
        MitreTechnique("TA0005", "Defense Evasion",    "T1036",     "Masquerading"),
        MitreTechnique("TA0011", "Command and Control","T1571",     "Non-Standard Port"),
    ],

    EventType.SUSPICIOUS_FLAGS: [
        MitreTechnique("TA0043", "Reconnaissance",     "T1046",     "Network Service Discovery"),
        MitreTechnique("TA0005", "Defense Evasion",    "T1036",     "Masquerading"),
    ],

    EventType.C2_BEACON: [
        MitreTechnique("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        MitreTechnique("TA0011", "Command and Control", "T1071.001", "Web Protocols"),
        MitreTechnique("TA0011", "Command and Control", "T1132",     "Data Encoding"),
        MitreTechnique("TA0011", "Command and Control", "T1573",     "Encrypted Channel"),
    ],

    EventType.JA3_ANOMALY: [
        MitreTechnique("TA0011", "Command and Control", "T1573",     "Encrypted Channel"),
        MitreTechnique("TA0011", "Command and Control", "T1573.002", "Asymmetric Cryptography"),
        MitreTechnique("TA0011", "Command and Control", "T1071.001", "Web Protocols"),
    ],

    EventType.IOC_MATCH: [
        MitreTechnique("TA0011", "Command and Control", "T1071",     "Application Layer Protocol"),
        MitreTechnique("TA0011", "Command and Control", "T1090",     "Proxy"),
    ],

    EventType.MALICIOUS_FILE: [
        MitreTechnique("TA0002", "Execution",           "T1204",     "User Execution"),
        MitreTechnique("TA0011", "Command and Control", "T1105",     "Ingress Tool Transfer"),
    ],

    EventType.HTTP_ATTACK: [
        MitreTechnique("TA0001", "Initial Access",      "T1190",     "Exploit Public-Facing Application"),
        MitreTechnique("TA0002", "Execution",           "T1059",     "Command and Scripting Interpreter"),
    ],

    EventType.TLS_ANOMALY: [
        MitreTechnique("TA0011", "Command and Control", "T1573",     "Encrypted Channel"),
        MitreTechnique("TA0005", "Defense Evasion",     "T1036",     "Masquerading"),
    ],

    EventType.KERBEROS_USER_ENUM: [
        MitreTechnique("TA0007", "Discovery",           "T1087.002", "Account Discovery: Domain Account"),
        MitreTechnique("TA0043", "Reconnaissance",      "T1589.001", "Gather Victim Identity Information: Credentials"),
    ],

    EventType.KERBEROS_BRUTE_FORCE: [
        MitreTechnique("TA0006", "Credential Access",   "T1110.003", "Brute Force: Password Spraying"),
        MitreTechnique("TA0006", "Credential Access",   "T1110",     "Brute Force"),
    ],

    EventType.KERBEROS_ROASTING: [
        MitreTechnique("TA0006", "Credential Access",   "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting"),
        MitreTechnique("TA0006", "Credential Access",   "T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting"),
    ],

    EventType.KERBEROS_ANOMALY: [
        MitreTechnique("TA0006", "Credential Access",   "T1558",     "Steal or Forge Kerberos Tickets"),
        MitreTechnique("TA0005", "Defense Evasion",     "T1600",     "Weaken Encryption"),
    ],

    EventType.WINRM_EXECUTION: [
        MitreTechnique("TA0008", "Lateral Movement",    "T1021.006", "Remote Services: Windows Remote Management"),
        MitreTechnique("TA0002", "Execution",           "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    ],

    EventType.NTLM_AUTHENTICATION: [
        MitreTechnique("TA0006", "Credential Access",   "T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"),
        MitreTechnique("TA0006", "Credential Access",   "T1110",     "Brute Force"),
    ],

    EventType.LDAP_ENUMERATION: [
        MitreTechnique("TA0007", "Discovery",           "T1087.002", "Account Discovery: Domain Account"),
        MitreTechnique("TA0007", "Discovery",           "T1482",     "Domain Trust Discovery"),
    ],

    EventType.SMB_LATERAL_MOVEMENT: [
        MitreTechnique("TA0008", "Lateral Movement",    "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
        MitreTechnique("TA0002", "Execution",           "T1569.002", "System Services: Service Execution"),
    ],

    EventType.SMB_FILE_ACCESS: [
        MitreTechnique("TA0008", "Lateral Movement",    "T1570",     "Lateral Tool Transfer"),
        MitreTechnique("TA0009", "Collection",          "T1039",     "Data from Network Shared Drive"),
    ],

    EventType.DCERPC_SUSPECT_BIND: [
        MitreTechnique("TA0008", "Lateral Movement",    "T1021.003", "Remote Services: DCOM"),
        MitreTechnique("TA0006", "Credential Access",   "T1003.006", "OS Credential Dumping: DCSync"),
    ],

    EventType.DCERPC_RECON: [
        MitreTechnique("TA0007", "Discovery",           "T1135",     "Network Share Discovery"),
        MitreTechnique("TA0043", "Reconnaissance",      "T1046",     "Network Service Discovery"),
    ],

    EventType.SUSPICIOUS_FILE_TRANSFER: [
        MitreTechnique("TA0008", "Lateral Movement",    "T1105",     "Ingress Tool Transfer"),
        MitreTechnique("TA0011", "Command and Control", "T1071.002", "Application Layer Protocol: File Transfer"),
    ],

    EventType.REVERSE_SHELL: [
        MitreTechnique("TA0002", "Execution",           "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
        MitreTechnique("TA0011", "Command and Control", "T1571",     "Non-Standard Port"),
    ],
}

# ── Kill Chain phase per EventType ────────────────────────────────────────────
#
# Maps each event type to its primary Lockheed Martin Kill Chain phase.

EVENT_TYPE_KILL_CHAIN: dict[str, str] = {
    EventType.PORT_SCAN:           "Reconnaissance",
    EventType.HOST_SCAN:           "Reconnaissance",
    EventType.ARP_SCAN:            "Reconnaissance",
    EventType.ARP_SPOOFING:        "Actions on Objectives",
    EventType.DOS_FLOOD:           "Actions on Objectives",
    EventType.SUSPICIOUS_FLAGS:    "Reconnaissance",
    EventType.BRUTE_FORCE:         "Exploitation",
    EventType.CREDENTIAL_EXPOSURE: "Actions on Objectives",
    EventType.DNS_ANOMALY:         "Command & Control",
    EventType.DNS_TUNNELING:       "Command & Control",
    EventType.ICMP_TUNNELING:      "Actions on Objectives",
    EventType.PROTOCOL_MISUSE:     "Delivery",
    EventType.C2_BEACON:           "Command & Control",
    EventType.JA3_ANOMALY:         "Command & Control",
    EventType.IOC_MATCH:           "Command & Control",
    EventType.MALICIOUS_FILE:      "Installation",
    EventType.HTTP_ATTACK:         "Exploitation",
    EventType.TLS_ANOMALY:         "Command & Control",
    # Enumeration is reconnaissance against the directory; everything that
    # follows it is an attempt to come away with credential material.
    EventType.KERBEROS_USER_ENUM:  "Reconnaissance",
    EventType.KERBEROS_BRUTE_FORCE: "Exploitation",
    EventType.KERBEROS_ROASTING:   "Exploitation",
    EventType.KERBEROS_ANOMALY:    "Exploitation",
    # A remote shell on the target is the objective, not a step toward one.
    EventType.WINRM_EXECUTION:     "Actions on Objectives",
    EventType.NTLM_AUTHENTICATION: "Exploitation",
    EventType.LDAP_ENUMERATION:    "Reconnaissance",
    EventType.SMB_LATERAL_MOVEMENT: "Actions on Objectives",
    EventType.SMB_FILE_ACCESS:     "Actions on Objectives",
    EventType.DCERPC_SUSPECT_BIND: "Actions on Objectives",
    EventType.DCERPC_RECON:        "Reconnaissance",
    EventType.SUSPICIOUS_FILE_TRANSFER: "Installation",
    EventType.REVERSE_SHELL:       "Actions on Objectives",
}


def techniques_for_event(event_type: EventType) -> list[MitreTechnique]:
    """Return MITRE techniques for a given event type."""
    return EVENT_TYPE_TECHNIQUES.get(event_type, [])


def kill_chain_phase(event_type: EventType) -> str:
    """Return the primary kill chain phase for a given event type."""
    return EVENT_TYPE_KILL_CHAIN.get(event_type, "Exploitation")


def techniques_for_events(events: list) -> list[MitreTechnique]:
    """Deduplicated list of MITRE techniques for a collection of events."""
    seen_ids: set[str] = set()
    result: list[MitreTechnique] = []
    for event in events:
        for tech in techniques_for_event(event.event_type):
            if tech.technique_id not in seen_ids:
                seen_ids.add(tech.technique_id)
                result.append(tech)
    return result


def kill_chain_phases_for_events(events: list) -> list[str]:
    """Ordered, deduplicated kill chain phases present in a collection of events."""
    from packetiq.correlation.models import KILL_CHAIN_PHASES
    phases = {kill_chain_phase(e.event_type) for e in events}
    return [p for p in KILL_CHAIN_PHASES if p in phases]
