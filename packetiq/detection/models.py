"""
Detection models — shared data types for the detection engine.
"""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

    @property
    def score(self) -> int:
        return {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}[self.value]

    @property
    def color(self) -> str:
        return {"CRITICAL": "bold red", "HIGH": "bold yellow",
                "MEDIUM": "bold cyan", "LOW": "bold green"}[self.value]


class EventType(str, Enum):
    BRUTE_FORCE         = "BRUTE_FORCE"
    PORT_SCAN           = "PORT_SCAN"
    HOST_SCAN           = "HOST_SCAN"
    ARP_SCAN            = "ARP_SCAN"
    ARP_SPOOFING        = "ARP_SPOOFING"
    DOS_FLOOD           = "DOS_FLOOD"
    DNS_ANOMALY         = "DNS_ANOMALY"
    DNS_TUNNELING       = "DNS_TUNNELING"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"
    PROTOCOL_MISUSE     = "PROTOCOL_MISUSE"
    ICMP_TUNNELING      = "ICMP_TUNNELING"
    SUSPICIOUS_FLAGS    = "SUSPICIOUS_FLAGS"
    C2_BEACON           = "C2_BEACON"
    JA3_ANOMALY         = "JA3_ANOMALY"
    IOC_MATCH           = "IOC_MATCH"
    MALICIOUS_FILE      = "MALICIOUS_FILE"
    HTTP_ATTACK         = "HTTP_ATTACK"
    TLS_ANOMALY         = "TLS_ANOMALY"
    # Active Directory authentication, read from Kerberos on the wire rather
    # than inferred from port 88 being open.
    KERBEROS_USER_ENUM  = "KERBEROS_USER_ENUM"
    KERBEROS_BRUTE_FORCE = "KERBEROS_BRUTE_FORCE"
    KERBEROS_ROASTING   = "KERBEROS_ROASTING"
    KERBEROS_ANOMALY    = "KERBEROS_ANOMALY"
    # Remote management and the identity that authenticates to it. Command
    # text is inside SPNEGO session encryption; the account is not.
    WINRM_EXECUTION     = "WINRM_EXECUTION"
    NTLM_AUTHENTICATION = "NTLM_AUTHENTICATION"
    # Reading the directory, and moving through the file-sharing layer.
    LDAP_ENUMERATION    = "LDAP_ENUMERATION"
    SMB_LATERAL_MOVEMENT = "SMB_LATERAL_MOVEMENT"
    SMB_FILE_ACCESS     = "SMB_FILE_ACCESS"
    DCERPC_SUSPECT_BIND = "DCERPC_SUSPECT_BIND"
    DCERPC_RECON        = "DCERPC_RECON"
    # Cleartext session recovery: the readable conversation on the wire.
    SUSPICIOUS_FILE_TRANSFER = "SUSPICIOUS_FILE_TRANSFER"
    REVERSE_SHELL       = "REVERSE_SHELL"


@dataclass
class DetectionEvent:
    """A single detection finding emitted by a detector."""

    event_type:   EventType
    severity:     Severity
    src_ip:       str
    description:  str

    dst_ip:       str | None  = None
    dst_port:     int | None  = None
    protocol:     str | None  = None
    timestamp:    float          = 0.0   # first occurrence
    packet_count: int            = 0
    confidence:   float          = 1.0   # 0.0–1.0

    # Free-form evidence dict — shown in verbose output and reports
    evidence:     dict           = field(default_factory=dict)

    def __str__(self) -> str:
        dst = f"→ {self.dst_ip}:{self.dst_port}" if self.dst_ip else ""
        return (
            f"[{self.severity}] {self.event_type} | "
            f"{self.src_ip} {dst} | {self.description}"
        )
