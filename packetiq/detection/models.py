"""
Detection models — shared data types for the detection engine.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


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


@dataclass
class DetectionEvent:
    """A single detection finding emitted by a detector."""

    event_type:   EventType
    severity:     Severity
    src_ip:       str
    description:  str

    dst_ip:       Optional[str]  = None
    dst_port:     Optional[int]  = None
    protocol:     Optional[str]  = None
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
