"""
Timeline models — data structures for chronological event reconstruction.
"""

from dataclasses import dataclass, field
from typing import Optional

from packetiq.detection.models import Severity


# Category tags for timeline events
class Category:
    THREAT      = "THREAT"       # detection engine finding
    CHAIN_START = "CHAIN_START"  # attack chain begins
    CHAIN_END   = "CHAIN_END"    # attack chain ends
    DNS         = "DNS"          # notable DNS activity
    HTTP        = "HTTP"         # notable HTTP activity
    FLOW_SPIKE  = "FLOW_SPIKE"   # high-volume traffic burst
    PIVOT       = "PIVOT"        # kill chain phase transition
    GAP         = "GAP"          # period of inactivity


CATEGORY_EMOJI = {
    Category.THREAT:      "⚡",
    Category.CHAIN_START: "⛓",
    Category.CHAIN_END:   "✓",
    Category.DNS:         "🔮",
    Category.HTTP:        "🌐",
    Category.FLOW_SPIKE:  "📈",
    Category.PIVOT:       "🔀",
    Category.GAP:         "─",
}

PHASE_BADGE = {
    "Reconnaissance":       "[RECON]",
    "Weaponization":        "[WEAPON]",
    "Delivery":             "[DELIVER]",
    "Exploitation":         "[EXPLOIT]",
    "Installation":         "[INSTALL]",
    "Command & Control":    "[C2]",
    "Actions on Objectives":"[ACTIONS]",
}


@dataclass
class TimelineEvent:
    """A single timestamped event on the reconstructed timeline."""
    timestamp:   float
    category:    str                   # Category constant
    description: str
    src_ip:      Optional[str] = None
    dst_ip:      Optional[str] = None
    dst_port:    Optional[int] = None
    protocol:    Optional[str] = None
    phase:       str           = ""    # Kill chain phase
    severity:    Optional[Severity] = None
    mitre_id:    Optional[str] = None  # e.g. "T1046"
    chain_name:  Optional[str] = None  # which chain this belongs to
    evidence:    dict          = field(default_factory=dict)

    @property
    def ts_str(self) -> str:
        from packetiq.utils.helpers import ts_to_str
        return ts_to_str(self.timestamp) if self.timestamp else "?"

    @property
    def emoji(self) -> str:
        return CATEGORY_EMOJI.get(self.category, "•")


@dataclass
class PhaseSegment:
    """A contiguous period dominated by a single kill chain phase."""
    phase:      str
    start_ts:   float
    end_ts:     float
    events:     list = field(default_factory=list)  # list[TimelineEvent]

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass
class ActivityBar:
    """
    Bucketed activity density for the ASCII spark-line.
    buckets[i] = number of events in time bucket i.
    """
    buckets:    list[int]
    bucket_secs: float
    total_events: int
    start_ts:   float
    end_ts:     float


@dataclass
class Timeline:
    """Complete reconstructed timeline for one PCAP analysis."""
    events:          list[TimelineEvent]  = field(default_factory=list)
    phase_segments:  list[PhaseSegment]   = field(default_factory=list)
    pivot_points:    list[TimelineEvent]  = field(default_factory=list)
    activity_bar:    Optional[ActivityBar] = None
    capture_start:   float = 0.0
    capture_end:     float = 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.capture_end - self.capture_start)

    @property
    def phases_seen(self) -> list[str]:
        """Ordered list of unique kill chain phases present."""
        from packetiq.correlation.models import KILL_CHAIN_PHASES
        seen = {e.phase for e in self.events if e.phase}
        return [p for p in KILL_CHAIN_PHASES if p in seen]
