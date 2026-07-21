"""
Evidence PCAP slicing — extract just the packets relevant to a finding into a
smaller capture you can open in Wireshark.

Filter by any combination of: IP(s), port(s), and a time window. A packet
matches if it satisfies every supplied criterion (IP set membership on either
endpoint, port set membership on either endpoint, and timestamp in range).
"""

from dataclasses import dataclass, field
from typing import Optional

from scapy.all import PcapReader, PcapWriter
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


@dataclass
class PcapFilter:
    ips:        set = field(default_factory=set)     # match if src or dst in this set
    ports:      set = field(default_factory=set)     # match if sport or dport in this set
    start_ts:   Optional[float] = None               # inclusive
    end_ts:     Optional[float] = None               # inclusive

    def matches(self, pkt) -> bool:
        # Time window
        ts = float(pkt.time)
        if self.start_ts is not None and ts < self.start_ts:
            return False
        if self.end_ts is not None and ts > self.end_ts:
            return False

        # IPs
        if self.ips:
            src = dst = None
            if pkt.haslayer(IP):
                src, dst = pkt[IP].src, pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src, dst = pkt[IPv6].src, pkt[IPv6].dst
            if not (src in self.ips or dst in self.ips):
                return False

        # Ports
        if self.ports:
            sport = dport = None
            if pkt.haslayer(TCP):
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            if not (sport in self.ports or dport in self.ports):
                return False

        return True

    @property
    def is_empty(self) -> bool:
        return not self.ips and not self.ports and self.start_ts is None and self.end_ts is None


def slice_pcap(
    src_path: str,
    out_path: str,
    pcap_filter: PcapFilter,
    max_packets: int = 0,
) -> int:
    """
    Stream src_path, write matching packets to out_path. Returns the number of
    packets written. `max_packets=0` means no limit.
    """
    written = 0
    writer = PcapWriter(out_path, append=False, sync=True)
    try:
        with PcapReader(src_path) as reader:
            for pkt in reader:
                try:
                    if pcap_filter.is_empty or pcap_filter.matches(pkt):
                        writer.write(pkt)
                        written += 1
                        if max_packets and written >= max_packets:
                            break
                except Exception:  # nosec B112 - skip an unreadable packet/source, keep slicing the rest
                    continue
    finally:
        writer.close()
    return written


def filter_for_event(event) -> PcapFilter:
    """Build a sensible evidence filter from a DetectionEvent."""
    ips = set()
    ports = set()
    if getattr(event, "src_ip", None):
        ips.add(event.src_ip)
    if getattr(event, "dst_ip", None):
        ips.add(event.dst_ip)
    if getattr(event, "dst_port", None):
        ports.add(event.dst_port)
    # drop placeholder values
    ips.discard("(local host)")
    return PcapFilter(ips=ips, ports=ports)
