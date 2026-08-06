"""
Data Extractor — Layer 2 of PacketIQ.

Aggregates raw packet records into structured analytics:
  - IP conversation pairs
  - Protocol distribution
  - Port usage
  - TCP session tracking
  - DNS query inventory
  - HTTP request inventory
  - Top talkers
  - Capture timeline bounds
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from packetiq.parser.pcap_parser import RawPacketRecord
from packetiq.utils.helpers import (
    format_bytes,
    format_duration,
    get_service_name,
    is_private_ip,
    ts_to_str,
)

# Addresses that are protocol sentinels rather than hosts: a booting client
# sends DHCP from 0.0.0.0 before it owns an address. Treating these as hosts
# invents devices that never existed.
_NON_HOST_IPS = {"0.0.0.0", "::"}  # nosec B104 # sentinel values, not a socket bind


@dataclass
class FlowKey:
    """Bidirectional flow identifier — normalized so A→B == B→A."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str

    def canonical(self) -> tuple:
        """Return consistent key regardless of direction."""
        ep_a = (self.src_ip, self.src_port)
        ep_b = (self.dst_ip, self.dst_port)
        if ep_a > ep_b:
            ep_a, ep_b = ep_b, ep_a
        return (ep_a, ep_b, self.protocol)


@dataclass
class FlowStats:
    """Aggregated metrics for a single bidirectional flow."""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    service: str

    packets: int = 0
    bytes_total: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    tcp_flags_seen: set = field(default_factory=set)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


@dataclass
class ExtractionResult:
    """Complete structured output of the extraction pass."""

    # ── Capture metadata ────────────────────────────────────
    total_packets: int = 0
    total_bytes: int = 0
    capture_start: float = 0.0
    capture_end: float = 0.0

    # ── Protocol distribution ────────────────────────────────
    protocol_counts: dict = field(default_factory=dict)   # proto → pkt count

    # ── Port statistics ──────────────────────────────────────
    dst_port_counts: dict = field(default_factory=dict)   # port → pkt count
    src_port_counts: dict = field(default_factory=dict)

    # ── IP statistics ────────────────────────────────────────
    ip_src_counts: dict = field(default_factory=dict)     # ip → pkt count
    ip_dst_counts: dict = field(default_factory=dict)
    unique_src_ips: set = field(default_factory=set)
    unique_dst_ips: set = field(default_factory=set)
    external_ips: set = field(default_factory=set)        # non-RFC1918

    # ── Flow / session table ─────────────────────────────────
    flows: dict = field(default_factory=dict)             # canonical key → FlowStats

    # ── Application data ────────────────────────────────────
    dns_queries: list = field(default_factory=list)       # (ts, src, qname)
    http_requests: list = field(default_factory=list)     # (ts, src, dst, method, host, path)
    http_responses: list = field(default_factory=list)    # (ts, src, dst, status)

    # ── Observed software banners (real, for CVE lookup) ─────
    # each: {"source": "http-server"|"http-user-agent", "value": str, "ips": [..]}
    software_banners: list = field(default_factory=list)

    # ── TCP connection tracking ──────────────────────────────
    tcp_syn_pairs: dict = field(default_factory=dict)     # (src,dst,dport) → ts list
    open_connections: int = 0
    completed_connections: int = 0

    # ── Proven service exposure ──────────────────────────────────────
    # (ip, port, proto) → {"state": "open"|"closed"|"filtered", "service": str,
    #                      "sent": int, "recv": int, "clients": {ip, ...}}
    # A service is only "open" when the packets *prove* it answered: a SYN-ACK
    # sourced from that ip:port (TCP), or a reply sourced from it after traffic
    # was sent to it (UDP). "closed" means it answered a SYN with RST — positive
    # proof there is nothing listening. "filtered" means it was probed and never
    # answered at all. Consumers (threat forecast, reports) must never treat
    # "closed"/"filtered" as attack surface.
    service_exposure: dict = field(default_factory=dict)

    # ── ARP / layer-2 tracking (host discovery & cache poisoning) ─
    # sender IP → set of distinct target IPs it sent ARP requests for
    arp_request_targets: dict = field(default_factory=dict)
    # sender IP → number of ARP requests it sent
    arp_request_counts: dict = field(default_factory=dict)
    # sender IP → set of source MACs it used (normally exactly one)
    arp_sender_macs: dict = field(default_factory=dict)
    # claimed IPv4 → set of MACs seen announcing it (>1 ⇒ possible spoofing)
    arp_ip_to_macs: dict = field(default_factory=dict)
    # sender IP → (first_ts, last_ts) of its ARP requests
    arp_request_window: dict = field(default_factory=dict)
    arp_total: int = 0            # total ARP frames seen
    arp_replies: int = 0          # total ARP replies (op == 2)

    # ── Device inventory (real physical hosts, keyed by NIC/MAC) ─────
    # Only hosts that actually transmitted a frame are real devices; an IP that
    # merely appears as an ARP-probe target or an unanswered SYN destination is
    # NOT proof a device exists. These structures let the graph show the true
    # device inventory (and merge a host's IPv4 + IPv6 into one node) instead of
    # inventing a node for every probed address.
    transmitted_ips: set = field(default_factory=set)   # IPs seen as a frame source
    ip_to_mac: dict = field(default_factory=dict)        # IP → dominant source MAC
    mac_to_ips: dict = field(default_factory=dict)       # MAC → {IPs it sourced}
    devices: list = field(default_factory=list)          # [{id, mac, ips, packets, kind, chassis}]
    ip_to_device: dict = field(default_factory=dict)     # IP → canonical device id (node id)
    # Same-chassis inference: IP-less L2 NICs that share an OUI where at least one
    # is switch infrastructure are LIKELY one physical device presenting two MACs
    # (e.g. a switch's STP control-plane MAC + its DHCP management interface). We
    # surface this as an explicit inference; we never merge the NICs, because the
    # packets prove two distinct MACs. [{oui, macs:[...]}]
    chassis_groups: list = field(default_factory=list)

    # ── Passive fingerprinting ───────────────────────────────────
    src_ip_ttl: dict = field(default_factory=dict)   # ip → first observed TTL

    # ── Raw timeline (chronologically sorted list of key events) ─
    timeline: list = field(default_factory=list)


class DataExtractor:
    """
    Single-pass aggregator: iterates RawPacketRecord stream and builds
    an ExtractionResult. Designed for streaming — call feed() per packet,
    then call finalize() when done.
    """

    def __init__(self):
        self._result = ExtractionResult()
        self._r = self._result  # shorthand

        # Internal accumulators
        self._proto_counts:    dict = defaultdict(int)
        self._dst_port_counts: dict = defaultdict(int)
        self._src_port_counts: dict = defaultdict(int)
        self._ip_src_counts:   dict = defaultdict(int)
        self._ip_dst_counts:   dict = defaultdict(int)
        self._flows:           dict = {}
        self._src_ip_ttl:      dict = {}

        # TCP half-open tracking: key=(src,dst,dport) → list of SYN timestamps
        self._syn_map:  dict = defaultdict(list)
        self._synack_map: set = set()
        self._fin_map:  set = set()

        # Proven service state: (ip, port, proto) → counters. See
        # ExtractionResult.service_exposure for the semantics.
        self._svc: dict = defaultdict(lambda: {
            "syn_in": 0, "synack": 0, "rst": 0, "sent": 0, "recv": 0,
            "clients": set(),
        })
        # Endpoints that were the destination of a flow's first packet.
        self._svc_server: set = set()

        self._first_ts: Optional[float] = None
        self._last_ts:  Optional[float] = None

        # Observed software banners: (source, value) → set of IPs
        self._banners: dict = defaultdict(set)

        # ARP accumulators
        self._arp_targets:     dict = defaultdict(set)   # sender_ip → {target_ip}
        self._arp_req_count:   dict = defaultdict(int)   # sender_ip → n requests
        self._arp_sender_macs: dict = defaultdict(set)   # sender_ip → {mac}
        self._arp_ip_macs:     dict = defaultdict(set)   # ip → {mac announcing it}
        self._arp_first_ts:    dict = {}                 # sender_ip → first req ts
        self._arp_last_ts:     dict = {}                 # sender_ip → last req ts
        self._arp_total:       int = 0
        self._arp_replies:     int = 0

        # Device inventory accumulators (keyed by transmitting NIC/MAC)
        self._mac_pkts:        dict = defaultdict(int)   # mac → frames sent
        self._mac_ips:         dict = defaultdict(set)   # mac → {IPs it sourced}
        self._mac_protos:      dict = defaultdict(set)   # mac → {display protocols}
        self._ip_mac_counts:   dict = defaultdict(lambda: defaultdict(int))  # ip → mac → n

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def feed(self, record: RawPacketRecord):
        """Process a single packet record."""
        r = self._r

        # ── Packet counters ──────────────────────────────────
        r.total_packets += 1
        r.total_bytes   += record.size

        ts = record.timestamp
        if self._first_ts is None or ts < self._first_ts:
            self._first_ts = ts
        if self._last_ts is None or ts > self._last_ts:
            self._last_ts = ts

        # ── Protocol ─────────────────────────────────────────
        # `proto` stays the transport/network class (TCP/UDP/ICMP/ARP) that the
        # detectors' flow logic depends on; the composition uses the most-specific
        # name (STP, DHCP, mDNS, …) so it matches Wireshark's protocol hierarchy.
        proto = record.protocol or "OTHER"
        self._proto_counts[record.display_protocol or proto] += 1

        # ── Device inventory (real transmitting NICs) ────────
        # The frame source MAC is the ground truth for "a device exists here".
        # Bind it to whatever IP the frame carried so a host's IPv4 + IPv6
        # collapse to one device, and probed-but-silent IPs never appear.
        if record.eth_src and record.eth_src not in ("ff:ff:ff:ff:ff:ff",):
            mac = record.eth_src
            self._mac_pkts[mac] += 1
            self._mac_protos[mac].add(record.display_protocol or proto)
            src_ip = record.src_ip or (record.arp_src_ip if record.is_arp else None)
            if src_ip and src_ip != "0.0.0.0":  # nosec B104 # DHCP-unspecified sentinel, not a socket bind
                self._mac_ips[mac].add(src_ip)
                self._ip_mac_counts[src_ip][mac] += 1

        # ── ARP (layer-2 host discovery / cache poisoning) ───
        if record.is_arp:
            self._feed_arp(record, ts)

        # ── IP ───────────────────────────────────────────────
        if record.src_ip:
            self._ip_src_counts[record.src_ip] += 1
            r.unique_src_ips.add(record.src_ip)
            if not is_private_ip(record.src_ip):
                r.external_ips.add(record.src_ip)
            if record.ttl and record.src_ip not in self._src_ip_ttl:
                self._src_ip_ttl[record.src_ip] = record.ttl

        if record.dst_ip:
            self._ip_dst_counts[record.dst_ip] += 1
            r.unique_dst_ips.add(record.dst_ip)
            if not is_private_ip(record.dst_ip):
                r.external_ips.add(record.dst_ip)

        # ── Ports ────────────────────────────────────────────
        if record.dst_port is not None:
            self._dst_port_counts[record.dst_port] += 1
        if record.src_port is not None:
            self._src_port_counts[record.src_port] += 1

        # ── Flow tracking ────────────────────────────────────
        if record.src_ip and record.dst_ip:
            fk = FlowKey(
                record.src_ip, record.dst_ip,
                record.src_port, record.dst_port,
                proto
            ).canonical()

            if fk not in self._flows:
                # The destination of a flow's *first* packet is the side that was
                # contacted — the only endpoint that can be a listening service.
                # (TCP is confirmed independently by SYN-ACK; this is what makes
                # UDP service detection possible without guessing by port range.)
                if record.dst_port is not None:
                    self._svc_server.add((record.dst_ip, record.dst_port, proto))
                self._flows[fk] = FlowStats(
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    src_port=record.src_port,
                    dst_port=record.dst_port,
                    protocol=proto,
                    service=record.service or "",
                    first_seen=ts,
                    last_seen=ts,
                )
            fs = self._flows[fk]
            fs.packets += 1
            fs.bytes_total += record.size
            fs.last_seen = max(fs.last_seen, ts)
            if record.tcp_flags:
                fs.tcp_flags_seen.add(record.tcp_flags)

        # ── Proven service exposure ───────────────────────────
        # Track each endpoint separately so we can tell a listening service
        # apart from an ephemeral client port, and prove open vs closed.
        if proto in ("TCP", "UDP") and record.src_ip and record.dst_ip:
            flags = record.tcp_flags or ""
            if record.dst_port is not None:
                d = self._svc[(record.dst_ip, record.dst_port, proto)]
                d["recv"] += 1
                # Bounded: we only ever report a client count and a few examples,
                # so a scan against one port cannot grow this without limit.
                if len(d["clients"]) < self._MAX_SVC_CLIENTS:
                    d["clients"].add(record.src_ip)
                if proto == "TCP" and "SYN" in flags and "ACK" not in flags:
                    d["syn_in"] += 1
            if record.src_port is not None:
                s = self._svc[(record.src_ip, record.src_port, proto)]
                s["sent"] += 1
                if proto == "TCP":
                    # A SYN-ACK can only come from something actually listening.
                    if "SYN" in flags and "ACK" in flags:
                        s["synack"] += 1
                    # A RST *from* the port is how a closed port refuses a SYN.
                    elif "RST" in flags:
                        s["rst"] += 1

        # ── TCP connection state ──────────────────────────────
        if proto == "TCP" and record.tcp_flags and record.src_ip:
            flags = record.tcp_flags
            key = (record.src_ip, record.dst_ip, record.dst_port)
            rkey = (record.dst_ip, record.src_ip, record.src_port)

            if "SYN" in flags and "ACK" not in flags:
                self._syn_map[key].append(ts)
            if "SYN" in flags and "ACK" in flags:
                self._synack_map.add(rkey)
            if "FIN" in flags or "RST" in flags:
                self._fin_map.add(key)

        # ── DNS ──────────────────────────────────────────────
        if record.has_dns and record.dns_qname:
            r.dns_queries.append({
                "ts":  ts,
                "src": record.src_ip,
                "dst": record.dst_ip,
                "qname": record.dns_qname,
                # mDNS / LLMNR / DNS — computed by the parser's display protocol
                "kind": record.display_protocol if record.display_protocol in ("mDNS", "LLMNR") else "DNS",
            })

        # ── HTTP ─────────────────────────────────────────────
        if record.has_http:
            if record.http_method:
                r.http_requests.append({
                    "ts":     ts,
                    "src":    record.src_ip,
                    "dst":    record.dst_ip,
                    "method": record.http_method,
                    "host":   record.http_host,
                    "path":   record.http_path,
                    "ua":     record.http_user_agent,
                })
                if record.http_user_agent:
                    self._banners[("http-user-agent", record.http_user_agent.strip()[:200])].add(record.src_ip)
            elif record.http_status:
                r.http_responses.append({
                    "ts":     ts,
                    "src":    record.src_ip,
                    "dst":    record.dst_ip,
                    "status": record.http_status,
                })
                if record.http_server:
                    self._banners[("http-server", record.http_server.strip()[:200])].add(record.src_ip)

    # MACs that never identify a real host — ignore for spoof/scan attribution.
    _NULL_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})

    def _feed_arp(self, record: RawPacketRecord, ts: float):
        """Accumulate ARP host-discovery and IP→MAC binding evidence."""
        self._arp_total += 1
        smac = record.arp_src_mac
        sip  = record.arp_src_ip
        tip  = record.arp_dst_ip

        # Every ARP frame (request or reply) announces the sender's own IP→MAC
        # binding; collecting these lets us spot one IP claimed by several MACs.
        if sip and sip != "0.0.0.0" and smac and smac not in self._NULL_MACS:  # nosec B104 # ARP sender-IP sentinel check, not a socket bind
            self._arp_ip_macs[sip].add(smac)

        if record.arp_op == 2:
            self._arp_replies += 1
            return

        # Requests (op == 1, and tolerate unknown ops) drive host-discovery scan
        # detection: one sender asking "who has X?" for many distinct targets.
        if sip and sip != "0.0.0.0" and tip and tip != sip:  # nosec B104 # ARP sender-IP sentinel check, not a socket bind
            self._arp_targets[sip].add(tip)
            self._arp_req_count[sip] += 1
            if smac and smac not in self._NULL_MACS:
                self._arp_sender_macs[sip].add(smac)
            if sip not in self._arp_first_ts:
                self._arp_first_ts[sip] = ts
            self._arp_last_ts[sip] = ts

    # Link-layer control protocols — a NIC that only ever emits these (and has no
    # IP) is switch/bridge infrastructure, not a host endpoint.
    _INFRA_PROTOS = {"STP", "CDP", "DTP", "VTP", "PVST", "LOOP", "SNAP", "ISL", "MRP"}
    # A single MAC fronting more than this many distinct IPs is a router/gateway
    # (or NAT), not one host — so its IPs must NOT be collapsed into one device.
    _GATEWAY_IP_FANOUT = 4
    # Cap on distinct client IPs remembered per exposed service (memory bound).
    _MAX_SVC_CLIENTS = 64

    @staticmethod
    def _canonical_ip(ips: set, ip_mac_counts: dict, mac: str) -> Optional[str]:
        """Pick the address that best names a device: a routable IPv4 first, then
        a global IPv6, falling back to link-local only if nothing else exists."""
        def _rank(ip: str) -> tuple:
            is_v6 = ":" in ip
            v4_ll = (not is_v6) and (ip.startswith("169.254.") or ip == "0.0.0.0")  # nosec B104 # link-local/unspecified rank, not a socket bind
            v6_ll = is_v6 and ip.lower().startswith("fe80")
            frames = ip_mac_counts.get(ip, {}).get(mac, 0)
            # lower tuple sorts first: prefer non-link-local, prefer IPv4, prefer busier
            return (v4_ll or v6_ll, is_v6, -frames, ip)
        return sorted(ips, key=_rank)[0] if ips else None

    def _build_device_inventory(self, r: ExtractionResult) -> None:
        """Reconstruct the real device inventory from transmitting NICs.

        A device is a MAC that actually sent a frame. Each device's IPv4/IPv6
        addresses collapse to one node; an IP that only ever appears as a probe
        *target* (ARP who-has / unanswered SYN) never becomes a device, because
        being asked about is not evidence of existence.
        """
        # IPs with evidence of existence: anything seen as a frame/ARP source.
        r.transmitted_ips = {
            ip for ip in (set(self._ip_src_counts) | set(self._arp_ip_macs))
            if ip and ip != "0.0.0.0"  # nosec B104 # DHCP-unspecified sentinel, not a socket bind
        }

        # IP → dominant source MAC (the NIC that sent the most frames for it).
        ip_to_mac: dict = {}
        for ip, macs in self._ip_mac_counts.items():
            if ip and ip != "0.0.0.0" and macs:  # nosec B104 # DHCP-unspecified sentinel, not a socket bind
                ip_to_mac[ip] = max(macs.items(), key=lambda kv: kv[1])[0]
        r.ip_to_mac  = ip_to_mac
        r.mac_to_ips = {m: set(ips) for m, ips in self._mac_ips.items()}

        # One device record per transmitting MAC, and the IP → device-id map the
        # graph uses to merge a host's addresses into a single node.
        devices: list = []
        ip_to_device: dict = {}
        for mac, pkts in sorted(self._mac_pkts.items(), key=lambda kv: -kv[1]):
            ips = set(self._mac_ips.get(mac, set()))
            protos = self._mac_protos.get(mac, set())
            gateway = len(ips) > self._GATEWAY_IP_FANOUT
            if not ips:
                kind = "infrastructure" if protos <= self._INFRA_PROTOS else "host"
                dev_id = mac
            elif gateway:
                kind = "gateway"
                dev_id = self._canonical_ip(ips, self._ip_mac_counts, mac) or mac
            else:
                kind = "endpoint"
                dev_id = self._canonical_ip(ips, self._ip_mac_counts, mac) or mac
            devices.append({
                "id": dev_id, "mac": mac, "ips": sorted(ips),
                "packets": pkts, "kind": kind,
                "protocols": sorted(protos),
                "chassis": None,   # set below if this NIC belongs to a chassis group
            })
            # A gateway fronts many hosts: keep those IPs as their own nodes.
            # A real endpoint: fold every one of its addresses onto the one node.
            if not gateway:
                for ip in ips:
                    ip_to_device[ip] = dev_id
        r.devices = devices
        r.ip_to_device = ip_to_device
        r.chassis_groups = self._infer_chassis_groups(devices)

    @staticmethod
    def _infer_chassis_groups(devices: list) -> list:
        """Flag NICs that are LIKELY the same physical device presenting two MACs.

        A managed switch commonly emits from two MACs on the same OUI — a
        control-plane MAC (STP/CDP/DTP) and a management interface (DHCP). The
        packets prove two distinct MACs, so these stay two separate NIC nodes;
        this is only an *inference* that they share a chassis, drawn from a
        conservative, evidence-backed signal:

          • same 24-bit OUI (same vendor block),
          • every member is an IP-less L2 device (kind 'infrastructure' or 'host'),
            so a routable endpoint PC of the same vendor is never swept in, and
          • at least one member is switch 'infrastructure'.

        Returns [{oui, macs:[...]}]; also stamps each grouped device['chassis'].
        """
        by_oui: dict = {}
        for d in devices:
            mac = d.get("mac") or ""
            if d.get("kind") in ("infrastructure", "host") and mac.count(":") >= 2:
                oui = ":".join(mac.split(":")[:3]).lower()
                by_oui.setdefault(oui, []).append(d)
        groups: list = []
        for oui, members in sorted(by_oui.items()):
            if len(members) >= 2 and any(m["kind"] == "infrastructure" for m in members):
                for m in members:
                    m["chassis"] = oui
                groups.append({"oui": oui, "macs": sorted(m["mac"] for m in members)})
        return groups

    def _resolve_service_exposure(self, r: ExtractionResult) -> None:
        """Decide, per host:port, whether the packets prove a service is there.

        Nothing here is inferred from the port number alone. A port is only
        "open" when it demonstrably answered; "closed" when it demonstrably
        refused; "filtered" when it was asked and stayed silent. Endpoints that
        are merely a client's ephemeral port resolve to no state and are dropped.
        """
        exposure: dict = {}
        for (ip, port, proto), c in self._svc.items():
            state = None
            if proto == "TCP":
                if c["synack"]:
                    state = "open"          # it completed a handshake: proven listening
                elif c["syn_in"] and c["rst"]:
                    state = "closed"        # it answered a SYN with RST: proven not listening
                elif c["syn_in"]:
                    state = "filtered"      # asked, never answered
            elif proto == "UDP" and (ip, port, proto) in self._svc_server:
                if c["recv"] and c["sent"]:
                    state = "open"          # it replied to traffic sent to it
                elif c["recv"]:
                    state = "filtered"      # sent to, never replied (or one-way by design)
            if state is None:
                continue
            exposure[(ip, port, proto)] = {
                "state":   state,
                "service": get_service_name(port),
                "sent":    c["sent"],
                "recv":    c["recv"],
                "clients": set(c["clients"]),
            }
        r.service_exposure = exposure

    def finalize(self) -> ExtractionResult:
        """Commit aggregated data into ExtractionResult and return it."""
        r = self._r

        r.capture_start     = self._first_ts or 0.0
        r.capture_end       = self._last_ts  or 0.0
        r.protocol_counts   = dict(self._proto_counts)
        r.dst_port_counts   = dict(self._dst_port_counts)
        r.src_port_counts   = dict(self._src_port_counts)
        r.ip_src_counts     = dict(self._ip_src_counts)
        r.ip_dst_counts     = dict(self._ip_dst_counts)
        r.flows             = self._flows

        # TCP connection counts
        r.open_connections      = sum(
            1 for k in self._syn_map if k not in self._synack_map
        )
        r.completed_connections = len(self._synack_map & set(self._syn_map.keys()))
        r.tcp_syn_pairs         = dict(self._syn_map)
        r.src_ip_ttl            = self._src_ip_ttl

        # ARP host-discovery / spoofing evidence
        r.arp_request_targets = {ip: set(t) for ip, t in self._arp_targets.items()}
        r.arp_request_counts  = dict(self._arp_req_count)
        r.arp_sender_macs     = {ip: set(m) for ip, m in self._arp_sender_macs.items()}
        r.arp_ip_to_macs      = {ip: set(m) for ip, m in self._arp_ip_macs.items()}
        r.arp_request_window  = {
            ip: (self._arp_first_ts[ip], self._arp_last_ts.get(ip, self._arp_first_ts[ip]))
            for ip in self._arp_first_ts
        }
        r.arp_total   = self._arp_total
        r.arp_replies = self._arp_replies

        # Device inventory — the true set of hosts that actually exist
        self._build_device_inventory(r)
        self._resolve_service_exposure(r)

        # Sort DNS / HTTP chronologically
        r.dns_queries    = sorted(r.dns_queries,    key=lambda x: x["ts"])
        r.http_requests  = sorted(r.http_requests,  key=lambda x: x["ts"])
        r.http_responses = sorted(r.http_responses, key=lambda x: x["ts"])

        # Materialize observed software banners (server software first — most CVE-relevant)
        r.software_banners = [
            {"source": src, "value": val, "ips": sorted(i for i in ips if i)}
            for (src, val), ips in self._banners.items()
        ]
        r.software_banners.sort(key=lambda b: (b["source"] != "http-server", b["value"].lower()))

        return r

    # ------------------------------------------------------------------ #
    #  Convenience summary builders (called by CLI / report engine)       #
    # ------------------------------------------------------------------ #

    @staticmethod
    def top_talkers(result: ExtractionResult, n: int = 10) -> list[dict]:
        """Return top N source IPs by packet count.

        Excludes the DHCP "unspecified" sentinel: a host booting without an
        address sends from 0.0.0.0, which is not a talker and listing it as one
        (with a scope and an OS guess) invents a host that does not exist.
        """
        sorted_ips = sorted(result.ip_src_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "packets": cnt} for ip, cnt in sorted_ips
                if ip not in _NON_HOST_IPS][:n]

    @staticmethod
    def top_destinations(result: ExtractionResult, n: int = 10) -> list[dict]:
        sorted_ips = sorted(result.ip_dst_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "packets": cnt} for ip, cnt in sorted_ips[:n]]

    @staticmethod
    def top_ports(result: ExtractionResult, n: int = 15) -> list[dict]:
        sorted_ports = sorted(result.dst_port_counts.items(), key=lambda x: x[1], reverse=True)
        from packetiq.utils.helpers import get_service_name
        return [
            {"port": port, "service": get_service_name(port), "packets": cnt}
            for port, cnt in sorted_ports[:n]
        ]

    @staticmethod
    def top_flows(result: ExtractionResult, n: int = 20) -> list[FlowStats]:
        """Return top N flows by byte volume."""
        sorted_flows = sorted(result.flows.values(), key=lambda f: f.bytes_total, reverse=True)
        return sorted_flows[:n]

    @staticmethod
    def capture_metadata(result: ExtractionResult) -> dict:
        """Summary dict for display in the panel."""
        duration = max(0.0, result.capture_end - result.capture_start)
        return {
            "Total Packets":     f"{result.total_packets:,}",
            "Total Bytes":       format_bytes(result.total_bytes),
            "Capture Start":     ts_to_str(result.capture_start) if result.capture_start else "N/A",
            "Capture End":       ts_to_str(result.capture_end)   if result.capture_end   else "N/A",
            "Duration":          format_duration(duration),
            "Unique Src IPs":    str(len(result.unique_src_ips)),
            "Unique Dst IPs":    str(len(result.unique_dst_ips)),
            "External IPs":      str(len(result.external_ips)),
            "Unique Flows":      str(len(result.flows)),
            "DNS Queries":       str(len(result.dns_queries)),
            "HTTP Requests":     str(len(result.http_requests)),
            "TCP Open (no 3WHS)": str(result.open_connections),
            "TCP Completed":     str(result.completed_connections),
        }
