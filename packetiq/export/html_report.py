"""
Standalone HTML report generator.

Produces a single self-contained .html file (inline CSS + an inline SVG network
graph — no external assets, no internet) from a completed analysis. Deterministic
and AI-free, so it works offline and in CI.

The report is "court-ready": it carries a chain-of-custody header (capture file
name/size/SHA-256, analysis time, tool version), an executive summary, a full
traffic-composition breakdown, top talkers / conversations / services, DNS &
HTTP activity, observed software banners, MITRE ATT&CK coverage, per-finding
explainability (why each finding was raised and the recommended action), a
consolidated analyst action list, and a print stylesheet so "Save as PDF"
produces a clean, paginated, light-on-white document.

Every section is derived solely from the captured evidence — no value is
inferred by a language model and nothing external is injected. The same capture
always yields the same report.
"""

from __future__ import annotations

import html
import math
from datetime import datetime

from packetiq.utils.helpers import (
    format_bytes,
    format_duration,
    get_service_name,
    is_private_ip,
)

_SEV_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#f59e0b", "MEDIUM": "#06b6d4", "LOW": "#22c55e"}
_PREC_COLOR = {"Confirmed": "#16a34a", "High": "#16a34a", "Probable": "#d97706", "Tentative": "#64748b"}
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _esc(v) -> str:
    return html.escape(str(v if v is not None else ""))


def _pct(part: float, whole: float) -> float:
    return (100.0 * part / whole) if whole else 0.0


def _service_for(port) -> str:
    """Human service name for a port number (falls back to the number)."""
    try:
        return get_service_name(int(port))
    except (TypeError, ValueError):
        return _esc(port)


def _os_hint(ttl) -> str:
    """Coarse passive OS family hint from an observed initial TTL (p0f-style).

    This is a heuristic lead, not a fact: observed TTLs are decremented per hop,
    so we bucket by the common initial values (64 / 128 / 255).
    """
    if not ttl:
        return "—"
    try:
        t = int(ttl)
    except (TypeError, ValueError):
        return "—"
    if t <= 64:
        return "Linux/Unix/macOS (TTL≤64)"
    if t <= 128:
        return "Windows (TTL≤128)"
    return "Router/appliance (TTL≤255)"


_GRAPH_ATTACK_EVENTS = {"PORT_SCAN", "HOST_SCAN", "ARP_SCAN", "ARP_SPOOFING",
                        "DOS_FLOOD", "BRUTE_FORCE", "HTTP_ATTACK"}


def _graphable(ip: str) -> bool:
    """Real endpoints only — drop broadcast/multicast/unspecified pseudo-hosts."""
    if not ip or ip in ("0.0.0.0", "255.255.255.255", "::", "::1"):  # nosec B104 - string comparison against pseudo-hosts, not a socket bind
        return False
    if ":" in ip:
        return not ip.lower().startswith("ff")
    o = ip.split(".")
    if len(o) == 4:
        try:
            if 224 <= int(o[0]) <= 239 or int(o[3]) == 255:
                return False
        except ValueError:
            return True
    return True


def _network_svg(result, events) -> str:
    """A real device-to-device network graph: one dot per physical host that
    ACTUALLY EXISTS in the capture (it transmitted a frame / answered ARP), with
    its IPv4 + IPv6 addresses merged to a single node. Probed-but-silent
    addresses are never drawn — a scanner's fan-out is shown as a count on the
    attacker, not as invented target dots. Hosts are coloured by role, with
    dashed-red arrowed scan/attack edges over the conversation edges."""
    ip_to_device = getattr(result, "ip_to_device", {}) or {}
    transmitted = getattr(result, "transmitted_ips", None)

    def node_of(ip: str) -> str:
        return ip_to_device.get(ip, ip)

    def exists(ip: str) -> bool:
        if not _graphable(ip):
            return False
        if not transmitted:      # inventory unavailable → fall back to graphability
            return True
        return ip in transmitted

    counts: dict = {}
    for ip, c in result.ip_src_counts.items():
        if exists(ip):
            counts[node_of(ip)] = counts.get(node_of(ip), 0) + c
    for ip, c in result.ip_dst_counts.items():
        if exists(ip):
            counts[node_of(ip)] = counts.get(node_of(ip), 0) + c
    # Seed every real IP device (incl. ARP-only hosts) from the inventory.
    for dev in (getattr(result, "devices", []) or []):
        if dev.get("kind") in ("endpoint", "gateway"):
            counts.setdefault(dev["id"], dev.get("packets", 0))

    attackers: set = set()
    targets: set = set()
    scan_stats: dict = {}
    for e in events:
        if e.event_type.value not in _GRAPH_ATTACK_EVENTS or not e.src_ip or not exists(e.src_ip):
            continue
        a = node_of(e.src_ip)
        attackers.add(a)
        probed: set = set()
        if e.dst_ip and _graphable(e.dst_ip):
            probed.add(e.dst_ip)
        for t in (getattr(e, "evidence", {}) or {}).get("sample_targets", []) or []:
            h = str(t).split(":")[0]
            if _graphable(h):
                probed.add(h)
        st = scan_stats.setdefault(a, {"scanned": set(), "alive": set()})
        for h in probed:
            st["scanned"].add(node_of(h))
            if exists(h):
                st["alive"].add(node_of(h))
                targets.add(node_of(h))
    for sender, tgts in (getattr(result, "arp_request_targets", {}) or {}).items():
        a = node_of(sender)
        if a in attackers:
            st = scan_stats.setdefault(a, {"scanned": set(), "alive": set()})
            for t in tgts:
                st["scanned"].add(node_of(t))
                if exists(t):
                    st["alive"].add(node_of(t))

    top = [n for n, _ in sorted(counts.items(), key=lambda x: -x[1])[:16]]
    for n in (attackers | targets):
        if n not in top:
            top.append(n)
    top = top[:20]

    # Real devices with no IP (a switch broadcasting STP/CDP, a host booting over
    # DHCP) — they exist on the segment, so include them for a complete topology.
    from packetiq.utils.helpers import oui_vendor
    infra_ids: list = []
    labels: dict = {}
    kinds: dict = {}
    for dev in (getattr(result, "devices", []) or []):
        did = str(dev["id"])
        if did in top or "." in did or ":" not in did:
            continue
        infra_ids.append(did)
        kinds[did] = dev.get("kind", "infrastructure")
        vendor = oui_vendor(dev.get("mac", ""))
        short = (dev.get("mac", "") or "")[-8:]
        if dev.get("kind") == "infrastructure":
            labels[did] = (f"{vendor} switch" if vendor else "Switch") + f" · {short}"
        else:
            protos = set(dev.get("protocols", []))
            base = f"{vendor} host" if vendor else "Host"
            labels[did] = base + (" (DHCP)" if "DHCP" in protos else " (no IP)")
    infra_ids = infra_ids[:6]

    if len(top) + len(infra_ids) < 2:
        return ("<p class='muted'>Only one active device observed in this capture — "
                "no host-to-host connections to graph.</p>")
    ring = top + infra_ids

    W = H = 560
    cx = cy = W / 2
    R = 210
    pos = {}
    for i, ip in enumerate(ring):
        ang = 2 * math.pi * i / len(ring) - math.pi / 2
        pos[ip] = (cx + R * math.cos(ang), cy + R * math.sin(ang))

    # conversation edges + attack/scan edges (all collapsed to device nodes)
    flow_edges: set = set()
    for fl in sorted(result.flows.values(), key=lambda f: -f.bytes_total):
        s, d = node_of(fl.src_ip), node_of(fl.dst_ip)
        if s in pos and d in pos and s != d and len(flow_edges) < 40:
            flow_edges.add((s, d))
    attack_edges: set = set()
    for e in events:
        if e.event_type.value not in _GRAPH_ATTACK_EVENTS or not e.src_ip or not exists(e.src_ip):
            continue
        s = node_of(e.src_ip)
        if s not in pos:
            continue
        dsts = {e.dst_ip} if e.dst_ip else set()
        for t in (getattr(e, "evidence", {}) or {}).get("sample_targets", []) or []:
            dsts.add(str(t).split(":")[0])
        for raw in dsts:
            d = node_of(raw)
            if d in pos and s != d and exists(raw):
                attack_edges.add((s, d))
    flow_edges -= attack_edges
    # L2-segment edges: one switch → every other device that shares its domain
    segment_edges: set = set()
    switch_ids = [i for i in infra_ids if kinds.get(i) == "infrastructure"]
    if len(switch_ids) == 1:
        sw = switch_ids[0]
        for other in ring:
            if other != sw and (other, sw) not in attack_edges:
                segment_edges.add((sw, other))

    parts = [f'<svg viewBox="0 0 {W} {H}" width="100%" style="max-width:620px">',
             '<defs><marker id="ah" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
             '<path d="M0,0 L7,3 L0,6 Z" fill="#dc2626"/></marker>'
             '<marker id="ahg" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">'
             '<path d="M0,0 L7,3 L0,6 Z" fill="#94a3b8"/></marker></defs>']

    def _edge(a, b, attack):
        x1, y1 = pos[a]; x2, y2 = pos[b]
        # shorten so the arrowhead sits at the node edge
        dx, dy = x2 - x1, y2 - y1
        d = math.hypot(dx, dy) or 1
        x2s, y2s = x2 - dx / d * 12, y2 - dy / d * 12
        if attack:
            return (f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2s:.0f}" y2="{y2s:.0f}" '
                    f'stroke="#dc2626" stroke-width="1.6" stroke-dasharray="5,4" opacity="0.6" marker-end="url(#ah)"/>')
        return (f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2s:.0f}" y2="{y2s:.0f}" '
                f'stroke="#94a3b8" stroke-width="1" opacity="0.4" marker-end="url(#ahg)"/>')

    # L2-segment links drawn first (faint, dotted, no arrow — a membership, not a flow)
    for a, b in segment_edges:
        x1, y1 = pos[a]; x2, y2 = pos[b]
        parts.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" '
                     f'stroke="#14b8a6" stroke-width="1" stroke-dasharray="2,4" opacity="0.4"/>')
    for a, b in flow_edges:
        parts.append(_edge(a, b, False))
    for a, b in attack_edges:
        parts.append(_edge(a, b, True))

    for ip, (x, y) in pos.items():
        is_infra = ip in infra_ids
        fill = ("#14b8a6" if is_infra else "#dc2626" if ip in attackers
                else "#f59e0b" if ip in targets
                else "#3b82f6" if is_private_ip(ip) else "#94a3b8")
        r = 6 + min(12, math.log10(max(counts.get(ip, 1), 1)) * 4)
        stroke = ' stroke="#fecaca" stroke-width="2"' if ip in attackers else ''
        if is_infra:
            s = r * 1.7
            parts.append(f'<rect x="{x - s / 2:.0f}" y="{y - s / 2:.0f}" width="{s:.0f}" height="{s:.0f}" '
                         f'rx="3" fill="{fill}" opacity="0.9"/>')
        else:
            parts.append(f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{r:.0f}" fill="{fill}" opacity="0.9"{stroke}/>')
        parts.append(f'<text x="{x:.0f}" y="{y - r - 4:.0f}" font-size="10" fill="#475569" '
                     f'text-anchor="middle">{_esc(labels.get(ip, ip))}</text>')
        st = scan_stats.get(ip)
        if st and st["scanned"]:
            parts.append(
                f'<text x="{x:.0f}" y="{y + r + 12:.0f}" font-size="9" fill="#dc2626" '
                f'text-anchor="middle">scanned {len(st["scanned"])} · {len(st["alive"])} live</text>')
    parts.append("</svg>")
    parts.append('<div class="legend"><span class="dot" style="background:#dc2626"></span>attacker '
                 '<span class="dot" style="background:#f59e0b"></span>target '
                 '<span class="dot" style="background:#3b82f6"></span>internal '
                 '<span class="dot" style="background:#14b8a6;border-radius:2px"></span>switch/infra '
                 '&nbsp;<span style="color:#dc2626">▬▶</span> scan/attack '
                 '<span style="color:#14b8a6">┈</span> L2 segment</div>')
    return "".join(parts)


# ── Traffic-composition sections (all grounded in ExtractionResult) ───────────

def _traffic_composition(result) -> str:
    protos = getattr(result, "protocol_counts", {}) or {}
    total_pkts = getattr(result, "total_packets", 0) or 0
    total_bytes = getattr(result, "total_bytes", 0) or 0
    dur = max(0.0, getattr(result, "capture_end", 0.0) - getattr(result, "capture_start", 0.0))

    total = sum(protos.values()) or 1
    rows = []
    for proto, cnt in sorted(protos.items(), key=lambda x: -x[1])[:12]:
        share = _pct(cnt, total)
        rows.append(
            f"<tr><td>{_esc(proto)}</td><td class='num'>{cnt:,}</td>"
            f"<td class='num'>{share:.1f}%</td>"
            f"<td class='barcell'><span class='bar' style='width:{min(100.0, share):.1f}%'></span></td></tr>"
        )
    tbl = (
        "<table><thead><tr><th>Protocol</th><th class='num'>Packets</th>"
        "<th class='num'>Share</th><th>Distribution</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows else "<p class='muted'>No protocol data extracted.</p>"
    )

    # Derived throughput / size / connection health
    avg_size = (total_bytes / total_pkts) if total_pkts else 0
    pps = (total_pkts / dur) if dur else 0.0
    bps = (total_bytes / dur) if dur else 0.0
    opened = getattr(result, "open_connections", 0) or 0
    completed = getattr(result, "completed_connections", 0) or 0
    attempts = opened + completed
    metrics = [
        f"average packet size <b>{avg_size:,.0f}</b> bytes",
        f"throughput <b>{pps:,.0f}</b> pkt/s (<b>{format_bytes(int(bps))}/s</b>)",
    ]
    if attempts:
        comp = _pct(completed, attempts)
        metrics.append(
            f"TCP handshakes <b>{completed:,}</b> completed / <b>{opened:,}</b> unanswered "
            f"(<b>{comp:.0f}%</b> completion"
            + (" — a low completion rate is consistent with scanning/SYN floods)" if comp < 40 else ")")
        )
    return tbl + f"<p class='muted' style='margin-top:8px'>{' · '.join(metrics)}.</p>"


_DEVICE_KIND_LABEL = {"endpoint": "Host", "gateway": "Gateway/Router",
                      "infrastructure": "Switch/Infra", "host": "Host (no IP)"}


def _device_inventory_table(result) -> str:
    """The real device inventory — one row per NIC that actually transmitted a
    frame, identified by MAC with vendor (OUI) and IP address(es). Grounded
    entirely in the capture: an address that was only *probed* never appears."""
    from packetiq.utils.helpers import oui_vendor
    devices = getattr(result, "devices", []) or []
    if not devices:
        return "<p class='muted'>No transmitting devices observed.</p>"
    rows = []
    for d in sorted(devices, key=lambda x: -x.get("packets", 0)):
        ips = ", ".join(ip for ip in d.get("ips", []) if ip) or "— (no IP)"
        vendor = oui_vendor(d.get("mac", "")) or "unknown"
        kind = _DEVICE_KIND_LABEL.get(d.get("kind", "endpoint"), "Host")
        protos = ", ".join(d.get("protocols", [])[:6])
        rows.append(
            f"<tr><td>{_esc(ips)}</td>"
            f"<td class='mono'>{_esc(d.get('mac', ''))}</td>"
            f"<td>{_esc(vendor)}</td>"
            f"<td><span class='pill'>{_esc(kind)}</span></td>"
            f"<td class='muted'>{_esc(protos)}</td>"
            f"<td class='num'>{d.get('packets', 0):,}</td></tr>"
        )
    n = len(devices)
    return (
        f"<p class='muted' style='margin-bottom:8px'>{n} physical "
        f"device{'s' if n != 1 else ''} transmitted in this capture "
        f"(identified by NIC/MAC; probed-but-silent addresses excluded).</p>"
        "<table><thead><tr><th>IP address(es)</th><th>MAC</th><th>Vendor</th>"
        "<th>Role</th><th>Protocols</th><th class='num'>Packets</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _top_talkers_table(result) -> str:
    src = getattr(result, "ip_src_counts", {}) or {}
    dst = getattr(result, "ip_dst_counts", {}) or {}
    ttl = getattr(result, "src_ip_ttl", {}) or {}
    combined: dict = {}
    for ip, c in src.items():
        combined[ip] = combined.get(ip, 0) + c
    for ip, c in dst.items():
        combined[ip] = combined.get(ip, 0) + c
    if not combined:
        return "<p class='muted'>No host activity recorded.</p>"
    total = sum(combined.values()) or 1
    rows = []
    for ip, tot in sorted(combined.items(), key=lambda x: -x[1])[:12]:
        scope = "internal" if is_private_ip(ip) else "external"
        rows.append(
            f"<tr><td>{_esc(ip)}</td>"
            f"<td><span class='pill'>{scope}</span></td>"
            f"<td class='num'>{src.get(ip, 0):,}</td>"
            f"<td class='num'>{dst.get(ip, 0):,}</td>"
            f"<td class='num'>{_pct(tot, total):.1f}%</td>"
            f"<td class='muted'>{_esc(_os_hint(ttl.get(ip)))}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Host</th><th>Scope</th><th class='num'>Sent</th>"
        "<th class='num'>Recv</th><th class='num'>Traffic</th><th>OS hint (passive)</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _conversations_table(result) -> str:
    flows = getattr(result, "flows", {}) or {}
    if not flows:
        return "<p class='muted'>No conversations recorded.</p>"
    top = sorted(flows.values(), key=lambda f: -getattr(f, "bytes_total", 0))[:15]
    rows = []
    for f in top:
        a = f"{f.src_ip}:{f.src_port}" if f.src_port else f.src_ip
        b = f"{f.dst_ip}:{f.dst_port}" if f.dst_port else f.dst_ip
        svc = f.service or _service_for(f.dst_port)
        rows.append(
            f"<tr><td>{_esc(a)}</td><td>{_esc(b)}</td><td>{_esc(f.protocol)}</td>"
            f"<td>{_esc(svc)}</td><td class='num'>{f.packets:,}</td>"
            f"<td class='num'>{format_bytes(f.bytes_total)}</td>"
            f"<td class='num'>{format_duration(f.duration)}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Source</th><th>Destination</th><th>Proto</th><th>Service</th>"
        "<th class='num'>Packets</th><th class='num'>Bytes</th><th class='num'>Duration</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _services_table(result) -> str:
    ports = getattr(result, "dst_port_counts", {}) or {}
    if not ports:
        return ""
    total = sum(ports.values()) or 1
    rows = []
    for p, c in sorted(ports.items(), key=lambda x: -x[1])[:15]:
        rows.append(
            f"<tr><td class='num'>{_esc(p)}</td><td>{_esc(_service_for(p))}</td>"
            f"<td class='num'>{c:,}</td><td class='num'>{_pct(c, total):.1f}%</td></tr>"
        )
    return (
        "<h2>Service &amp; port usage</h2>"
        "<table><thead><tr><th class='num'>Port</th><th>Service</th>"
        "<th class='num'>Packets</th><th class='num'>Share</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _dns_table(result) -> str:
    q = getattr(result, "dns_queries", []) or []
    counts: dict = {}
    kinds: dict = {}
    kind_totals: dict = {"DNS": 0, "mDNS": 0, "LLMNR": 0}
    for item in q:
        if not isinstance(item, dict):
            continue
        name = item.get("qname", "")
        if not name:
            continue
        kind = item.get("kind", "DNS")
        counts[name] = counts.get(name, 0) + 1
        kinds[name] = kind
        kind_totals[kind] = kind_totals.get(kind, 0) + 1
    if not counts:
        return ""
    rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{_esc(kinds.get(name, 'DNS'))}</td><td class='num'>{c:,}</td></tr>"
        for name, c in sorted(counts.items(), key=lambda x: -x[1])[:20]
    )
    # Distinguish real name resolution (unicast DNS) from local service discovery.
    breakdown = ", ".join(f"{v} {k}" for k, v in kind_totals.items() if v)
    note = ""
    if kind_totals.get("DNS", 0) == 0 and (kind_totals.get("mDNS", 0) or kind_totals.get("LLMNR", 0)):
        note = ("<p class='muted'>All queries are local service discovery (mDNS/LLMNR on the local segment) — "
                "no unicast DNS name resolution to an external resolver was observed in this capture.</p>")
    return (
        f"<h2>DNS activity ({len(counts)} unique names, {len(q):,} queries — {breakdown})</h2>"
        "<table><thead><tr><th>Queried name</th><th>Type</th><th class='num'>Count</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>{note}"
    )


def _http_table(result) -> str:
    reqs = getattr(result, "http_requests", []) or []
    if not reqs:
        return ""
    rows = []
    for r in reqs[:25]:
        if not isinstance(r, dict):
            continue
        host = r.get("host", "") or ""
        path = r.get("path", "") or ""
        rows.append(
            f"<tr><td>{_esc(r.get('method', ''))}</td><td>{_esc(host)}</td>"
            f"<td>{_esc(path[:80])}</td><td>{_esc(r.get('src', ''))}</td></tr>"
        )
    more = f"<p class='muted'>… and {len(reqs) - 25:,} more request(s).</p>" if len(reqs) > 25 else ""
    return (
        f"<h2>HTTP activity ({len(reqs):,} request(s))</h2>"
        "<table><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Source</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>{more}"
    )


def _software_table(result) -> str:
    banners = getattr(result, "software_banners", []) or []
    if not banners:
        return ""
    rows = []
    for b in banners[:25]:
        if not isinstance(b, dict):
            continue
        ips = ", ".join(b.get("ips", []) or [])
        rows.append(
            f"<tr><td>{_esc(b.get('source', ''))}</td><td>{_esc(b.get('value', ''))}</td>"
            f"<td class='muted'>{_esc(ips)}</td></tr>"
        )
    return (
        "<h2>Observed software (passive banners)</h2>"
        "<p class='muted'>Version strings seen on the wire — the basis for the CVE lookup. "
        "Nothing is inferred; only banners actually present in the traffic are listed.</p>"
        "<table><thead><tr><th>Source</th><th>Banner</th><th>Host(s)</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _attribution_html(attrs) -> str:
    if not attrs:
        return ""
    out = [
        "<h2>Threat-actor TTP overlap</h2>",
        "<p class='muted'>Behavioural overlap between the techniques observed here and documented "
        "threat-actor profiles. This is a <b>similarity score, not an attribution</b> — many actors "
        "share techniques, so treat this as an investigative lead only.</p>",
    ]
    for a in attrs[:5]:
        name = getattr(a, "actor_name", "?")
        conf = round((getattr(a, "confidence", 0.0) or 0.0) * 100)
        origin = getattr(a, "origin", "") or ""
        motive = getattr(a, "motivation", "") or ""
        desc = getattr(a, "description", "") or ""
        ttps = ", ".join(
            (getattr(t, "value", t) if not isinstance(t, str) else t).replace("_", " ")
            for t in (getattr(a, "matched_ttps", []) or [])
        )
        aliases = ", ".join(getattr(a, "aliases", []) or [])
        meta = " · ".join(x for x in (origin, motive, (f"aka {aliases}" if aliases else "")) if x)
        out.append(
            f"<div class='finding'><h3>{_esc(name)} "
            f"<span class='pill'>TTP overlap {conf}%</span></h3>"
            + (f"<p class='muted'>{_esc(meta)}</p>" if meta else "")
            + (f"<p>{_esc(desc)}</p>" if desc else "")
            + (f"<p class='muted'>Matched techniques: {_esc(ttps)}</p>" if ttps else "")
            + "</div>"
        )
    return "\n".join(out)


def _recommendations(events, chains) -> str:
    if not events:
        return (
            "<div class='summary' style='border-left-color:#22c55e'>No malicious activity was detected. "
            "Retain this capture and its SHA-256 for the case record; no containment action is indicated "
            "by this analysis.</div>"
        )
    from packetiq import triage

    high = [e for e in events if e.severity.value in ("CRITICAL", "HIGH")]
    focus = high or events
    internal = sorted({e.dst_ip for e in focus if e.dst_ip and is_private_ip(e.dst_ip)} |
                      {e.src_ip for e in focus if e.src_ip and is_private_ip(e.src_ip)})
    external = sorted({e.dst_ip for e in focus if e.dst_ip and not is_private_ip(e.dst_ip)} |
                      {e.src_ip for e in focus if e.src_ip and not is_private_ip(e.src_ip)})

    steps = []
    if internal:
        steps.append(
            f"<b>Contain &amp; triage</b> the involved internal host(s) — "
            f"{_esc(', '.join(internal[:8]))}: isolate from the network, preserve volatile memory, "
            "and review for persistence and lateral movement."
        )
    if external:
        steps.append(
            f"<b>Block &amp; hunt</b> the external indicator(s) at the perimeter — "
            f"{_esc(', '.join(external[:8]))}: add to firewall/EDR blocklists and search historical "
            "logs for prior contact. Confirm each is not shared infrastructure (CDN/hoster) first."
        )
    if chains:
        steps.append(
            f"<b>Reconstruct the incident</b>: {len(chains)} multi-stage chain(s) were correlated — "
            "walk the kill-chain timeline to scope the full intrusion before closing."
        )
    steps.append(
        "<b>Preserve evidence</b>: keep the original capture and this report (with its SHA-256) "
        "for the case record and any downstream escalation."
    )

    # Deduplicated per-finding recommendations, highest severity first.
    tips, seen = [], set()
    for e in sorted(events, key=lambda ev: -_SEV_RANK.get(ev.severity.value, 0)):
        et = e.event_type.value
        if et in seen:
            continue
        seen.add(et)
        rec = triage.explain(e).get("recommendation")
        if rec:
            tips.append(f"<b>{_esc(et.replace('_', ' '))}:</b> {_esc(rec)}")
        if len(tips) >= 8:
            break

    ol = "".join(f"<li>{s}</li>" for s in steps)
    ul = "".join(f"<li>{t}</li>" for t in tips)
    return (
        f"<ol class='recs'>{ol}</ol>"
        + (f"<p class='muted'>Recommended handling by finding type:</p><ul class='recs'>{ul}</ul>" if ul else "")
    )


def _methodology() -> str:
    from packetiq.export import report_style as st
    return (
        "<div class='summary' style='border-left-color:#3b82f6'>"
        "<p><b>Scope &amp; method.</b> " + _esc(st.METHODOLOGY) + "</p>"
        "<p>Each finding is additionally graded for <i>precision</i> (Confirmed / Probable / "
        "Tentative), reflecting evidentiary strength. The report is reproducible: the same "
        "capture always yields the same report.</p>"
        "</div>"
    )


def _limitations(attrs=None) -> str:
    """The same assurance statement the PDF carries — one house style, one caveat."""
    from packetiq.export import report_style as st
    blocks = ["<p>" + _esc(st.LIMITATIONS) + "</p>"]
    if attrs:
        blocks.append("<p><b>" + _esc(st.ATTRIBUTION_CAVEAT) + "</b></p>")
    return "<div class='summary' style='border-left-color:#94a3b8'>" + "".join(blocks) + "</div>"


def _doc_header(file_meta, risk, events, chains, generated, pcap_sha256, tool_version,
                analyst, risk_color) -> str:
    """Cover block: identity, verdict band and document details — mirrors the PDF cover."""
    from packetiq.export import report_style as st
    fname = file_meta.get("filename", "capture")
    rid = st.report_id(fname, pcap_sha256 or "")

    def row(k, v):
        return f"<tr><td class='cl'>{_esc(k)}</td><td class='cv'>{v}</td></tr>"

    details = "".join([
        row("Report reference", f"<code>{_esc(rid)}</code>"),
        row("Generated", _esc(generated)),
        row("Evidence file", f"<code>{_esc(fname)}</code>"),
        row("Evidence SHA-256", f"<code>{_esc(pcap_sha256)}</code>" if pcap_sha256
            else "<span class='muted'>not computed</span>"),
        row("Analyst", _esc(analyst) if analyst else "<span class='muted'>—</span>"),
        row("Produced by", f"{_esc(st.BRAND)} v{_esc(tool_version)} — automated analysis"),
        row("Classification", _esc(st.CLASSIFICATION)),
    ])

    return f"""
  <div class="cover">
    <div class="eyebrow">{_esc(st.BRAND.upper())}</div>
    <h1>{_esc(st.DOC_TITLE)}</h1>
    <p class="cover-file">{_esc(fname)}</p>
    <div class="band" style="background:{risk_color}">
      <div class="bstat"><div class="bl">OVERALL RISK</div><div class="bv">{risk.score}<span>/100</span></div></div>
      <div class="bstat"><div class="bl">SEVERITY TIER</div><div class="bv">{_esc(risk.tier)}</div></div>
      <div class="bstat"><div class="bl">FINDINGS</div><div class="bv">{len(events)}<span>&nbsp;in {len(chains)} chain(s)</span></div></div>
    </div>
    <p class="muted cover-sum">{_esc(risk.summary)}</p>
    <div class="custody"><table>{details}</table></div>
    <p class="foot cover-note">This document was generated automatically from the named evidence file.
      The findings it contains are the output of deterministic detectors and reputation lookups; they
      require analyst validation before they are relied upon. See <b>Limitations &amp; assurance</b> at
      the end of this report.</p>
  </div>"""


def _events_rows(events) -> str:
    from packetiq import triage
    rows = []
    for e in events:
        c = _SEV_COLOR.get(e.severity.value, "#94a3b8")
        prec = triage.precision(e)
        pc = _PREC_COLOR.get(prec, "#64748b")
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        rows.append(
            f"<tr><td><span class='badge' style='background:{c}'>{_esc(e.severity.value)}</span></td>"
            f"<td><span class='pill' style='color:{pc};border-color:{pc}'>{_esc(prec)}</span></td>"
            f"<td>{_esc(e.event_type.value.replace('_',' '))}</td>"
            f"<td>{_esc(e.src_ip or '—')}</td><td>{_esc(dst)}</td>"
            f"<td>{int(round(float(e.confidence or 0)*100))}%</td>"
            f"<td>{_esc(e.description)}</td></tr>"
        )
    return "\n".join(rows) or "<tr><td colspan='7' class='muted'>No threats detected.</td></tr>"


def _findings_detail(events) -> str:
    """Per-finding explainability — why it was raised + recommended action."""
    from packetiq import triage
    if not events:
        return "<p class='muted'>No findings to detail.</p>"
    out = []
    for i, e in enumerate(events[:40], 1):
        ex = triage.explain(e)
        c = _SEV_COLOR.get(e.severity.value, "#94a3b8")
        pc = _PREC_COLOR.get(ex["precision"], "#64748b")
        evp = "".join(f"<li>{_esc(p)}</li>" for p in ex["evidence_points"])
        mitre = ", ".join(f"{m['id']} {m['name']}" for m in ex["mitre"])
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        out.append(
            f"<div class='finding'>"
            f"<h3>{i}. {_esc(e.event_type.value.replace('_',' '))} "
            f"<span class='badge' style='background:{c}'>{_esc(e.severity.value)}</span> "
            f"<span class='pill' style='color:{pc};border-color:{pc}'>{_esc(ex['precision'])} · {ex['confidence_pct']}%</span></h3>"
            f"<p class='muted'>{_esc(e.src_ip or '—')} → {_esc(dst)} · {_esc(ex['kill_chain_phase'])}</p>"
            f"<p><b>What:</b> {_esc(ex['what'])}</p>"
            f"<p><b>Why it matters:</b> {_esc(ex['why'])}</p>"
            + (f"<p><b>Evidence:</b></p><ul>{evp}</ul>" if evp else "")
            + f"<p class='rec'><b>Recommended action:</b> {_esc(ex['recommendation'])}</p>"
            + (f"<p class='muted'>MITRE: {_esc(mitre)}</p>" if mitre else "")
            + "</div>"
        )
    if len(events) > 40:
        out.append(f"<p class='muted'>… and {len(events) - 40} more finding(s) in the events table above.</p>")
    return "\n".join(out)


def _attack_coverage_html(events) -> str:
    from packetiq.export.attack_navigator import coverage
    cov = coverage(events)
    if not cov:
        return "<p class='muted'>No ATT&CK techniques mapped.</p>"
    by_tactic: dict = {}
    for t in cov:
        by_tactic.setdefault(t["tactic"], []).append(t)
    cols = []
    for tactic, techs in by_tactic.items():
        cells = "".join(
            f"<div class='tcell' style='border-left:3px solid {_SEV_COLOR.get(t['severity'],'#888')}'>"
            f"<b>{_esc(t['id'])}</b> <span class='muted'>×{t['count']}</span><br>{_esc(t['name'])}</div>"
            for t in techs
        )
        cols.append(f"<div class='tcol'><div class='thead'>{_esc(tactic)}</div>{cells}</div>")
    return f"<div class='matrix'>{''.join(cols)}</div>"


def _predictions_html(result, events) -> str:
    """Grounded attack forecast — possible attacks given exposure & behaviour."""
    try:
        from packetiq import prediction
        preds = prediction.predict(result, events)
    except Exception:
        preds = []
    if not preds:
        return "<p class='muted'>No specific attack exposure predicted from the observed services and behaviour.</p>"
    intro = ("<p class='muted'>A forecast of attacks this capture is <em>exposed to</em>, derived from the "
             "observed services and behaviour — possible attacks, not confirmed events. Each rests on the "
             "evidence listed.</p>")
    blocks = []
    for p in preds:
        ev = "".join(f"<li>{_esc(e)}</li>" for e in (p.evidence or []))
        mitre = " ".join(f"<span class='muted'>{_esc(m)}</span>" for m in (p.mitre or []))
        blocks.append(
            f"<div class='finding' style='border-left:3px solid {_SEV_COLOR.get(p.severity, '#888')}'>"
            f"<b>{_esc(p.attack)}</b> — <span class='muted'>{_esc(p.likelihood)} likelihood · {_esc(p.severity)} impact · {_esc(p.category)}</span>"
            f"<br>{_esc(p.rationale)}"
            f"<ul>{ev}</ul>"
            f"<div><b>Recommended:</b> {_esc(p.recommendation)}</div>"
            f"<div style='margin-top:4px'>{mitre}</div></div>"
        )
    return intro + "".join(blocks)


def _chains_html(chains) -> str:
    if not chains:
        return "<p class='muted'>No multi-stage attack chains correlated.</p>"
    out = []
    for i, c in enumerate(chains, 1):
        techs = ", ".join(f"{t.technique_id}" for t in c.mitre_techniques[:8])
        phases = " → ".join(c.kill_chain_phases) if c.kill_chain_phases else "—"
        out.append(
            f"<div class='chain'><h3>{i}. {_esc(c.name)} "
            f"<span class='pill'>{_esc(c.severity.value)}</span> "
            f"<span class='pill'>{int(c.confidence*100)}%</span></h3>"
            f"<p>{_esc(c.description)}</p>"
            f"<p class='muted'>Kill chain: {_esc(phases)}<br>MITRE: {_esc(techs)}</p>"
            + (f"<p class='note'>{_esc(c.analyst_note)}</p>" if c.analyst_note else "")
            + "</div>"
        )
    return "\n".join(out)


_ATTACKER_EVENTS = {"PORT_SCAN", "HOST_SCAN", "ARP_SCAN", "ARP_SPOOFING",
                    "DOS_FLOOD", "BRUTE_FORCE", "HTTP_ATTACK"}


def _iocs_html(events, result) -> str:
    """Indicators extracted from flagged traffic — external threat-intel IOCs
    AND internal hosts of interest (attackers/scanners), so an internal pentest
    is not reported as 'no IOCs'."""
    if not events:
        return "<p class='muted'>No indicators extracted.</p>"
    rows, seen = [], set()
    for e in events:
        sev = e.severity.value
        etype = e.event_type.value.replace("_", " ")
        ev = getattr(e, "evidence", {}) or {}
        # External indicators (classic threat-intel IOCs)
        for ip in (e.dst_ip, e.src_ip):
            if ip and not is_private_ip(ip) and ("ip", ip) not in seen:
                seen.add(("ip", ip))
                rows.append((ip, "IPv4 (external)", etype, sev))
        dom = ev.get("domain") or (ev.get("indicator") if ev.get("kind") == "domain" else None)
        if dom and ("dom", dom) not in seen:
            seen.add(("dom", dom))
            rows.append((dom, "Domain", etype, sev))
        h = ev.get("sha256") or ev.get("md5") or ev.get("hash")
        if h and ("h", h) not in seen:
            seen.add(("h", h))
            rows.append((h, "File hash", etype, sev))
        # Internal hosts of interest — the attacker/scanner sources
        if e.event_type.value in _ATTACKER_EVENTS and e.src_ip and ("host", e.src_ip) not in seen:
            seen.add(("host", e.src_ip))
            rows.append((e.src_ip, "Internal host (attacker)", etype, sev))
        mac = ev.get("sender_mac") or ev.get("conflicting_macs")
        if mac and ("mac", mac) not in seen:
            seen.add(("mac", mac))
            rows.append((mac, "MAC address", etype, sev))
    if not rows:
        return "<p class='muted'>No indicators extracted.</p>"
    rows.sort(key=lambda r: -_SEV_RANK.get(r[3], 0))
    body = "".join(
        f"<tr><td><code>{_esc(ind)}</code></td><td>{_esc(kind)}</td><td>{_esc(src)}</td>"
        f"<td><span class='badge' style='background:{_SEV_COLOR.get(sev,'#94a3b8')}'>{_esc(sev)}</span></td></tr>"
        for ind, kind, src, sev in rows[:60]
    )
    return (
        "<table><thead><tr><th>Indicator</th><th>Type</th><th>First flagged by</th>"
        "<th>Severity</th></tr></thead>"
        f"<tbody>{body}</tbody></table>"
        "<p class='muted'>Indicators are extracted from flagged traffic only. External IPs may be shared "
        "infrastructure (CDN / hoster); internal hosts of interest are the sources of scanning/attack "
        "behaviour on your own network — validate against the raw capture before acting.</p>"
    )


def _exec_summary(file_meta, result, events, chains, risk) -> str:
    sev = risk.by_severity or {}
    from collections import Counter
    top_types = Counter(e.event_type.value.replace("_", " ") for e in events
                        if e.severity.value in ("CRITICAL", "HIGH"))
    top = ", ".join(t for t, _ in top_types.most_common(3)) or "no high-severity findings"
    protos = getattr(result, "protocol_counts", {}) or {}
    proto_str = ", ".join(f"{p}" for p, _ in sorted(protos.items(), key=lambda x: -x[1])[:4]) or "—"
    ext = getattr(result, "external_ips", set()) or set()
    return (
        f"PacketIQ analysed <b>{_esc(file_meta.get('filename',''))}</b> "
        f"({result.total_packets:,} packets, {format_bytes(getattr(result, 'total_bytes', 0))}, over "
        f"{format_duration(max(0.0, result.capture_end - result.capture_start))}). "
        f"Traffic was predominantly {_esc(proto_str)} across {len(getattr(result, 'flows', {}) or {}):,} "
        f"conversation(s) with {len(ext):,} external host(s). "
        f"The overall risk is <b>{risk.score}/100 ({_esc(risk.tier)})</b>. "
        f"A total of <b>{len(events)} finding(s)</b> were raised "
        f"({sev.get('CRITICAL',0)} critical, {sev.get('HIGH',0)} high, "
        f"{sev.get('MEDIUM',0)} medium, {sev.get('LOW',0)} low), correlated into "
        f"<b>{len(chains)} attack chain(s)</b>. Principal concerns: <b>{_esc(top)}</b>. "
        f"Every finding below is evidence-backed and graded for precision; see the "
        f"detailed analysis for the reasoning and recommended actions."
    )


def _vulns_html(vulns: dict) -> str:
    """Optional vulnerability section (NVD CPE + CVSS + CISA KEV) — only rendered
    when an assessment is supplied (it requires a network lookup)."""
    if not vulns or not vulns.get("products"):
        return ""
    rk = vulns.get("risk", {})
    tot = vulns.get("totals", {})
    out = [f"<p><b>Vulnerability risk:</b> {rk.get('score', 0)}/100 ({_esc(rk.get('tier', ''))}) · "
           f"{tot.get('cves', 0)} CVE(s), {tot.get('kev', 0)} actively exploited (CISA KEV).</p>"]
    for c in vulns.get("correlations", []):
        out.append(f"<p class='note'>⚡ Exploit attempt for {_esc(c.get('name'))} "
                   f"({_esc(', '.join(c.get('cves', [])))}) → target {_esc(c.get('target'))}"
                   + (f" — runs {_esc(', '.join(c.get('target_software', [])))}" if c.get("target_software") else "") + "</p>")
    for p in vulns["products"]:
        rows = "".join(
            f"<tr><td>{_esc(c['id'])}</td><td>{_esc(c['cvss'])}</td><td>{_esc(c['severity'])}</td>"
            f"<td>{'KEV' if c.get('kev') else ''}{' · ransomware' if c.get('ransomware') else ''}</td></tr>"
            for c in p.get("cves", [])) or "<tr><td colspan='4' class='muted'>No CVEs.</td></tr>"
        out.append(
            f"<div class='finding'><h3>{_esc(p['product'])} {_esc(p['version'])} "
            f"<span class='pill'>{len(p.get('cves', []))} CVE(s)</span></h3>"
            f"<p class='muted'>{_esc(p.get('source', ''))} · CPE {_esc(p.get('cpe') or 'n/a')} · "
            f"hosts {_esc(', '.join(p.get('ips', [])))}</p>"
            f"<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>Status</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div>")
    return "\n".join(out)


def build_html(file_meta: dict, result, events, chains, risk, attrs=None,
               *, pcap_sha256: str | None = None, tool_version: str = "1.0.0",
               analyst: str | None = None, vulns: dict | None = None) -> str:
    risk_color = _SEV_COLOR.get(risk.tier, "#94a3b8")
    dur = max(0.0, result.capture_end - result.capture_start)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    sev_counts = risk.by_severity or {}

    def stat(label, val):
        return f"<div class='stat'><div class='v'>{_esc(val)}</div><div class='l'>{label}</div></div>"

    stats = "".join([
        stat("Packets", f"{result.total_packets:,}"),
        stat("Bytes", format_bytes(result.total_bytes)),
        stat("Duration", format_duration(dur)),
        stat("Flows", f"{len(result.flows):,}"),
        stat("External IPs", len(result.external_ips)),
        stat("Events", len(events)),
        stat("Chains", len(chains)),
    ])

    def coc(label, val):
        return f"<tr><td class='cl'>{_esc(label)}</td><td class='cv'>{val}</td></tr>"

    custody = "".join([
        coc("Capture file", _esc(file_meta.get("filename", "—"))),
        coc("File size", _esc(format_bytes(result.total_bytes))),
        coc("SHA-256", f"<code>{_esc(pcap_sha256)}</code>" if pcap_sha256 else "<span class='muted'>not computed</span>"),
        coc("Capture window", f"{_esc(datetime.fromtimestamp(result.capture_start).strftime('%Y-%m-%d %H:%M:%S')) if result.capture_start else '—'} → "
                              f"{_esc(datetime.fromtimestamp(result.capture_end).strftime('%Y-%m-%d %H:%M:%S')) if result.capture_end else '—'}"),
        coc("Analysed", _esc(generated)),
        coc("Analyst", _esc(analyst) if analyst else "<span class='muted'>—</span>"),
        coc("Tool", f"PacketIQ v{_esc(tool_version)}"),
    ])

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PacketIQ Report — {_esc(file_meta.get('filename',''))}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0; background:#0b0f1a; color:#e2e8f0; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 24px; counter-reset: sec; }}
  h1 {{ font-size: 30px; line-height:1.15; margin: 0 0 6px; letter-spacing:-.01em; }}
  /* Sections number themselves, so the document always reads as a report. */
  h2 {{ font-size: 16px; margin: 30px 0 10px; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }}
  .wrap > h2::before {{ counter-increment: sec; content: counter(sec) ". "; color:#60a5fa; font-weight:700; }}
  h3 {{ font-size: 14px; margin: 0 0 6px; }}
  /* ── Cover block ─────────────────────────────────────────────── */
  .cover {{ border-bottom:2px solid #1e293b; padding-bottom:18px; margin-bottom:6px; }}
  .cover .eyebrow {{ font-size:11px; font-weight:700; letter-spacing:.14em; color:#60a5fa; margin-bottom:6px; }}
  .cover-file {{ font-size:14px; color:#94a3b8; margin:0 0 18px; }}
  .cover-sum {{ font-size:13px; line-height:1.55; margin:10px 0 16px; }}
  .cover-note {{ margin-top:14px; }}
  .band {{ display:flex; flex-wrap:wrap; gap:0; border-radius:10px; overflow:hidden;
           -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .bstat {{ flex:1 1 150px; padding:14px 18px; color:#fff; }}
  .bstat .bl {{ font-size:10px; font-weight:700; letter-spacing:.09em; opacity:.85; }}
  .bstat .bv {{ font-size:26px; font-weight:700; line-height:1.2; }}
  .bstat .bv span {{ font-size:12px; font-weight:600; opacity:.85; }}
  .muted {{ color:#94a3b8; }} .note {{ color:#fbbf24; font-size:13px; }} .rec {{ color:#34d399; }}
  .risk {{ display:inline-block; padding:6px 14px; border-radius:8px; font-weight:700; color:#fff; background:{risk_color}; }}
  .summary {{ background:#111827; border:1px solid #1e293b; border-left:4px solid {risk_color}; border-radius:10px; padding:14px 16px; margin:14px 0; font-size:13px; line-height:1.5; }}
  .custody {{ background:#0d1424; border:1px solid #1e293b; border-radius:10px; padding:6px 14px; margin:12px 0; }}
  .custody td {{ padding:5px 8px; border-bottom:1px solid #16203400; font-size:12px; }}
  .custody .cl {{ color:#94a3b8; width:140px; }} .custody .cv {{ color:#e2e8f0; }}
  .stats {{ display:flex; flex-wrap:wrap; gap:12px; margin:16px 0; }}
  .stat {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:12px 16px; min-width:90px; }}
  .stat .v {{ font-size:20px; font-weight:700; }} .stat .l {{ font-size:11px; color:#94a3b8; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th, td {{ text-align:left; padding:7px 8px; border-bottom:1px solid #1e293b; vertical-align:top; }}
  th {{ color:#94a3b8; font-weight:600; }}
  td.num, th.num {{ text-align:right; font-variant-numeric: tabular-nums; white-space:nowrap; }}
  .barcell {{ width:38%; min-width:120px; }}
  .bar {{ display:inline-block; height:10px; min-width:2px; background:#3b82f6; border-radius:3px; vertical-align:middle;
          -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .badge {{ color:#fff; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700;
            -webkit-print-color-adjust:exact; print-color-adjust:exact; }}
  .pill {{ background:#1e293b; color:#cbd5e1; padding:2px 8px; border-radius:10px; font-size:11px; border:1px solid #334155; }}
  .chain, .finding {{ background:#111827; border:1px solid #1e293b; border-radius:10px; padding:12px 16px; margin-bottom:10px; }}
  .finding p {{ margin:5px 0; font-size:13px; }} .finding ul {{ margin:4px 0 4px 18px; color:#cbd5e1; font-size:12px; }}
  ol.recs, ul.recs {{ margin:6px 0 6px 20px; font-size:13px; line-height:1.5; }}
  ol.recs li, ul.recs li {{ margin:6px 0; }}
  .matrix {{ display:flex; gap:8px; overflow-x:auto; }}
  .tcol {{ min-width:150px; flex:1; }}
  .thead {{ font-size:11px; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:.04em; padding-bottom:6px; border-bottom:1px solid #1e293b; margin-bottom:6px; }}
  .tcell {{ background:#111827; border:1px solid #1e293b; border-radius:5px; padding:6px 8px; margin-bottom:5px; font-size:11px; }}
  .legend {{ font-size:11px; color:#94a3b8; margin-top:6px; }}
  .legend .dot {{ display:inline-block; width:9px; height:9px; border-radius:50%; margin:0 4px 0 10px; vertical-align:middle; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; }}
  .foot {{ margin-top:30px; color:#64748b; font-size:11px; }}
  /* Print / Save-as-PDF: clean light document with sensible page breaks */
  @page {{ margin: 18mm 14mm; }}
  @media print {{
    :root {{ color-scheme: light; }}
    body {{ background:#fff; color:#0f172a; }}
    .wrap {{ max-width:none; padding:0 6px; }}
    h2 {{ page-break-after:avoid; break-after:avoid; border-bottom:1px solid #cbd5e1; }}
    h2 + * {{ page-break-before:avoid; break-before:avoid; }}
    h3 {{ page-break-after:avoid; break-after:avoid; }}
    .cover {{ page-break-after:always; border-bottom:none; }}
    .cover .eyebrow {{ color:#1e4e79 !important; }}
    .wrap > h2::before {{ color:#1e4e79 !important; }}
    .cover-file, .foot {{ color:#475569 !important; }}
    tr, .bstat {{ page-break-inside:avoid; }}
    thead {{ display:table-header-group; }}
    .summary, .custody, .stat, .chain, .finding, .tcell {{ background:#fff !important; border-color:#cbd5e1 !important; }}
    .custody .cv, .finding p, td, h1, h2, h3 {{ color:#0f172a !important; }}
    .muted {{ color:#475569 !important; }} .rec {{ color:#047857 !important; }}
    .pill {{ background:#f1f5f9; color:#0f172a; }}
    .finding, .chain {{ page-break-inside:avoid; }}
    table {{ page-break-inside:auto; }}
    a {{ color:#1d4ed8; text-decoration:none; }}
    .no-print {{ display:none !important; }}
  }}
</style></head>
<body><div class="wrap">
  {_doc_header(file_meta, risk, events, chains, generated, pcap_sha256, tool_version, analyst, risk_color)}

  <h2>Executive summary</h2>
  <div class="summary">{_exec_summary(file_meta, result, events, chains, risk)}</div>

  <div class="stats">{stats}</div>

  <h2>Chain of custody</h2>
  <div class="custody"><table>{custody}</table></div>

  <h2>Severity breakdown</h2>
  <p>{"".join(f"<span class='pill' style='border-left:4px solid {_SEV_COLOR.get(s,'#888')}'>&nbsp;{_esc(s)}: {sev_counts.get(s,0)}&nbsp;</span> " for s in ('CRITICAL','HIGH','MEDIUM','LOW'))}</p>

  <h2>Traffic composition</h2>
  {_traffic_composition(result)}

  <h2>Top talkers</h2>
  {_top_talkers_table(result)}

  <h2>Top conversations</h2>
  {_conversations_table(result)}

  {_services_table(result)}

  {_dns_table(result)}

  {_http_table(result)}

  {_software_table(result)}

  <h2>MITRE ATT&CK coverage</h2>
  {_attack_coverage_html(events)}

  {("<h2>Vulnerability assessment (NVD + CISA KEV)</h2>" + _vulns_html(vulns)) if vulns and vulns.get("products") else ""}

  {_attribution_html(attrs)}

  <h2>Network connection graph</h2>
  {_network_svg(result, events)}

  <h2>Device inventory</h2>
  {_device_inventory_table(result)}

  <h2>Detection events ({len(events)})</h2>
  <table><thead><tr><th>Severity</th><th>Precision</th><th>Type</th><th>Source</th><th>Destination</th><th>Conf.</th><th>Description</th></tr></thead>
  <tbody>{_events_rows(events)}</tbody></table>

  <h2>Finding analysis (why &amp; recommended actions)</h2>
  {_findings_detail(events)}

  <h2>Threat forecast (possible attacks from this capture)</h2>
  {_predictions_html(result, events)}

  <h2>Attack chains ({len(chains)})</h2>
  {_chains_html(chains)}

  <h2>Indicators of compromise</h2>
  {_iocs_html(events, result)}

  <h2>Analyst recommendations &amp; next steps</h2>
  {_recommendations(events, chains)}

  <h2>Scope &amp; methodology</h2>
  {_methodology()}

  <h2>Limitations &amp; assurance</h2>
  {_limitations(attrs)}

  <p class="foot">Report {_esc(_report_ref(file_meta, pcap_sha256))} · generated {_esc(generated)} by
     PacketIQ v{_esc(tool_version)}. Findings are derived from the captured evidence and should be
     validated against the raw capture. Precision grades indicate detection confidence, not legal
     certainty. {_esc(_classification())}.</p>
</div></body></html>"""


def _report_ref(file_meta: dict, pcap_sha256=None) -> str:
    from packetiq.export import report_style as st
    return st.report_id(file_meta.get("filename", "capture"), pcap_sha256 or "")


def _classification() -> str:
    from packetiq.export import report_style as st
    return st.CLASSIFICATION
