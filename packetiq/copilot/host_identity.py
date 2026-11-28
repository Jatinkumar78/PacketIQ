"""
Host identity synthesis — one consolidated profile per internal host: its IP,
MAC, computer name, logged-in user, OS and role, plus the flag for the one that
is compromised.

Why this module exists
----------------------
A responder's first task is "identify the victim host", and the answer is
scattered across four extractors that each knew one piece: the device inventory
held the MAC, NetBIOS Browser/DHCP held the computer name, Kerberos held the
user, and the RAT detector held which host was beaconing out. No single section
tied them to one host, so a small local model, asked for "the MAC of the infected
client" or "its host name", answered "not present" (the MAC was never in the
context) or reached for the domain controller's name (which was loud in DNS)
instead of the workstation's.

This module does that join once, as fact. For each internal host it reads the
MAC from the inventory, the name/OS from the host's own announcements (falling
back to its Kerberos machine account), the user from the Kerberos requests that
host sent, and the role from the services it answers; it marks the host that
contacted a RAT C2 as infected. Every value is read from a dict another extractor
already populated — nothing is inferred except the host role and (clearly
labelled) a domain controller's name taken from the DNS lookups of it, so the
section states facts the model can read off instead of reasoning toward.

Pure and deterministic: it takes already-extracted dicts and returns text / JSON,
with no I/O and no dependence on scapy, so the CLI copilot context
(`context_builder`) and the web copilot context (`webapp.app._build_chat_context`)
both call the one function and answer identically.
"""

from __future__ import annotations

import ipaddress
import re

# Services whose presence marks a host as a domain controller. A DC answers the
# directory from several of these at once; a workstation answers none of them.
_DIRECTORY_PORTS = frozenset({53, 88, 389, 636, 3268, 3269})
_DIRECTORY_MIN = 2   # serve at least this many of the above to be called a DC

# A MAC that sources more than this many IPs is a router/gateway fronting a whole
# internet's worth of addresses, not an endpoint host — the same fan-out test the
# device inventory uses. Endpoints source their own one or two addresses.
_GATEWAY_FANOUT = 4

# Names that appear under the realm domain in DNS but are not a host whose name we
# would attribute to the DC (WPAD/ISATAP are service auto-discovery names).
_NON_HOST_LABELS = frozenset({"wpad", "isatap", "www", "localhost", "time", "dns"})

# A plain single-label host name under a domain, e.g. `luckyturkey-dc` in
# `luckyturkey-dc.theluckyturkey.com`; an underscore-led SRV name never matches.
_HOST_LABEL = re.compile(r"^([a-z0-9][a-z0-9-]*)\.(.+)$", re.IGNORECASE)

_WORKSTATION_PREFIXES = ("DESKTOP-", "LAPTOP-", "WIN-")


def open_ports_from_exposure(service_exposure: dict | None) -> dict[str, list[list]]:
    """Reshape the tuple-keyed ``service_exposure`` into ``{ip: [[port, proto,
    service], …]}`` of the ports each host actually answered.

    The CLI holds ``service_exposure`` keyed by ``(ip, port, proto)`` tuples, which
    cannot be a JSON key; the web side already carries this reshaped form. Giving
    both callers the same shape lets the synthesiser read one structure.
    """
    out: dict[str, list[list]] = {}
    for key, info in (service_exposure or {}).items():
        if not isinstance(key, tuple) or len(key) != 3:
            continue
        if (info or {}).get("state") != "open":
            continue
        ip, port, proto = key
        out.setdefault(str(ip), []).append([int(port), str(proto), str(info.get("service") or "")])
    return out


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _internal_hosts(ip_to_mac: dict, mac_to_ips: dict) -> list[tuple[str, str]]:
    """The internal endpoint hosts to profile: a private IP with its own MAC,
    excluding a gateway MAC that fronts many addresses. Sorted by IP."""
    hosts: list[tuple[str, str]] = []
    for ip, mac in (ip_to_mac or {}).items():
        if not _is_private(ip):
            continue
        fanout = len(mac_to_ips.get(mac) or [ip])
        if fanout > _GATEWAY_FANOUT:
            continue
        hosts.append((ip, mac))
    hosts.sort(key=lambda h: _ip_sort_key(h[0]))
    return hosts


def _ip_sort_key(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _served_ports(ip: str, open_ports: dict) -> set[int]:
    return {int(entry[0]) for entry in (open_ports.get(ip) or []) if entry}


def _is_dc(ip: str, open_ports: dict) -> bool:
    return len(_served_ports(ip, open_ports) & _DIRECTORY_PORTS) >= _DIRECTORY_MIN


def _name_from_host_names(ip: str, mac: str, host_names: dict) -> dict:
    """Merge a host's by-IP and by-MAC name evidence into one record."""
    by_ip = (host_names or {}).get("by_ip") or {}
    by_mac = (host_names or {}).get("by_mac") or {}
    merged: dict = {"name": "", "fqdn": "", "os": "", "role": "", "sources": []}
    for rec in (by_ip.get(ip), by_mac.get(mac)):
        if not rec:
            continue
        for field_name in ("name", "fqdn", "os", "role"):
            if rec.get(field_name) and not merged[field_name]:
                merged[field_name] = rec[field_name]
        for src in rec.get("sources") or []:
            if src not in merged["sources"]:
                merged["sources"].append(src)
    return merged


def _machine_hostname(ip: str, kerberos: dict) -> str:
    """The host name derived from a host's Kerberos machine account (``HOST$``)."""
    by_host = (kerberos or {}).get("by_host") or {}
    for acct in (by_host.get(ip) or {}).get("machine_accounts") or []:
        base = acct.rstrip("$")
        if base:
            return base.upper()
    return ""


def _users_for(ip: str, kerberos: dict) -> list[str]:
    by_host = (kerberos or {}).get("by_host") or {}
    return list((by_host.get(ip) or {}).get("user_accounts") or [])


def _realm(kerberos: dict) -> str:
    realms = (kerberos or {}).get("realms") or []
    # Prefer the dotted DNS realm (THELUCKYTURKEY.COM) over the short NetBIOS one.
    dotted = [r for r in realms if "." in r]
    chosen = (dotted or realms or [""])[0]
    return chosen.upper()


def _dc_name_from_dns(dns_queries: list | None, domain: str) -> str:
    """A domain controller's name taken from the DNS lookups of it, used only when
    the DC did not announce its own name. Conservative: returns a name only when
    exactly one plain host label is queried under the realm domain, so an ordinary
    A-record lookup is never mistaken for the DC."""
    if not domain:
        return ""
    domain = domain.lower().rstrip(".")
    candidates: set[str] = set()
    for q in dns_queries or []:
        qname = (q.get("qname") or "").lower().rstrip(".")
        m = _HOST_LABEL.match(qname)
        if not m:
            continue
        label, parent = m.group(1), m.group(2)
        if parent == domain and label not in _NON_HOST_LABELS:
            candidates.add(label)
    if len(candidates) == 1:
        return candidates.pop().upper()
    # When the host part is ambiguous (a workstation registers its own name under
    # the domain too), fall back only to a candidate that names itself a DC — a
    # strong, conventional signal — and otherwise abstain rather than guess.
    dc_like = [c for c in candidates if "dc" in c]
    return dc_like[0].upper() if len(dc_like) == 1 else ""


def _rat_channels(netsupport: dict | None) -> list[dict]:
    return list((netsupport or {}).get("channels") or [])


def build_host_identity(
    ip_to_mac: dict | None,
    mac_to_ips: dict | None,
    host_names: dict | None,
    kerberos: dict | None,
    netsupport: dict | None,
    open_ports: dict | None,
    dns_queries: list | None,
) -> list[dict]:
    """One profile per internal host, the single source of truth for every
    consumer: the two copilot contexts, the CLI panel and the web panel.

    Each profile carries ip, mac, hostname, fqdn, os, users, role, and — for the
    host that contacted a RAT C2 — ``infected`` with the C2 and malware family.
    """
    ip_to_mac = ip_to_mac or {}
    mac_to_ips = mac_to_ips or {}
    open_ports = open_ports or {}
    host_names = host_names or {}
    kerberos = kerberos or {}
    dns_queries = dns_queries or []

    channels = _rat_channels(netsupport)
    infected_by_ip: dict[str, dict] = {c["client"]: c for c in channels if c.get("client")}
    domain = _realm(kerberos).lower()

    profiles: list[dict] = []
    for ip, mac in _internal_hosts(ip_to_mac, mac_to_ips):
        names = _name_from_host_names(ip, mac, host_names)
        hostname = names["name"]
        name_sources = list(names["sources"])
        is_dc = _is_dc(ip, open_ports)

        if not hostname:
            machine = _machine_hostname(ip, kerberos)
            if machine:
                hostname = machine
                name_sources.append("Kerberos machine account")
        if not hostname and is_dc:
            dc_name = _dc_name_from_dns(dns_queries, domain)
            if dc_name:
                hostname = dc_name
                name_sources.append("DNS lookups of it (DC did not self-announce)")

        role = "domain controller" if is_dc else _endpoint_role(hostname, names["role"])
        chan = infected_by_ip.get(ip)
        profiles.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "fqdn": names["fqdn"],
            "os": names["os"],
            "users": _users_for(ip, kerberos),
            "role": role,
            "name_sources": name_sources,
            "realm": _realm(kerberos) if is_dc else "",
            "infected": bool(chan),
            "c2": chan.get("c2") if chan else "",
            "malware": (netsupport or {}).get("family", "") if chan else "",
            "rat_first_seen": chan.get("first_seen_utc") if chan else "",
        })
    return profiles


def _endpoint_role(hostname: str, announced_role: str) -> str:
    if hostname and hostname.upper().startswith(_WORKSTATION_PREFIXES):
        return "workstation"
    if "workstation" in (announced_role or "").lower():
        return "workstation"
    if "server" in (announced_role or "").lower():
        return "server"
    return "host"


def _display_label(profile: dict) -> str:
    if profile["infected"]:
        return "INFECTED WINDOWS CLIENT"
    return {
        "domain controller": "DOMAIN CONTROLLER",
        "workstation": "WORKSTATION",
        "server": "SERVER",
    }.get(profile["role"], "HOST")


def host_identity_section(
    ip_to_mac: dict | None,
    mac_to_ips: dict | None,
    host_names: dict | None,
    kerberos: dict | None,
    netsupport: dict | None,
    open_ports: dict | None,
    dns_queries: list | None,
) -> str:
    """Render the HOST IDENTITY section (and the RAT C2 block when a RAT is
    present) for the copilot context, or "" when there is no internal host to
    profile and no RAT."""
    profiles = build_host_identity(
        ip_to_mac, mac_to_ips, host_names, kerberos, netsupport, open_ports, dns_queries)
    channels = _rat_channels(netsupport)
    if not profiles and not channels:
        return ""

    lines: list[str] = []
    if profiles:
        lines.append("=== HOST IDENTITY / ASSET INVENTORY ===")
        lines.append("  Each internal host below is identified from THIS capture's link-layer, "
                     "name-service and Kerberos evidence. When asked for a host's IP, MAC, name, "
                     "user or OS, read it from the matching host here — do NOT give the domain "
                     "controller's name for a workstation, or a value that is not listed.")
        for i, p in enumerate(profiles, 1):
            lines.append(f"  [{i}] {_display_label(p)} — {p['ip']}")
            if p["hostname"]:
                src = f"   ({', '.join(p['name_sources'])})" if p["name_sources"] else ""
                lines.append(f"        Host name       : {p['hostname']}{src}")
            if p["fqdn"]:
                lines.append(f"        FQDN            : {p['fqdn']}")
            lines.append(f"        MAC address     : {p['mac']}")
            if p["users"]:
                lines.append(f"        Windows user    : {', '.join(p['users'])}   "
                             "(Kerberos AS-REQ, non-machine account)")
            if p["os"]:
                lines.append(f"        Operating system: {p['os']} (announced)")
            role = p["role"] + (f" for realm {p['realm']}" if p["realm"] else "")
            lines.append(f"        Role            : {role}")
            if p["infected"]:
                lines.append(f"        Compromise      : contacted the {p['malware']} C2 {p['c2']} "
                             "(see RAT C2 section) — this is the infected host")
                lines.append(f"        ANSWER — infected Windows client IP address : {p['ip']}")
                lines.append(f"        ANSWER — infected Windows client MAC address: {p['mac']}")
                if p["hostname"]:
                    lines.append(f"        ANSWER — infected Windows client host name  : {p['hostname']}")
                if p["users"]:
                    lines.append(f"        ANSWER — Windows user account name          : {p['users'][0]}")

    rat = _rat_block(channels, netsupport)
    if rat:
        if lines:
            lines.append("")
        lines.extend(rat)
    return "\n".join(lines)


def _rat_block(channels: list[dict], netsupport: dict | None) -> list[str]:
    if not channels:
        return []
    family = (netsupport or {}).get("family", "a Remote Access Trojan")
    lines = ["=== REMOTE ACCESS TROJAN (RAT) C2 ==="]
    lines.append(f"  {family} command-and-control was identified by its own protocol signature on "
                 "the wire (it is plain HTTP, not TLS, and names itself in its headers).")
    for c in channels:
        lines.append(f"  C2 server            : {c.get('c2')}")
        lines.append(f"  Infected host        : {c.get('client')}")
        if c.get("client_agent"):
            lines.append(f"  Client (victim) agent: {c['client_agent']}")
        if c.get("gateway"):
            lines.append(f"  C2 gateway banner    : {c['gateway']}")
        if c.get("uri"):
            lines.append(f"  C2 URL               : {c['uri']}")
        if c.get("commands"):
            lines.append(f"  Commands observed    : {', '.join(c['commands'])} "
                         "(NetSupport command protocol; the DATA= payloads are encrypted)")
        lines.append(f"  First seen (start of the RAT traffic): {c.get('first_seen_utc')}")
        lines.append(f"        ANSWER — date/start time of the {_short_family(family)} RAT traffic: "
                     f"{c.get('first_seen_utc')}")
        lines.append(f"        ANSWER — RAT C2 server: {c.get('c2')}")
    return lines


def _short_family(family: str) -> str:
    """"NetSupport RAT (NetSupport Manager)" → "NetSupport", for the answer line."""
    return family.split(" ")[0] if family else "RAT"


def host_identity_payload(
    ip_to_mac: dict | None,
    mac_to_ips: dict | None,
    host_names: dict | None,
    kerberos: dict | None,
    netsupport: dict | None,
    open_ports: dict | None,
    dns_queries: list | None,
) -> dict:
    """JSON-ready view for the web Assets panel: the host profiles and the RAT C2
    channels, built from the one ``build_host_identity`` so the panel, the CLI and
    the copilot never disagree."""
    profiles = build_host_identity(
        ip_to_mac, mac_to_ips, host_names, kerberos, netsupport, open_ports, dns_queries)
    return {
        "hosts": profiles,
        "rat": {
            "family": (netsupport or {}).get("family", ""),
            "channels": _rat_channels(netsupport),
        } if _rat_channels(netsupport) else {},
    }
