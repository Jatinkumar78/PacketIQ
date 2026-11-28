"""Tests for the host-identity synthesis (`packetiq.copilot.host_identity`) and its
visible CLI panel — the consolidated per-host IP/MAC/name/user/OS/role view, with the
RAT C2 that marks the infected host, and the exact answer lines the copilot reads off.

The synthesiser is pure (dicts in, text/JSON out), so these feed the already-extracted
dicts directly rather than building packets.
"""

from packetiq.copilot import host_identity as hi

# A realistic capture: a domain controller, an infected Windows workstation, and a
# gateway MAC fronting a whole internet of external addresses.
IP_TO_MAC = {
    "10.11.10.10": "00:c0:4f:a2:95:e7",
    "10.11.10.147": "00:12:f0:e5:17:43",
    "10.11.10.1": "00:03:31:c4:58:2d",
    "8.8.8.8": "00:03:31:c4:58:2d",
}
MAC_TO_IPS = {
    "00:c0:4f:a2:95:e7": ["10.11.10.10"],
    "00:12:f0:e5:17:43": ["10.11.10.147"],
    "00:03:31:c4:58:2d": ["10.11.10.1", "8.8.8.8"] + [f"52.1.2.{i}" for i in range(30)],
}
HOST_NAMES = {
    "by_ip": {"10.11.10.147": {"name": "DESKTOP-5OMVI3L", "fqdn": "",
                               "os": "Windows 10/11 or Server 2016+",
                               "role": "workstation, server",
                               "mac": "00:12:f0:e5:17:43", "sources": ["NetBIOS Browser"]}},
    "by_mac": {"00:12:f0:e5:17:43": {"name": "DESKTOP-5OMVI3L",
                                     "fqdn": "DESKTOP-5OMVI3L.theluckyturkey.com",
                                     "os": "", "role": "", "sources": ["DHCP"]}},
}
KERBEROS = {
    "realms": ["THELUCKYTURKEY", "THELUCKYTURKEY.COM"],
    "by_host": {"10.11.10.147": {"machine_accounts": ["DESKTOP-5OMVI3L$"],
                                 "user_accounts": ["edward.winslow"],
                                 "all": ["DESKTOP-5OMVI3L$", "edward.winslow"]}},
}
NETSUPPORT = {
    "family": "NetSupport RAT (NetSupport Manager)",
    "detected": True,
    "channels": [{"client": "10.11.10.147", "server": "93.152.209.36", "port": 443,
                  "c2": "93.152.209.36:443", "first_seen": 1.0,
                  "first_seen_utc": "2026-11-10 18:22:07 UTC",
                  "client_agent": "NetSupport Manager/1.3",
                  "gateway": "NetSupport Gateway/1.92 (Windows NT)",
                  "uri": "http://93.152.209.36/fakeurl.htm",
                  "commands": ["POLL", "ENCD"], "request_count": 127}],
}
OPEN_PORTS = {
    "10.11.10.10": [[53, "udp", "DNS"], [389, "tcp", "LDAP"], [445, "tcp", "SMB"]],
    "10.11.10.147": [[137, "udp", "NetBIOS-NS"]],
}
DNS = [{"qname": "luckyturkey-dc.theluckyturkey.com"},
       {"qname": "wpad.theluckyturkey.com"},
       {"qname": "desktop-5omvi3l.theluckyturkey.com"},
       {"qname": "_ldap._tcp.dc._msdcs.theluckyturkey.com"}]


def _build(**over):
    kw = dict(ip_to_mac=IP_TO_MAC, mac_to_ips=MAC_TO_IPS, host_names=HOST_NAMES,
              kerberos=KERBEROS, netsupport=NETSUPPORT, open_ports=OPEN_PORTS, dns_queries=DNS)
    kw.update(over)
    return hi.build_host_identity(**kw)


# ── open_ports_from_exposure ──────────────────────────────────────────────────

def test_open_ports_reshapes_only_open_tuple_keyed_services():
    exposure = {
        ("10.11.10.10", 53, "UDP"): {"state": "open", "service": "DNS"},
        ("10.11.10.10", 80, "TCP"): {"state": "filtered", "service": "HTTP"},
        "not-a-tuple": {"state": "open"},
        ("x", 1): {"state": "open"},  # wrong-length tuple
    }
    out = hi.open_ports_from_exposure(exposure)
    assert out == {"10.11.10.10": [[53, "UDP", "DNS"]]}
    assert hi.open_ports_from_exposure(None) == {}


# ── address helpers ───────────────────────────────────────────────────────────

def test_is_private_and_sort_key():
    assert hi._is_private("10.11.10.147") is True
    assert hi._is_private("8.8.8.8") is False
    assert hi._is_private("not-an-ip") is False
    assert hi._ip_sort_key("10.0.0.1")[0] == 0
    assert hi._ip_sort_key("not-an-ip") == (1, "not-an-ip")


def test_internal_hosts_excludes_gateway_and_public_addresses():
    hosts = hi._internal_hosts(IP_TO_MAC, MAC_TO_IPS)
    ips = [ip for ip, _ in hosts]
    assert ips == ["10.11.10.10", "10.11.10.147"]          # sorted, gateway + 8.8.8.8 dropped


def test_internal_hosts_without_inventory_keeps_the_private_host():
    # No mac_to_ips (synthetic capture): fan-out falls back to 1, so the host stays.
    hosts = hi._internal_hosts({"10.0.0.5": "aa:bb:cc:dd:ee:ff"}, {})
    assert hosts == [("10.0.0.5", "aa:bb:cc:dd:ee:ff")]


# ── role / name resolution ────────────────────────────────────────────────────

def test_is_dc_needs_two_directory_services():
    assert hi._is_dc("10.11.10.10", OPEN_PORTS) is True
    assert hi._is_dc("10.11.10.147", OPEN_PORTS) is False
    assert hi._is_dc("10.11.10.10", {"10.11.10.10": [[53, "udp", "DNS"]]}) is False


def test_machine_hostname_strips_the_dollar_and_uppercases():
    assert hi._machine_hostname("10.11.10.147", KERBEROS) == "DESKTOP-5OMVI3L"
    assert hi._machine_hostname("10.0.0.9", KERBEROS) == ""
    assert hi._machine_hostname("1.2.3.4", {"by_host": {"1.2.3.4": {"machine_accounts": ["$"]}}}) == ""


def test_realm_prefers_the_dotted_dns_form():
    assert hi._realm({"realms": ["THELUCKYTURKEY", "THELUCKYTURKEY.COM"]}) == "THELUCKYTURKEY.COM"
    assert hi._realm({"realms": ["WORKGROUP"]}) == "WORKGROUP"
    assert hi._realm({}) == ""


def test_endpoint_role_from_name_then_announcement():
    assert hi._endpoint_role("DESKTOP-5OMVI3L", "") == "workstation"
    assert hi._endpoint_role("", "workstation, server") == "workstation"
    assert hi._endpoint_role("FILESRV01", "server") == "server"
    assert hi._endpoint_role("MYSTERY", "") == "host"


def test_display_label_covers_every_role():
    assert hi._display_label({"infected": True, "role": "workstation"}) == "INFECTED WINDOWS CLIENT"
    assert hi._display_label({"infected": False, "role": "domain controller"}) == "DOMAIN CONTROLLER"
    assert hi._display_label({"infected": False, "role": "workstation"}) == "WORKSTATION"
    assert hi._display_label({"infected": False, "role": "server"}) == "SERVER"
    assert hi._display_label({"infected": False, "role": "host"}) == "HOST"


# ── DC name from DNS ──────────────────────────────────────────────────────────

def test_dc_name_from_dns_single_candidate():
    dns = [{"qname": "luckyturkey-dc.theluckyturkey.com"}, {"qname": "wpad.theluckyturkey.com"}]
    assert hi._dc_name_from_dns(dns, "theluckyturkey.com") == "LUCKYTURKEY-DC"


def test_dc_name_from_dns_prefers_the_dc_like_candidate_when_ambiguous():
    # Two host labels under the domain (the workstation registers its own): fall back
    # to the one that names itself a DC.
    assert hi._dc_name_from_dns(DNS, "theluckyturkey.com") == "LUCKYTURKEY-DC"


def test_dc_name_from_dns_abstains_when_still_ambiguous_or_empty():
    two_plain = [{"qname": "alpha.x.com"}, {"qname": "beta.x.com"}]
    assert hi._dc_name_from_dns(two_plain, "x.com") == ""
    assert hi._dc_name_from_dns(DNS, "") == ""
    # An underscore-led SRV name is not a host label, and a different domain is skipped.
    assert hi._dc_name_from_dns([{"qname": "_ldap._tcp.x.com"},
                                 {"qname": "host.other.com"}], "x.com") == ""


# ── build_host_identity ───────────────────────────────────────────────────────

def test_build_full_profile_marks_the_infected_workstation_and_the_dc():
    profiles = _build()
    by_ip = {p["ip"]: p for p in profiles}

    dc = by_ip["10.11.10.10"]
    assert dc["role"] == "domain controller"
    assert dc["realm"] == "THELUCKYTURKEY.COM"
    assert dc["hostname"] == "LUCKYTURKEY-DC"          # from the DNS lookups of it
    assert dc["infected"] is False

    vic = by_ip["10.11.10.147"]
    assert vic["hostname"] == "DESKTOP-5OMVI3L"
    assert vic["fqdn"] == "DESKTOP-5OMVI3L.theluckyturkey.com"
    assert vic["mac"] == "00:12:f0:e5:17:43"
    assert vic["users"] == ["edward.winslow"]
    assert vic["os"] == "Windows 10/11 or Server 2016+"
    assert vic["role"] == "workstation"
    assert vic["infected"] is True
    assert vic["c2"] == "93.152.209.36:443"
    assert "NetSupport" in vic["malware"]
    assert vic["rat_first_seen"] == "2026-11-10 18:22:07 UTC"


def test_build_falls_back_to_the_kerberos_machine_account_for_the_name():
    profiles = _build(host_names={})
    vic = {p["ip"]: p for p in profiles}["10.11.10.147"]
    assert vic["hostname"] == "DESKTOP-5OMVI3L"
    assert "Kerberos machine account" in vic["name_sources"]


def test_build_with_no_rat_leaves_no_host_infected():
    profiles = _build(netsupport={})
    assert all(p["infected"] is False for p in profiles)
    assert all(p["c2"] == "" for p in profiles)


def test_build_on_empty_inputs_is_empty():
    assert hi.build_host_identity(None, None, None, None, None, None, None) == []


# ── section text ──────────────────────────────────────────────────────────────

def test_section_carries_every_answer_line():
    out = hi.host_identity_section(IP_TO_MAC, MAC_TO_IPS, HOST_NAMES, KERBEROS,
                                   NETSUPPORT, OPEN_PORTS, DNS)
    assert "HOST IDENTITY" in out
    assert "REMOTE ACCESS TROJAN (RAT) C2" in out
    for answer in ("10.11.10.147", "00:12:f0:e5:17:43", "DESKTOP-5OMVI3L",
                   "edward.winslow", "2026-11-10 18:22:07 UTC", "93.152.209.36:443"):
        assert answer in out
    assert "DOMAIN CONTROLLER" in out
    assert "INFECTED WINDOWS CLIENT" in out


def test_section_empty_when_nothing_to_show():
    assert hi.host_identity_section(None, None, None, None, None, None, None) == ""


def test_section_profiles_only_when_no_rat():
    out = hi.host_identity_section(IP_TO_MAC, MAC_TO_IPS, HOST_NAMES, KERBEROS,
                                   {}, OPEN_PORTS, DNS)
    assert "HOST IDENTITY" in out
    assert "REMOTE ACCESS TROJAN" not in out


def test_section_rat_only_when_the_victim_has_no_inventory_entry():
    # The RAT names a client that is not in the device inventory: no profile, but the
    # RAT block still reports the channel (exercises the no-leading-blank path too).
    out = hi.host_identity_section({}, {}, {}, {}, NETSUPPORT, {}, [])
    assert "HOST IDENTITY / ASSET INVENTORY" not in out
    assert "REMOTE ACCESS TROJAN (RAT) C2" in out
    assert "2026-11-10 18:22:07 UTC" in out


def test_rat_block_tolerates_a_bare_channel():
    bare = {"family": "", "channels": [{"client": "10.0.0.5", "c2": "9.9.9.9:443",
                                        "first_seen_utc": "t"}]}
    lines = hi._rat_block(bare["channels"], bare)
    text = "\n".join(lines)
    assert "9.9.9.9:443" in text
    assert "Client (victim) agent" not in text      # optional fields omitted
    assert hi._rat_block([], {}) == []


def test_short_family():
    assert hi._short_family("NetSupport RAT (NetSupport Manager)") == "NetSupport"
    assert hi._short_family("") == "RAT"


# ── payload ───────────────────────────────────────────────────────────────────

def test_payload_shapes_hosts_and_rat():
    pay = hi.host_identity_payload(IP_TO_MAC, MAC_TO_IPS, HOST_NAMES, KERBEROS,
                                   NETSUPPORT, OPEN_PORTS, DNS)
    assert [h["ip"] for h in pay["hosts"]] == ["10.11.10.10", "10.11.10.147"]
    assert pay["rat"]["family"] == "NetSupport RAT (NetSupport Manager)"
    assert pay["rat"]["channels"][0]["c2"] == "93.152.209.36:443"


def test_payload_without_rat_has_empty_rat():
    pay = hi.host_identity_payload(IP_TO_MAC, MAC_TO_IPS, HOST_NAMES, KERBEROS,
                                   {}, OPEN_PORTS, DNS)
    assert pay["rat"] == {}


# ── CLI visible panel ─────────────────────────────────────────────────────────

class _Result:
    """A stand-in for ExtractionResult carrying only the identity-bearing fields."""
    def __init__(self, **kw):
        self.ip_to_mac = kw.get("ip_to_mac", {})
        self.mac_to_ips = kw.get("mac_to_ips", {})
        self.host_names = kw.get("host_names", {})
        self.kerberos = kw.get("kerberos", {})
        self.netsupport = kw.get("netsupport", {})
        self.service_exposure = kw.get("service_exposure", {})
        self.dns_queries = kw.get("dns_queries", [])


def _panel_output(result) -> str:
    """Capture the panel through the UI's own rich console (immune to the global
    stdout swapping other CLI tests do; see test_copilot_credential_exposure)."""
    from packetiq.cli import _print_host_identity, ui
    with ui.console.capture() as cap:
        _print_host_identity(result)
    return cap.get()


def test_cli_panel_silent_when_no_hosts():
    assert _panel_output(_Result()).strip() == ""


def test_cli_panel_shows_hosts_and_the_rat_c2():
    exposure = {("10.11.10.10", 53, "UDP"): {"state": "open", "service": "DNS"},
                ("10.11.10.10", 389, "TCP"): {"state": "open", "service": "LDAP"},
                ("10.11.10.147", 137, "UDP"): {"state": "open", "service": "NetBIOS-NS"}}
    out = _panel_output(_Result(
        ip_to_mac=IP_TO_MAC, mac_to_ips=MAC_TO_IPS, host_names=HOST_NAMES,
        kerberos=KERBEROS, netsupport=NETSUPPORT, service_exposure=exposure, dns_queries=DNS))
    assert "HOST IDENTITY" in out
    # Single-token values survive rich wrapping at the fixed 80-column test width.
    assert "DESKTOP-5OMVI3L" in out
    assert "edward.winslow" in out
    assert "00:12:f0:e5:17:43" in out
    assert "INFECTED" in out
    assert "93.152.209.36:443" in out


def test_cli_panel_names_an_unidentified_host():
    # A profiled host with no announced name and no user exercises the fallback label
    # and the MAC-only detail line.
    out = _panel_output(_Result(
        ip_to_mac={"10.0.0.5": "aa:bb:cc:dd:ee:ff"}, mac_to_ips={},
        service_exposure={}))
    assert "(name not announced)" in out
    assert "aa:bb:cc:dd:ee:ff" in out
