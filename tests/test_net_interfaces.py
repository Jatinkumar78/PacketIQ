"""Tests for cross-platform capture-interface enumeration (net_interfaces).

These are deterministic and platform-independent: the OS-specific sources
(scapy, macOS ``networksetup``/``ifconfig``) are monkeypatched with fixed
fixtures, so the classification, link-status parsing and ranking logic is
exercised identically on macOS, Linux and CI.
"""

from packetiq import net_interfaces as ni


def test_every_interface_kind_is_enumerated_and_well_formed():
    """Well-formed records for one adapter of every kind we can classify.

    The list comes from `conftest.FIXED_INTERFACES` rather than the host, so this
    runs the real enumeration end to end — metadata lookup, platform dispatch,
    labelling, ranking — against the same input on every machine. Reading the
    machine's own NICs made it a different test on each one: this Mac has four
    bridge adapters and covered the bridge arm of `_score` for free, a Linux
    runner has none and did not.
    """
    recs = ni.list_interfaces()
    assert isinstance(recs, list)
    for r in recs:
        assert set(r) >= {"name", "label", "ip", "mac", "kind", "up",
                          "is_default", "recommended"}
        assert isinstance(r["name"], str) and r["name"]
        assert r["up"] in (True, False, None)
    # At most one interface is flagged recommended.
    assert sum(1 for r in recs if r["recommended"]) <= 1
    assert {r["kind"] for r in recs} == {
        "loopback", "ethernet", "wifi", "wwan", "vpn",
        "bridge", "system", "virtual", "other",
    }


def test_a_description_that_only_repeats_the_device_name_is_not_a_label(monkeypatch):
    """scapy fills `description` with the device name itself on several platforms.

    Treating that as a friendly name would put "lo0" in the picker where the
    readable "Loopback" belongs, so a description equal to the name counts as no
    description at all.
    """
    monkeypatch.setattr(ni.sys, "platform", "linux")
    monkeypatch.setattr(ni, "_scapy_metadata", lambda: (
        {"lo0": {"ip": "", "mac": "", "flags": "", "description": "lo0"}},
        ["lo0"], None))
    monkeypatch.setattr(ni, "_linux_link_up", lambda dev: None)

    rec = ni.list_interfaces()[0]
    assert rec["kind"] == "loopback"
    assert rec["label"] == "Loopback"


def _rec(name="en0", kind="ethernet", up=None, ip="", is_default=False):
    return {"name": name, "kind": kind, "up": up, "ip": ip, "is_default": is_default}


def test_the_ranking_weights_order_the_kinds_a_user_expects():
    """`_score` sorts ascending, so a *lower* key is a better capture candidate.

    Asserted directly because these weights decide what the live-capture picker
    puts at the top, and driving them through `list_interfaces` only proves the
    ordering of whichever adapters that host happens to have.
    """
    order = ["ethernet", "wifi", "bridge", "other", "wwan",
             "vpn", "loopback", "system", "virtual"]
    keys = [ni._score(_rec(kind=k)) for k in order]
    assert keys == sorted(keys), f"kind ranking is out of order: {list(zip(order, keys))}"
    assert keys[0] == keys[1], "ethernet and wifi are equally good capture targets"
    assert keys[-2] == keys[-1], "system and virtual plumbing rank equally last"


def test_a_live_addressed_default_interface_outranks_a_bare_one():
    better = ni._score(_rec(name="a", up=True, ip="10.0.0.5", is_default=True))
    worse = ni._score(_rec(name="a", up=False))
    assert better < worse
    # Each signal counts on its own, too.
    bare = ni._score(_rec(name="a"))
    assert ni._score(_rec(name="a", up=True)) < bare
    assert ni._score(_rec(name="a", ip="10.0.0.5")) < bare
    assert ni._score(_rec(name="a", is_default=True)) < bare
    assert ni._score(_rec(name="a", up=False)) > bare


def test_interfaces_that_tie_are_ordered_by_name():
    assert ni._score(_rec(name="en1")) < ni._score(_rec(name="en2"))


def test_kind_classification():
    assert ni._kind_for("en0", "Wi-Fi") == "wifi"
    assert ni._kind_for("en3", "Ethernet Adapter (en3)") == "ethernet"
    assert ni._kind_for("bridge0", "Thunderbolt Bridge") == "bridge"
    assert ni._kind_for("lo0", "") == "loopback"
    assert ni._kind_for("utun0", "") == "vpn"
    assert ni._kind_for("awdl0", "") == "system"
    assert ni._kind_for("eth0", "") == "ethernet"


def test_macos_friendly_name_parsing(monkeypatch):
    sample = (
        "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb\n\n"
        "Hardware Port: Ethernet Adapter (en3)\nDevice: en3\nEthernet Address: cc:dd\n\n"
        "VLAN Configurations\n===================\n"
    )
    monkeypatch.setattr(ni, "_run", lambda cmd, timeout=4.0: sample)
    names = ni._macos_friendly_names()
    assert names == {"en0": "Wi-Fi", "en3": "Ethernet Adapter (en3)"}


def test_macos_link_status_parsing(monkeypatch):
    sample = (
        "en0: flags=8863\n\tstatus: active\n"
        "en3: flags=8863\n\tstatus: inactive\n"
        "lo0: flags=8049\n"          # no status line → absent (unknown)
    )
    monkeypatch.setattr(ni, "_run", lambda cmd, timeout=4.0: sample)
    st = ni._macos_link_status()
    assert st == {"en0": True, "en3": False}
    assert "lo0" not in st


def test_ranking_and_recommendation(monkeypatch):
    """An up ethernet with an IP should outrank Wi-Fi/loopback and be recommended."""
    meta = {
        "lo0": {"ip": "127.0.0.1", "mac": "", "flags": "LOOPBACK", "description": ""},
        "en0": {"ip": "10.0.0.5", "mac": "a", "flags": "RUNNING", "description": ""},
        "en5": {"ip": "192.168.1.9", "mac": "b", "flags": "RUNNING", "description": ""},
        "utun0": {"ip": "", "mac": "", "flags": "", "description": ""},
    }
    monkeypatch.setattr(ni, "_scapy_metadata",
                        lambda: (meta, ["lo0", "en0", "en5", "utun0"], "en0"))
    monkeypatch.setattr(ni.sys, "platform", "darwin")
    monkeypatch.setattr(ni, "_macos_friendly_names",
                        lambda: {"en0": "Wi-Fi", "en5": "USB LAN"})
    # en5 has an active link, en0/Wi-Fi does not.
    monkeypatch.setattr(ni, "_macos_link_status",
                        lambda: {"en0": False, "en5": True})

    recs = ni.list_interfaces()
    order = [r["name"] for r in recs]
    assert order[0] == "en5"                         # up + ip + ethernet ranks first
    assert order.index("en5") < order.index("lo0")   # real NIC above loopback
    assert order.index("utun0") == len(order) - 1     # vpn ranks last
    rec = [r for r in recs if r["recommended"]]
    assert len(rec) == 1 and rec[0]["name"] == "en5"  # recommend the live NIC
    assert dict((r["name"], r["label"]) for r in recs)["en5"] == "USB LAN"


def test_no_scapy_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(ni, "_scapy_metadata", lambda: ({}, [], None))
    assert ni.list_interfaces() == []


class _FakeIfaces:
    def __init__(self, providers):
        self.providers = providers
        self.reloaded = 0

    def reload(self):
        self.reloaded += 1


class _FakeConf:
    def __init__(self, ifaces):
        self.ifaces = ifaces


def test_rescan_reloads_only_with_a_provider():
    """A live re-scan (Wireshark-style) must fire when scapy has a provider…"""
    ifs = _FakeIfaces(providers={"bpf": object()})
    ni._rescan_scapy(_FakeConf(ifs))
    assert ifs.reloaded == 1


def test_rescan_skips_when_no_provider():
    """…but never when there is none — reload() would clear the interface list."""
    ifs = _FakeIfaces(providers={})
    ni._rescan_scapy(_FakeConf(ifs))
    assert ifs.reloaded == 0
    # Also tolerate a conf whose ifaces is None (half-initialised scapy).
    ni._rescan_scapy(_FakeConf(None))  # must not raise


def test_rescan_swallows_reload_failure():
    """A failing reload must not propagate; the cached list stays usable."""
    class Boom(_FakeIfaces):
        def reload(self):
            raise RuntimeError("bpf busy")

    ni._rescan_scapy(_FakeConf(Boom(providers={"bpf": object()})))  # no exception


def test_scapy_metadata_forces_a_rescan(monkeypatch):
    """_scapy_metadata must invoke the live re-scan so new NICs are picked up."""
    calls = {"n": 0}
    monkeypatch.setattr(ni, "_rescan_scapy",
                        lambda conf: calls.__setitem__("n", calls["n"] + 1))
    meta, names, default = ni._scapy_metadata()
    # scapy is a hard dependency, so the import succeeds and the re-scan runs once.
    assert calls["n"] == 1
    assert isinstance(names, list)
