"""Interface enumeration, capture privileges, live sniffing, and Zeek ingest.

These are the parts of PacketIQ that touch the host itself, so they are the
hardest to cover and the easiest to break on a machine that is not the
developer's. Every OS-specific branch here is driven with a stubbed OS rather
than skipped, so the Linux and Windows paths are exercised on macOS CI too.
"""

import io

import pytest

from packetiq import capture_setup, live, net_interfaces
from packetiq.inputs import zeek

TS = 1700000000.0


# ── Interface classification ─────────────────────────────────────────────────

@pytest.mark.parametrize("friendly,expect", [
    ("Wi-Fi", "wifi"),
    ("WiFi (en0)", "wifi"),
    ("AirPort", "wifi"),
    ("Wireless LAN adapter", "wifi"),
    ("Thunderbolt Bridge", "bridge"),
    ("Bluetooth PAN", "system"),
    ("Ethernet", "ethernet"),
    ("USB 10/100 LAN", "ethernet"),
])
def test_the_friendly_name_decides_the_interface_kind(friendly, expect):
    """The friendly name is what the user recognises, so it wins over the device
    name — `en0` is Wi-Fi on a laptop and Ethernet on a Mac mini."""
    assert net_interfaces._kind_for("en0", friendly) == expect


@pytest.mark.parametrize("name,expect", [
    ("lo0", "loopback"),
    ("lo", "loopback"),
    ("awdl0", "system"),
    ("utun3", "vpn"),
    ("docker0", "virtual"),
    ("vboxnet1", "virtual"),
    ("veth1234", "virtual"),
])
def test_the_device_name_classifies_when_there_is_no_friendly_name(name, expect):
    assert net_interfaces._kind_for(name) == expect


def test_an_unrecognised_device_is_classified_as_other():
    """Better to list it as unknown than to guess and mislabel a real NIC."""
    assert net_interfaces._kind_for("xn17", "") == "other"


# ── Running OS query commands ────────────────────────────────────────────────

def test_a_missing_os_tool_yields_no_output(monkeypatch):
    monkeypatch.setattr(net_interfaces.shutil, "which", lambda exe: None)
    assert net_interfaces._run(["networksetup", "-listallhardwareports"]) == ""


def test_a_failing_os_tool_yields_no_output(monkeypatch):
    """A timeout or a non-zero exit must degrade to 'no extra detail', never raise."""
    monkeypatch.setattr(net_interfaces.shutil, "which", lambda exe: f"/usr/sbin/{exe}")

    def boom(*a, **kw):
        raise OSError("command failed")

    monkeypatch.setattr(net_interfaces.subprocess, "run", boom)
    assert net_interfaces._run(["networksetup", "-listallhardwareports"]) == ""


# ── Linux link state ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("state,expect", [
    ("up\n", True),
    ("down\n", False),
    ("lowerlayerdown\n", False),
    ("unknown\n", None),
])
def test_linux_link_state_is_read_from_sysfs(monkeypatch, state, expect):
    """`unknown` is what loopback and many virtual drivers report — it must stay
    None rather than being reported as down, which would hide a usable NIC."""
    monkeypatch.setattr("builtins.open", lambda *a, **kw: io.StringIO(state))
    assert net_interfaces._linux_link_up("eth0") is expect


def test_an_interface_with_no_sysfs_entry_has_an_unknown_link_state(monkeypatch):
    def missing(*a, **kw):
        raise FileNotFoundError("no such device")

    monkeypatch.setattr("builtins.open", missing)
    assert net_interfaces._linux_link_up("eth0") is None


# ── Interface listing ────────────────────────────────────────────────────────

def test_listing_survives_scapy_being_unavailable(monkeypatch):
    """Without scapy there is nothing to enumerate, but the caller still needs a
    well-formed answer instead of a traceback."""
    import builtins
    real_import = builtins.__import__

    def no_scapy(name, *a, **kw):
        if name.startswith("scapy"):
            raise ImportError("scapy unavailable")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_scapy)
    meta, names, default = net_interfaces._scapy_metadata()

    assert names == [] and default is None


def test_a_linux_host_reads_link_state_from_sysfs(monkeypatch):
    """Drives the whole listing with the platform forced to Linux."""
    monkeypatch.setattr(net_interfaces.sys, "platform", "linux")
    monkeypatch.setattr(net_interfaces, "_scapy_metadata", lambda: (
        {"eth0": {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "flags": "UP,RUNNING"},
         "lo": {"ip": "127.0.0.1", "mac": "", "flags": "UP"}},
        ["eth0", "lo"], "eth0"))
    monkeypatch.setattr(net_interfaces, "_linux_link_up",
                        lambda dev: True if dev == "eth0" else None)

    records = net_interfaces.list_interfaces()
    by_name = {r["name"]: r for r in records}

    assert by_name["eth0"]["up"] is True
    assert by_name["eth0"]["recommended"] is True
    assert by_name["lo"]["kind"] == "loopback"
    assert by_name["lo"]["recommended"] is False, "loopback is never auto-picked"


def test_an_unknown_platform_reports_no_link_state(monkeypatch):
    monkeypatch.setattr(net_interfaces.sys, "platform", "freebsd")
    monkeypatch.setattr(net_interfaces, "_scapy_metadata", lambda: (
        {"em0": {"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "flags": "UP,RUNNING"}},
        ["em0"], None))

    records = net_interfaces.list_interfaces()
    assert records[0]["up"] is True, "an address plus RUNNING is enough to infer up"


def test_a_host_with_only_loopback_still_recommends_something(monkeypatch):
    """A recommendation of None would leave the GUI with no selectable default."""
    monkeypatch.setattr(net_interfaces.sys, "platform", "linux")
    monkeypatch.setattr(net_interfaces, "_scapy_metadata", lambda: (
        {"lo": {"ip": "127.0.0.1", "mac": "", "flags": "UP"}}, ["lo"], None))
    monkeypatch.setattr(net_interfaces, "_linux_link_up", lambda dev: None)

    records = net_interfaces.list_interfaces()
    assert [r["recommended"] for r in records] == [True]


# ── Capture privileges ───────────────────────────────────────────────────────

def test_root_can_always_capture_on_macos(monkeypatch):
    monkeypatch.setattr(capture_setup.os, "geteuid", lambda: 0)
    assert capture_setup._mac_capture_ok() is True


def test_access_bpf_membership_grants_capture_before_a_device_exists(monkeypatch):
    """After the setup helper runs, the group exists but /dev/bpfN permissions
    are only applied when the next device is opened. Reporting 'not ready' there
    would send the user round the setup loop a second time.
    """
    import grp

    monkeypatch.setattr(capture_setup.os, "geteuid", lambda: 501)
    monkeypatch.setattr(capture_setup.os, "getgroups", lambda: [501, 20, 4242])
    monkeypatch.setattr(grp, "getgrall",
                        lambda: [type("G", (), {"gr_name": "access_bpf", "gr_gid": 4242})()])
    monkeypatch.setattr(capture_setup.os.path, "exists", lambda p: False)

    assert capture_setup._mac_capture_ok() is True


def test_no_bpf_group_membership_means_no_capture(monkeypatch):
    import grp

    monkeypatch.setattr(capture_setup.os, "geteuid", lambda: 501)
    monkeypatch.setattr(capture_setup.os, "getgroups", lambda: [501, 20])
    monkeypatch.setattr(grp, "getgrall",
                        lambda: [type("G", (), {"gr_name": "access_bpf", "gr_gid": 4242})()])

    assert capture_setup._mac_capture_ok() is False


def test_windows_capture_falls_back_to_checking_for_npcap(monkeypatch):
    """`ctypes.windll` does not exist off Windows, so the admin check raises and
    the Npcap probe is the answer. That is the branch every non-Windows run
    takes, and it had never been exercised."""
    monkeypatch.setattr(capture_setup, "_npcap_installed", lambda: True)
    assert capture_setup._windows_capture_ok() is True

    monkeypatch.setattr(capture_setup, "_npcap_installed", lambda: False)
    assert capture_setup._windows_capture_ok() is False


def test_a_setcap_invocation_that_cannot_run_is_reported(monkeypatch):
    monkeypatch.setattr(capture_setup.shutil, "which", lambda exe: f"/usr/sbin/{exe}")

    def boom(*a, **kw):
        raise OSError("no such file")

    monkeypatch.setattr(capture_setup.subprocess, "run", boom)

    ok, msg = capture_setup._linux_setup()
    assert ok is False
    assert "setcap failed" in msg and "no such file" in msg


# ── Live sniffing ────────────────────────────────────────────────────────────

class _FakeSniffer:
    """Stands in for scapy's AsyncSniffer without touching a real interface."""
    started = False
    stopped = False

    def __init__(self, iface=None, prn=None, store=None, promisc=None):
        self.iface, self.prn = iface, prn

    def start(self):
        type(self).started = True

    def stop(self):
        type(self).stopped = True


def _fake_scapy(monkeypatch, sniffer_cls=_FakeSniffer):
    import sys
    import types as _types

    fake_all = _types.ModuleType("scapy.all")
    fake_all.AsyncSniffer = sniffer_cls
    monkeypatch.setitem(sys.modules, "scapy.all", fake_all)


def test_a_live_capture_runs_until_interrupted_and_always_stops_the_sniffer(monkeypatch):
    """Ctrl-C is the documented way to end `packetiq live`. The sniffer thread
    must be torn down on that path, not left running behind the process."""
    _FakeSniffer.started = _FakeSniffer.stopped = False
    _fake_scapy(monkeypatch)

    ticks = {"n": 0}

    def fake_sleep(secs):
        ticks["n"] += 1
        if ticks["n"] >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(live.time, "sleep", fake_sleep)

    alerts: list = []
    mon = live.sniff_live("lo0", alerts.append, interval_secs=0.01)

    assert _FakeSniffer.started and _FakeSniffer.stopped
    assert ticks["n"] == 3, "the scan loop ran until the interrupt"
    assert mon is not None


def test_captured_packets_are_fed_to_the_detectors(monkeypatch):
    """The sniffer callback is where a live packet becomes a parsed record."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    captured = {}

    class Capturing(_FakeSniffer):
        def start(self):
            captured["prn"] = self.prn

    _fake_scapy(monkeypatch, Capturing)
    monkeypatch.setattr(live.time, "sleep", lambda s: (_ for _ in ()).throw(KeyboardInterrupt))

    mon = live.sniff_live("lo0", lambda ev: None, interval_secs=0.01)

    pkt = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / TCP(sport=40000, dport=22, flags="S")
    pkt.time = TS
    captured["prn"](pkt)

    assert len(mon.buf) == 1, "the live packet reached the monitor"


def test_a_permission_error_becomes_actionable_guidance(monkeypatch):
    """"Operation not permitted" from BPF tells the user nothing; the message has
    to name sudo and CAP_NET_RAW."""
    class Denied(_FakeSniffer):
        def start(self):
            raise PermissionError(13, "Operation not permitted")

    _fake_scapy(monkeypatch, Denied)

    with pytest.raises(RuntimeError, match="sudo|CAP_NET_RAW"):
        live.sniff_live("eth0", lambda ev: None, interval_secs=0.01)


def test_a_packet_the_parser_rejects_does_not_reach_the_monitor(monkeypatch):
    captured = {}

    class Capturing(_FakeSniffer):
        def start(self):
            captured["prn"] = self.prn

    _fake_scapy(monkeypatch, Capturing)
    monkeypatch.setattr(live.time, "sleep", lambda s: (_ for _ in ()).throw(KeyboardInterrupt))

    mon = live.sniff_live("lo0", lambda ev: None, interval_secs=0.01)
    captured["prn"](object())          # not a packet at all

    assert len(mon.buf) == 0


# ── Zeek conn.log ingest ─────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expect", [
    ("1.5", 1.5), (2, 2.0), ("", 0.0), (None, 0.0), ("-", 0.0), ("abc", 0.0),
])
def test_zeek_numeric_fields_tolerate_the_unset_marker(value, expect):
    """Zeek writes `-` for an unset field; treating that as an error would drop
    every flow that has no duration recorded."""
    assert zeek._to_float(value) == expect


@pytest.mark.parametrize("value,expect", [
    ("42", 42), ("42.9", 42), ("", 0), (None, 0), ("-", 0),
])
def test_zeek_integer_fields_tolerate_the_unset_marker(value, expect):
    assert zeek._to_int(value) == expect


def test_a_json_lines_conn_log_is_parsed(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(
        '{"ts":1700000000.0,"id.orig_h":"10.0.0.5","id.orig_p":51000,'
        '"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp",'
        '"duration":1.5,"orig_bytes":500,"resp_bytes":9000}\n',
        encoding="utf-8")

    result = zeek.load_conn_log(str(log))
    assert len(result.flows) == 1
    flow = next(iter(result.flows.values()))
    assert flow.dst_port == 443 and flow.protocol == "TCP"


def test_a_malformed_json_line_is_skipped_not_fatal(tmp_path):
    """A conn.log truncated by log rotation still holds usable flows."""
    log = tmp_path / "conn.log"
    log.write_text(
        '{"ts":1700000000.0,"id.orig_h":"10.0.0.5","id.orig_p":51000,'
        '"id.resp_h":"93.184.216.34","id.resp_p":443,"proto":"tcp"}\n'
        '{"ts":1700000001.0,"id.orig_h":"10.0.0.6",\n'
        '{"ts":1700000002.0,"id.orig_h":"10.0.0.7","id.orig_p":51001,'
        '"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp"}\n',
        encoding="utf-8")

    result = zeek.load_conn_log(str(log))
    assert len(result.flows) == 2


def test_a_tsv_conn_log_without_a_fields_header_yields_nothing(tmp_path):
    """Without `#fields` the columns are unnamed — guessing them would invent data."""
    log = tmp_path / "conn.log"
    log.write_text("#separator \\x09\n#path\tconn\n"
                   "1700000000.0\tCabc\t10.0.0.5\t51000\t1.1.1.1\t53\tudp\n",
                   encoding="utf-8")

    assert zeek.load_conn_log(str(log)).flows == {}


def test_tsv_comment_and_blank_lines_are_skipped(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        "\n"
        "#types\ttime\taddr\tport\taddr\tport\tenum\n"
        "1700000000.0\t10.0.0.5\t51000\t1.1.1.1\t53\tudp\n"
        "#close\t2026-01-01-00-00-00\n",
        encoding="utf-8")

    result = zeek.load_conn_log(str(log))
    assert len(result.flows) == 1
    assert next(iter(result.flows.values())).protocol == "UDP"


def test_a_record_missing_an_endpoint_is_skipped(tmp_path):
    log = tmp_path / "conn.log"
    log.write_text(
        '{"ts":1700000000.0,"id.orig_p":51000,"id.resp_p":443,"proto":"tcp"}\n'
        '{"ts":1700000001.0,"id.orig_h":"10.0.0.5","id.orig_p":51001,'
        '"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp"}\n',
        encoding="utf-8")

    assert len(zeek.load_conn_log(str(log)).flows) == 1
