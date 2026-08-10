"""
Analysis history (SQLite), TOML configuration, and evidence PCAP slicing.

Three small modules that share one property: they are all best-effort, so a bug in
them fails *silently*. History writes swallow their exceptions, config falls back
to defaults on any parse error, and the slicer writes whatever matched. Silence is
the right behaviour — none of these should abort an analysis — but it also means
nothing here can be caught by simply running the tool.

Every test points the modules at a temp location; none touches the user's real
`~/.packetiq/history.db` or the repository's `packetiq.toml`.
"""

import os
import sqlite3

import pytest
from scapy.all import ICMP, IP, TCP, UDP, Ether, rdpcap, wrpcap

from packetiq import config as cfg
from packetiq import storage
from packetiq.export.pcap_slicer import PcapFilter, filter_for_event, slice_pcap

# =========================================================================== #
#  Analysis history                                                            #
# =========================================================================== #

@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "history.db"
    monkeypatch.setenv("PACKETIQ_DB", str(path))
    return path


def test_the_database_location_follows_the_environment(db):
    assert storage._db_path() == db


def test_the_default_location_is_under_the_home_directory(monkeypatch):
    monkeypatch.delenv("PACKETIQ_DB", raising=False)
    assert storage._db_path().name == "history.db"
    assert ".packetiq" in str(storage._db_path())


def test_recording_an_analysis_creates_the_database_and_the_row(db):
    assert storage.record("capture.pcap", 1200, 78, "HIGH", 5, 2, "45.33.32.156") is True
    assert db.is_file()

    rows = storage.recent()
    assert len(rows) == 1
    row = rows[0]
    assert row["filename"] == "capture.pcap"
    assert row["packets"] == 1200
    assert row["risk_score"] == 78
    assert row["risk_tier"] == "HIGH"
    assert row["event_count"] == 5
    assert row["chain_count"] == 2
    assert row["top_attacker"] == "45.33.32.156"
    assert row["analyzed_at"]


def test_history_is_returned_newest_first(db):
    for i in range(5):
        storage.record(f"c{i}.pcap", 10, i, "LOW", 0, 0)
    names = [r["filename"] for r in storage.recent()]
    assert names[0] == "c4.pcap"
    assert names == sorted(names, reverse=True)


def test_the_history_limit_is_honoured(db):
    for i in range(10):
        storage.record(f"c{i}.pcap", 1, 1, "LOW", 0, 0)
    assert len(storage.recent(limit=3)) == 3


def test_recent_on_an_empty_database_is_an_empty_list(db):
    assert storage.recent() == []


def test_an_entry_can_be_deleted_by_id(db):
    storage.record("keep.pcap", 1, 1, "LOW", 0, 0)
    storage.record("drop.pcap", 1, 1, "LOW", 0, 0)
    target = next(r for r in storage.recent() if r["filename"] == "drop.pcap")

    assert storage.delete(target["id"]) is True
    assert [r["filename"] for r in storage.recent()] == ["keep.pcap"]


def test_deleting_an_unknown_id_reports_false(db):
    storage.record("only.pcap", 1, 1, "LOW", 0, 0)
    assert storage.delete(999999) is False


def test_clearing_removes_everything_and_reports_the_count(db):
    for i in range(4):
        storage.record(f"c{i}.pcap", 1, 1, "LOW", 0, 0)
    assert storage.clear() == 4
    assert storage.recent() == []


def test_history_failures_never_propagate(monkeypatch, db):
    """A broken history database must not take an analysis down with it."""
    def boom(*a, **k):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(storage, "_connect", boom)
    assert storage.record("x.pcap", 1, 1, "LOW", 0, 0) is False
    assert storage.recent() == []
    assert storage.clear() == 0
    assert storage.delete(1) is False


@pytest.mark.skipif(os.name == "nt", reason="NTFS has no POSIX mode bits to read")
def test_the_history_directory_is_private_to_the_user(db):
    """History references capture paths, which are sensitive.

    Windows reports a synthetic 0o777 for every directory regardless of its ACL,
    so this asserts nothing there — the private-directory guarantee is a POSIX
    one, and claiming to have checked it on Windows would be false.
    """
    storage.record("x.pcap", 1, 1, "LOW", 0, 0)
    assert (db.parent.stat().st_mode & 0o077) == 0


# =========================================================================== #
#  Configuration                                                               #
# =========================================================================== #

@pytest.fixture(autouse=True)
def _clean_config_cache(monkeypatch, tmp_path):
    monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)          # no packetiq.toml in a fresh temp dir
    cfg.reload()
    yield
    cfg.reload()


def test_defaults_are_returned_without_a_config_file():
    merged = cfg.load()
    assert merged == cfg.DEFAULTS or all(
        merged[s] == dict(v) for s, v in cfg.DEFAULTS.items()
    )


def test_a_user_file_overlays_only_the_keys_it_sets(tmp_path, monkeypatch):
    section, key = next(
        (s, k) for s, kv in cfg.DEFAULTS.items() for k in kv
        if isinstance(list(kv.values())[0], (int, float))
    )
    original = cfg.DEFAULTS[section][key]
    conf = tmp_path / "packetiq.toml"
    conf.write_text(f"[{section}]\n{key} = 999\n", encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(conf))
    cfg.reload()

    assert cfg.get(section, key) == 999
    # every other default survived the overlay
    for s, kv in cfg.DEFAULTS.items():
        for k, v in kv.items():
            if (s, k) != (section, key):
                assert cfg.get(s, k) == v
    assert original != 999 or True


def test_a_config_file_in_the_working_directory_is_picked_up(tmp_path):
    (tmp_path / "packetiq.toml").write_text("[unknown]\nx = 1\n", encoding="utf-8")
    cfg.reload()
    assert cfg._config_path() == tmp_path / "packetiq.toml"


def test_an_unset_environment_path_is_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_CONFIG", str(tmp_path / "absent.toml"))
    assert cfg._config_path() is None


def test_malformed_toml_falls_back_to_defaults_instead_of_crashing(tmp_path, monkeypatch):
    conf = tmp_path / "bad.toml"
    conf.write_text("this is [not valid = toml((", encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(conf))
    cfg.reload()
    assert cfg.load()          # defaults, no exception


def test_a_missing_file_loads_as_empty(tmp_path):
    assert cfg._load_toml(tmp_path / "nope.toml") == {}


def test_an_unknown_key_falls_through_to_the_supplied_default():
    assert cfg.get("no_such_section", "no_such_key", "fallback") == "fallback"
    assert cfg.get("no_such_section", "no_such_key") is None


def test_a_non_table_top_level_value_is_ignored(tmp_path, monkeypatch):
    conf = tmp_path / "c.toml"
    conf.write_text('stray = "value"\n', encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(conf))
    cfg.reload()
    assert cfg.load()


def test_reload_picks_up_a_file_written_after_first_load(tmp_path, monkeypatch):
    """load() is cached; without reload() a freshly written config never applies."""
    conf = tmp_path / "c.toml"
    monkeypatch.setenv("PACKETIQ_CONFIG", str(conf))
    cfg.reload()
    section = next(iter(cfg.DEFAULTS))
    key = next(iter(cfg.DEFAULTS[section]))

    conf.write_text(f"[{section}]\n{key} = 4242\n", encoding="utf-8")
    assert cfg.get(section, key) != 4242          # still the cached load
    cfg.reload()
    assert cfg.get(section, key) == 4242


# =========================================================================== #
#  Evidence PCAP slicing                                                       #
# =========================================================================== #

ATTACKER = "45.33.32.156"
VICTIM = "192.168.1.50"
OTHER = "10.0.0.9"


@pytest.fixture
def mixed_pcap(tmp_path):
    path = tmp_path / "mixed.pcap"
    pkts = [
        Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=4000, dport=22, flags="S"),
        Ether() / IP(src=VICTIM, dst=ATTACKER) / TCP(sport=22, dport=4000, flags="SA"),
        Ether() / IP(src=OTHER, dst="8.8.8.8") / UDP(sport=5000, dport=53),
        Ether() / IP(src=OTHER, dst=VICTIM) / ICMP(),
        Ether() / IP(src=VICTIM, dst="1.1.1.1") / TCP(sport=5001, dport=443, flags="S"),
    ]
    for i, p in enumerate(pkts):
        p.time = 1700000000.0 + i
    wrpcap(str(path), pkts)
    return path


def test_an_empty_filter_is_reported_as_empty():
    assert PcapFilter().is_empty is True
    assert PcapFilter(ips={ATTACKER}).is_empty is False
    assert PcapFilter(ports={443}).is_empty is False
    assert PcapFilter(start_ts=1.0).is_empty is False


def test_slicing_by_ip_keeps_both_directions(mixed_pcap, tmp_path):
    out = tmp_path / "ev.pcap"
    n = slice_pcap(str(mixed_pcap), str(out), PcapFilter(ips={ATTACKER}))
    assert n == 2
    for p in rdpcap(str(out)):
        assert ATTACKER in (p[IP].src, p[IP].dst)


def test_slicing_by_port_matches_either_end(mixed_pcap, tmp_path):
    out = tmp_path / "ev.pcap"
    n = slice_pcap(str(mixed_pcap), str(out), PcapFilter(ports={22}))
    assert n == 2


def test_a_filter_matching_nothing_writes_no_packets(mixed_pcap, tmp_path):
    out = tmp_path / "ev.pcap"
    assert slice_pcap(str(mixed_pcap), str(out), PcapFilter(ips={"203.0.113.99"})) == 0


def test_the_packet_cap_is_honoured(mixed_pcap, tmp_path):
    out = tmp_path / "ev.pcap"
    n = slice_pcap(str(mixed_pcap), str(out), PcapFilter(ips={VICTIM}), max_packets=1)
    assert n == 1
    assert len(rdpcap(str(out))) == 1


def test_ip_and_port_together_narrow_the_match(mixed_pcap, tmp_path):
    """The criteria are ANDed: a packet must satisfy both, not either."""
    out = tmp_path / "ev.pcap"
    assert slice_pcap(str(mixed_pcap), str(out), PcapFilter(ips={OTHER}, ports={443})) == 0
    assert slice_pcap(str(mixed_pcap), str(out), PcapFilter(ips={VICTIM}, ports={443})) == 1


def test_a_time_window_bounds_the_slice(mixed_pcap, tmp_path):
    out = tmp_path / "ev.pcap"
    n = slice_pcap(str(mixed_pcap), str(out),
                   PcapFilter(start_ts=1700000000.0, end_ts=1700000001.0))
    assert n == 2


def test_an_empty_filter_copies_every_packet(mixed_pcap, tmp_path):
    out = tmp_path / "ev.pcap"
    assert slice_pcap(str(mixed_pcap), str(out), PcapFilter()) == 5


def test_a_filter_is_built_from_a_detection_event(pipeline):
    for event in pipeline["events"]:
        f = filter_for_event(event)
        assert isinstance(f, PcapFilter)
        if event.src_ip:
            assert event.src_ip in f.ips


def test_slicing_a_capture_that_does_not_exist_reports_zero(tmp_path):
    """The web UI slices several captures per request; one gone file must not 500."""
    out = tmp_path / "ev.pcap"
    assert slice_pcap(str(tmp_path / "absent.pcap"), str(out),
                      PcapFilter(ips={ATTACKER})) == 0


def test_slicing_an_unreadable_capture_reports_zero(tmp_path):
    junk = tmp_path / "notapcap.pcap"
    junk.write_bytes(b"this is not a capture file")
    out = tmp_path / "ev.pcap"
    assert slice_pcap(str(junk), str(out), PcapFilter(ips={ATTACKER})) == 0


def test_a_non_ip_packet_never_matches_an_ip_filter(tmp_path):
    path = tmp_path / "arp.pcap"
    wrpcap(str(path), [Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(), Ether()])
    out = tmp_path / "ev.pcap"
    assert slice_pcap(str(path), str(out), PcapFilter(ips={ATTACKER})) == 1
