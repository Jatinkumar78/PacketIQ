"""Tests for the tunable configuration system."""

import os

import pytest

from packetiq import config


@pytest.fixture(autouse=True)
def _reset_profile_and_config():
    """Guarantee no active profile or config path leaks out of a test here.

    An active profile is process-global, so a test that forgets to clear it would
    silently lower every detector threshold for the rest of the suite. This resets
    unconditionally after each test, independent of monkeypatch's own undo order.
    """
    yield
    os.environ.pop("PACKETIQ_PROFILE", None)
    os.environ.pop("PACKETIQ_CONFIG", None)
    config.set_active_profile(None)
    config.reload()


def test_defaults_when_no_file(monkeypatch):
    monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
    config.reload()
    assert config.get("brute_force", "ssh_threshold", None) == 20
    assert config.get("beacon", "cv_threshold_med", None) == 0.25


def test_user_config_overrides_defaults(tmp_path, monkeypatch):
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text(
        "[brute_force]\nssh_threshold = 3\n\n[dns]\ndga_entropy_threshold = 2.5\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        assert config.get("brute_force", "ssh_threshold", None) == 3
        assert config.get("dns", "dga_entropy_threshold", None) == 2.5
        # untouched keys still fall back to defaults
        assert config.get("brute_force", "ftp_threshold", None) == 15
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


def test_config_changes_detector_behavior(tmp_path, monkeypatch):
    """Lowering the SSH threshold should make a small burst trip the detector."""
    from packetiq.detection import brute_force
    from packetiq.detection.models import EventType
    from packetiq.extractor.data_extractor import ExtractionResult

    res = ExtractionResult()
    res.tcp_syn_pairs = {("1.2.3.4", "10.0.0.1", 22): [float(i) for i in range(4)]}
    res.flows = {}

    # default threshold (20) → no detection on 4 attempts
    monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
    config.reload()
    assert not [e for e in brute_force.detect(res) if e.event_type == EventType.BRUTE_FORCE]

    # lowered threshold (3) → detection fires
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text("[brute_force]\nssh_threshold = 3\n", encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        hits = [e for e in brute_force.detect(res) if e.event_type == EventType.BRUTE_FORCE]
        assert hits, "lowered threshold should trip brute-force detection"
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


# ── Named sensitivity profiles (the `ctf` preset) ─────────────────────────────

def test_the_ctf_profile_ships_and_is_listed():
    assert "ctf" in config.available_profiles()


def test_available_profiles_is_empty_when_the_directory_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_PROFILES_DIR", tmp_path / "does-not-exist")
    assert config.available_profiles() == []


def test_no_profile_is_active_by_default(monkeypatch):
    monkeypatch.delenv("PACKETIQ_PROFILE", raising=False)
    config.set_active_profile(None)
    assert config.active_profile() is None


def test_the_ctf_profile_lowers_scan_brute_and_beacon_minimums():
    config.set_active_profile("ctf")
    assert config.active_profile() == "ctf"
    assert config.get("port_scan", "vertical_port_threshold", None) == 3
    assert config.get("port_scan", "horizontal_host_threshold", None) == 3
    assert config.get("brute_force", "ssh_threshold", None) == 3
    assert config.get("beacon", "min_connections", None) == 3
    # a key the profile does not touch still reads its production default
    assert config.get("beacon", "cv_threshold_med", None) == 0.25


def test_an_unknown_profile_name_is_ignored(monkeypatch):
    monkeypatch.delenv("PACKETIQ_PROFILE", raising=False)
    config.set_active_profile("no-such-profile")
    assert config.get("brute_force", "ssh_threshold", None) == 20


def test_the_profile_can_be_chosen_by_environment_variable(monkeypatch):
    monkeypatch.setenv("PACKETIQ_PROFILE", "ctf")
    config.set_active_profile(None)        # defer to the env var
    config.reload()
    assert config.active_profile() == "ctf"
    assert config.get("brute_force", "ssh_threshold", None) == 3


def test_clearing_the_profile_restores_the_production_defaults():
    config.set_active_profile("ctf")
    assert config.get("brute_force", "ssh_threshold", None) == 3
    config.set_active_profile("")          # falsy name clears it
    assert config.active_profile() is None
    assert config.get("brute_force", "ssh_threshold", None) == 20


def test_the_user_file_still_overrides_an_active_profile(tmp_path, monkeypatch):
    """A profile is a starting posture; the user's own file has the last word."""
    cfg = tmp_path / "packetiq.toml"
    cfg.write_text("[brute_force]\nssh_threshold = 7\n", encoding="utf-8")
    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.set_active_profile("ctf")       # profile says 3
    config.reload()
    assert config.get("brute_force", "ssh_threshold", None) == 7   # user file wins


def test_the_ctf_profile_makes_a_small_brute_force_trip_the_detector():
    """Four SSH attempts are below the production floor (20) but at the ctf floor (3)."""
    from packetiq.detection import brute_force
    from packetiq.detection.models import EventType
    from packetiq.extractor.data_extractor import ExtractionResult

    res = ExtractionResult()
    res.tcp_syn_pairs = {("1.2.3.4", "10.0.0.1", 22): [float(i) for i in range(4)]}
    res.flows = {}

    config.set_active_profile(None)
    assert not [e for e in brute_force.detect(res) if e.event_type == EventType.BRUTE_FORCE]

    config.set_active_profile("ctf")
    hits = [e for e in brute_force.detect(res) if e.event_type == EventType.BRUTE_FORCE]
    assert hits, "the ctf profile should let a four-attempt brute force trip the detector"


def test_the_cli_profile_flag_activates_the_profile():
    from click.testing import CliRunner

    from packetiq.cli import main

    result = CliRunner().invoke(main, ["--profile", "ctf"])
    assert result.exit_code == 0
    assert config.active_profile() == "ctf"
    assert "profile" in result.output.lower()
