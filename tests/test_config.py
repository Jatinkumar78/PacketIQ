"""Tests for the tunable configuration system."""


from packetiq import config


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
