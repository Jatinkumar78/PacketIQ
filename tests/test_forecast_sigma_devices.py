"""Threat forecasting, Sigma rule emission, device typing, and config loading.

The forecast is the most opinionated thing PacketIQ says, so every claim it
makes has to be traceable to something in the packets. The tests here check the
evidence lines it cites, not just that a prediction appeared.
"""



from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.prediction import predict as forecast
from packetiq.sigma.generator import SigmaGenerator

TS = 1700000000.0


def _event(etype, severity=Severity.HIGH, src="45.33.32.156", dst="192.168.1.50",
           evidence=None, description="finding", port=445):
    return DetectionEvent(event_type=etype, severity=severity, src_ip=src,
                          description=description, dst_ip=dst, dst_port=port,
                          protocol="TCP", timestamp=TS, packet_count=10,
                          evidence=evidence or {})


def _exposed(result, ip, port, proto="TCP", service="SSH", clients=("192.168.1.99",),
             state="open"):
    result.service_exposure[(ip, port, proto)] = {
        "state": state, "service": service, "sent": 20, "recv": 15,
        "clients": set(clients),
    }
    return result


def _result(**kw):
    r = ExtractionResult()
    r.capture_start = TS
    r.capture_end = TS + 600
    for k, v in kw.items():
        setattr(r, k, v)
    return r


# ── Forecast evidence ────────────────────────────────────────────────────────

def test_a_probed_service_cites_the_scan_that_probed_it():
    """"Someone scanned this exact port" is the strongest evidence the forecast
    has, and it is what raises the likelihood from Medium to High."""
    result = _exposed(_result(transmitted_ips={"192.168.1.50"}), "192.168.1.50", 22)
    scan = _event(EventType.PORT_SCAN, evidence={"sample_ports": [21, 22, 23, 80]},
                  dst="192.168.1.50", port=22)

    preds = forecast(result, [scan])
    # Filter on the category, not on the word "SSH": the Initial Access forecast
    # also names SSH when listing what the scan found.
    ssh = [p for p in preds if p.category == "Credential Access"]

    assert ssh, "an exposed SSH service should be forecast"
    assert any("probed by a scan" in line for line in ssh[0].evidence)
    assert ssh[0].likelihood == "High"


def test_a_service_reached_from_off_network_says_so():
    result = _exposed(_result(transmitted_ips={"192.168.1.50"}), "192.168.1.50", 22,
                      clients=("185.199.108.153",))

    preds = forecast(result, [])
    ssh = [p for p in preds if p.category == "Credential Access"]

    assert ssh
    assert any("reachable from outside" in line for line in ssh[0].evidence)
    assert ssh[0].likelihood == "High"


def test_a_service_only_used_from_inside_is_a_lower_likelihood():
    # Both endpoints must be inside the monitored network — membership comes from
    # link-layer evidence, so a host that never transmitted counts as off-net.
    result = _exposed(_result(transmitted_ips={"192.168.1.50", "192.168.1.99"}),
                      "192.168.1.50", 22, clients=("192.168.1.99",))

    ssh = [p for p in forecast(result, []) if p.category == "Credential Access"]
    assert ssh and ssh[0].likelihood == "Medium"


def test_a_scan_that_found_live_services_names_them():
    result = _exposed(_result(transmitted_ips={"192.168.1.50"}), "192.168.1.50", 22)
    preds = forecast(result, [_event(EventType.PORT_SCAN)])
    exploit = [p for p in preds if p.category == "Initial Access"]

    assert exploit
    assert any("live services the scan could have found" in line
               for line in exploit[0].evidence)
    assert exploit[0].likelihood == "High"


def test_a_scan_that_found_nothing_says_so_and_is_low_likelihood():
    """Honest reporting of a failed sweep. Claiming High here would manufacture
    urgency out of an attack that achieved nothing."""
    preds = forecast(_result(), [_event(EventType.PORT_SCAN)])
    exploit = [p for p in preds if p.category == "Initial Access"]

    assert exploit
    assert any("found nothing open" in line for line in exploit[0].evidence)
    assert exploit[0].likelihood == "Low"


def test_layer_two_activity_forecasts_interception_and_quotes_the_finding():
    arp = _event(EventType.ARP_SPOOFING, src="192.168.1.99", dst=None,
                 description="192.168.1.99 claimed 192.168.1.1 with a second MAC")

    preds = forecast(_result(), [arp])
    mitm = [p for p in preds if p.category == "Lateral Movement"]

    assert mitm
    assert mitm[0].evidence == ["192.168.1.99 claimed 192.168.1.1 with a second MAC"]
    assert "192.168.1.99" in mitm[0].affected


def test_an_arp_sweep_also_forecasts_interception():
    preds = forecast(_result(), [_event(EventType.ARP_SCAN, src="192.168.1.99", dst=None)])
    assert any(p.category == "Lateral Movement" for p in preds)


def test_a_quiet_capture_forecasts_nothing():
    """No observed exposure and no findings means no prediction — the forecast
    must not invent risk from an empty capture."""
    assert forecast(_result(), []) == []


def test_a_closed_port_is_never_forecast_as_exposure():
    """A RST proves nothing is listening. Treating it as attack surface was the
    original false-positive source this whole path was rewritten to fix."""
    result = _exposed(_result(transmitted_ips={"192.168.1.50"}), "192.168.1.50", 22,
                      state="closed")
    assert [p for p in forecast(result, []) if p.category == "Credential Access"] == []


def test_a_cleartext_service_is_called_out_as_such():
    result = _exposed(_result(transmitted_ips={"192.168.1.50"}), "192.168.1.50", 21,
                      service="FTP")
    ftp = [p for p in forecast(result, []) if "cleartext" in " ".join(p.evidence)]

    assert ftp
    assert any("cleartext protocol" in line for line in ftp[0].evidence)


# ── Sigma rule emission ──────────────────────────────────────────────────────

def test_a_ja3_finding_becomes_a_sigma_rule_naming_the_family_and_hash():
    """The rule has to carry the hash — a Sigma rule that only says 'malicious
    TLS' cannot be deployed anywhere."""
    ev = _event(EventType.JA3_ANOMALY, severity=Severity.CRITICAL,
                evidence={"malware": "Emotet", "ja3_hash": "b" * 32})

    rules = SigmaGenerator().generate([ev], [])
    ja3 = [r for r in rules if "TLS Fingerprint" in r.title]

    assert len(ja3) == 1
    assert "Emotet" in ja3[0].title
    assert "b" * 32 in ja3[0].raw_yaml
    assert ja3[0].level == "critical"
    assert "attack.command_and_control" in ja3[0].tags


def test_a_ja3_finding_with_no_family_still_produces_a_usable_rule():
    ev = _event(EventType.JA3_ANOMALY, evidence={"ja3_hash": "c" * 32})
    ja3 = [r for r in SigmaGenerator().generate([ev], []) if "TLS Fingerprint" in r.title]

    assert ja3 and "Unknown malware" in ja3[0].title


# ── Device typing ────────────────────────────────────────────────────────────

def test_a_nic_fronting_many_addresses_is_typed_as_a_gateway():
    """A router's MAC carries traffic for every host behind it. Folding those
    addresses into one node would collapse the whole network into a single dot.
    """
    from packetiq.extractor.data_extractor import DataExtractor

    ex = DataExtractor()
    mac = "aa:bb:cc:00:00:01"
    fanout = ex._GATEWAY_IP_FANOUT + 3
    ex._mac_pkts[mac] = 500
    ex._mac_ips[mac] = {f"10.0.0.{i}" for i in range(1, fanout + 1)}
    ex._mac_protos[mac] = {"IPv4"}
    for i in range(1, fanout + 1):
        ex._ip_mac_counts.setdefault(f"10.0.0.{i}", {})[mac] = 10

    result = ex.finalize()
    gateways = [d for d in result.devices if d["kind"] == "gateway"]

    assert len(gateways) == 1
    assert len(gateways[0]["ips"]) == fanout
    assert result.ip_to_device.get("10.0.0.5") in (None, "10.0.0.5"), (
        "a gateway must not absorb the hosts behind it")


def test_a_nic_with_a_couple_of_addresses_is_an_endpoint():
    from packetiq.extractor.data_extractor import DataExtractor

    ex = DataExtractor()
    mac = "aa:bb:cc:00:00:02"
    ex._mac_pkts[mac] = 100
    ex._mac_ips[mac] = {"10.0.0.9", "fd00::9"}
    ex._mac_protos[mac] = {"IPv4", "IPv6"}
    ex._ip_mac_counts.setdefault("10.0.0.9", {})[mac] = 60
    ex._ip_mac_counts.setdefault("fd00::9", {})[mac] = 40

    result = ex.finalize()
    assert [d["kind"] for d in result.devices] == ["endpoint"]


# ── TOML config loading ──────────────────────────────────────────────────────
#
# `_load_toml` prefers `tomllib` and falls back to the `tomli` backport, and no
# supported interpreter has both as a given: `tomllib` arrived in 3.11, and
# `tomli` is only a dependency *below* 3.11. Reaching for whichever module the
# interpreter happens to ship therefore measures the interpreter, not PacketIQ —
# and it showed up twice. The 3.9 leg reported the `tomllib` branch as untested
# because it cannot exist there, and on a clean 3.11/3.12 install the backport
# test failed outright, because hiding `tomllib` and importing the real `tomli`
# found nothing and landed in `except Exception: return {}`.
#
# Binding a stand-in that delegates to whatever parser *is* present makes the
# same lines run on every leg, so the coverage number stops depending on which
# Python is measuring it.

def _bind_toml_parser(monkeypatch, name, seen=None):
    """Bind ``sys.modules[name]`` to a stand-in that parses for real."""
    import sys
    import types

    try:
        import tomllib as parser  # 3.11+
    except ModuleNotFoundError:       # 3.9 / 3.10 — the backport is a hard dep there
        import tomli as parser

    module = types.ModuleType(name)

    def load(fh):
        if seen is not None:
            seen[name] = True
        return parser.load(fh)

    module.load = load                                       # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, name, module)


def _hide(monkeypatch, *names):
    """Make ``import <name>`` raise, and return the real ``__import__``."""
    import builtins

    real_import = builtins.__import__

    def guarded(name, *a, **kw):
        if name in names:
            raise ModuleNotFoundError(f"No module named {name!r}")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", guarded)
    return real_import


def _restore_import(monkeypatch, real_import):
    """Put the real ``__import__`` back.

    Deliberately not ``monkeypatch.undo()``: that would also revert conftest's
    autouse history-DB isolation, since pytest hands the fixture and the test the
    same monkeypatch instance.
    """
    import builtins

    monkeypatch.setattr(builtins, "__import__", real_import)


def test_the_toml_backport_is_used_when_the_stdlib_module_is_absent(tmp_path, monkeypatch):
    """Python 3.9 and 3.10 have no `tomllib`, so the whole config system runs
    through `tomli` there. On 3.11+ that path is otherwise never executed, which
    is exactly how it would rot unnoticed until a 3.9 user hit it.
    """
    from packetiq import config

    cfg = tmp_path / "packetiq.toml"
    cfg.write_text("[brute_force]\nssh_threshold = 7\n", encoding="utf-8")

    seen: dict = {}
    _bind_toml_parser(monkeypatch, "tomli", seen)
    real_import = _hide(monkeypatch, "tomllib")

    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        assert config.get("brute_force", "ssh_threshold", None) == 7
        assert seen.get("tomli") is True
    finally:
        _restore_import(monkeypatch, real_import)
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


def test_the_stdlib_parser_is_used_when_it_is_available(tmp_path, monkeypatch):
    """The mirror image, and the reason the 3.9 leg could never reach 100%: with
    no `tomllib` to import, the preferred branch is unreachable on that
    interpreter and its lines read as untested."""
    from packetiq import config

    cfg = tmp_path / "packetiq.toml"
    cfg.write_text("[brute_force]\nssh_threshold = 9\n", encoding="utf-8")

    seen: dict = {}
    _bind_toml_parser(monkeypatch, "tomllib", seen)

    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        assert config.get("brute_force", "ssh_threshold", None) == 9
        assert seen.get("tomllib") is True
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


def test_a_config_file_that_is_not_valid_toml_falls_back_to_defaults(tmp_path, monkeypatch):
    """A broken packetiq.toml must not stop the tool starting.

    Bound to the stand-in for the same reason as above: without it, the parse
    error surfaces from the `tomli` arm on 3.9/3.10 and from the `tomllib` arm on
    3.11+, so the two `except Exception` lines swap places between matrix legs.
    """
    from packetiq import config

    cfg = tmp_path / "packetiq.toml"
    cfg.write_text("[brute_force\nssh_threshold = ", encoding="utf-8")

    _bind_toml_parser(monkeypatch, "tomllib")

    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        assert config.get("brute_force", "ssh_threshold", None) == 20
    finally:
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()


def test_a_broken_config_is_also_survivable_without_the_stdlib_parser(tmp_path, monkeypatch):
    """The 3.9 path needs the same guarantee as the 3.11+ one."""
    from packetiq import config

    cfg = tmp_path / "packetiq.toml"
    cfg.write_text("[brute_force\n", encoding="utf-8")

    real_import = _hide(monkeypatch, "tomllib", "tomli")

    monkeypatch.setenv("PACKETIQ_CONFIG", str(cfg))
    config.reload()
    try:
        assert config.get("brute_force", "ssh_threshold", None) == 20
    finally:
        _restore_import(monkeypatch, real_import)
        monkeypatch.delenv("PACKETIQ_CONFIG", raising=False)
        config.reload()
