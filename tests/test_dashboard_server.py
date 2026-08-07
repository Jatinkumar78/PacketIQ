"""
Standalone 3D dashboard server (`packetiq dashboard <pcap>`).

This module runs the whole pipeline and serialises the result into a template, so
it reaches into the attribute surface of eight other packages. Nothing exercised
it before: a renamed field anywhere upstream would have turned the command into an
AttributeError at launch, which is the worst place to find out.

The tests drive the real pipeline over the synthetic attack capture and assert the
payload is genuinely JSON-serialisable, because that is the failure the template
injection would otherwise hit at request time.
"""

import json

import pytest
from fastapi.testclient import TestClient

from packetiq.dashboard import launch_dashboard
from packetiq.dashboard import server as dash


@pytest.fixture(scope="module")
def payload(attack_pcap):
    return dash._run_and_serialize(attack_pcap)


# --------------------------------------------------------------------------- #
#  Pipeline → payload                                                           #
# --------------------------------------------------------------------------- #

def test_the_payload_carries_every_section_the_template_reads(payload):
    assert set(payload) == {
        "meta", "risk", "protocols", "top_ports", "top_src_ips", "events",
        "chains", "timeline", "activity_bar", "phases_seen", "fingerprints",
        "sigma_rules", "attributions",
    }


def test_the_payload_is_json_serialisable(payload):
    """It is injected into the page as JSON; a stray object breaks the route."""
    text = json.dumps(payload, ensure_ascii=False)
    assert json.loads(text) == payload


def test_metadata_reports_the_real_capture_not_placeholders(payload, attack_pcap):
    meta = payload["meta"]
    assert meta["pcap_file"] == "attack.pcap"
    assert meta["total_packets"] > 0
    assert meta["total_bytes"] > 0
    assert meta["unique_src_ips"] > 0
    assert meta["unique_flows"] > 0
    assert meta["dns_queries"] > 0
    assert meta["file_size"].endswith(("B", "KB", "MB", "GB"))
    assert meta["capture_start"] and meta["capture_end"]


def test_risk_is_a_real_score_with_a_tier(payload):
    risk = payload["risk"]
    assert 0 <= risk["score"] <= 100
    assert risk["tier"]
    assert isinstance(risk["breakdown"], dict)


def test_the_synthetic_attacks_are_present_in_the_event_list(payload):
    assert payload["events"], "the attack capture must produce events"
    kinds = {e["event_type"] for e in payload["events"]}
    assert {"BRUTE_FORCE", "PORT_SCAN"} & kinds


def test_every_serialised_event_has_the_fields_the_ui_binds_to(payload):
    for e in payload["events"]:
        assert set(e) >= {"event_type", "severity", "src_ip", "dst_ip", "dst_port",
                          "protocol", "timestamp", "ts_str", "packet_count",
                          "confidence", "description", "evidence"}
        assert isinstance(e["dst_port"], int)      # never None — the UI sorts on it
        assert isinstance(e["src_ip"], str)


def test_top_ports_and_ips_are_ordered_by_count_and_capped(payload):
    ports = [p["count"] for p in payload["top_ports"]]
    ips = [i["count"] for i in payload["top_src_ips"]]
    assert ports == sorted(ports, reverse=True)
    assert ips == sorted(ips, reverse=True)
    assert len(payload["top_ports"]) <= 20
    assert len(payload["top_src_ips"]) <= 15


def test_the_timeline_and_activity_bar_are_populated(payload):
    assert payload["timeline"]
    bar = payload["activity_bar"]
    assert isinstance(bar["buckets"], list)
    assert bar["bucket_secs"] >= 0
    assert bar["total"] >= 0


def test_timeline_timestamps_are_shortened_for_display(payload):
    for e in payload["timeline"]:
        assert len(e["ts_str"]) <= 12


def test_fingerprints_and_sigma_rules_serialise(payload):
    for f in payload["fingerprints"]:
        assert set(f) == {"src_ip", "os_guess", "observed_ttl", "initial_ttl",
                          "hops", "is_external"}
    for r in payload["sigma_rules"]:
        assert set(r) == {"title", "level", "yaml"}
        assert "detection:" in r["yaml"]


def test_chains_serialise_with_their_mitre_techniques(payload):
    for c in payload["chains"]:
        assert set(c) >= {"chain_id", "name", "severity", "attacker_ips",
                          "target_ips", "event_count", "phases", "mitre"}
        assert c["attacker_ips"] == sorted(c["attacker_ips"])
        for t in c["mitre"]:
            assert set(t) == {"id", "name"}


def test_attributions_keep_their_disclaimer(payload):
    """Attribution is a TTP-overlap hint; the caveat must survive serialisation."""
    for a in payload["attributions"]:
        assert set(a) >= {"name", "confidence", "matched_ttps", "disclaimer"}
        assert 0 <= a["confidence"] <= 100


# --------------------------------------------------------------------------- #
#  HTTP surface                                                                 #
# --------------------------------------------------------------------------- #

def test_the_index_route_injects_the_data_into_the_page(payload):
    client = TestClient(dash._build_app(payload))
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "__PACKETIQ_DATA__" not in resp.text, "placeholder was left unreplaced"
    assert payload["meta"]["pcap_file"] in resp.text


def test_the_api_route_returns_the_same_payload(payload):
    client = TestClient(dash._build_app(payload))
    resp = client.get("/api/data")
    assert resp.status_code == 200
    assert resp.json() == json.loads(json.dumps(payload))


def test_interactive_api_docs_are_disabled():
    """The dashboard is a viewer, not an API product — no schema surface."""
    client = TestClient(dash._build_app({"meta": {}}))
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404


def test_unicode_in_the_payload_survives_injection():
    data = {"meta": {"pcap_file": "café-日本.pcap"}}
    client = TestClient(dash._build_app(data))
    assert "café-日本.pcap" in client.get("/").text


# --------------------------------------------------------------------------- #
#  launch_dashboard                                                             #
# --------------------------------------------------------------------------- #

def test_launch_binds_loopback_only_and_opens_a_browser(attack_pcap, monkeypatch):
    """Binding anything but loopback would expose the capture to the network."""
    served = {}
    monkeypatch.setattr(dash.uvicorn, "run",
                        lambda app, **kw: served.update(kw, app=app))
    opened = []
    monkeypatch.setattr(dash.webbrowser, "open", opened.append)

    class ImmediateTimer:
        def __init__(self, delay, fn):
            self.fn = fn

        def start(self):
            self.fn()

    monkeypatch.setattr(dash.threading, "Timer", ImmediateTimer)

    launch_dashboard(attack_pcap, port=9123, open_browser=True)

    assert served["host"] == "127.0.0.1"
    assert served["port"] == 9123
    assert opened == ["http://127.0.0.1:9123/"]


def test_launch_can_skip_the_browser(attack_pcap, monkeypatch):
    monkeypatch.setattr(dash.uvicorn, "run", lambda app, **kw: None)
    opened = []
    monkeypatch.setattr(dash.webbrowser, "open", opened.append)
    monkeypatch.setattr(dash.threading, "Timer",
                        lambda *a, **k: pytest.fail("browser timer must not be armed"))

    launch_dashboard(attack_pcap, port=9124, open_browser=False)
    assert opened == []
