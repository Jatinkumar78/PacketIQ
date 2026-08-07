"""
OSINT feed refresher (`packetiq feeds update`).

This module writes the files the IOC matcher later reads, so a normalizer that
quietly drops or mangles rows would degrade detection with no visible error. It
also talks to five external services, which is why nothing here touches the
network: every response is supplied by the test.

The behaviour that matters is "a failed feed leaves the previous copy intact" —
a refresh must never be able to blank out working intel.
"""

import types

import pytest

from packetiq.enrichment import update as upd


@pytest.fixture
def cache(tmp_path, monkeypatch):
    d = tmp_path / "feeds"
    monkeypatch.setattr(upd, "cache_dir", lambda: d)
    return d


def _fake_requests(monkeypatch, handler):
    """Replace requests.get with a handler(url) -> response-like object."""
    monkeypatch.setattr(upd, "requests", types.SimpleNamespace(get=handler))


def _ok(text):
    return types.SimpleNamespace(text=text, raise_for_status=lambda: None)


# --------------------------------------------------------------------------- #
#  Normalizers                                                                  #
# --------------------------------------------------------------------------- #

FEODO_CSV = (
    "# comment line\n"
    "first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n"
    "2024-01-01,192.0.2.10,447,online,2024-06-01,Dridex\n"
    "2024-01-02,198.51.100.7,443,offline,2024-06-02,Emotet\n"
)


def test_feodo_rows_become_ip_and_malware_pairs():
    assert upd._norm_feodo(FEODO_CSV) == ["192.0.2.10,Dridex", "198.51.100.7,Emotet"]


def test_feodo_skips_the_header_and_comment_rows():
    assert "first_seen_utc" not in "".join(upd._norm_feodo(FEODO_CSV))


def test_feodo_ignores_a_row_that_is_not_an_ipv4_address():
    csv = "first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\n" \
          "2024-01-01,not-an-ip,447,online,2024-06-01,Dridex\n"
    assert upd._norm_feodo(csv) == []


def test_feodo_ignores_a_truncated_row():
    assert upd._norm_feodo("2024-01-01,192.0.2.10,447\n") == []


def test_tor_list_keeps_addresses_and_drops_comments():
    text = "# Tor exit list\n185.220.101.1\n\n  185.220.101.2  \n"
    assert upd._norm_tor(text) == ["185.220.101.1", "185.220.101.2"]


def test_spamhaus_drop_extracts_cidrs_from_json_lines():
    text = ('{"cidr":"192.0.2.0/24","sblid":"SBL1"}\n'
            '{"type":"metadata","version":1}\n'
            '{"cidr":"198.51.100.0/22"}\n')
    assert upd._norm_drop(text) == ["192.0.2.0/24", "198.51.100.0/22"]


def test_spamhaus_drop_survives_a_malformed_line():
    """One broken line must not cost the whole feed."""
    text = '{"cidr":"192.0.2.0/24"}\nthis is not json\n{"cidr":"203.0.113.0/24"}\n'
    assert upd._norm_drop(text) == ["192.0.2.0/24", "203.0.113.0/24"]


def test_malwarebazaar_keeps_only_full_length_sha256():
    good = "a" * 64
    text = f"# recent\n{good}\n{'b' * 32}\n\n"
    assert upd._norm_malwarebazaar(text) == [good]


THREATFOX_CSV = (
    '"first_seen","ioc_id","ioc","ioc_type","threat_type","malware","alias","malware_printable"\n'
    '"2024-01-01","1","1.2.3.4:8080","ip:port","botnet_cc","win.qakbot","","QakBot"\n'
    '"2024-01-02","2","evil.example.com","domain","botnet_cc","win.emotet","","Emotet"\n'
)


def test_threatfox_rows_become_tab_separated_triples():
    rows = upd._norm_threatfox(THREATFOX_CSV)
    assert rows == ["1.2.3.4:8080\tip:port\tQakBot", "evil.example.com\tdomain\tEmotet"]


def test_threatfox_falls_back_to_the_malware_id_when_the_pretty_name_is_blank():
    csv = ('"2024-01-01","1","1.2.3.4:8080","ip:port","botnet_cc","win.qakbot","",""\n')
    assert upd._norm_threatfox(csv) == ["1.2.3.4:8080\tip:port\twin.qakbot"]


def test_threatfox_ignores_unsupported_ioc_types():
    csv = ('"2024-01-01","1","deadbeef","sha256_hash","payload","win.x","","X"\n')
    assert upd._norm_threatfox(csv) == []


def test_threatfox_ignores_short_and_comment_rows():
    assert upd._norm_threatfox("# header comment\n") == []
    assert upd._norm_threatfox('"a","b","c"\n') == []


# --------------------------------------------------------------------------- #
#  update_feeds                                                                 #
# --------------------------------------------------------------------------- #

def test_a_successful_refresh_writes_every_feed_with_a_stamped_header(cache, monkeypatch):
    bodies = {
        "feodo_c2.csv": FEODO_CSV,
        "threatfox.tsv": THREATFOX_CSV,
        "tor_exits.txt": "185.220.101.1\n",
        "spamhaus_drop.txt": '{"cidr":"192.0.2.0/24"}\n',
        "malwarebazaar_sha256.txt": "a" * 64 + "\n",
    }
    by_url = {url: bodies[name] for name, (url, _, _) in upd.FEEDS.items()}
    _fake_requests(monkeypatch, lambda url, **kw: _ok(by_url[url]))

    results = upd.update_feeds()

    assert set(results) == set(upd.FEEDS)
    assert all(isinstance(v, int) and v > 0 for v in results.values()), results
    for name in upd.FEEDS:
        text = (cache / name).read_text(encoding="utf-8")
        assert text.startswith("# PacketIQ feed:")
        assert "# Refreshed:" in text
        assert text.endswith("\n")


def test_the_cache_directory_is_created_when_absent(cache, monkeypatch):
    assert not cache.exists()
    _fake_requests(monkeypatch, lambda url, **kw: _ok("185.220.101.1\n"))
    upd.update_feeds()
    assert cache.is_dir()


def test_a_feed_that_errors_is_reported_and_leaves_the_old_copy_intact(cache, monkeypatch):
    cache.mkdir(parents=True)
    stale = cache / "tor_exits.txt"
    stale.write_text("# previous good copy\n1.2.3.4\n", encoding="utf-8")

    tor_url = upd.FEEDS["tor_exits.txt"][0]

    def handler(url, **kw):
        if url == tor_url:
            raise ConnectionError("network unreachable")
        return _ok("185.220.101.1\n")

    _fake_requests(monkeypatch, handler)
    results = upd.update_feeds()

    assert isinstance(results["tor_exits.txt"], str)
    assert results["tor_exits.txt"].startswith("error: ConnectionError")
    assert stale.read_text(encoding="utf-8") == "# previous good copy\n1.2.3.4\n"


def test_an_http_error_status_is_reported_per_feed(cache, monkeypatch):
    def raise_http():
        raise RuntimeError("503 Server Error")

    _fake_requests(
        monkeypatch,
        lambda url, **kw: types.SimpleNamespace(text="", raise_for_status=raise_http),
    )
    results = upd.update_feeds()
    assert all(str(v).startswith("error: RuntimeError") for v in results.values())


def test_a_feed_that_parses_to_nothing_is_an_error_not_an_empty_file(cache, monkeypatch):
    """Writing zero rows would silently erase working intel."""
    _fake_requests(monkeypatch, lambda url, **kw: _ok("# only comments\n"))
    results = upd.update_feeds()

    assert all(v == "error: feed returned no usable rows" for v in results.values()), results
    assert not any(cache.glob("*")) or all(
        not (cache / n).exists() for n in upd.FEEDS
    )


def test_progress_is_reported_for_every_feed(cache, monkeypatch):
    _fake_requests(monkeypatch, lambda url, **kw: _ok("185.220.101.1\n"))
    seen = []
    upd.update_feeds(progress=seen.append)
    assert seen == list(upd.FEEDS)


def test_every_feed_is_fetched_with_a_timeout_and_identifying_user_agent(cache, monkeypatch):
    """No timeout means `feeds update` can hang forever on a dead endpoint."""
    calls = []

    def handler(url, **kw):
        calls.append(kw)
        return _ok("185.220.101.1\n")

    _fake_requests(monkeypatch, handler)
    upd.update_feeds()

    assert len(calls) == len(upd.FEEDS)
    assert all(c["timeout"] == upd._TIMEOUT for c in calls)
    assert all("PacketIQ" in c["headers"]["User-Agent"] for c in calls)


def test_feed_definitions_are_well_formed():
    for name, (url, header, normalizer) in upd.FEEDS.items():
        assert url.startswith("https://"), f"{name} must be fetched over TLS"
        assert len(header) == 3
        assert callable(normalizer)
