"""The IOC store: lookups, severity mapping, and feed-file resolution.

Every threat-intel finding in the product comes out of these three lookups, and
the parent-domain walk in particular is what makes a match on `evil.com` also
catch `cdn.sub.evil.com`. A silent miss here reads exactly like a clean capture.
"""

import ipaddress

import pytest

from packetiq.detection.models import Severity
from packetiq.enrichment import feeds
from packetiq.enrichment.feeds import IOCHit, IOCStore


def _hit(indicator, kind="domain", label="Malware"):
    return IOCHit(indicator=indicator, kind=kind, source="TestFeed",
                  label=label, severity=Severity.CRITICAL)


# ── IP and CIDR lookups ──────────────────────────────────────────────────────

def test_an_exact_ip_match_wins():
    store = IOCStore()
    store.bad_ips["185.199.108.153"] = _hit("185.199.108.153", "ip")

    assert store.lookup_ip("185.199.108.153").label == "Malware"
    assert store.lookup_ip("185.199.108.154") is None


def test_an_ip_inside_a_listed_netblock_matches():
    store = IOCStore()
    store.bad_cidrs.append((ipaddress.ip_network("185.199.108.0/24"),
                            _hit("185.199.108.0/24", "cidr", "Listed netblock")))

    assert store.lookup_ip("185.199.108.153").label == "Listed netblock"
    assert store.lookup_ip("185.199.109.1") is None


def test_something_that_is_not_an_address_never_matches_a_netblock():
    """The IP field can carry a hostname when a capture was parsed loosely.

    Letting ipaddress raise here would abort the whole enrichment pass.
    """
    store = IOCStore()
    store.bad_cidrs.append((ipaddress.ip_network("10.0.0.0/8"), _hit("10.0.0.0/8", "cidr")))

    assert store.lookup_ip("not-an-ip") is None
    assert store.lookup_ip("") is None


# ── Domain lookups ───────────────────────────────────────────────────────────

def test_an_exact_domain_match_is_returned():
    store = IOCStore()
    store.bad_domains["evil.example.com"] = _hit("evil.example.com")

    assert store.lookup_domain("evil.example.com") is not None


def test_a_subdomain_matches_its_listed_parent():
    """Feeds list registrable domains; malware uses fresh subdomains of them."""
    store = IOCStore()
    store.bad_domains["evil.example.com"] = _hit("evil.example.com")

    assert store.lookup_domain("cdn.evil.example.com") is not None
    assert store.lookup_domain("a.b.c.evil.example.com") is not None


def test_a_sibling_domain_does_not_match():
    store = IOCStore()
    store.bad_domains["evil.example.com"] = _hit("evil.example.com")

    assert store.lookup_domain("good.example.com") is None


def test_the_public_suffix_alone_is_never_treated_as_a_parent():
    """The walk stops before the last two labels, so a listing on `evil.com`
    can never make every `.com` domain a match."""
    store = IOCStore()
    store.bad_domains["example.com"] = _hit("example.com")

    assert store.lookup_domain("unrelated.org") is None


def test_a_domain_lookup_normalises_case_and_the_root_dot():
    store = IOCStore()
    store.bad_domains["evil.example.com"] = _hit("evil.example.com")

    assert store.lookup_domain("EVIL.Example.COM.") is not None


def test_an_empty_domain_is_not_looked_up():
    store = IOCStore()
    store.bad_domains["evil.example.com"] = _hit("evil.example.com")

    assert store.lookup_domain("") is None
    assert store.lookup_domain(None) is None


def test_a_hash_lookup_normalises_case():
    store = IOCStore()
    store.bad_hashes["a" * 64] = _hit("a" * 64, "hash")

    assert store.lookup_hash("A" * 64) is not None
    assert store.lookup_hash(None) is None


# ── Severity mapping ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("label,expected", [
    ("Tor exit node", Severity.MEDIUM),
    ("TOR EXIT relay", Severity.MEDIUM),
    ("Listed netblock (Spamhaus DROP)", Severity.HIGH),
    ("spamhaus drop", Severity.HIGH),
    ("Emotet (ThreatFox)", Severity.CRITICAL),
    ("Dridex C2", Severity.CRITICAL),
])
def test_feed_labels_map_to_proportionate_severities(label, expected):
    """A Tor exit is not a compromise; a named C2 is. Flattening the two would
    either bury real findings or fill the report with MEDIUM noise."""
    assert feeds._sev(label) == expected


# ── Feed file resolution ─────────────────────────────────────────────────────

def test_a_refreshed_feed_takes_precedence_over_the_bundled_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_FEED_DIR", str(tmp_path))
    refreshed = tmp_path / "feodo.csv"
    refreshed.write_text("1.2.3.4,Dridex\n", encoding="utf-8")

    path, origin = feeds._resolve("feodo.csv")
    assert path == refreshed
    assert origin == "refreshed"


def test_a_feed_with_no_copy_anywhere_resolves_to_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_FEED_DIR", str(tmp_path))
    assert feeds._resolve("not_a_real_feed.txt") == (None, None)


def test_feed_details_omits_feeds_that_are_not_on_disk(tmp_path, monkeypatch):
    """The GUI provenance panel must not invent a row for a feed that is absent."""
    monkeypatch.setenv("PACKETIQ_FEED_DIR", str(tmp_path))
    monkeypatch.setattr(feeds, "_BUNDLED_DIR", tmp_path / "nothing-here")

    assert feeds.feed_details() == []


def test_the_search_path_lists_the_bundled_copy_before_the_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("PACKETIQ_FEED_DIR", str(tmp_path))
    paths = feeds._feed_paths("feodo.csv")

    assert len(paths) == 2
    assert paths[1] == tmp_path / "feodo.csv"


# ── Store construction from feed files ───────────────────────────────────────

def _feed_dir(tmp_path, monkeypatch, **files):
    monkeypatch.setenv("PACKETIQ_FEED_DIR", str(tmp_path))
    monkeypatch.setattr(feeds, "_BUNDLED_DIR", tmp_path / "absent")
    for name, content in files.items():
        (tmp_path / name.replace("__", ".")).write_text(content, encoding="utf-8")
    feeds.load_store.cache_clear()
    return feeds


def test_a_threatfox_row_with_too_few_columns_is_skipped(tmp_path, monkeypatch):
    """Feed files are third-party text; a short row must not abort the load."""
    f = _feed_dir(tmp_path, monkeypatch,
                  threatfox__tsv="justoneclumn\n1.2.3.4:443\tip:port\tEmotet\n")
    try:
        store = f.load_store()
        assert store.lookup_ip("1.2.3.4") is not None
        assert "Emotet" in store.lookup_ip("1.2.3.4").label
    finally:
        f.load_store.cache_clear()


def test_a_malformed_cidr_in_the_drop_feed_is_skipped(tmp_path, monkeypatch):
    f = _feed_dir(tmp_path, monkeypatch,
                  spamhaus_drop__txt="not-a-cidr\n185.199.108.0/24\n")
    try:
        store = f.load_store()
        assert store.lookup_ip("185.199.108.5") is not None
    finally:
        f.load_store.cache_clear()
