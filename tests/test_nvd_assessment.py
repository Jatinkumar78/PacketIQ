"""CPE resolution and the version-aware vulnerability assessment.

`assess_vulnerabilities` is the path behind `packetiq vuln` and the web app's
vulnerability panel. It resolves each observed banner to an official CPE, pulls
the CVEs configured against that exact CPE, marks the actively-exploited ones
from CISA KEV, and rolls the result up per host.

Only the two HTTP calls are stubbed. Everything downstream — the CPE preference
order, the KEV-first sort, the host roll-up, the risk tiering and the wording of
the note — runs for real, because those are what a reader of the report sees.
"""

import pytest

from packetiq.enrichment import nvd

CVE_LOG4SHELL = {
    "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Log4Shell remote code execution."}],
        "published": "2021-12-10T00:00:00.000",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0,
                                                    "baseSeverity": "CRITICAL"}}]},
    }
}
CVE_MINOR = {
    "cve": {
        "id": "CVE-2020-9999",
        "descriptions": [{"lang": "en", "value": "Information disclosure."}],
        "published": "2020-05-05T00:00:00.000",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3,
                                                    "baseSeverity": "MEDIUM"}}]},
    }
}
CVE_UNSCORED = {
    "cve": {
        "id": "CVE-2024-0000",
        "descriptions": [{"lang": "en", "value": "Awaiting analysis."}],
        "published": "2024-01-01T00:00:00.000",
        "metrics": {},
    }
}


class Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


# The genuine resolver, captured before the autouse fixture replaces it. The
# key-resolution tests below need the real one back — reaching for
# `monkeypatch.undo()` would also revert conftest's autouse history-DB
# isolation, since pytest hands the fixture and the test the same instance.
_REAL_GET_API_KEY = nvd.get_api_key


@pytest.fixture(autouse=True)
def _no_sleeping_and_no_key(monkeypatch):
    """Keep the polite-rate-limit sleeps out of the test run, and make the key
    resolution deterministic regardless of the developer's own environment."""
    monkeypatch.setattr(nvd.time, "sleep", lambda s: None)
    monkeypatch.setattr(nvd, "get_api_key", lambda: None)


@pytest.fixture
def real_api_key_lookup(monkeypatch):
    monkeypatch.setattr(nvd, "get_api_key", _REAL_GET_API_KEY)


def _routes(monkeypatch, cpe_payload=None, cve_payload=None, cpe_status=200, cve_status=200):
    """Route the two NVD endpoints to canned payloads."""
    def get(url, params=None, headers=None, timeout=None):
        if url == nvd.CPE_URL:
            return Resp(cpe_payload or {"products": []}, cpe_status)
        return Resp(cve_payload or {"vulnerabilities": []}, cve_status)

    monkeypatch.setattr(nvd.requests, "get", get)


def _banner(value="Apache/2.4.49 (Unix)", ips=("192.168.1.10",), source="http-server"):
    return {"source": source, "value": value, "ips": list(ips)}


def _no_kev(monkeypatch):
    # nvd imports `kev` inside the function, so the module itself is the seam.
    from packetiq.enrichment import kev
    monkeypatch.setattr(kev, "kev_info", lambda cid: None)
    monkeypatch.setattr(kev, "is_kev", lambda cid: False)


# ── CPE resolution ───────────────────────────────────────────────────────────

def test_a_cpe_matching_the_observed_version_is_preferred(monkeypatch):
    """A version-specific CPE is what makes the CVE list version-aware.

    Falling back to the generic product CPE would report every Apache CVE ever
    filed against a host running one specific build.
    """
    _routes(monkeypatch, cpe_payload={"products": [
        {"cpe": {"cpeName": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}},
        {"cpe": {"cpeName": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}},
    ]})

    cpe = nvd.resolve_cpe("Apache", "2.4.49")
    assert cpe == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_an_application_cpe_is_preferred_over_an_operating_system_one(monkeypatch):
    _routes(monkeypatch, cpe_payload={"products": [
        {"cpe": {"cpeName": "cpe:2.3:o:vendor:firmware:1.0:*:*:*:*:*:*:*"}},
        {"cpe": {"cpeName": "cpe:2.3:a:vendor:app:1.0:*:*:*:*:*:*:*"}},
    ]})

    assert ":a:" in nvd.resolve_cpe("app", "1.0")


def test_a_deprecated_cpe_is_never_returned(monkeypatch):
    _routes(monkeypatch, cpe_payload={"products": [
        {"cpe": {"cpeName": "cpe:2.3:a:old:thing:1.0:*:*:*:*:*:*:*", "deprecated": True}},
        {"cpe": {"cpeName": ""}},
    ]})

    assert nvd.resolve_cpe("thing", "1.0") is None


def test_no_matching_cpe_resolves_to_nothing(monkeypatch):
    _routes(monkeypatch, cpe_payload={"products": []})
    assert nvd.resolve_cpe("Unheardof", "9.9") is None


def test_an_empty_product_is_not_looked_up(monkeypatch):
    monkeypatch.setattr(nvd.requests, "get",
                        lambda *a, **kw: pytest.fail("must not call NVD"))
    assert nvd.resolve_cpe("", "") is None


def test_a_cpe_endpoint_error_resolves_to_nothing(monkeypatch):
    _routes(monkeypatch, cpe_status=503)
    assert nvd.resolve_cpe("Apache", "2.4.49") is None


def test_an_unreachable_cpe_endpoint_resolves_to_nothing(monkeypatch):
    def get(*a, **kw):
        raise ConnectionError("nvd unreachable")

    monkeypatch.setattr(nvd.requests, "get", get)
    assert nvd.resolve_cpe("Apache", "2.4.49") is None


# ── CVEs by CPE ──────────────────────────────────────────────────────────────

def test_cves_for_a_cpe_are_sorted_worst_first(monkeypatch):
    _routes(monkeypatch, cve_payload={"vulnerabilities": [CVE_UNSCORED, CVE_MINOR,
                                                          CVE_LOG4SHELL]})
    client = nvd.NVDClient()

    ids = [c["id"] for c in nvd._cves_by_cpe(client, "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*")]
    assert ids == ["CVE-2021-44228", "CVE-2020-9999", "CVE-2024-0000"]


def test_a_cve_endpoint_error_yields_no_cves(monkeypatch):
    _routes(monkeypatch, cve_status=500)
    assert nvd._cves_by_cpe(nvd.NVDClient(), "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*") == []


# ── Full assessment ──────────────────────────────────────────────────────────

def test_an_assessment_resolves_cpes_and_rolls_up_per_host(monkeypatch):
    _no_kev(monkeypatch)
    _routes(monkeypatch,
            cpe_payload={"products": [{"cpe": {"cpeName":
                "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}}]},
            cve_payload={"vulnerabilities": [CVE_LOG4SHELL, CVE_MINOR]})

    out = nvd.assess_vulnerabilities([_banner()])

    assert len(out["products"]) == 1
    product = out["products"][0]
    assert product["product"] == "Apache" and product["version"] == "2.4.49"
    assert product["cpe"].endswith("2.4.49:*:*:*:*:*:*:*")
    assert product["max_cvss"] == 10.0
    assert product["kev_count"] == 0

    assert [h["ip"] for h in out["hosts"]] == ["192.168.1.10"]
    assert out["hosts"][0]["cve_count"] == 2
    assert out["hosts"][0]["max_cvss"] == 10.0
    assert "Apache 2.4.49" in out["hosts"][0]["products"]


def test_an_actively_exploited_cve_sorts_ahead_of_a_higher_scoring_one(monkeypatch):
    """CISA KEV means it is being used right now. That outranks raw CVSS —
    otherwise the one CVE an operator must patch today can fall off the list."""
    from packetiq.enrichment import kev
    monkeypatch.setattr(kev, "kev_info",
                        lambda cid: {"cve": cid, "due": "2021-12-24",
                                     "action": "Patch", "ransomware": True}
                        if cid == "CVE-2020-9999" else None)
    monkeypatch.setattr(kev, "is_kev", lambda cid: cid == "CVE-2020-9999")
    _routes(monkeypatch,
            cpe_payload={"products": [{"cpe": {"cpeName":
                "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}}]},
            cve_payload={"vulnerabilities": [CVE_LOG4SHELL, CVE_MINOR]})

    out = nvd.assess_vulnerabilities([_banner()])
    cves = out["products"][0]["cves"]

    assert cves[0]["id"] == "CVE-2020-9999", "the KEV entry leads despite a lower CVSS"
    assert cves[0]["kev"] is True
    assert out["products"][0]["kev_count"] == 1
    assert out["risk"]["score"] >= 90 and out["risk"]["tier"] == "CRITICAL"


def test_an_assessment_falls_back_to_keyword_search_without_a_cpe(monkeypatch):
    """Unusual or in-house software has no CPE. A keyword match is weaker, but
    reporting nothing at all would hide a real finding."""
    _no_kev(monkeypatch)
    calls = []
    monkeypatch.setattr(nvd, "resolve_cpe", lambda *a, **kw: None)
    monkeypatch.setattr(nvd.NVDClient, "search",
                        lambda self, kw, limit=8: calls.append(kw) or [
                            {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL",
                             "description": "x", "published": "2021-12-10", "url": "u"}])

    out = nvd.assess_vulnerabilities([_banner()])

    assert calls == ["Apache 2.4.49"]
    assert out["products"][0]["cpe"] is None
    assert out["products"][0]["cves"][0]["id"] == "CVE-2021-44228"


def test_the_same_product_seen_twice_is_assessed_once(monkeypatch):
    _no_kev(monkeypatch)
    _routes(monkeypatch)
    monkeypatch.setattr(nvd, "resolve_cpe", lambda *a, **kw: None)
    monkeypatch.setattr(nvd.NVDClient, "search", lambda self, kw, limit=8: [])

    out = nvd.assess_vulnerabilities([_banner(), _banner(ips=["192.168.1.11"])])
    assert len(out["products"]) == 1


def test_the_number_of_products_assessed_is_capped(monkeypatch):
    """Each product costs at least one NVD round trip under a rate limit."""
    _no_kev(monkeypatch)
    _routes(monkeypatch)
    monkeypatch.setattr(nvd, "resolve_cpe", lambda *a, **kw: None)
    monkeypatch.setattr(nvd.NVDClient, "search", lambda self, kw, limit=8: [])

    banners = [_banner(value=f"Product{i}/1.{i}.0") for i in range(20)]
    out = nvd.assess_vulnerabilities(banners, max_products=3)

    assert len(out["products"]) == 3


def test_an_nvd_failure_partway_through_keeps_what_was_already_found(monkeypatch):
    """A rate-limit rejection on the third product must not discard the first two."""
    _no_kev(monkeypatch)
    monkeypatch.setattr(nvd, "resolve_cpe", lambda *a, **kw: None)

    seen = {"n": 0}

    def flaky_search(self, kw, limit=8):
        seen["n"] += 1
        if seen["n"] == 3:
            raise RuntimeError("429 Too Many Requests")
        return []

    monkeypatch.setattr(nvd.NVDClient, "search", flaky_search)

    banners = [_banner(value=f"Product{i}/1.{i}.0") for i in range(5)]
    out = nvd.assess_vulnerabilities(banners)

    assert len(out["products"]) == 2
    assert "RuntimeError" in out["error"] and "429" in out["error"]


def test_a_capture_with_no_version_bearing_banners_says_so(monkeypatch):
    """The honest answer for an all-HTTPS capture: nothing was observed, so
    nothing is claimed."""
    _no_kev(monkeypatch)
    _routes(monkeypatch)

    out = nvd.assess_vulnerabilities([_banner(value="Mozilla/5.0 (X11; Linux)")])

    assert out["products"] == [] and out["hosts"] == []
    assert out["risk"]["tier"] == "NONE" and out["risk"]["score"] == 0
    assert "never invents" in out["note"]


def test_software_with_no_current_cves_is_reported_as_such(monkeypatch):
    _no_kev(monkeypatch)
    _routes(monkeypatch,
            cpe_payload={"products": [{"cpe": {"cpeName":
                "cpe:2.3:a:nginx:nginx:1.27.0:*:*:*:*:*:*:*"}}]},
            cve_payload={"vulnerabilities": []})

    out = nvd.assess_vulnerabilities([_banner(value="nginx/1.27.0")])

    assert out["products"][0]["cves"] == []
    assert "no current CVEs matched" in out["note"]


def test_an_anonymous_run_says_which_rate_limit_it_used(monkeypatch):
    _no_kev(monkeypatch)
    _routes(monkeypatch)
    monkeypatch.setattr(nvd, "resolve_cpe", lambda *a, **kw: None)
    monkeypatch.setattr(nvd.NVDClient, "search", lambda self, kw, limit=8: [])

    out = nvd.assess_vulnerabilities([_banner()])

    assert out["available"] is False
    assert "anonymous rate limit" in out["note"].lower()


# ── Exploit-attempt correlation ──────────────────────────────────────────────

def test_an_observed_exploit_attempt_is_correlated_to_its_cve(monkeypatch):
    """"We saw the attack AND the target runs the vulnerable software" is a far
    stronger statement than either half alone."""
    label = next(iter(nvd.EXPLOIT_SIGNATURE_CVE))
    from packetiq.enrichment import kev
    monkeypatch.setattr(kev, "kev_info", lambda cid: None)
    monkeypatch.setattr(kev, "is_kev", lambda cid: True)
    _routes(monkeypatch,
            cpe_payload={"products": [{"cpe": {"cpeName":
                "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}}]},
            cve_payload={"vulnerabilities": [CVE_LOG4SHELL]})

    out = nvd.assess_vulnerabilities(
        [_banner()],
        http_attacks=[{"attack_type": label, "dst_ip": "192.168.1.10"},
                      {"attack_type": "Not a mapped signature", "dst_ip": "192.168.1.10"}])

    assert len(out["correlations"]) == 1, "only mapped signatures correlate"
    corr = out["correlations"][0]
    assert corr["attack"] == label
    assert corr["target"] == "192.168.1.10"
    assert corr["kev"] is True
    assert "Apache 2.4.49" in corr["target_software"]


# ── API key resolution ───────────────────────────────────────────────────────

def test_an_api_key_is_read_from_the_environment(monkeypatch, tmp_path, real_api_key_lookup):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NVD_API_KEY", "  abc123  ")
    assert nvd.get_api_key() == "abc123"


def test_an_api_key_falls_back_to_a_dotenv_file(monkeypatch, tmp_path, real_api_key_lookup):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    (tmp_path / ".env").write_text('NVD_API_KEY="frombytes"\n', encoding="utf-8")

    assert nvd.get_api_key() == "frombytes"


def test_no_api_key_anywhere_is_none(monkeypatch, tmp_path, real_api_key_lookup):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)

    assert nvd.get_api_key() is None


def test_an_empty_api_key_in_dotenv_is_treated_as_absent(monkeypatch, tmp_path, real_api_key_lookup):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    (tmp_path / ".env").write_text("NVD_API_KEY=\n", encoding="utf-8")

    assert nvd.get_api_key() is None


# ── Search edge cases ────────────────────────────────────────────────────────

def test_an_empty_keyword_is_not_searched(monkeypatch):
    monkeypatch.setattr(nvd.requests, "get",
                        lambda *a, **kw: pytest.fail("must not call NVD"))
    assert nvd.NVDClient().search("   ") == []


def test_a_404_from_nvd_is_an_empty_result_not_an_error(monkeypatch):
    _routes(monkeypatch, cve_status=404)
    assert nvd.NVDClient().search("Apache 2.4.49") == []


def test_a_cve_with_no_cvss_metrics_still_parses():
    parsed = nvd._parse_cve(CVE_UNSCORED)
    assert parsed["id"] == "CVE-2024-0000"
    assert parsed["cvss"] is None and parsed["severity"] == ""


def test_a_v2_only_cve_uses_its_v2_score():
    """Pre-2016 CVEs carry no CVSS v3 block at all."""
    item = {"cve": {"id": "CVE-2000-0001",
                    "descriptions": [{"lang": "en", "value": "Old issue."}],
                    "published": "2000-01-01T00:00:00.000",
                    "metrics": {"cvssMetricV2": [{"baseSeverity": "LOW",
                                                  "cvssData": {"baseScore": 2.6}}]}}}
    parsed = nvd._parse_cve(item)
    assert parsed["cvss"] == 2.6 and parsed["severity"] == "LOW"
