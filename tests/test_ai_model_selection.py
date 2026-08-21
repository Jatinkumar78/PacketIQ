"""Choosing which model answers — and stopping the local runtime choosing for you.

The reported problem: with several models pulled, Ollama's copilot could answer
through a different one from run to run, because the resolver fell through to
``models[0]`` — whatever the daemon happened to list first. On a machine with
modest RAM that could be a model several times too large, which does not fail
outright; it swaps, and a question that took seconds takes minutes.

Two halves are covered here. The user can now pin a model (web UI, ``/api/ai/model``
or ``--model``), and when they have not, the automatic pick is deterministic and
sized against the machine's real RAM rather than arbitrary.
"""

import ctypes
import os

import httpx
import pytest
from fastapi.testclient import TestClient

from packetiq.webapp import app as webapp
from packetiq.webapp import create_app

# Captured at import, before `fixed_system_ram` can replace it, so the tests that
# exercise the real detector have something to call.
_REAL_SYSTEM_RAM = webapp._system_ram_bytes

GB = 1024 ** 3
_MODEL_VARS = ("OLLAMA_MODEL", "GEMINI_MODEL", "GROQ_MODEL", "ANTHROPIC_MODEL")
_KEY_VARS = ("GEMINI_API_KEY", "GROQ_API_KEY", "ANTHROPIC_API_KEY")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No host .env, no host daemon, no leaked pin between tests."""
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    webapp._OLLAMA_PROBE.update(at=0.0, up=False, models=[], info={})
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    for var in _MODEL_VARS + _KEY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("PACKETIQ_ENABLE_OLLAMA", raising=False)
    yield
    webapp._AI_FORCED["provider"] = None
    webapp._AI_COOLDOWN.clear()
    webapp._OLLAMA_PROBE.update(at=0.0, up=False, models=[], info={})


def _tags(*models):
    """Stub Ollama's /api/tags with (name, size_bytes, parameter_size) triples."""
    payload = {"models": [
        {"name": name, "size": size,
         "details": {"parameter_size": params, "quantization_level": "Q4_K_M"}}
        for name, size, params in models
    ]}

    class _Resp:
        status_code = 200

        def json(self):
            return payload

    return lambda url, timeout=None: _Resp()


DEFAULT = webapp._OLLAMA_DEFAULT_MODEL
TINY = ("qwen2.5:0.5b", 400_000_000, "0.5B")
SMALL = ("qwen2.5:3b", 2 * GB, "3.1B")
HUGE = ("llama3:70b", 39 * GB, "70.6B")


# ── reading the machine's real RAM ───────────────────────────────────────────

def test_ram_comes_from_posix_sysconf(monkeypatch):
    monkeypatch.setattr(os, "sysconf",
                        lambda name: {"SC_PHYS_PAGES": 4096, "SC_PAGE_SIZE": 4096}[name])
    assert _REAL_SYSTEM_RAM() == 4096 * 4096


def test_ram_falls_through_to_windows_when_sysconf_has_no_answer(monkeypatch):
    """Windows has no sysconf at all, so the second source has to carry it."""
    monkeypatch.setattr(os, "sysconf", lambda name: (_ for _ in ()).throw(ValueError(name)))
    monkeypatch.setattr(webapp, "_ram_bytes_windows", lambda: 8 * GB)
    assert _REAL_SYSTEM_RAM() == 8 * GB


def test_ram_is_none_when_neither_source_answers(monkeypatch):
    monkeypatch.setattr(os, "sysconf", lambda name: 0)
    monkeypatch.setattr(webapp, "_ram_bytes_windows", lambda: 0)
    assert _REAL_SYSTEM_RAM() is None


def test_windows_helper_reads_the_filled_struct(monkeypatch):
    """GlobalMemoryStatusEx writes into the struct it is handed and returns non-zero."""
    class _Kernel32:
        @staticmethod
        def GlobalMemoryStatusEx(ref):
            assert ref._obj.dwLength == ctypes.sizeof(webapp._MemoryStatusEx)
            ref._obj.ullTotalPhys = 12 * GB
            return 1

    monkeypatch.setattr(ctypes, "windll", type("W", (), {"kernel32": _Kernel32()}),
                        raising=False)
    assert webapp._ram_bytes_windows() == 12 * GB


def test_windows_helper_reports_zero_when_the_call_fails(monkeypatch):
    class _Kernel32:
        @staticmethod
        def GlobalMemoryStatusEx(ref):
            return 0

    monkeypatch.setattr(ctypes, "windll", type("W", (), {"kernel32": _Kernel32()}),
                        raising=False)
    assert webapp._ram_bytes_windows() == 0


def test_budget_is_a_fraction_of_total_ram(monkeypatch):
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 16 * GB)
    assert webapp._ram_budget_bytes() == int(16 * GB * webapp._RAM_BUDGET_FRACTION)
    assert webapp._ram_budget_bytes() < 16 * GB, "a model may not claim the whole machine"


def test_no_budget_is_claimed_when_ram_is_unknown(monkeypatch):
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: None)
    assert webapp._ram_budget_bytes() is None


# ── what the daemon told us about each model ─────────────────────────────────

def test_probe_keeps_the_size_and_details_the_daemon_reported(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(SMALL, HUGE))
    probe = webapp._ollama_probe(force=True)
    assert probe["models"] == ["qwen2.5:3b", "llama3:70b"]
    assert probe["info"]["llama3:70b"] == {
        "size": 39 * GB, "parameter_size": "70.6B", "quantization": "Q4_K_M"}
    assert webapp._ollama_model_size("qwen2.5:3b") == 2 * GB


def test_probe_ignores_a_nameless_entry(monkeypatch):
    """A name is the only field we can address a model by; without one it is noise."""
    class _Resp:
        status_code = 200

        def json(self):
            return {"models": [{"size": 1}, {"name": "qwen2.5:3b", "size": 2 * GB}]}

    monkeypatch.setattr(httpx, "get", lambda url, timeout=None: _Resp())
    probe = webapp._ollama_probe(force=True)
    assert probe["models"] == ["qwen2.5:3b"]
    # Absent detail fields become empty strings rather than None.
    assert probe["info"]["qwen2.5:3b"]["parameter_size"] == ""


def test_size_is_zero_for_a_model_the_daemon_never_mentioned(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(SMALL))
    assert webapp._ollama_model_size("something:else") == 0


# ── the automatic pick, when the user has not chosen ─────────────────────────

def test_the_tuned_default_wins_when_it_is_installed_and_fits(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(SMALL, (DEFAULT, 4 * GB, "7.6B")))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 16 * GB)
    assert webapp._ollama_model() == DEFAULT


def test_the_default_is_passed_over_when_it_exceeds_the_budget(monkeypatch):
    """A 4 GB machine has no business loading the 7B default just because it is there."""
    monkeypatch.setattr(httpx, "get", _tags(TINY, (DEFAULT, 4 * GB, "7.6B")))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 4 * GB)
    assert webapp._ollama_model() == TINY[0]


def test_the_largest_model_that_fits_is_chosen(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(HUGE, TINY, SMALL))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 16 * GB)
    assert webapp._ollama_model() == SMALL[0]


def test_the_smallest_model_is_chosen_when_none_fit(monkeypatch):
    """Something has to answer; the cheapest thing installed is the least bad."""
    monkeypatch.setattr(httpx, "get", _tags(HUGE, SMALL))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 2 * GB)
    assert webapp._ollama_model() == SMALL[0]


def test_the_smallest_model_is_chosen_when_ram_cannot_be_read(monkeypatch):
    """With no budget to check against, err small — an oversized model swaps."""
    monkeypatch.setattr(httpx, "get", _tags(HUGE, SMALL, TINY))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: None)
    assert webapp._ollama_model() == TINY[0]


def test_the_default_still_wins_when_ram_cannot_be_read(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(TINY, (DEFAULT, 4 * GB, "7.6B")))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: None)
    assert webapp._ollama_model() == DEFAULT


def test_equal_sized_models_are_ordered_by_name(monkeypatch):
    """Two models of the same size must not trade places between runs."""
    monkeypatch.setattr(httpx, "get", _tags(("zzz:7b", 2 * GB, "7B"), ("aaa:7b", 2 * GB, "7B")))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 1 * GB)  # neither fits
    assert webapp._ollama_model() == "aaa:7b"


def test_pulling_a_bigger_model_does_not_change_the_answer(monkeypatch):
    """The regression this was reported as: the pick used to be `models[0]`, so
    the daemon's listing order — which changes when you pull something — decided
    which model served the copilot."""
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 16 * GB)
    monkeypatch.setattr(httpx, "get", _tags(SMALL))
    before = webapp._ollama_model()
    # A 70B lands at the head of the daemon's list (most recently modified).
    monkeypatch.setattr(httpx, "get", _tags(HUGE, SMALL))
    assert webapp._ollama_model() == before == SMALL[0]


def test_nothing_installed_falls_back_to_the_documented_default(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags())
    assert webapp._ollama_model() == DEFAULT


def test_a_pin_beats_every_automatic_rule(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(HUGE, SMALL))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 4 * GB)
    monkeypatch.setenv("OLLAMA_MODEL", HUGE[0])
    assert webapp._ollama_model() == HUGE[0]
    assert webapp._model_pin("ollama") == HUGE[0]


def test_a_pin_may_come_from_the_env_file(monkeypatch):
    monkeypatch.setattr(webapp, "_read_env", lambda: {"GEMINI_MODEL": "gemini-x"})
    assert webapp._model_pin("gemini") == "gemini-x"
    assert webapp._model_env_name("gemini") == "GEMINI_MODEL"


# ── what the picker is allowed to offer ──────────────────────────────────────

def test_local_options_carry_real_sizes_and_a_fit_verdict(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(HUGE, SMALL))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 16 * GB)
    opts = webapp._model_options("ollama")
    assert [o["name"] for o in opts] == [SMALL[0], HUGE[0]], "smallest first"
    assert opts[0]["size_bytes"] == 2 * GB and opts[0]["parameter_size"] == "3.1B"
    assert opts[0]["fits_ram"] is True
    assert opts[1]["fits_ram"] is False


def test_no_fit_verdict_is_offered_when_ram_is_unknown(monkeypatch):
    """Saying "fits" without knowing the machine's RAM would be a guess."""
    monkeypatch.setattr(httpx, "get", _tags(SMALL))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: None)
    assert webapp._model_options("ollama")[0]["fits_ram"] is None


def test_no_fit_verdict_when_the_daemon_reported_no_size(monkeypatch):
    monkeypatch.setattr(httpx, "get", _tags(("nosize:1b", 0, "1B")))
    assert webapp._model_options("ollama")[0]["fits_ram"] is None


def test_cloud_options_are_the_models_this_code_knows_how_to_call():
    """Nothing invented: the candidate list plus the provider's declared default."""
    names = [o["name"] for o in webapp._model_options("gemini")]
    assert names[:len(webapp._MODEL_CANDIDATES["gemini"])] == webapp._MODEL_CANDIDATES["gemini"]
    assert webapp._model_options("anthropic")[0]["name"] == \
        [m for n, _, m in webapp._PROVIDER_SPECS if n == "anthropic"][0]
    assert [o["name"] for o in webapp._model_options("groq")] == \
        [m for n, _, m in webapp._PROVIDER_SPECS if n == "groq"]


def test_a_hand_set_model_is_listed_even_if_we_do_not_know_it(monkeypatch):
    """A model set in .env must show as the current selection, not vanish."""
    monkeypatch.setenv("GEMINI_MODEL", "gemini-something-new")
    opts = webapp._model_options("gemini")
    assert opts[-1]["name"] == "gemini-something-new"
    assert opts[-1]["installed"] is False


# ── the HTTP surface the web UI drives ───────────────────────────────────────

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                       # isolate .env reads/writes
    monkeypatch.setattr(httpx, "get", _tags(HUGE, SMALL))
    monkeypatch.setattr(webapp, "_system_ram_bytes", lambda: 16 * GB)
    monkeypatch.setattr(webapp, "_read_env", lambda: {})
    monkeypatch.setattr(webapp, "_ollama_warm", lambda model, host: None)
    with TestClient(create_app()) as c:
        yield c
    for var in _MODEL_VARS:
        os.environ.pop(var, None)                     # endpoints write real os.environ


def _provider(payload, name):
    return [p for p in payload["providers"] if p["name"] == name][0]


def test_status_reports_ram_and_every_provider_model(client):
    j = client.get("/api/ai/status").json()
    assert j["ram"]["total_bytes"] == 16 * GB
    assert j["ram"]["budget_bytes"] == int(16 * GB * webapp._RAM_BUDGET_FRACTION)
    ollama = _provider(j, "ollama")
    assert ollama["model"] == SMALL[0] and ollama["model_pinned"] is False
    assert [m["name"] for m in ollama["models"]] == [SMALL[0], HUGE[0]]
    assert _provider(j, "gemini")["model"] == webapp._MODEL_CANDIDATES["gemini"][0]
    assert j["active_model"] == SMALL[0]


def test_pinning_a_model_takes_effect_and_persists(client, tmp_path):
    j = client.post("/api/ai/model",
                    json={"provider": "ollama", "model": HUGE[0]}).json()
    ollama = _provider(j, "ollama")
    assert ollama["model"] == HUGE[0] and ollama["model_pinned"] is True
    assert "OLLAMA_MODEL=" + HUGE[0] in (tmp_path / ".env").read_text(encoding="utf-8")


def test_a_pin_can_be_kept_out_of_the_env_file(client, tmp_path):
    client.post("/api/ai/model",
                json={"provider": "ollama", "model": HUGE[0], "persist": False})
    assert os.environ["OLLAMA_MODEL"] == HUGE[0]
    assert not (tmp_path / ".env").exists()


def test_clearing_the_pin_returns_to_automatic(client, tmp_path):
    client.post("/api/ai/model", json={"provider": "ollama", "model": HUGE[0]})
    j = client.post("/api/ai/model", json={"provider": "ollama", "model": ""}).json()
    ollama = _provider(j, "ollama")
    assert ollama["model_pinned"] is False and ollama["model"] == SMALL[0]
    assert "OLLAMA_MODEL" not in (tmp_path / ".env").read_text(encoding="utf-8")


def test_clearing_a_pin_can_leave_the_env_file_alone(client, tmp_path):
    client.post("/api/ai/model", json={"provider": "ollama", "model": HUGE[0]})
    client.post("/api/ai/model", json={"provider": "ollama", "model": "", "persist": False})
    assert "OLLAMA_MODEL" not in os.environ
    assert "OLLAMA_MODEL=" + HUGE[0] in (tmp_path / ".env").read_text(encoding="utf-8")


def test_pinning_revives_a_model_an_earlier_call_had_benched(client):
    webapp._mark_model_dead("gemini", "gemini-flash-lite-latest")
    client.post("/api/ai/model",
                json={"provider": "gemini", "model": "gemini-flash-lite-latest"})
    assert webapp._model_alive("gemini", "gemini-flash-lite-latest")


def test_a_model_that_is_not_pulled_is_refused_with_the_command_to_pull_it(client):
    r = client.post("/api/ai/model", json={"provider": "ollama", "model": "mistral:7b"})
    assert r.status_code == 400
    assert "ollama pull mistral:7b" in r.json()["detail"]
    assert "OLLAMA_MODEL" not in os.environ


def test_an_unknown_provider_is_refused(client):
    r = client.post("/api/ai/model", json={"provider": "openai", "model": "gpt"})
    assert r.status_code == 400 and "Unknown provider" in r.json()["detail"]


@pytest.mark.parametrize("model", ["x" * 201, "a\nb", "a\rb"])
def test_a_malformed_model_name_is_refused(client, model):
    r = client.post("/api/ai/model", json={"provider": "gemini", "model": model})
    assert r.status_code == 400 and "valid model name" in r.json()["detail"]


def test_an_unwritable_env_file_still_pins_for_this_session(client, monkeypatch):
    """Losing the file is not losing the choice — the run in progress keeps it."""
    def _boom(key, value):
        raise OSError("read-only file system")

    monkeypatch.setattr(webapp, "_env_upsert", _boom)
    j = client.post("/api/ai/model", json={"provider": "ollama", "model": HUGE[0]}).json()
    assert _provider(j, "ollama")["model_pinned"] is True


def test_an_unwritable_env_file_still_clears_the_pin_for_this_session(client, monkeypatch):
    client.post("/api/ai/model", json={"provider": "ollama", "model": HUGE[0]})

    def _boom(key):
        raise OSError("read-only file system")

    monkeypatch.setattr(webapp, "_env_remove", _boom)
    j = client.post("/api/ai/model", json={"provider": "ollama", "model": ""}).json()
    assert _provider(j, "ollama")["model_pinned"] is False


# ── the same choice from the CLI ─────────────────────────────────────────────

def test_the_cli_provider_list_matches_the_providers_that_exist():
    """One list of providers, not two that drift."""
    from packetiq.cli import _AI_PROVIDERS

    assert _AI_PROVIDERS == ["auto"] + [n for n, _, _ in webapp._PROVIDER_SPECS]


def test_cli_model_flag_pins_the_named_provider(monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    MultiProviderClient(provider="ollama", model=SMALL[0])
    assert os.environ["OLLAMA_MODEL"] == SMALL[0]
    assert webapp._AI_FORCED["provider"] == "ollama"
    os.environ.pop("OLLAMA_MODEL", None)


def test_cli_model_flag_alone_pins_whichever_provider_will_answer(monkeypatch):
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setenv("GROQ_API_KEY", "gsk_test")
    monkeypatch.delenv("GROQ_MODEL", raising=False)
    monkeypatch.setattr(httpx, "get", _tags())          # no local daemon models
    MultiProviderClient(model="llama-3.1-8b-instant")
    assert os.environ["GROQ_MODEL"] == "llama-3.1-8b-instant"
    os.environ.pop("GROQ_MODEL", None)


def test_cli_model_flag_is_dropped_when_no_provider_is_configured(monkeypatch):
    """Nothing can answer, so there is nothing to configure — and nothing to leak."""
    from packetiq.copilot.multi_provider import MultiProviderClient

    monkeypatch.setattr(webapp, "_detect_provider", lambda skip=None: {
        "provider": None, "key": None, "model": ""})
    MultiProviderClient(model="whatever:1b")
    assert not any(v in os.environ for v in _MODEL_VARS)
