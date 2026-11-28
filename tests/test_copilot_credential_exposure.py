"""
Credential-exposure synthesis for the copilot (`packetiq.copilot.credentials`).

The synthesiser is the join the user asked for and the fix for a real wrong answer:
it folds every credential a capture leaks or an attacker steals into one view,
aligned to the account that owns it, a hash resolved to the plaintext it cracked
to, and the credential-access techniques (a registry hive dump) named with their
exact commands. A small local model was getting the registry-hive question wrong
because it had to pick two commands out of eight and format them; this section
states the answer outright, so these tests assert that answer verbatim — SYSTEM
then SAM, comma-joined — as well as the no-fabrication direction: a hash that was
not cracked is reported as a hash, never as a guessed password.
"""

from __future__ import annotations

from packetiq.copilot.credentials import (
    _hive_answer_line,
    _norm,
    build_credential_exposure,
    collect_exposed_credentials,
    credential_access_techniques,
    credential_exposure_payload,
    credential_exposure_section,
)

# A real AS-REP roast digest shape: the realm after "@" is what the account's
# domain is read from. Truncated body — the parser only needs the "user@REALM:".
_ASREP = ("$krb5asrep$23$larry.doe@DIRECTORY.THM:f8716efbaa984508ddde606756441480"
          "$805ab8be8cfb018a282718f7c040cd43924c6f9afeb")


# --------------------------------------------------------------------------- #
#  _norm                                                                        #
# --------------------------------------------------------------------------- #

def test_norm_strips_domain_and_lowercases():
    assert _norm("DIRECTORY\\Larry.Doe") == "larry.doe"
    assert _norm("larry.doe") == "larry.doe"
    assert _norm("host/Admin") == "admin"


# --------------------------------------------------------------------------- #
#  collect_exposed_credentials                                                  #
# --------------------------------------------------------------------------- #

def test_cleartext_plaintext_credential_is_collected():
    recs = collect_exposed_credentials(
        {"valid_credentials": [{"protocol": "FTP", "username": "bob", "password": "s3cret"}]},
        None, None, None,
    )
    assert len(recs) == 1
    assert recs[0]["principal"] == "bob"
    assert recs[0]["plaintext"] == "s3cret"
    assert "FTP login sent unencrypted" in recs[0]["sources"][0]


def test_cleartext_entry_without_username_is_skipped():
    recs = collect_exposed_credentials(
        {"valid_credentials": [{"protocol": "FTP", "password": "x"}]}, None, None, None)
    assert recs == []


def test_telnet_login_collected_and_passwordless_skipped():
    recs = collect_exposed_credentials(
        {"telnet_logins": [
            {"username": "root", "password": "toor", "server": "10.0.0.9"},
            {"username": "nopass"},            # no password → not a leaked credential
        ]},
        None, None, None,
    )
    assert len(recs) == 1
    assert recs[0]["principal"] == "root"
    assert recs[0]["plaintext"] == "toor"
    assert "Telnet login on 10.0.0.9" in recs[0]["sources"][0]


def test_http_credential_collected_with_host():
    recs = collect_exposed_credentials(
        None,
        {"credentials": [{"via": "Basic", "username": "alice", "password": "pw", "host": "app.local"}]},
        None, None,
    )
    assert recs[0]["principal"] == "alice"
    assert "HTTP Basic credential on app.local" in recs[0]["sources"][0]


def test_http_credential_without_username_is_skipped():
    recs = collect_exposed_credentials(
        None, {"credentials": [{"via": "token", "password": "pw"}]}, None, None)
    assert recs == []


def test_asrep_hash_folds_with_cracked_plaintext_into_one_record():
    recs = collect_exposed_credentials(
        None, None,
        {"asrep_hashes": {"larry.doe": _ASREP},
         "valid_accounts": {"larry.doe": "AS-REP issued without pre-authentication"}},
        {"credentials": {"larry.doe": "Password1!"}},
    )
    assert len(recs) == 1, "the hash and its cracked plaintext are one account, not two"
    rec = recs[0]
    assert rec["principal"] == "larry.doe"
    assert rec["domain"] == "DIRECTORY.THM"          # read from the hash, not guessed
    assert rec["plaintext"] == "Password1!"
    assert rec["hash"] == _ASREP
    assert rec["hash_mode"] == "hashcat -m 18200"
    assert rec["confirmed_in_ad"] is True


def test_asrep_hash_without_crack_stays_hash_only():
    recs = collect_exposed_credentials(
        None, None, {"asrep_hashes": {"svc": _ASREP}}, {})
    assert recs[0]["plaintext"] is None
    assert recs[0]["hash"] == _ASREP


def test_asrep_without_realm_has_no_domain():
    recs = collect_exposed_credentials(
        None, None, {"asrep_hashes": {"svc": "garbage-without-a-realm"}}, {})
    assert recs[0]["domain"] is None


def test_offline_cracked_account_not_elsewhere_is_recovered():
    """Defensive: a cracked password the other sources never produced is still shown."""
    recs = collect_exposed_credentials(None, None, None, {"credentials": {"ghost": "GhostPw!"}})
    assert recs[0]["principal"] == "ghost"
    assert recs[0]["plaintext"] == "GhostPw!"
    assert recs[0]["sources"] == ["recovered offline from the capture's own credential material"]


def test_domain_backfilled_onto_existing_domainless_record():
    """A cleartext record (no domain) that the AS-REP realm later fills in."""
    recs = collect_exposed_credentials(
        {"valid_credentials": [{"protocol": "FTP", "username": "larry.doe", "password": "pw"}]},
        None,
        {"asrep_hashes": {"larry.doe": _ASREP}},
        {},
    )
    assert len(recs) == 1
    assert recs[0]["domain"] == "DIRECTORY.THM"
    assert recs[0]["plaintext"] == "pw"


# --------------------------------------------------------------------------- #
#  alignment (via build_credential_exposure)                                    #
# --------------------------------------------------------------------------- #

def _larry_sources():
    return (None, None,
            {"asrep_hashes": {"larry.doe": _ASREP}},
            {"credentials": {"larry.doe": "Password1!"}})


def test_alignment_dedupes_rich_and_bare_winrm_entries():
    winrm = {"accounts": [
        {"user": "larry.doe", "domain": "directory.thm", "workstation": "KALI"},
        {"user": "larry.doe", "domain": "", "workstation": ""},     # barer repeat
    ]}
    recs, _ = build_credential_exposure(*_larry_sources(), winrm)
    used = recs[0]["used_for"]
    assert used == ["authenticated the WinRM remote session as "
                    "directory.thm\\larry.doe from workstation KALI"]


def test_alignment_collapses_two_identical_sessions():
    """Two WinRM entries with the same domain+workstation are one session, reported once."""
    winrm = {"accounts": [
        {"user": "larry.doe", "domain": "directory.thm", "workstation": "KALI"},
        {"user": "larry.doe", "domain": "directory.thm", "workstation": "KALI"},
    ]}
    recs, _ = build_credential_exposure(*_larry_sources(), winrm)
    assert len(recs[0]["used_for"]) == 1


def test_alignment_bare_only_entry_still_reported():
    winrm = {"accounts": [{"user": "larry.doe", "domain": "", "workstation": ""}]}
    recs, _ = build_credential_exposure(*_larry_sources(), winrm)
    assert recs[0]["used_for"] == ["authenticated the WinRM remote session as larry.doe"]


def test_alignment_ignores_unmatched_and_userless_accounts():
    winrm = {"accounts": [{"user": "someone.else", "domain": "d", "workstation": "W"},
                          {"workstation": "W"}]}          # no user key at all
    recs, _ = build_credential_exposure(*_larry_sources(), winrm)
    assert recs[0]["used_for"] == []


def test_alignment_backfills_domain_from_winrm_when_absent():
    sources = ({"valid_credentials": [{"protocol": "FTP", "username": "jo", "password": "pw"}]},
               None, None, None)
    winrm = {"accounts": [{"user": "jo", "domain": "CORP", "workstation": "PC1"}]}
    recs, _ = build_credential_exposure(*sources, winrm)
    assert recs[0]["domain"] == "CORP"


# --------------------------------------------------------------------------- #
#  credential_access_techniques + _hive_answer_line                             #
# --------------------------------------------------------------------------- #

def test_registry_hive_dump_recognised_as_credential_pair():
    techs = credential_access_techniques({"commands": [
        "whoami /all",
        "reg save HKLM\\SYSTEM C:\\SYSTEM",
        "reg save HKLM\\SAM C:\\SAM",
        "reg save HKLM\\SECURITY C:\\SECURITY",
    ]})
    assert len(techs) == 1
    t = techs[0]
    assert t["technique"] == "Registry hive dump"
    assert t["mitre"] == ["T1003.002", "T1003.004"]
    assert t["has_credential_pair"] is True
    assert t["commands"] == ["reg save HKLM\\SYSTEM C:\\SYSTEM",
                             "reg save HKLM\\SAM C:\\SAM",
                             "reg save HKLM\\SECURITY C:\\SECURITY"]


def test_hive_answer_line_is_system_then_sam_comma_joined():
    techs = credential_access_techniques({"commands": [
        "reg save HKLM\\SYSTEM C:\\SYSTEM", "reg save HKLM\\SAM C:\\SAM"]})
    assert _hive_answer_line(techs[0]["hives"]) == \
        "reg save HKLM\\SYSTEM C:\\SYSTEM,reg save HKLM\\SAM C:\\SAM"


def test_sam_without_system_is_not_a_credential_pair():
    techs = credential_access_techniques({"commands": ["reg save HKLM\\SAM C:\\SAM"]})
    assert techs[0]["has_credential_pair"] is False
    # SAM alone is still the answer tail, but SYSTEM is absent.
    assert _hive_answer_line(techs[0]["hives"]) == "reg save HKLM\\SAM C:\\SAM"


def test_hive_answer_line_none_when_only_security():
    techs = credential_access_techniques({"commands": ["reg save HKLM\\SECURITY C:\\SECURITY"]})
    assert _hive_answer_line(techs[0]["hives"]) is None


def test_long_hklm_form_and_unknown_hive_are_handled():
    techs = credential_access_techniques({"commands": [
        "reg save HKEY_LOCAL_MACHINE\\SAM C:\\sam.hiv",
        "reg save HKLM\\FOO C:\\foo",                 # unknown hive → default T1003
    ]})
    t = techs[0]
    assert "T1003" in t["mitre"]
    hives = [h for h, _, _ in t["hives"]]
    assert hives == ["SAM", "FOO"]


def test_other_credential_access_techniques_detected_and_deduped():
    techs = credential_access_techniques({"commands": [
        "ntdsutil \"ac i ntds\" ifm",
        "procdump.exe -ma lsass.exe out.dmp",
        "rundll32 comsvcs.dll MiniDump 123 lsass.dmp full",   # second LSASS hit → one tech
        "mimikatz sekurlsa::logonpasswords",
    ]})
    labels = [t["technique"] for t in techs]
    assert any("NTDS.dit" in label for label in labels)
    assert sum("LSASS" in label for label in labels) == 1      # deduped
    assert any("Mimikatz" in label for label in labels)


def test_no_commands_yields_no_techniques():
    assert credential_access_techniques({}) == []
    assert credential_access_techniques(None) == []


# --------------------------------------------------------------------------- #
#  build_credential_exposure — filtering                                        #
# --------------------------------------------------------------------------- #

def test_record_without_a_secret_is_filtered_out():
    """A valid-credentials entry whose password is missing carries no secret."""
    recs, techs = build_credential_exposure(
        {"valid_credentials": [{"protocol": "FTP", "username": "nopw", "password": None}]},
        None, None, None, None,
    )
    assert recs == []
    assert techs == []


# --------------------------------------------------------------------------- #
#  credential_exposure_section (rendered text)                                  #
# --------------------------------------------------------------------------- #

def test_section_empty_when_nothing_exposed():
    assert credential_exposure_section(None, None, None, None, None) == ""


def test_section_states_password_ad_alignment_and_exact_answer():
    section = credential_exposure_section(
        None, None,
        {"asrep_hashes": {"larry.doe": _ASREP},
         "valid_accounts": {"larry.doe": "AS-REP issued without pre-authentication"}},
        {"credentials": {"larry.doe": "Password1!"},
         "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM", "reg save HKLM\\SAM C:\\SAM",
                      "reg save HKLM\\SECURITY C:\\SECURITY"]},
        {"accounts": [{"user": "larry.doe", "domain": "directory.thm", "workstation": "KALI"}]},
    )
    assert "larry.doe @ DIRECTORY.THM" in section
    assert "PASSWORD (plaintext): Password1!" in section
    assert "cracked to the plaintext above" in section
    assert "account confirmed to exist" in section
    assert "directory.thm\\larry.doe from workstation KALI" in section
    # The exact room answer: SYSTEM then SAM, comma-separated.
    assert "reg save HKLM\\SYSTEM C:\\SYSTEM,reg save HKLM\\SAM C:\\SAM" in section
    assert "SAM + SYSTEM pair IS the credential theft" in section


def test_section_reports_uncracked_hash_as_hash_not_password():
    section = credential_exposure_section(
        None, None, {"asrep_hashes": {"svc": _ASREP}}, {}, None)
    assert "NOT cracked" in section
    assert "PASSWORD (plaintext)" not in section


def test_section_renders_unknown_hive_meaning_default():
    section = credential_exposure_section(
        None, None, None, {"commands": ["reg save HKLM\\FOO C:\\foo"]}, None)
    assert "HKLM\\FOO" in section
    assert "a registry hive" in section          # the default meaning
    assert "ANSWER" not in section               # no SAM/SYSTEM pair → no answer line


# --------------------------------------------------------------------------- #
#  credential_exposure_payload (JSON for the web Credentials panel)             #
# --------------------------------------------------------------------------- #

def test_payload_empty_when_nothing_exposed():
    payload = credential_exposure_payload(None, None, None, None, None)
    assert payload == {"records": [], "techniques": []}


def test_payload_shape_for_records_and_hive_dump():
    payload = credential_exposure_payload(
        None, None,
        {"asrep_hashes": {"larry.doe": _ASREP}},
        {"credentials": {"larry.doe": "Password1!"},
         "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM", "reg save HKLM\\SAM C:\\SAM"]},
        {"accounts": [{"user": "larry.doe", "domain": "directory.thm", "workstation": "KALI"}]},
    )
    rec = payload["records"][0]
    assert rec["principal"] == "larry.doe"
    assert rec["plaintext"] == "Password1!"
    assert rec["domain"] == "DIRECTORY.THM"

    tech = payload["techniques"][0]
    assert tech["technique"] == "Registry hive dump"
    assert tech["has_credential_pair"] is True
    assert tech["answer"] == "reg save HKLM\\SYSTEM C:\\SYSTEM,reg save HKLM\\SAM C:\\SAM"
    # hives are serialised to objects with a plain-language meaning (not raw tuples).
    assert {h["hive"] for h in tech["hives"]} == {"SYSTEM", "SAM"}
    sam = next(h for h in tech["hives"] if h["hive"] == "SAM")
    assert sam["dest"] == "C:\\SAM"
    assert "NTLM hashes" in sam["meaning"]


def test_payload_answer_is_none_without_credential_pair():
    payload = credential_exposure_payload(
        None, None, None, {"commands": ["reg save HKLM\\SECURITY C:\\SECURITY"]}, None)
    tech = payload["techniques"][0]
    assert tech["has_credential_pair"] is False
    assert tech["answer"] is None
    assert tech["hives"][0]["meaning"].startswith("LSA secrets")


# --------------------------------------------------------------------------- #
#  context-builder integration (both copilots share the one synthesiser)        #
# --------------------------------------------------------------------------- #

def test_cli_context_builder_wrapper_passes_result_fields():
    from packetiq.copilot.context_builder import _credential_exposure

    class _R:
        cleartext = {}
        http_forensics = {}
        kerberos = {"asrep_hashes": {"larry.doe": _ASREP}}
        offline = {"credentials": {"larry.doe": "Password1!"}}
        winrm = {}

    out = _credential_exposure(_R())
    assert "Password1!" in out
    assert "CREDENTIAL EXPOSURE" in out


def test_web_chat_context_includes_credential_exposure():
    from packetiq.webapp.app import _build_chat_context

    ctx = _build_chat_context({
        "meta": {"filename": "x.pcap"}, "risk": {"score": 1, "tier": "LOW"},
        "events": [], "chains": [], "attributions": [], "open_ports": {},
        "kerberos": {"asrep_hashes": {"larry.doe": _ASREP}},
        "winrm": {"accounts": [{"user": "larry.doe", "domain": "directory.thm",
                                "workstation": "KALI"}]},
        "cleartext": {}, "http_forensics": {},
        "offline": {"credentials": {"larry.doe": "Password1!"},
                    "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM",
                                 "reg save HKLM\\SAM C:\\SAM"]},
    })
    assert "CREDENTIAL EXPOSURE" in ctx
    assert "reg save HKLM\\SYSTEM C:\\SYSTEM,reg save HKLM\\SAM C:\\SAM" in ctx


# --------------------------------------------------------------------------- #
#  CLI visible panel (`cli._print_credential_exposure`)                         #
# --------------------------------------------------------------------------- #

class _Result:
    """A stand-in for ExtractionResult carrying only the credential-bearing dicts."""
    def __init__(self, **kw):
        self.cleartext = kw.get("cleartext", {})
        self.http_forensics = kw.get("http_forensics", {})
        self.kerberos = kw.get("kerberos", {})
        self.offline = kw.get("offline", {})
        self.winrm = kw.get("winrm", {})


def _panel_output(result) -> str:
    """Capture the panel through the UI's own rich console.

    `console.capture()` intercepts at the Console, so it is immune to the global
    stdout swapping other CLI tests do (e.g. `_force_utf8_output`), which makes a
    plain capsys read order-dependent."""
    from packetiq.cli import _print_credential_exposure, ui
    with ui.console.capture() as cap:
        _print_credential_exposure(result)
    return cap.get()


def test_cli_panel_silent_when_nothing_exposed():
    assert _panel_output(_Result()).strip() == ""


def test_cli_panel_shows_password_alignment_and_technique():
    out = _panel_output(_Result(
        kerberos={"asrep_hashes": {"larry.doe": _ASREP},
                  "valid_accounts": {"larry.doe": "AS-REP issued without pre-authentication"}},
        offline={"credentials": {"larry.doe": "Password1!"},
                 "commands": ["reg save HKLM\\SYSTEM C:\\SYSTEM", "reg save HKLM\\SAM C:\\SAM"]},
        winrm={"accounts": [{"user": "larry.doe", "domain": "directory.thm",
                             "workstation": "KALI"}]},
    ))
    assert "CREDENTIAL EXPOSURE" in out
    assert "Password1!" in out
    assert "larry.doe" in out
    assert "Registry hive dump" in out
    assert "secretsdump" in out


def test_cli_panel_renders_hash_only_record():
    out = _panel_output(_Result(kerberos={"asrep_hashes": {"svc": _ASREP}}))
    assert "hash only" in out
    assert "hashcat -m 18200" in out
