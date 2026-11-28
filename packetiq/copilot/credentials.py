"""
Credential exposure synthesis — one consolidated view of every credential a
capture leaks or an attacker steals, each one aligned to the account it belongs
to and, where PacketIQ cracked it, resolved from a hash to its plaintext.

The copilot's other sections each report a single protocol's findings: the
Kerberos section carries the AS-REP roast hash, the offline section carries the
password that hash cracked to and the decrypted WinRM commands, the cleartext
section carries an FTP or HTTP login read straight off the wire. An analyst who
asks "what credentials were exposed", "which user leaked a password", or "what
did the attacker use to dump the hashes" then has to stitch those apart sections
back together — and a small local model does that stitch unreliably, which is how
a correct capture still produces a wrong answer.

This module does the stitch once, as fact. It collects every credential from
every source, folds a hash and the plaintext it cracked to into one record, and
names the credential-access *techniques* — a registry hive dump steals the local
password hashes without any password ever crossing the wire — with the exact
commands that performed them. Nothing here is inferred: every value is read from
a dict another extractor already populated, so the section states facts the model
can read off instead of reasoning toward.

Pure and deterministic. It takes the already-extracted dicts and returns text,
with no I/O and no dependence on scapy, so the CLI copilot context
(`context_builder`) and the web copilot context (`webapp.app._build_chat_context`)
both call the one function and answer identically.
"""

from __future__ import annotations

import re

# `$krb5asrep$23$larry.doe@DIRECTORY.THM:<hex>$<hex>` — the realm after the "@" is
# authoritative for the account's domain, so it is read from the hash itself rather
# than guessed from the capture's (often noisy) list of observed realms.
_ASREP_REALM = re.compile(r"\$krb5asrep\$[^$]*\$[^@]+@([A-Za-z0-9.\-]+):", re.IGNORECASE)

# `reg save HKLM\SAM C:\path` — capture the hive name and the destination path it was
# written to. Windows accepts HKLM and the long form HKEY_LOCAL_MACHINE; both parse.
_REG_SAVE = re.compile(
    r"reg\s+save\s+(?:HKLM|HKEY_LOCAL_MACHINE)\\(\w+)\s+(\S+)",
    re.IGNORECASE,
)

# What each dumped hive gives an attacker, and the MITRE sub-technique it maps to.
# SAM + SYSTEM together are the credential theft: SAM holds the local account NTLM
# hashes, SYSTEM holds the boot key that decrypts them.
_HIVE_MEANING = {
    "SAM": ("T1003.002", "local account password hashes (the NTLM hashes themselves)"),
    "SYSTEM": ("T1003.002", "the boot key (SysKey) that decrypts the SAM hashes"),
    "SECURITY": ("T1003.004", "LSA secrets: cached domain logons and service-account passwords"),
}

# Other on-host credential-theft actions worth naming if they appear in a decrypted
# shell. Matched loosely because the exact invocation varies (procdump, comsvcs,
# ntdsutil, the Volume Shadow Copy trick); each maps to its MITRE technique.
_OTHER_CREDENTIAL_ACCESS = (
    (re.compile(r"\bntds\.dit\b|\bntdsutil\b", re.IGNORECASE),
     "T1003.003", "NTDS.dit domain database dump (every domain account's hash)"),
    (re.compile(r"\blsass\b|comsvcs\.dll.*MiniDump|procdump.*lsass", re.IGNORECASE),
     "T1003.001", "LSASS process memory dump (logged-on credentials and tickets)"),
    (re.compile(r"\bmimikatz\b|sekurlsa|lsadump", re.IGNORECASE),
     "T1003", "Mimikatz credential extraction"),
)


def _norm(name: str) -> str:
    """Fold an account name for matching: drop any domain prefix and lowercase.

    ``DIRECTORY\\larry.doe`` and ``larry.doe`` are the same account; a hash keyed one
    way must still find the plaintext keyed the other."""
    return name.split("\\")[-1].split("/")[-1].strip().lower()


def _cracked_plaintext(principal: str, offline: dict) -> str | None:
    """The plaintext the offline step cracked for this account, matched tolerantly."""
    want = _norm(principal)
    for account, password in (offline.get("credentials") or {}).items():
        if _norm(account) == want:
            return password
    return None


def collect_exposed_credentials(
    cleartext: dict | None,
    http_forensics: dict | None,
    kerberos: dict | None,
    offline: dict | None,
) -> list[dict]:
    """Every credential the capture exposes, one record per account, deduplicated.

    A record carries whichever of plaintext / hash the capture actually yields; when
    both exist for one account (a Kerberos roast that was then cracked), they are
    folded into the single record so the account is reported once, hash *and*
    password together.
    """
    cleartext = cleartext or {}
    http_forensics = http_forensics or {}
    kerberos = kerberos or {}
    offline = offline or {}

    records: list[dict] = []
    index: dict[str, dict] = {}   # normalised principal -> record (for folding)

    def _record(principal: str, *, domain: str | None = None) -> dict:
        key = _norm(principal)
        rec = index.get(key)
        if rec is None:
            rec = {
                "principal": principal,
                "domain": domain,
                "plaintext": None,
                "hash": None,
                "hash_mode": None,
                "sources": [],
                "confirmed_in_ad": False,
                "used_for": [],
            }
            index[key] = rec
            records.append(rec)
        elif domain and not rec["domain"]:
            rec["domain"] = domain
        return rec

    # 1. Plaintext credentials read straight off the wire (HTTP Basic, FTP, Telnet…).
    for c in cleartext.get("valid_credentials") or []:
        user = c.get("username")
        if not user:
            continue
        rec = _record(user)
        rec["plaintext"] = c.get("password")
        proto = c.get("protocol") or "a cleartext protocol"
        rec["sources"].append(f"{proto} login sent unencrypted (read off the wire)")

    for tel in cleartext.get("telnet_logins") or []:
        user = tel.get("username")
        if not user or not tel.get("password"):
            continue
        rec = _record(user)
        rec["plaintext"] = tel.get("password")
        rec["sources"].append(f"Telnet login on {tel.get('server') or '?'} (cleartext)")

    # 2. Credentials in an HTTP login POST or Basic header (also plaintext).
    for c in http_forensics.get("credentials") or []:
        user = c.get("username")
        if not user:
            continue
        rec = _record(user)
        rec["plaintext"] = c.get("password")
        via = c.get("via") or "HTTP"
        host = c.get("host")
        rec["sources"].append(f"HTTP {via} credential" + (f" on {host}" if host else ""))

    # 3. Kerberos AS-REP roast material — a hash, resolved to its cracked plaintext
    #    when the offline step recovered it.
    for account, digest in (kerberos.get("asrep_hashes") or {}).items():
        realm = None
        m = _ASREP_REALM.search(digest or "")
        if m:
            realm = m.group(1)
        rec = _record(account, domain=realm)
        rec["hash"] = digest
        rec["hash_mode"] = "hashcat -m 18200"
        rec["sources"].append("Kerberos AS-REP roast (account has pre-authentication disabled)")
        plain = _cracked_plaintext(account, offline)
        if plain:
            rec["plaintext"] = plain

    # 4. Any cracked account the offline step reported that no source above covered
    #    (defensive: keeps a recovered password from being silently dropped).
    for account, password in (offline.get("credentials") or {}).items():
        rec = _record(account)
        if not rec["plaintext"]:
            rec["plaintext"] = password
        if not rec["sources"]:
            rec["sources"].append("recovered offline from the capture's own credential material")

    # 5. Align each account with Active Directory: confirmed-to-exist, and whether its
    #    credential was then used to authenticate a remote session.
    valid_accounts = kerberos.get("valid_accounts") or {}
    confirmed = {_norm(a) for a in valid_accounts}
    for rec in records:
        if _norm(rec["principal"]) in confirmed:
            rec["confirmed_in_ad"] = True

    return records


def _alignment(records: list[dict], winrm: dict | None) -> None:
    """Fill each record's ``used_for`` from where its account authenticated.

    The point the user asked for — "person X visited Y and also leaked password Z" —
    is this join: the account whose password PacketIQ recovered is the same account
    that then logged in and ran commands, so the section says so outright."""
    winrm = winrm or {}
    index = {_norm(r["principal"]): r for r in records}

    # The same account can appear in winrm["accounts"] more than once — a rich entry
    # (domain + workstation) and a barer repeat of the same login. Group by account and
    # keep only the informative entries, so one session is reported once, not twice.
    by_user: dict[str, list[dict]] = {}
    for account in winrm.get("accounts") or []:
        user = account.get("user")
        if user and _norm(user) in index:
            by_user.setdefault(_norm(user), []).append(account)

    for key, accounts in by_user.items():
        rec = index[key]
        informative = [a for a in accounts if a.get("domain") or a.get("workstation")]
        seen: set[tuple[str, str]] = set()
        for account in (informative or accounts[:1]):
            domain = account.get("domain")
            station = account.get("workstation")
            sig = (domain or "", station or "")
            if sig in seen:
                continue
            seen.add(sig)
            who = "\\".join(x for x in (domain, account.get("user")) if x)
            note = f"authenticated the WinRM remote session as {who}"
            if station:
                note += f" from workstation {station}"
            if note not in rec["used_for"]:
                rec["used_for"].append(note)
            if domain and not rec["domain"]:
                rec["domain"] = domain


def credential_access_techniques(offline: dict | None) -> list[dict]:
    """Credential-theft actions recovered from a decrypted shell — the hives and
    process dumps an attacker carries off to crack offline, not a password on the
    wire. Returns one entry per technique actually seen, with its exact commands."""
    offline = offline or {}
    commands = offline.get("commands") or []

    hive_dumps: list[tuple[str, str, str]] = []   # (hive, command, dest)
    for cmd in commands:
        m = _REG_SAVE.search(cmd)
        if m:
            hive_dumps.append((m.group(1).upper(), cmd, m.group(2)))

    techniques: list[dict] = []
    if hive_dumps:
        hives = [h for h, _, _ in hive_dumps]
        techniques.append({
            "technique": "Registry hive dump",
            "mitre": sorted({_HIVE_MEANING.get(h, ("T1003", ""))[0] for h in hives}),
            "commands": [c for _, c, _ in hive_dumps],
            "hives": hive_dumps,
            "has_credential_pair": "SAM" in hives and "SYSTEM" in hives,
        })

    seen = {t["technique"] for t in techniques}
    for pattern, mitre, label in _OTHER_CREDENTIAL_ACCESS:
        matched = [c for c in commands if pattern.search(c)]
        if matched and label not in seen:
            techniques.append({
                "technique": label,
                "mitre": [mitre],
                "commands": matched,
                "hives": [],
                "has_credential_pair": False,
            })
            seen.add(label)
    return techniques


def _hive_answer_line(hive_dumps: list[tuple[str, str, str]]) -> str | None:
    """The SAM + SYSTEM commands in the order they were typed, comma-joined — the
    literal answer to "what command dumped the hashes/registry hives"."""
    pair = [cmd for hive, cmd, _ in hive_dumps if hive in ("SYSTEM", "SAM")]
    if not pair:
        return None
    return ",".join(pair)


def build_credential_exposure(
    cleartext: dict | None,
    http_forensics: dict | None,
    kerberos: dict | None,
    offline: dict | None,
    winrm: dict | None,
) -> tuple[list[dict], list[dict]]:
    """Collect, align and filter in one call: returns ``(exposed_credentials,
    access_techniques)``.

    This is the single source of truth both renderers draw from — the copilot-context
    text (`credential_exposure_section`) and the CLI's visible panel
    (`cli._print_credential_exposure`) — so the terminal and the AI never disagree. A
    record survives only if it actually carries a secret (a plaintext password or a
    crackable hash); an account merely confirmed to exist is the Kerberos section's job.
    """
    records = collect_exposed_credentials(cleartext, http_forensics, kerberos, offline)
    _alignment(records, winrm)
    techniques = credential_access_techniques(offline)
    records = [r for r in records if r["plaintext"] or r["hash"]]
    return records, techniques


def credential_exposure_section(
    cleartext: dict | None,
    http_forensics: dict | None,
    kerberos: dict | None,
    offline: dict | None,
    winrm: dict | None,
) -> str:
    """Render the consolidated CREDENTIAL EXPOSURE section, or "" when the capture
    exposes no credential and performs no credential-access technique."""
    records, techniques = build_credential_exposure(
        cleartext, http_forensics, kerberos, offline, winrm)
    if not records and not techniques:
        return ""

    lines = ["=== CREDENTIAL EXPOSURE (leaked & stolen credentials) ==="]
    lines.append("  Every credential below is a fact PacketIQ recovered from THIS capture — read "
                 "in cleartext, or cracked offline from the capture's own hash. State a password "
                 "here plainly when asked \"what is X's password\" or \"which credentials leaked\". "
                 "A hash shown without a plaintext was not cracked; report the hash, not a guess.")

    if records:
        lines.append(f"  EXPOSED CREDENTIALS ({len(records)}):")
        for i, rec in enumerate(records, 1):
            who = rec["principal"]
            if rec["domain"]:
                who = f"{who} @ {rec['domain']}"
            lines.append(f"    [{i}] {who}")
            if rec["plaintext"]:
                lines.append(f"          PASSWORD (plaintext): {rec['plaintext']}")
            if rec["hash"]:
                state = "cracked to the plaintext above" if rec["plaintext"] else "NOT cracked"
                lines.append(f"          hash ({rec['hash_mode']}, {state}): {rec['hash']}")
            for src in rec["sources"]:
                lines.append(f"          source              : {src}")
            if rec["confirmed_in_ad"]:
                lines.append("          Active Directory    : account confirmed to exist (the KDC answered for it)")
            for use in rec["used_for"]:
                lines.append(f"          credential then used: {use}")

    if techniques:
        lines.append("  CREDENTIAL ACCESS TECHNIQUES (credential theft performed ON the target — the "
                     "hashes are carried off for OFFLINE cracking, so no password crosses the wire):")
        for tech in techniques:
            mitre = " / ".join(tech["mitre"])
            lines.append(f"    [{mitre}] {tech['technique']}:")
            for cmd in tech["commands"]:
                lines.append(f"        {cmd}")
            for hive, _, dest in tech["hives"]:
                meaning = _HIVE_MEANING.get(hive, (None, "a registry hive"))[1]
                lines.append(f"        → HKLM\\{hive} → {dest}: {meaning}")
            if tech.get("has_credential_pair"):
                lines.append("        The SAM + SYSTEM pair IS the credential theft: together they let the "
                             "attacker recover every local account's NTLM hash offline (e.g. "
                             "secretsdump.py -sam SAM -system SYSTEM LOCAL).")
                answer = _hive_answer_line(tech["hives"])
                if answer:
                    lines.append("        ANSWER — if asked \"what command did the attacker use to dump the "
                                 "hashes / registry hives\", it is these two commands (SYSTEM and SAM), "
                                 "comma-separated:")
                    lines.append(f"          {answer}")

    return "\n".join(lines)


def credential_exposure_payload(
    cleartext: dict | None,
    http_forensics: dict | None,
    kerberos: dict | None,
    offline: dict | None,
    winrm: dict | None,
) -> dict:
    """JSON-ready structured view of the credential exposure, for the web Credentials
    panel. Exactly the data `credential_exposure_section` renders as text, shaped for a
    UI: each dumped hive carries its plain-language meaning, and a SAM+SYSTEM technique
    carries the exact `answer` command string. Built from the one `build_credential_
    exposure`, so the panel, the CLI panel and the copilot never disagree.
    """
    records, techniques = build_credential_exposure(
        cleartext, http_forensics, kerberos, offline, winrm)
    techs = []
    for tech in techniques:
        techs.append({
            "technique": tech["technique"],
            "mitre": tech["mitre"],
            "commands": tech["commands"],
            "hives": [{"hive": hive, "command": cmd, "dest": dest,
                       "meaning": _HIVE_MEANING.get(hive, (None, "a registry hive"))[1]}
                      for hive, cmd, dest in tech["hives"]],
            "has_credential_pair": tech["has_credential_pair"],
            "answer": _hive_answer_line(tech["hives"]) if tech["has_credential_pair"] else None,
        })
    return {"records": records, "techniques": techs}
