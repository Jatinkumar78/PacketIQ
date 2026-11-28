"""
Context Builder — serializes all PacketIQ analysis data into a structured
text block that Claude can reason over.

Design goals:
  - Deterministic output (same analysis → same context)
  - Token-efficient (no redundant prose, tight formatting)
  - SOC-oriented (emphasizes what matters for incident response)
  - Safe to cache with Anthropic prompt caching
"""

from datetime import datetime

from packetiq.copilot.credentials import credential_exposure_section
from packetiq.correlation.models import AttackChain
from packetiq.detection.models import DetectionEvent
from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.utils.helpers import (
    format_bytes,
    format_duration,
    is_private_ip,
    monitored_network,
    ts_to_str,
)

# An evidence-rich capture can touch thousands of external IPs. Enumerating all of
# them buries the actual findings (detections, attack chains, MITRE) and overflows
# a local model's context window, so it silently truncates and drops the evidence
# it most needs. We cap every long IP/domain enumeration to the top entries by
# volume and add an "… and N more" line, keeping the context signal-dense.
_MAX_IP_LIST = 30


def build_context(
    file_meta: dict,
    result: ExtractionResult,
    events: list[DetectionEvent],
    chains: list[AttackChain],
    risk_score: int = 0,
    risk_tier: str = "UNKNOWN",
) -> str:
    """
    Build the complete PCAP analysis context string for the AI copilot.
    Returns a structured text block ready to be embedded in the system prompt.
    """
    sections: list[str] = []

    sections.append(_header(file_meta, result, risk_score, risk_tier))
    sections.append(_capture_stats(result))
    sections.append(_protocol_distribution(result))
    sections.append(_network_topology(result))
    sections.append(_port_activity(result))
    sections.append(_discovered_services(result))
    sections.append(_cleartext_sessions(result))
    sections.append(_decoded_artifacts(result))
    sections.append(_http_forensics(result))
    sections.append(_offline_recovery(result))
    sections.append(_credential_exposure(result))
    sections.append(_detection_events(events))
    sections.append(_attack_chains(chains))
    sections.append(_dns_intelligence(result))
    sections.append(_directory_services(result))
    sections.append(_directory_reads(result))
    sections.append(_file_sharing(result))
    sections.append(_rpc_interfaces(result))
    sections.append(_remote_management(result))
    sections.append(_http_activity(result))
    sections.append(_ioc_summary(result, events, chains))

    return "\n\n".join(s for s in sections if s.strip())


# ── Section builders ──────────────────────────────────────────────────────────

def _header(meta: dict, result: ExtractionResult, score: int, tier: str) -> str:
    duration = max(0.0, result.capture_end - result.capture_start)
    return f"""=== PACKETIQ ANALYSIS CONTEXT ===
File      : {meta.get('filename', 'unknown')}
Size      : {format_bytes(meta.get('filesize', 0))}
Packets   : {result.total_packets:,}
Duration  : {format_duration(duration)}
Start     : {ts_to_str(result.capture_start) if result.capture_start else 'N/A'}
End       : {ts_to_str(result.capture_end)   if result.capture_end   else 'N/A'}
Risk Score: {score}/100 [{tier}]
Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""


def _capture_stats(result: ExtractionResult) -> str:
    lines = [
        "=== CAPTURE STATISTICS ===",
        f"Total Bytes        : {format_bytes(result.total_bytes)}",
        f"Unique Source IPs  : {len(result.unique_src_ips)}",
        f"Unique Dest IPs    : {len(result.unique_dst_ips)}",
        f"External IPs       : {len(result.external_ips)}",
        f"Unique Flows       : {len(result.flows)}",
        f"DNS Queries        : {len(result.dns_queries)}",
        f"HTTP Requests      : {len(result.http_requests)}",
        f"TCP Completed 3WHS : {result.completed_connections}",
        f"TCP Half-Open SYNs : {result.open_connections}",
    ]
    return "\n".join(lines)


def _protocol_distribution(result: ExtractionResult) -> str:
    total = max(result.total_packets, 1)
    lines = ["=== PROTOCOL DISTRIBUTION ==="]
    for proto, cnt in sorted(result.protocol_counts.items(), key=lambda x: x[1], reverse=True):
        pct = cnt / total * 100
        lines.append(f"  {proto:<10} {cnt:>8,} pkts  ({pct:.1f}%)")
    return "\n".join(lines)


def _network_topology(result: ExtractionResult) -> str:
    total = max(result.total_packets, 1)
    # Label hosts by the capture's own evidence of where the network boundary
    # is, not by RFC1918 — otherwise a publicly addressed LAN is handed to the
    # model as a page of "EXTERNAL" hosts and it reasons from a false premise.
    local = monitored_network(result)

    def _scope(ip: str) -> str:
        inside = ip in local if local else is_private_ip(ip)
        return "INTERNAL" if inside else "EXTERNAL"

    lines = ["=== TOP SOURCE IPs (by packet count) ==="]
    top_src = sorted(result.ip_src_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    for ip, cnt in top_src:
        lines.append(f"  {ip:<20} {cnt:>7,} pkts  [{_scope(ip)}]")

    lines.append("\n=== TOP DESTINATION IPs (by packet count) ===")
    top_dst = sorted(result.ip_dst_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    for ip, cnt in top_dst:
        lines.append(f"  {ip:<20} {cnt:>7,} pkts  [{_scope(ip)}]")

    ext = result.external_ips
    if ext:
        # Rank external contacts by traffic volume and cap the list — the top
        # peers are what an analyst needs; the long tail only buries the findings.
        dst = result.ip_dst_counts
        ranked = sorted(ext, key=lambda ip: dst.get(ip, 0), reverse=True)
        shown = ranked[:_MAX_IP_LIST]
        lines.append(f"\n=== EXTERNAL IP CONTACTS ({len(ext)} total, top {len(shown)} by volume) ===")
        for ip in shown:
            lines.append(f"  {ip:<20} {dst.get(ip, 0):>7,} pkts")
        if len(ext) > len(shown):
            lines.append(f"  … and {len(ext) - len(shown):,} more external IPs")

    return "\n".join(lines)


def _port_activity(result: ExtractionResult) -> str:
    from packetiq.utils.helpers import get_service_name
    lines = ["=== TOP DESTINATION PORTS ==="]
    top_ports = sorted(result.dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    for port, cnt in top_ports:
        svc = get_service_name(port)
        lines.append(f"  {port:<6} ({svc:<12}) {cnt:>7,} pkts")
    return "\n".join(lines)


def _discovered_services(result: ExtractionResult) -> str:
    """The ports an attacker found open, stated as measured fact.

    A port is listed here only when it demonstrably answered a handshake, which
    is the difference between "a port we saw traffic to" and "a service that is
    actually there". This is the answer to "what ports did the scan find open",
    and it is grouped by host so the target of a scan is unambiguous.
    """
    exposure = getattr(result, "service_exposure", {}) or {}
    tcp_by_host: dict[str, set[int]] = {}
    udp_by_host: dict[str, set[int]] = {}
    for (ip, port, proto), info in exposure.items():
        if info.get("state") != "open":
            continue
        bucket = tcp_by_host if (proto or "").lower() == "tcp" else udp_by_host
        bucket.setdefault(ip, set()).add(port)
    if not tcp_by_host and not udp_by_host:
        return ""

    lines = ["=== OPEN PORTS DISCOVERED (services that answered a handshake) ==="]
    winrm_ports = {5985, 5986} if (getattr(result, "winrm", None) or {}).get("requests") else set()
    if tcp_by_host:
        # The scanned target is the host that answered on many TCP ports; a single
        # service answering on 443 is not a scan result.
        target = max(tcp_by_host, key=lambda ip: len(tcp_by_host[ip]))
        if len(tcp_by_host[target]) >= 4:
            scan_found = sorted(p for p in tcp_by_host[target] if p not in winrm_ports)
            lines.append(
                "  ANSWER to \"what ports did the threat actor initially find open\" — the TCP "
                f"ports the scan of {target} found, lowest to highest, comma-separated: "
                + ", ".join(str(p) for p in scan_found))
            if winrm_ports & tcp_by_host[target]:
                lines.append("  (Port 5985/WinRM answered too, but it carried the remote-management "
                             "session opened AFTER the scan, so it is NOT part of the initial "
                             "scan's answer. UDP ports below are not part of a TCP-scan answer.)")
    lines.append("  Full open-port inventory by host (a TCP port scan reports the TCP ports; UDP "
                 "is listed separately and is not part of a TCP-scan answer):")
    for ip in sorted(set(tcp_by_host) | set(udp_by_host)):
        lines.append(f"    {ip}:")
        tcp = sorted(tcp_by_host.get(ip, set()))
        udp = sorted(udp_by_host.get(ip, set()))
        if tcp:
            lines.append(f"        open TCP ports: {', '.join(str(p) for p in tcp)}")
        if udp:
            lines.append(f"        open UDP ports: {', '.join(str(p) for p in udp)}")
    return "\n".join(lines)


def _cleartext_sessions(result: ExtractionResult) -> str:
    """The readable conversation an unencrypted capture hands you.

    This is the section that answers a cleartext-capture investigation: the
    credential that worked, the files that moved, and the commands an attacker
    typed into a recovered shell. Everything here was read directly off the
    wire, so it is stated as fact, not inferred.
    """
    ct = getattr(result, "cleartext", None) or {}
    if not ct:
        return ""

    lines = ["=== RECOVERED CLEARTEXT SESSIONS ==="]

    valid = ct.get("valid_credentials") or []
    if valid:
        lines.append("  CREDENTIALS RECOVERED (sent unencrypted, read off the wire):")
        for c in valid:
            lines.append(f"    {c['protocol']} login SUCCEEDED: username={c['username']}  "
                         f"password={c['password']}")
    if ct.get("failed_password_attempts"):
        lines.append(f"  Password-spray attempts before success: "
                     f"{ct['failed_password_attempts']} (a brute-force run)")

    for ftp in ct.get("ftp_sessions") or []:
        if not (ftp.get("working_directory") or ftp.get("uploaded") or ftp.get("downloaded")):
            continue
        lines.append(f"  FTP SESSION as {ftp.get('username') or '?'} on {ftp.get('server')}:")
        if ftp.get("working_directory"):
            lines.append(f"    working directory after login: {ftp['working_directory']}")
        if ftp.get("uploaded"):
            lines.append(f"    files UPLOADED: {', '.join(ftp['uploaded'])}")
        if ftp.get("downloaded"):
            lines.append(f"    files downloaded: {', '.join(ftp['downloaded'])}")

    for up in ct.get("uploaded_files") or []:
        lines.append(f"  UPLOADED FILE ({up.get('kind')}): indicators found inside it:")
        for url in up.get("urls") or []:
            lines.append(f"    URL in file: {url}")
        for cb in up.get("callbacks") or []:
            lines.append(f"    call-back address in file: {cb}")

    for sh in ct.get("shell_sessions") or []:
        lines.append("  INTERACTIVE SHELL recovered (commands the attacker typed, "
                     "read from the cleartext stream):")
        if sh.get("hostname"):
            lines.append(f"    compromised host hostname: {sh['hostname']}")
        if sh.get("became_root"):
            lines.append("    the attacker escalated to root in this session")
        for i, cmd in enumerate(sh.get("commands") or [], 1):
            lines.append(f"    command {i}: {cmd}")
        for proj in sh.get("github_projects") or []:
            lines.append(f"    GitHub project fetched: {proj}")
        for url in (sh.get("urls") or [])[:8]:
            lines.append(f"    URL contacted: {url}")

    for em in ct.get("email_sessions") or []:
        lines.append(f"  EMAIL (SMTP) on {em.get('server')}:")
        if em.get("mail_from"):
            lines.append(f"    from: {em['mail_from']}")
        if em.get("recipients"):
            lines.append(f"    to: {', '.join(em['recipients'])}")
        if em.get("subject"):
            lines.append(f"    subject: {em['subject']}")
        if em.get("username"):
            lines.append(f"    authenticated as: {em['username']}")

    for irc in ct.get("irc_sessions") or []:
        lines.append(f"  IRC CHAT on {irc.get('server')} as {irc.get('nick') or '?'}"
                     + (f" in {', '.join(irc['channels'])}" if irc.get("channels") else "") + ":")
        for msg in (irc.get("messages") or [])[:30]:
            lines.append(f"    message: {msg}")

    for tel in ct.get("telnet_logins") or []:
        lines.append(f"  TELNET LOGIN on {tel.get('server')}: "
                     f"username={tel.get('username') or '?'}"
                     + (f" password={tel['password']}" if tel.get("password") else ""))

    return "\n".join(lines)


def _decoded_artifacts(result: ExtractionResult) -> str:
    """What was hidden under encoding, and the secrets carved out of the streams.

    This is the section that answers a CTF or a deep-forensics question: the
    flag, the key, the command that was Base64'd or XOR'd out of plain sight.
    Every value here was read from the capture, after any decoding named, so it
    is stated as fact. A flag string in this section is the literal flag.
    """
    art = getattr(result, "artifacts", None) or {}
    if not art:
        return ""

    lines = ["=== DECODED ARTIFACTS & SECRETS ==="]

    flags = art.get("flags") or []
    if flags:
        lines.append("  CTF FLAGS RECOVERED (the literal flag string on the wire):")
        for f in flags:
            tail = " (written reversed in the capture)" if f.get("orientation") == "reversed" else ""
            lines.append(f"    {f['value']}{tail}")

    secrets = art.get("secrets") or []
    if secrets:
        lines.append("  SECRETS CARVED FROM THE STREAMS (read off the wire, treat as compromised):")
        for s in secrets:
            lines.append(f"    {s['detail']}: {s['value']}")

    payloads = art.get("decoded_payloads") or []
    if payloads:
        lines.append("  OBFUSCATED PAYLOADS DECODED (transform chain -> content):")
        for d in payloads:
            lines.append(f"    [{d['chain']}] {d['preview']}")

    return "\n".join(lines)


def _http_forensics(result: ExtractionResult) -> str:
    """The full HTTP exchange: what was POSTed, the credentials and cookies, the
    custom headers, the uploads, and what a compressed response body was hiding.

    This is the section that answers a web-forensics question the request line
    alone cannot: the password in the login POST, the session cookie to revoke,
    the API key in an X-header, the file that was uploaded. Everything here was
    read from the reassembled HTTP body, so it is stated as fact.
    """
    hf = getattr(result, "http_forensics", None) or {}
    if not hf:
        return ""

    lines = ["=== HTTP DEEP INSPECTION ==="]
    lines.append(f"  Transactions parsed: {hf.get('transactions', 0)}")

    for c in hf.get("credentials") or []:
        who = c.get("username") or "(token)"
        lines.append(f"  CREDENTIAL ({c.get('via')}): {who} / {c.get('password')} "
                     f"on {c.get('host')}")
    for sc in hf.get("session_cookies") or []:
        lines.append(f"  SESSION COOKIE on {sc['host']}: {sc['name']}={sc['value']} "
                     f"(replayable to hijack the session)")
    for name, value in (hf.get("custom_headers") or {}).items():
        lines.append(f"  custom header {name}: {value}")
    for p in hf.get("posts") or []:
        params = ", ".join(f"{k}={v}" for k, v in (p.get("params") or {}).items())
        lines.append(f"  POST {p.get('host')}{p.get('path')}: {params}")
    for up in hf.get("uploads") or []:
        lines.append(f"  FILE UPLOADED to {up['host']}: {up['filename']} "
                     f"(form field {up.get('field') or '?'})")
    for d in hf.get("decompressed") or []:
        lines.append(f"  decompressed {d['encoding']} response body "
                     f"({d['bytes']} bytes) from {d['server']}")
    for f in hf.get("flags") or []:
        lines.append(f"  FLAG recovered from an HTTP body: {f['value']}")
    for s in hf.get("secrets") or []:
        lines.append(f"  SECRET in an HTTP body: {s['detail']}: {s['value']}")

    return "\n".join(lines)


def _offline_recovery(result: ExtractionResult) -> str:
    """What the opt-in offline step recovered: the cracked password, the decrypted
    WinRM commands, and the flag.

    This is the section that answers the questions the packets alone cannot: the
    password behind an AS-REP roast, and the commands and flag inside an encrypted
    WinRM session. Every value here was computed offline from the capture's own
    material (the roast was cracked, the session key was reconstructed and
    verified against the handshake, and the sealed bodies were decrypted), so it
    is stated as fact, not inferred. When this section is present, the remote-
    management note above about command text being unrecoverable no longer applies.
    """
    off = getattr(result, "offline", None) or {}
    if not (off.get("credentials") or off.get("commands") or off.get("flags")):
        return ""

    lines = ["=== OFFLINE RECOVERY (AS-REP crack + WinRM decryption) ==="]
    lines.append("  These facts were recovered offline from the capture's own credential "
                 "material. State them plainly when asked.")
    for account, password in (off.get("credentials") or {}).items():
        lines.append(f"  CRACKED PASSWORD: the account {account} has password {password}")
    cmd_sessions = off.get("command_sessions") or []
    if cmd_sessions:
        lines.append("  COMMANDS RUN ON THE TARGET (decrypted from WinRM). Each remote shell is a "
                     "separate session; count \"the Nth command\" WITHIN one session, numbered in "
                     "the order typed (use the main session for a room question):")
        main = max(cmd_sessions, key=len)
        for i, cmds in enumerate(cmd_sessions, 1):
            lines.append(f"    session {i}{' (main)' if cmds is main else ''}:")
            for n, cmd in enumerate(cmds, 1):
                lines.append(f"      {n}. {cmd}")
    else:
        for command in off.get("commands") or []:
            lines.append(f"  COMMAND RUN ON THE TARGET (decrypted from WinRM): {command}")
    for path in off.get("exfiltrated_files") or []:
        lines.append(f"  FILE WRITTEN / EXFILTRATED on the target: {path}")
    for flag in off.get("flags") or []:
        lines.append(f"  FLAG RECOVERED: {flag}")
    return "\n".join(lines)


def _credential_exposure(result: ExtractionResult) -> str:
    """Consolidated credential-exposure section: every leaked or stolen credential,
    aligned to its account and resolved to plaintext where cracked.

    Shared verbatim with the web copilot (`webapp.app._build_chat_context`) so the two
    answer a credential question identically. See `packetiq.copilot.credentials`.
    """
    return credential_exposure_section(
        getattr(result, "cleartext", None),
        getattr(result, "http_forensics", None),
        getattr(result, "kerberos", None),
        getattr(result, "offline", None),
        getattr(result, "winrm", None),
    )


def _detection_events(events: list[DetectionEvent]) -> str:
    if not events:
        return "=== DETECTION EVENTS ===\nNone detected."

    lines = [f"=== DETECTION EVENTS ({len(events)} total) ==="]
    for i, e in enumerate(events, 1):
        dst = f"{e.dst_ip}:{e.dst_port}" if e.dst_ip and e.dst_port else (e.dst_ip or "—")
        lines.append(
            f"\n[{i}] [{e.severity.value}] {e.event_type.value}\n"
            f"    Source      : {e.src_ip or '—'}\n"
            f"    Destination : {dst}\n"
            f"    Protocol    : {e.protocol or '—'}\n"
            f"    Description : {e.description}\n"
            f"    Confidence  : {e.confidence * 100:.0f}%\n"
            f"    Packets     : {e.packet_count}"
        )
        # Include key evidence fields (skip internal/noisy ones)
        for k, v in e.evidence.items():
            if k in ("note",):
                continue
            if isinstance(v, list):
                v = ", ".join(str(x) for x in v[:5])
            lines.append(f"    {k:<16}: {v}")

    return "\n".join(lines)


def _attack_chains(chains: list[AttackChain]) -> str:
    if not chains:
        return "=== ATTACK CHAINS ===\nNo multi-stage chains correlated."

    lines = [f"=== ATTACK CHAINS ({len(chains)} identified) ==="]
    for i, chain in enumerate(chains, 1):
        phases   = " → ".join(chain.kill_chain_phases) if chain.kill_chain_phases else "—"
        attackers = ", ".join(sorted(chain.attacker_ips))
        targets   = ", ".join(sorted(chain.target_ips))
        techs     = "; ".join(f"{t.technique_id} {t.technique_name}"
                              for t in chain.mitre_techniques[:8])
        duration = format_duration(chain.duration)

        lines.append(
            f"\n[CHAIN {i}] {chain.name}\n"
            f"  Severity      : {chain.severity.value}\n"
            f"  Confidence    : {chain.confidence * 100:.0f}%\n"
            f"  Events Linked : {chain.event_count}\n"
            f"  Duration      : {duration}\n"
            f"  Attacker IPs  : {attackers}\n"
            f"  Target IPs    : {targets}\n"
            f"  Kill Chain    : {phases}\n"
            f"  Primary Phase : {chain.primary_phase}\n"
            f"  MITRE ATT&CK  : {techs}\n"
            f"  Description   : {chain.description}"
        )
        if chain.analyst_note:
            lines.append(f"  Analyst Note  : {chain.analyst_note}")

    return "\n".join(lines)


def _dns_intelligence(result: ExtractionResult) -> str:
    if not result.dns_queries:
        return ""

    lines = [f"=== DNS INTELLIGENCE ({len(result.dns_queries)} queries) ==="]

    # Domain frequency
    freq: dict[str, int] = {}
    for q in result.dns_queries:
        domain = q.get("qname", "")
        if domain:
            freq[domain] = freq.get(domain, 0) + 1

    lines.append("Top Queried Domains:")
    for domain, cnt in sorted(freq.items(), key=lambda x: x[1], reverse=True)[:20]:
        lines.append(f"  {domain:<50} {cnt:>5}x")

    return "\n".join(lines)


def _directory_services(result: ExtractionResult) -> str:
    """Active Directory authentication, stated as fact rather than inference.

    This section exists because of a specific failure. On a real AD intrusion
    capture the copilot could not say which accounts the attacker had found,
    not because the model was weak but because nothing in its context mentioned
    Kerberos at all -- the grounding filter then correctly stripped every name
    it guessed. The parser now reads those messages, and this is where they
    reach the model.

    Valid accounts are listed with the KDC reply that proved them, so an answer
    built on this section can cite why an account is known to exist instead of
    asserting it.
    """
    krb = getattr(result, "kerberos", None) or {}
    if not krb:
        return ""

    lines = ["=== ACTIVE DIRECTORY / KERBEROS ==="]
    lines.append(f"  Messages observed : {krb.get('messages', 0)}")

    types = krb.get("message_types") or {}
    if types:
        lines.append("  Message types     : "
                     + ", ".join(f"{k} x{v}" for k, v in sorted(types.items())))

    realms = krb.get("realms") or []
    if realms:
        lines.append(f"  Realm(s)          : {', '.join(realms)}")

    errors = krb.get("kdc_errors") or {}
    if errors:
        lines.append("  KDC replies       : "
                     + ", ".join(f"{k} x{v}" for k, v in errors.items()))

    valid = krb.get("valid_accounts") or {}
    if valid:
        lines.append(f"  ACCOUNTS CONFIRMED TO EXIST ({len(valid)}) — the KDC answered "
                     f"for each of these:")
        for name, proof in valid.items():
            lines.append(f"    {name:<24} proved by {proof}")

    hashes = krb.get("asrep_hashes") or {}
    if hashes:
        lines.append(f"  AS-REP ROASTABLE CREDENTIAL MATERIAL ({len(hashes)}) — these "
                     f"accounts have pre-authentication disabled, so the KDC's reply "
                     f"carried a hash crackable offline (hashcat -m 18200):")
        for name, digest in hashes.items():
            lines.append(f"    {name}: {digest}")
            # A small model cannot reliably take "the last N characters" of a long
            # blob, so the common tail lengths are stated outright as plain facts.
            lines.append(f"      last 30 chars of this hash: {digest[-30:]}")
            lines.append(f"      last 20 chars of this hash: {digest[-20:]}")
            lines.append(f"      last 16 chars of this hash: {digest[-16:]}")
        lines.append("    The password is NOT in this capture. It is recovered by "
                     "cracking the hash above against a wordlist, offline, which this "
                     "tool does not do. Report the hash, not a guessed password.")

    tried = krb.get("usernames_seen") or []
    if tried:
        lines.append(f"  Principals probed : {len(tried)} distinct")
        lines.append("    " + ", ".join(tried[:40]))
        if len(tried) > 40:
            lines.append(f"    … and {len(tried) - 40} more")

    spns = krb.get("service_principals") or []
    if spns:
        lines.append(f"  Service principals requested ({len(spns)}): "
                     + ", ".join(spns[:20]))

    undecodable = krb.get("undecodable_messages") or 0
    if undecodable:
        lines.append(f"  Not decodable     : {undecodable} message(s), typically "
                     f"fragmented across TCP segments")

    return "\n".join(lines)


def _directory_reads(result: ExtractionResult) -> str:
    """What was asked of the directory over LDAP, in the filter's own notation.

    A filter is reported as written, because that is how it is recognised: a
    responder reading `(&(objectClass=user)(servicePrincipalName=*))` knows at
    once what it was for.
    """
    ldap = getattr(result, "ldap", None) or {}
    if not ldap:
        return ""

    lines = ["=== DIRECTORY READS (LDAP) ==="]
    lines.append(f"  Operations     : {ldap.get('operations', 0)}, "
                 f"{ldap.get('searches', 0)} search(es)")
    if ldap.get("rootdse_searches"):
        lines.append(f"  RootDSE queries: {ldap['rootdse_searches']} "
                     f"(the query you run before you know the domain's own names)")
    if ldap.get("clients"):
        lines.append(f"  Client(s)      : {', '.join(ldap['clients'])}")
    for name, count in (ldap.get("filters") or {}).items():
        lines.append(f"    filter  {name}  x{count}")
    for base, count in (ldap.get("base_objects") or {}).items():
        lines.append(f"    base    {base}  x{count}")
    attributes = ldap.get("attributes_requested") or {}
    if attributes:
        lines.append("  Attributes asked for: " + ", ".join(list(attributes)[:20]))
    notable = ldap.get("notable_attributes") or {}
    for attribute, meaning in notable.items():
        lines.append(f"    NOTE: {attribute} -> {meaning}")
    if ldap.get("binds"):
        lines.append("  Binds          : " + ", ".join(ldap["binds"]))
    lines.append(f"  StartTLS       : {'yes' if ldap.get('starttls') else 'not observed'}")
    return "\n".join(lines)


def _file_sharing(result: ExtractionResult) -> str:
    """SMB: which shares were reached, which files were touched, by whom."""
    smb = getattr(result, "smb", None) or {}
    if not smb:
        return ""

    lines = ["=== FILE SHARING (SMB) ==="]
    lines.append(f"  Operations : {smb.get('operations', 0)} across "
                 f"{smb.get('sessions', 0)} session(s)")
    commands = smb.get("commands") or {}
    if commands:
        lines.append("  Commands   : " + ", ".join(f"{k} x{v}" for k, v in commands.items()))
    for account in smb.get("accounts") or []:
        who = "\\".join(x for x in (account.get("domain"), account.get("user")) if x)
        lines.append(f"  AUTHENTICATED AS: {who} "
                     f"(client called itself {account.get('workstation') or 'not sent'})")
    if smb.get("anonymous_sessions"):
        lines.append(f"  Anonymous sessions: {smb['anonymous_sessions']} "
                     f"(null session: authenticated as nobody)")
    shares = smb.get("shares") or {}
    if shares:
        lines.append("  Shares     : " + ", ".join(f"{k} x{v}" for k, v in shares.items()))
    files = smb.get("files") or {}
    if files:
        lines.append("  Files      : " + ", ".join(list(files)[:20]))
    pipes = smb.get("named_pipes") or {}
    for pipe, meaning in pipes.items():
        lines.append(f"    PIPE: {pipe} -> {meaning}")
    lines.append(f"  Bytes      : {smb.get('bytes_written', 0)} written, "
                 f"{smb.get('bytes_read', 0)} read")
    if smb.get("smb1_seen"):
        lines.append("  SMB1       : negotiated (deprecated dialect, EternalBlue surface)")
    return "\n".join(lines)


def _rpc_interfaces(result: ExtractionResult) -> str:
    """Which DCERPC interfaces were bound, named by what they are used for.

    The interface UUID is the whole signal: it says which remote-procedure
    service was asked for, in clear text, even when the call that follows is
    encrypted. A bind to drsuapi is DCSync; to svcctl, PsExec.
    """
    rpc = getattr(result, "dcerpc", None) or {}
    if not rpc:
        return ""

    lines = ["=== RPC INTERFACES (DCERPC) ==="]
    lines.append(f"  Binds      : {rpc.get('binds', 0)} across "
                 f"{rpc.get('sessions', 0)} session(s)")
    interfaces = rpc.get("interfaces") or {}
    for name, meaning in interfaces.items():
        lines.append(f"    {name}: {meaning}")
    operations = rpc.get("operations") or []
    for op in operations:
        lines.append(f"    OPERATION: {op}")
    if rpc.get("endpoint_mapper_requests") or rpc.get("rejected_binds"):
        lines.append(f"  Surface mapping: {rpc.get('endpoint_mapper_requests', 0)} "
                     f"endpoint-mapper bind(s), {rpc.get('rejected_binds', 0)} rejected. "
                     f"This is reconnaissance of the RPC surface, not execution.")
    return "\n".join(lines)


def _remote_management(result: ExtractionResult) -> str:
    """WS-Management sessions, and who authenticated to them.

    Stated separately from the HTTP section because 792 POSTs to one path are
    not web browsing: they are somebody working on the target. The model is
    told plainly that the command text is unrecoverable, so it answers "a
    remote session ran for two minutes as this account" rather than inventing
    the commands.
    """
    wrm = getattr(result, "winrm", None) or {}
    if not wrm:
        return ""

    lines = ["=== REMOTE MANAGEMENT (WinRM / WS-Management) ==="]
    lines.append(f"  Requests to /wsman : {wrm.get('requests', 0)} "
                 f"across {wrm.get('sessions', 0)} session(s)")
    if wrm.get("clients"):
        lines.append(f"  Client(s)          : {', '.join(wrm['clients'])}")
    if wrm.get("targets"):
        lines.append(f"  Target(s)          : {', '.join(wrm['targets'])}")

    for account in wrm.get("accounts") or []:
        who = "\\".join(x for x in (account.get("domain"), account.get("user")) if x)
        station = account.get("workstation") or "not sent"
        lines.append(f"  AUTHENTICATED AS   : {who}  (client called itself {station})")

    agents = wrm.get("user_agents") or {}
    if agents:
        lines.append("  Client software    : "
                     + ", ".join(f"{name} x{n}" for name, n in agents.items()))

    actions = wrm.get("actions_seen") or {}
    if actions:
        lines.append("  Actions in clear   : "
                     + ", ".join(f"{a} x{n}" for a, n in actions.items()))

    lines.append(f"  Payload            : {wrm.get('payload_bytes', 0)} bytes, "
                 f"{wrm.get('encrypted_requests', 0)} request(s) SPNEGO-encrypted")
    if (getattr(result, "offline", None) or {}).get("commands"):
        lines.append("  NOTE: the command text was SPNEGO-encrypted on the wire but has "
                     "been RECOVERED by offline decryption (the account's AS-REP roast was "
                     "cracked and the WinRM session decrypted with the recovered password). "
                     "The commands, the files written and any flag are in the OFFLINE "
                     "RECOVERY section below; use those to answer, and do not say the "
                     "session is unrecoverable.")
    else:
        lines.append("  NOTE: the command text is inside SPNEGO session encryption and is "
                     "not in the packets as they stand. Do not invent which commands ran. "
                     "If the account authenticating here has a roastable AS-REP (see the "
                     "ACTIVE DIRECTORY / KERBEROS section), PacketIQ can recover the "
                     "commands and any flag OFFLINE by cracking the roast and decrypting "
                     "the session: re-run with `packetiq crack <pcap>` or "
                     "`packetiq chat <pcap> --crack`. Otherwise the host's PowerShell "
                     "operational and WinRM event logs hold the command text. The account, "
                     "workstation and client software above are read from unencrypted "
                     "headers and are reliable.")
    return "\n".join(lines)


def _http_activity(result: ExtractionResult) -> str:
    if not result.http_requests:
        return ""

    lines = [f"=== HTTP ACTIVITY ({len(result.http_requests)} requests) ==="]
    for r in result.http_requests[:30]:
        method = r.get("method", "?") or "?"
        host   = r.get("host",   "?") or "?"
        path   = r.get("path",   "/") or "/"
        src    = r.get("src",    "?") or "?"
        lines.append(f"  {method:<6} {src:<18} → {host}{path}")

    return "\n".join(lines)


def _ioc_summary(
    result: ExtractionResult,
    events: list[DetectionEvent],
    chains: list[AttackChain],
) -> str:
    """Pre-computed IOC list for quick reference."""
    lines = ["=== IOC SUMMARY ==="]

    # Attacker IPs from detection events
    attacker_ips = sorted({
        e.src_ip for e in events
        if e.src_ip and e.severity.value in ("CRITICAL", "HIGH")
    })
    if attacker_ips:
        lines.append(f"Suspected Attacker IPs (HIGH/CRITICAL events) — {len(attacker_ips)}:")
        for ip in attacker_ips[:_MAX_IP_LIST]:
            lines.append(f"  {ip}")
        if len(attacker_ips) > _MAX_IP_LIST:
            lines.append(f"  … and {len(attacker_ips) - _MAX_IP_LIST:,} more")

    # Target IPs
    target_ips = sorted({
        e.dst_ip for e in events
        if e.dst_ip and e.severity.value in ("CRITICAL", "HIGH")
    })
    if target_ips:
        lines.append(f"Targeted IPs — {len(target_ips)}:")
        for ip in target_ips[:_MAX_IP_LIST]:
            lines.append(f"  {ip}")
        if len(target_ips) > _MAX_IP_LIST:
            lines.append(f"  … and {len(target_ips) - _MAX_IP_LIST:,} more")

    # External IPs contacted (top by volume; the full set is a count, not a dump)
    if result.external_ips:
        ext = sorted(result.external_ips,
                     key=lambda ip: result.ip_dst_counts.get(ip, 0), reverse=True)
        shown = ext[:_MAX_IP_LIST]
        lines.append(f"External IPs Contacted ({len(ext)} total, top {len(shown)} by volume):")
        for ip in shown:
            lines.append(f"  {ip}")
        if len(ext) > len(shown):
            lines.append(f"  … and {len(ext) - len(shown):,} more")

    # Suspicious domains
    suspicious_domains = sorted({
        q.get("qname", "")
        for q in result.dns_queries
        if q.get("qname") and (
            len(q["qname"]) > 30 or
            any(q["qname"].endswith(tld) for tld in (".xyz", ".tk", ".ml", ".top", ".pw"))
        )
    })
    if suspicious_domains:
        lines.append("Suspicious Domains:")
        for d in suspicious_domains:
            lines.append(f"  {d}")

    return "\n".join(lines)
