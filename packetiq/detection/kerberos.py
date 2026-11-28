"""
Kerberos detection — Active Directory authentication attacks read from the wire.

Why this module exists
----------------------
PacketIQ was strong on network-layer attacks and blind on enterprise
authentication. On a real AD intrusion capture it reported a port scan and
nothing else, while 60 AS-REQs carrying 54 distinct usernames sat unread in the
packets, six of which the KDC confirmed as real accounts. The copilot could not
answer questions about that capture for the simple reason that no Kerberos
evidence ever reached it.

What the KDC tells an attacker, and therefore tells us
------------------------------------------------------
A pre-authentication probe is an AS-REQ sent with no PA-ENC-TIMESTAMP. The KDC
answers it in one of three ways, and each answer is a fact about the directory:

  * ``KDC_ERR_C_PRINCIPAL_UNKNOWN`` (6)  -- that account does not exist.
  * ``KDC_ERR_PREAUTH_REQUIRED`` (25)    -- that account EXISTS. This is the
    harvest; a KDC only asks for pre-authentication from a principal it knows.
  * an AS-REP (11) instead of an error  -- the account exists AND has
    pre-authentication disabled, so the reply carries material an attacker can
    crack offline. That is AS-REP roasting.

Reading those three outcomes is the whole of user enumeration detection, and it
is why this module reports named accounts rather than a count: "six valid
accounts were confirmed" is a lead, "djohn, kranith, ray, john.doe,
ranith.kays, joan.ray" is an investigation.

Nothing here is inferred from a port being open. Every finding names the
messages it came from, and an account is only reported as valid when the KDC
itself said so.
"""

from __future__ import annotations

import contextlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from packetiq import config
from packetiq.detection.models import DetectionEvent, EventType, Severity

# ── Kerberos protocol constants ──────────────────────────────────────────────
# RFC 4120 section 7.5.9 for the error codes, 7.5.1 for the encryption types.
# Only the codes this module reasons about are named; an unnamed code is still
# reported, by number, rather than silently dropped.

AS_REQ, AS_REP, TGS_REQ, TGS_REP, KRB_ERROR_TYPE = 10, 11, 12, 13, 30

ERR_PRINCIPAL_UNKNOWN = 6     # user does not exist
ERR_PREAUTH_FAILED    = 24    # user exists, wrong password
ERR_PREAUTH_REQUIRED  = 25    # user exists  <- the enumeration signal
ERR_CLIENT_REVOKED    = 18    # user exists, account disabled or locked out
ERR_WRONG_REALM       = 68

ERROR_NAMES: dict[int, str] = {
    6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    12: "KDC_ERR_POLICY",
    13: "KDC_ERR_BADOPTION",
    14: "KDC_ERR_ETYPE_NOSUPP",
    18: "KDC_ERR_CLIENT_REVOKED",
    23: "KDC_ERR_KEY_EXPIRED",
    24: "KDC_ERR_PREAUTH_FAILED",
    25: "KDC_ERR_PREAUTH_REQUIRED",
    32: "KRB_AP_ERR_TKT_EXPIRED",
    37: "KRB_AP_ERR_SKEW",
    52: "KRB_ERR_RESPONSE_TOO_BIG",
    68: "KDC_ERR_WRONG_REALM",
}

# An account is proven to exist when the KDC answers one of these: each reply is
# about a principal it recognised. Error 6 is the opposite proof.
EXISTS_CODES = frozenset({ERR_PREAUTH_FAILED, ERR_PREAUTH_REQUIRED, ERR_CLIENT_REVOKED})

ETYPE_NAMES: dict[int, str] = {
    1:  "des-cbc-crc",
    3:  "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
}

RC4_ETYPES = frozenset({23, 24})
AES_ETYPES = frozenset({17, 18})

MITRE_USER_ENUM = "T1087.002"   # Account Discovery: Domain Account
MITRE_SPRAY     = "T1110.003"   # Brute Force: Password Spraying
MITRE_KERBEROAST = "T1558.003"  # Steal or Forge Kerberos Tickets: Kerberoasting
MITRE_ASREPROAST = "T1558.004"  # Steal or Forge Kerberos Tickets: AS-REP Roasting
MITRE_TICKETS   = "T1558"       # Steal or Forge Kerberos Tickets


def _text(value) -> str | None:
    """Unwrap a scapy ASN.1 value to a plain string.

    scapy hands back ``ASN1_GENERAL_STRING`` / ``ASN1_INTEGER`` wrappers whose
    ``.val`` is sometimes ``bytes`` and sometimes ``str``. Calling ``str()`` on
    the wrapper gives a repr, not the value, which is a quiet way to put
    ``<ASN1_GENERAL_STRING['johndoe']>`` into a report.
    """
    value = getattr(value, "val", value)
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def _int(value) -> int | None:
    """Unwrap a scapy ASN.1 integer, returning None when it is not one."""
    value = getattr(value, "val", value)
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _principal(name) -> str:
    """Join a Kerberos PrincipalName into the usual slash-separated form.

    A service principal arrives as its components, so ``["HTTP", "dc01.thm"]``
    is the SPN ``HTTP/dc01.thm``; a user principal is a single component.
    """
    if name is None:
        return ""
    parts = [_text(p) or "" for p in getattr(name, "nameString", []) or []]
    return "/".join(p for p in parts if p)


def format_asrep_hash(cname: str, realm: str, etype: int, cipher: bytes) -> str:
    """Format the encrypted part of an AS-REP as a hashcat -m 18200 string.

    This is the forensic artifact of AS-REP roasting: the material an attacker
    carries off to crack the account's password offline. Surfacing it tells a
    responder exactly which credential left the network and must be rotated,
    and lets the incident record carry the evidence rather than a claim.

    The layout is the one hashcat and John read:

      * RC4 (etype 23): ``$krb5asrep$23$user@REALM:<16-byte checksum>$<rest>``,
        where the checksum is the first 16 bytes of the cipher.
      * AES (17/18): ``$krb5asrep$<etype>$user@REALM$<cipher less last 12>$<last 12>``,
        where the trailing 12 bytes are the HMAC.

    The tool does not crack the hash; recovering the password from it is an
    offline step performed with a wordlist, deliberately outside this program.
    """
    if not cipher or not cname or not realm:
        return ""
    principal = f"{cname}@{realm.upper()}"
    if etype == 23:
        checksum, edata = cipher[:16], cipher[16:]
        return f"$krb5asrep$23${principal}:{checksum.hex()}${edata.hex()}"
    if etype in (17, 18):
        edata, mac = cipher[:-12], cipher[-12:]
        return f"$krb5asrep${etype}${principal}${edata.hex()}${mac.hex()}"
    return ""


def _asrep_hash_from_reply(root) -> str:
    """Pull the crackable hash out of an AS-REP, preferring the RC4 form.

    An AS-REP can carry the account key in several encryption types at once;
    the RC4 one (etype 23) is the cheapest to crack and the one tooling asks
    for, so it is the one reported when present.
    """
    enc = getattr(root, "encPart", None)
    if enc is None:
        return ""
    etype = _int(getattr(enc, "etype", None))
    cipher_field = getattr(enc, "cipher", None)
    cipher = getattr(cipher_field, "val", cipher_field)
    if not isinstance(cipher, (bytes, bytearray)) or etype is None:
        return ""
    cname = _principal(getattr(root, "cname", None))
    realm = _text(getattr(root, "crealm", None)) or ""
    return format_asrep_hash(cname, realm, etype, bytes(cipher))


@dataclass
class KerberosMessage:
    """One Kerberos message, reduced to the fields a responder reasons about."""

    ts: float
    src: str
    dst: str
    msg_type: int
    cname: str = ""
    sname: str = ""
    realm: str = ""
    etypes: tuple[int, ...] = ()
    error_code: int | None = None
    has_preauth: bool = False
    # The crackable material from an AS-REP, in hashcat's -m 18200 form. Empty
    # for every message that is not an AS-REP, and for an AS-REP whose encrypted
    # part could not be read.
    asrep_hash: str = ""

    @property
    def is_request(self) -> bool:
        return self.msg_type in (AS_REQ, TGS_REQ)


@dataclass
class _ClientState:
    """What one client has done against one KDC."""

    tried: list[tuple[float, str]] = field(default_factory=list)   # (ts, cname)
    unknown: list[str] = field(default_factory=list)               # err 6
    confirmed: dict[str, str] = field(default_factory=dict)        # cname -> error name
    preauth_failures: list[str] = field(default_factory=list)      # err 24
    asrep_roastable: list[str] = field(default_factory=list)       # AS-REP to a bare AS-REQ
    asrep_hashes: dict[str, str] = field(default_factory=dict)     # account -> -m 18200 hash
    roastable_spns: dict[str, tuple[int, ...]] = field(default_factory=dict)
    rc4_only_requests: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    realm_counts: Counter = field(default_factory=Counter)
    probes_without_preauth: int = 0

    def realm(self) -> str:
        """The realm this client was actually working against.

        Reported as the most-probed one rather than a joined set: a sweep that
        starts with one stray request to a mistyped realm would otherwise make
        every finding read "DIRECTORY.THM, NM", which buries the answer to the
        first question a responder asks.
        """
        if not self.realm_counts:
            return "unknown"
        return self.realm_counts.most_common(1)[0][0]

    def other_realms(self) -> list[str]:
        main = self.realm()
        return sorted(r for r in self.realm_counts if r != main)


class KerberosAccumulator:
    """Collects Kerberos messages over one PCAP pass, then reports on them.

    ``feed(pkt)`` filters internally so this can share the engine's existing
    raw-packet loop rather than reading the capture again.
    """

    def __init__(self) -> None:
        self.messages: list[KerberosMessage] = []
        self.clients: dict[tuple[str, str], _ClientState] = defaultdict(_ClientState)
        self.parse_failures = 0

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        """Record one packet if it carries Kerberos. Anything else is ignored."""
        from scapy.layers.kerberos import Kerberos
        if not pkt.haslayer(Kerberos):
            return

        src, dst = _endpoints(pkt)
        if src is None or dst is None:
            return

        try:
            msg = self._decode(pkt, src, dst)
        except Exception:
            # A truncated or fragmented Kerberos message is a fact about the
            # capture, not an error to swallow silently: it is counted and
            # reported alongside the findings.
            self.parse_failures += 1
            return
        if msg is None:
            return

        self.messages.append(msg)
        self._absorb(msg)

    def _decode(self, pkt, src: str, dst: str) -> KerberosMessage | None:
        from scapy.layers.kerberos import (
            KRB_AS_REP,
            KRB_AS_REQ,
            KRB_ERROR,
            KRB_TGS_REP,
            KRB_TGS_REQ,
            Kerberos,
        )

        root = pkt[Kerberos].root
        ts = float(pkt.time)

        if isinstance(root, (KRB_AS_REQ, KRB_TGS_REQ)):
            body = root.reqBody
            etypes = tuple(e for e in (_int(x) for x in (body.etype or [])) if e is not None)
            return KerberosMessage(
                ts=ts, src=src, dst=dst,
                msg_type=AS_REQ if isinstance(root, KRB_AS_REQ) else TGS_REQ,
                cname=_principal(body.cname),
                sname=_principal(body.sname),
                realm=_text(body.realm) or "",
                etypes=etypes,
                has_preauth=bool(root.padata),
            )

        if isinstance(root, (KRB_AS_REP, KRB_TGS_REP)):
            # A KDC-REP names the client realm `crealm`, not `realm`. Reading
            # `realm` here raised AttributeError, which this class counts as an
            # undecodable message -- so every AS-REP was silently discarded and
            # AS-REP roasting could never fire. Caught by constructing a real
            # AS-REP in the tests rather than by reasoning about the RFC.
            return KerberosMessage(
                ts=ts, src=src, dst=dst,
                msg_type=AS_REP if isinstance(root, KRB_AS_REP) else TGS_REP,
                cname=_principal(root.cname),
                realm=_text(root.crealm) or "",
                asrep_hash=_asrep_hash_from_reply(root) if isinstance(root, KRB_AS_REP) else "",
            )

        if isinstance(root, KRB_ERROR):
            return KerberosMessage(
                ts=ts, src=src, dst=dst, msg_type=KRB_ERROR_TYPE,
                sname=_principal(root.sname),
                realm=_text(root.realm) or "",
                error_code=_int(root.errorCode),
            )

        return None

    def _absorb(self, msg: KerberosMessage) -> None:
        """Fold one message into the per-client picture.

        A KDC reply does not repeat the username it is about, so a reply is
        attributed to the most recent request that same client sent. Kerberos
        pre-authentication probing is sequential -- a prober waits for each
        answer before sending the next name -- so this pairing is sound for the
        traffic the detector exists to read, and every finding says which
        request a reply was matched to.
        """
        if msg.is_request:
            state = self.clients[(msg.src, msg.dst)]
            if msg.cname:
                state.tried.append((msg.ts, msg.cname))
            if msg.realm:
                state.realm_counts[msg.realm] += 1
            if msg.msg_type == AS_REQ and not msg.has_preauth:
                state.probes_without_preauth += 1
            if msg.msg_type == TGS_REQ and msg.sname and not msg.sname.startswith("krbtgt"):
                state.roastable_spns[msg.sname] = msg.etypes
            if msg.etypes and set(msg.etypes) & RC4_ETYPES and not set(msg.etypes) & AES_ETYPES:
                state.rc4_only_requests += 1
            state.first_ts = state.first_ts or msg.ts
            state.last_ts = msg.ts
            return

        # A reply travels dst -> src relative to the request.
        replied_to = self.clients.get((msg.dst, msg.src))
        if replied_to is None or not replied_to.tried:
            return
        subject = replied_to.tried[-1][1]
        replied_to.last_ts = msg.ts

        if msg.msg_type == KRB_ERROR_TYPE:
            if msg.error_code == ERR_PRINCIPAL_UNKNOWN:
                replied_to.unknown.append(subject)
            elif msg.error_code in EXISTS_CODES:
                replied_to.confirmed[subject] = ERROR_NAMES.get(
                    msg.error_code, f"error {msg.error_code}")
                if msg.error_code == ERR_PREAUTH_FAILED:
                    replied_to.preauth_failures.append(subject)
        elif msg.msg_type == AS_REP and replied_to.probes_without_preauth:
            # The KDC issued a ticket for a request that carried no
            # pre-authentication: the account has preauth disabled.
            #
            # Unlike a KRB-ERROR, an AS-REP names its own account in `cname`, so
            # that is used rather than the positional "most recent request"
            # guess. Without this, two AS-REPs for one account (an AES one and
            # an RC4 one, as a roasting tool collects) get pinned to whichever
            # usernames happened to precede them, inventing a roastable account
            # that never existed and splitting one account's two hashes apart.
            account = msg.cname or subject
            replied_to.confirmed[account] = "AS-REP issued without pre-authentication"
            if account not in replied_to.asrep_roastable:
                replied_to.asrep_roastable.append(account)
            # Keep the crackable hash with the account it belongs to. An RC4
            # hash replaces an AES one already stored, because RC4 is the one a
            # cracker will actually use and the account should be reported by
            # its weakest exposed form.
            if msg.asrep_hash and (account not in replied_to.asrep_hashes
                                   or msg.asrep_hash.startswith("$krb5asrep$23$")):
                replied_to.asrep_hashes[account] = msg.asrep_hash

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Structured Kerberos facts for the report, the UI and the copilot.

        Returned even when no detector fires, because "the capture contains
        Kerberos and here is what it says" is itself an answer to most
        directory-forensics questions.
        """
        if not self.messages:
            return {}

        by_type: dict[str, int] = defaultdict(int)
        for m in self.messages:
            by_type[_msg_name(m.msg_type)] += 1

        realms = sorted({m.realm for m in self.messages if m.realm})
        accounts: dict[str, str] = {}
        tried: set[str] = set()
        spns: dict[str, tuple[int, ...]] = {}
        hashes: dict[str, str] = {}
        errors: dict[str, int] = defaultdict(int)
        for m in self.messages:
            if m.error_code is not None:
                errors[ERROR_NAMES.get(m.error_code, f"error {m.error_code}")] += 1
        # Per requesting host, so a host's own machine account and its logged-in
        # user can be told apart from everything else the capture saw. An AS-REQ is
        # sent BY the client, so the request's source is the host the identity
        # belongs to; a KDC reply echoing the name does not create an entry here
        # because a reply is not a request.
        by_host: dict[str, dict] = {}
        for (src, _dst), state in self.clients.items():
            names = [n for _, n in state.tried]
            if not names:
                continue
            bucket = by_host.setdefault(
                src, {"machine_accounts": set(), "user_accounts": set(), "all": set()})
            for name in names:
                bucket["all"].add(name)
                target = "machine_accounts" if name.endswith("$") else "user_accounts"
                bucket[target].add(name)

        for state in self.clients.values():
            accounts.update(state.confirmed)
            tried.update(name for _, name in state.tried)
            spns.update(state.roastable_spns)
            hashes.update(state.asrep_hashes)

        return {
            "messages": len(self.messages),
            "message_types": dict(by_type),
            "realms": realms,
            "usernames_seen": sorted(tried),
            "by_host": {ip: {k: sorted(v) for k, v in d.items()}
                        for ip, d in sorted(by_host.items())},
            "valid_accounts": dict(sorted(accounts.items())),
            "service_principals": sorted(spns),
            # account -> hashcat -m 18200 string. The crackable material that
            # left the network, kept with the account it belongs to.
            "asrep_hashes": dict(sorted(hashes.items())),
            "kdc_errors": dict(sorted(errors.items(), key=lambda kv: -kv[1])),
            "undecodable_messages": self.parse_failures,
        }

    def finalize(self) -> list[DetectionEvent]:
        events: list[DetectionEvent] = []
        min_names = config.get("kerberos", "user_enum_min_names", 10)
        min_unknown = config.get("kerberos", "user_enum_min_unknown", 3)
        spray_min = config.get("kerberos", "spray_min_users", 5)

        for (src, dst), state in self.clients.items():
            events.extend(self._enumeration(src, dst, state, min_names, min_unknown))
            events.extend(self._spraying(src, dst, state, spray_min))
            events.extend(self._roasting(src, dst, state))
            events.extend(self._weak_crypto(src, dst, state))
        return events

    def _enumeration(self, src, dst, state, min_names, min_unknown) -> list[DetectionEvent]:
        """Many distinct principals probed, and the KDC disowned some of them.

        Both conditions matter. A workstation legitimately asks for tickets all
        day, but it asks for its own user; a sweep through names the directory
        does not know is not something normal authentication produces.
        """
        names = [n for _, n in state.tried]
        distinct = sorted(set(names))
        if len(distinct) < min_names or len(state.unknown) < min_unknown:
            return []

        valid = sorted(state.confirmed)
        realm = state.realm()
        duration = max(state.last_ts - state.first_ts, 0.0)
        desc = (
            f"Kerberos user enumeration — {len(distinct)} distinct principals probed "
            f"against realm {realm}; the KDC rejected {len(state.unknown)} as unknown "
            f"and confirmed {len(valid)} as real"
        )
        return [DetectionEvent(
            event_type=EventType.KERBEROS_USER_ENUM,
            severity=Severity.HIGH if valid else Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=88, protocol="KERBEROS",
            timestamp=state.first_ts,
            packet_count=len(names),
            confidence=0.95 if valid else 0.8,
            description=desc,
            evidence={
                "realm": realm,
                "principals_probed": len(distinct),
                "rejected_unknown": len(state.unknown),
                "valid_accounts": ", ".join(valid) if valid else "none confirmed",
                "confirmed_by": ", ".join(sorted(set(state.confirmed.values()))) or "—",
                "other_realms_probed": ", ".join(state.other_realms()) or "none",
                "probes_without_preauth": state.probes_without_preauth,
                "duration_secs": round(duration, 2),
                "sample_names": ", ".join(distinct[:12]),
                "mitre": MITRE_USER_ENUM,
                "note": "An account is listed as valid only because the KDC itself "
                        "answered for it; names are attributed to the most recent "
                        "preceding AS-REQ from this client.",
            },
        )]

    def _spraying(self, src, dst, state, spray_min) -> list[DetectionEvent]:
        """One password tried against many accounts: KDC_ERR_PREAUTH_FAILED."""
        users = sorted(set(state.preauth_failures))
        if len(users) < spray_min:
            return []
        return [DetectionEvent(
            event_type=EventType.KERBEROS_BRUTE_FORCE,
            severity=Severity.HIGH,
            src_ip=src, dst_ip=dst, dst_port=88, protocol="KERBEROS",
            timestamp=state.first_ts,
            packet_count=len(state.preauth_failures),
            confidence=0.9,
            description=(
                f"Kerberos password spraying — pre-authentication failed for "
                f"{len(users)} distinct accounts from one source"
            ),
            evidence={
                "accounts_attempted": ", ".join(users[:12]),
                "distinct_accounts": len(users),
                "failed_attempts": len(state.preauth_failures),
                "realm": state.realm(),
                "mitre": MITRE_SPRAY,
                "note": "Every account named here exists: the KDC returned "
                        "KDC_ERR_PREAUTH_FAILED, which it only sends for a "
                        "principal it knows.",
            },
        )]

    def _roasting(self, src, dst, state) -> list[DetectionEvent]:
        """Ticket material an attacker can take away and crack offline."""
        events: list[DetectionEvent] = []

        if state.asrep_roastable:
            events.append(DetectionEvent(
                event_type=EventType.KERBEROS_ROASTING,
                severity=Severity.CRITICAL,
                src_ip=src, dst_ip=dst, dst_port=88, protocol="KERBEROS",
                timestamp=state.first_ts,
                packet_count=len(state.asrep_roastable),
                confidence=0.9,
                description=(
                    f"AS-REP roasting — the KDC issued a ticket without "
                    f"pre-authentication for {len(state.asrep_roastable)} account(s), "
                    f"so the reply carries crackable material"
                ),
                evidence={
                    "accounts": ", ".join(sorted(state.asrep_roastable)),
                    "realm": state.realm(),
                    "crackable_hashes": "; ".join(
                        f"{a}: {h}" for a, h in sorted(state.asrep_hashes.items())
                    ) or "encrypted part not readable",
                    "hash_format": "hashcat -m 18200 / john krb5asrep",
                    "mitre": MITRE_ASREPROAST,
                    "note": "These accounts have 'do not require Kerberos "
                            "pre-authentication' set, which is the configuration "
                            "that makes the attack possible. The hash above is the "
                            "material that left the network; recovering the password "
                            "from it is an offline crack this tool does not perform, "
                            "and the account must be treated as compromised meanwhile.",
                },
            ))

        if state.roastable_spns:
            rc4 = sorted(s for s, et in state.roastable_spns.items()
                         if set(et) & RC4_ETYPES and not set(et) & AES_ETYPES)
            events.append(DetectionEvent(
                event_type=EventType.KERBEROS_ROASTING,
                severity=Severity.HIGH if rc4 else Severity.MEDIUM,
                src_ip=src, dst_ip=dst, dst_port=88, protocol="KERBEROS",
                timestamp=state.first_ts,
                packet_count=len(state.roastable_spns),
                confidence=0.85 if rc4 else 0.6,
                description=(
                    f"Kerberoasting — service tickets requested for "
                    f"{len(state.roastable_spns)} service principal(s)"
                    + (f", {len(rc4)} of them forced to RC4" if rc4 else "")
                ),
                evidence={
                    "service_principals": ", ".join(sorted(state.roastable_spns)[:12]),
                    "rc4_forced": ", ".join(rc4) if rc4 else "none",
                    "realm": state.realm(),
                    "mitre": MITRE_KERBEROAST,
                    "note": "Requesting a service ticket is normal; requesting many, "
                            "or forcing RC4 when the client also supports AES, is the "
                            "part that distinguishes harvesting from use.",
                },
            ))
        return events

    def _weak_crypto(self, src, dst, state) -> list[DetectionEvent]:
        """RC4 asked for where AES was not offered at all."""
        if not state.rc4_only_requests:
            return []
        return [DetectionEvent(
            event_type=EventType.KERBEROS_ANOMALY,
            severity=Severity.MEDIUM,
            src_ip=src, dst_ip=dst, dst_port=88, protocol="KERBEROS",
            timestamp=state.first_ts,
            packet_count=state.rc4_only_requests,
            confidence=0.7,
            description=(
                f"Kerberos encryption downgrade — {state.rc4_only_requests} request(s) "
                f"offered only RC4 where a current Windows client offers AES"
            ),
            evidence={
                "rc4_only_requests": state.rc4_only_requests,
                "realm": state.realm(),
                "weak_etypes": ", ".join(ETYPE_NAMES[e] for e in sorted(RC4_ETYPES)),
                "mitre": MITRE_TICKETS,
                "note": "RC4 ticket material is far cheaper to crack than AES, so "
                        "tooling asks for it deliberately.",
            },
        )]


def _msg_name(msg_type: int) -> str:
    return {
        AS_REQ: "AS-REQ", AS_REP: "AS-REP",
        TGS_REQ: "TGS-REQ", TGS_REP: "TGS-REP",
        KRB_ERROR_TYPE: "KRB-ERROR",
    }.get(msg_type, f"type {msg_type}")


def _endpoints(pkt) -> tuple[str | None, str | None]:
    """Source and destination addresses, IPv4 or IPv6."""
    with contextlib.suppress(Exception):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IP):
            return pkt[IP].src, pkt[IP].dst
        if pkt.haslayer(IPv6):
            return pkt[IPv6].src, pkt[IPv6].dst
    return None, None
