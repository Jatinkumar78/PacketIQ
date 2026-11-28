"""
Tests for Kerberos detection.

Every packet in here is a real Kerberos message, built with scapy's own
Kerberos layer and round-tripped through bytes before the detector sees it, so
the tests exercise the same decode path a capture does rather than a convenient
stand-in. Nothing is mocked at the protocol level.

The scenarios are the ones the module was written for, taken from a real
Active Directory intrusion capture: a pre-authentication sweep through a
username wordlist, the KDC's three different answers, password spraying, the
two roasting variants, and an RC4 downgrade.
"""

from scapy.asn1.asn1 import ASN1_GENERAL_STRING, ASN1_INTEGER
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.kerberos import (
    KRB_AS_REP,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_KDC_REQ_BODY,
    KRB_TGS_REQ,
    Kerberos,
    PrincipalName,
)

from packetiq.detection import kerberos as krb
from packetiq.detection.models import EventType, Severity

ATTACKER = "10.0.2.74"
KDC = "10.0.2.75"
REALM = "DIRECTORY.THM"


# ── packet construction ───────────────────────────────────────────────────────

def _principal(*parts):
    return PrincipalName(
        nameString=[ASN1_GENERAL_STRING(p) for p in parts],
        nameType=ASN1_INTEGER(1),
    )


def _wire(pkt):
    """Serialise and re-parse, so the detector decodes bytes like it would a capture."""
    return IP(bytes(pkt))


def _wire_live(pkt):
    """A packet fed without a bytes round-trip.

    Real AS-REPs from a capture carry an encrypted part and decode fine, but
    scapy cannot re-dissect an AS-REP it built itself once that part is present
    (the ASN.1 it writes does not satisfy the dissector it reads back with).
    The detector reads the same ``encPart`` from a live object, so hash tests
    feed one directly; the byte-level decoding is covered elsewhere.
    """
    return pkt


def as_req(user, *, realm=REALM, etypes=(18, 17, 23), src=ATTACKER, dst=KDC):
    body = KRB_KDC_REQ_BODY(
        cname=_principal(user),
        realm=ASN1_GENERAL_STRING(realm),
        sname=_principal("krbtgt", realm),
        etype=[ASN1_INTEGER(e) for e in etypes],
    )
    return _wire(IP(src=src, dst=dst) / UDP(sport=45000, dport=88)
                 / Kerberos(root=KRB_AS_REQ(reqBody=body)))


def tgs_req(spn_parts, *, realm=REALM, etypes=(23,), src=ATTACKER, dst=KDC):
    body = KRB_KDC_REQ_BODY(
        realm=ASN1_GENERAL_STRING(realm),
        sname=_principal(*spn_parts),
        etype=[ASN1_INTEGER(e) for e in etypes],
    )
    return _wire(IP(src=src, dst=dst) / UDP(sport=45000, dport=88)
                 / Kerberos(root=KRB_TGS_REQ(reqBody=body)))


def krb_error(code, *, realm=REALM, src=KDC, dst=ATTACKER):
    err = KRB_ERROR(
        errorCode=ASN1_INTEGER(code),
        realm=ASN1_GENERAL_STRING(realm),
        sname=_principal("krbtgt", realm),
    )
    return _wire(IP(src=src, dst=dst) / UDP(sport=88, dport=45000) / Kerberos(root=err))


def as_rep(user, *, realm=REALM, src=KDC, dst=ATTACKER):
    rep = KRB_AS_REP(crealm=ASN1_GENERAL_STRING(realm), cname=_principal(user))
    return _wire(IP(src=src, dst=dst) / UDP(sport=88, dport=45000) / Kerberos(root=rep))


def _run(packets):
    acc = krb.KerberosAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc


# ── value unwrapping ──────────────────────────────────────────────────────────

def test_asn1_strings_are_unwrapped_to_their_value_not_their_repr():
    """str() on a scapy ASN.1 wrapper yields "<ASN1_GENERAL_STRING['johndoe']>".

    Putting that in a report is a quiet way to make a username unreadable, and
    it survives every type check, so it is asserted directly.
    """
    assert krb._text(ASN1_GENERAL_STRING("johndoe")) == "johndoe"
    assert krb._text(b"raw-bytes") == "raw-bytes"
    assert krb._text("already-a-string") == "already-a-string"
    assert krb._text(None) is None


def test_undecodable_bytes_become_replacement_characters_rather_than_an_exception():
    """A truncated capture can hand us a partial UTF-8 sequence mid-username."""
    assert krb._text(b"\xff\xfeabc").endswith("abc")


def test_integers_unwrap_and_non_numeric_values_return_none():
    assert krb._int(ASN1_INTEGER(25)) == 25
    assert krb._int(7) == 7
    assert krb._int(None) is None
    assert krb._int(b"not a number") is None


def test_a_service_principal_keeps_its_slash_separated_form():
    """HTTP/web.thm is one SPN, not two names, and a report that splits it is wrong."""
    assert krb._principal(_principal("HTTP", "web.directory.thm")) == "HTTP/web.directory.thm"
    assert krb._principal(_principal("johndoe")) == "johndoe"
    assert krb._principal(None) == ""


def test_an_empty_principal_does_not_become_a_stray_slash():
    assert krb._principal(PrincipalName(nameString=[])) == ""


def test_a_message_knows_whether_it_is_a_request():
    assert krb.KerberosMessage(0.0, "a", "b", krb.AS_REQ).is_request
    assert krb.KerberosMessage(0.0, "a", "b", krb.TGS_REQ).is_request
    assert not krb.KerberosMessage(0.0, "a", "b", krb.KRB_ERROR_TYPE).is_request


def test_an_unrecognised_message_type_is_still_named_by_number():
    """Reporting "type 42" beats dropping a message nobody anticipated."""
    assert krb._msg_name(krb.AS_REQ) == "AS-REQ"
    assert krb._msg_name(99) == "type 99"


# ── packet intake ─────────────────────────────────────────────────────────────

def test_packets_without_kerberos_are_ignored_entirely():
    acc = _run([IP(src=ATTACKER, dst=KDC) / TCP(dport=443),
                IP(src=ATTACKER, dst=KDC) / UDP(dport=53)])
    assert acc.messages == []
    assert acc.summary() == {}


def test_a_kerberos_message_with_no_ip_layer_is_skipped_not_crashed():
    """Kerberos over a link-layer-only frame has no addresses to attribute it to."""
    body = KRB_KDC_REQ_BODY(cname=_principal("u"), realm=ASN1_GENERAL_STRING(REALM),
                            sname=_principal("krbtgt", REALM), etype=[ASN1_INTEGER(18)])
    bare = UDP(sport=45000, dport=88) / Kerberos(root=KRB_AS_REQ(reqBody=body))
    acc = _run([UDP(bytes(bare))])
    assert acc.messages == []


def test_kerberos_over_ipv6_is_read_the_same_as_over_ipv4():
    body = KRB_KDC_REQ_BODY(cname=_principal("v6user"), realm=ASN1_GENERAL_STRING(REALM),
                            sname=_principal("krbtgt", REALM), etype=[ASN1_INTEGER(18)])
    pkt = IPv6(src="fd00::1", dst="fd00::2") / UDP(sport=45000, dport=88) \
        / Kerberos(root=KRB_AS_REQ(reqBody=body))
    acc = _run([IPv6(bytes(pkt))])
    assert [m.cname for m in acc.messages] == ["v6user"]


def test_a_message_that_cannot_be_decoded_is_counted_rather_than_dropped(monkeypatch):
    """An undecodable Kerberos message is a fact about the capture.

    This counter earns its place twice over. A message fragmented across TCP
    segments genuinely cannot be decoded from the segment scapy hands us, and
    silently discarding it would make the message tally disagree with the
    packet count for no visible reason. It also caught a bug in this module:
    the capture this was written from reported two undecodable messages, which
    turned out not to be fragments at all but AS-REPs lost to reading `realm`
    on a structure whose field is `crealm`. A silent `except` would have hidden
    a CRITICAL finding; a counter made it visible.
    """
    acc = krb.KerberosAccumulator()

    def truncated(*_args, **_kwargs):
        raise ValueError("ASN.1 runs past the end of this segment")

    monkeypatch.setattr(acc, "_decode", truncated)
    acc.feed(as_req("whoever"))

    assert acc.parse_failures == 1
    assert acc.messages == []
    assert acc.summary() == {}


def test_a_kerberos_message_type_the_module_does_not_model_is_ignored_quietly():
    """AP-REQ and friends carry no principal the detectors reason about."""
    from scapy.layers.kerberos import KRB_AP_REQ
    pkt = IP(src=ATTACKER, dst=KDC) / UDP(sport=45000, dport=88) \
        / Kerberos(root=KRB_AP_REQ())
    acc = _run([IP(bytes(pkt))])
    assert acc.messages == []
    assert acc.parse_failures == 0


# ── the enumeration that started this ─────────────────────────────────────────

def _sweep(valid_users=("djohn", "john.doe"), total=12):
    """A pre-authentication sweep: `total` names tried, some of them real."""
    names = [f"probe{i:02d}" for i in range(total - len(valid_users))] + list(valid_users)
    packets = []
    for name in names:
        packets.append(as_req(name))
        packets.append(krb_error(krb.ERR_PREAUTH_REQUIRED if name in valid_users
                                 else krb.ERR_PRINCIPAL_UNKNOWN))
    return packets, names


def test_the_kdc_telling_an_attacker_an_account_exists_is_what_we_report():
    """KDC_ERR_PREAUTH_REQUIRED is only ever sent for a principal that exists.

    This is the whole detection. The capture it was built from probed 54 names
    and the KDC confirmed six; naming those six is the difference between a
    count and a lead.
    """
    packets, _ = _sweep(valid_users=("djohn", "john.doe", "ray"), total=15)
    events = _run(packets).finalize()

    enum = [e for e in events if e.event_type is EventType.KERBEROS_USER_ENUM]
    assert len(enum) == 1
    assert enum[0].severity is Severity.HIGH
    assert enum[0].evidence["valid_accounts"] == "djohn, john.doe, ray"
    assert enum[0].evidence["realm"] == REALM
    assert enum[0].evidence["rejected_unknown"] == 12
    assert enum[0].evidence["principals_probed"] == 15
    assert enum[0].evidence["mitre"] == krb.MITRE_USER_ENUM


def test_a_sweep_that_confirms_nothing_is_reported_but_ranked_lower():
    """Still an enumeration attempt, just one that came away empty-handed."""
    packets, _ = _sweep(valid_users=(), total=12)
    enum = [e for e in _run(packets).finalize()
            if e.event_type is EventType.KERBEROS_USER_ENUM]
    assert len(enum) == 1
    assert enum[0].severity is Severity.MEDIUM
    assert enum[0].evidence["valid_accounts"] == "none confirmed"
    assert enum[0].evidence["confirmed_by"] == "—"


def test_a_handful_of_normal_logons_is_not_called_an_enumeration():
    """A workstation authenticates constantly; it just does so as its own user."""
    packets = []
    for _ in range(20):
        packets.append(as_req("alice"))
        packets.append(krb_error(krb.ERR_PREAUTH_REQUIRED))
    assert _run(packets).finalize() == []


def test_many_names_with_no_rejections_is_not_an_enumeration_either():
    """Both halves of the rule matter.

    A busy jump host legitimately requests tickets for many principals. What it
    does not do is ask for accounts the directory has never heard of, so the
    unknown-principal count is required as well as the name count.
    """
    packets = []
    for i in range(20):
        packets.append(as_req(f"realuser{i}"))
        packets.append(krb_error(krb.ERR_PREAUTH_REQUIRED))
    assert [e for e in _run(packets).finalize()
            if e.event_type is EventType.KERBEROS_USER_ENUM] == []


def test_the_reported_realm_is_the_one_actually_targeted():
    """One stray probe at a mistyped realm should not retitle the finding.

    The source capture contained a single request to realm "NM" among sixty to
    DIRECTORY.THM. Joining the set made every finding read "DIRECTORY.THM, NM".
    """
    packets, _ = _sweep(total=12)
    packets.insert(0, as_req("stray", realm="NM"))
    enum = [e for e in _run(packets).finalize()
            if e.event_type is EventType.KERBEROS_USER_ENUM][0]
    assert enum.evidence["realm"] == REALM
    assert enum.evidence["other_realms_probed"] == "NM"


def test_a_client_with_no_realm_at_all_reports_unknown_rather_than_crashing():
    state = krb._ClientState()
    assert state.realm() == "unknown"
    assert state.other_realms() == []


# ── password spraying ─────────────────────────────────────────────────────────

def test_preauth_failures_across_many_accounts_are_password_spraying():
    """KDC_ERR_PREAUTH_FAILED means the account exists and the password was wrong.

    Spread thinly across many accounts it stays under per-account lockout,
    which is exactly why spraying is preferred to brute force.
    """
    packets = []
    for i in range(6):
        packets.append(as_req(f"user{i}"))
        packets.append(krb_error(krb.ERR_PREAUTH_FAILED))
    events = _run(packets).finalize()

    spray = [e for e in events if e.event_type is EventType.KERBEROS_BRUTE_FORCE]
    assert len(spray) == 1
    assert spray[0].severity is Severity.HIGH
    assert spray[0].evidence["distinct_accounts"] == 6
    assert spray[0].evidence["mitre"] == krb.MITRE_SPRAY


def test_a_few_wrong_passwords_are_not_called_spraying():
    packets = []
    for i in range(3):
        packets.append(as_req(f"user{i}"))
        packets.append(krb_error(krb.ERR_PREAUTH_FAILED))
    assert [e for e in _run(packets).finalize()
            if e.event_type is EventType.KERBEROS_BRUTE_FORCE] == []


def test_a_locked_out_account_still_counts_as_proof_the_account_exists():
    """KDC_ERR_CLIENT_REVOKED is only sent about a principal the KDC knows."""
    packets, _ = _sweep(valid_users=(), total=12)
    packets += [as_req("disabled.user"), krb_error(krb.ERR_CLIENT_REVOKED)]
    summary = _run(packets).summary()
    assert "disabled.user" in summary["valid_accounts"]
    assert summary["valid_accounts"]["disabled.user"] == "KDC_ERR_CLIENT_REVOKED"


def test_an_error_code_with_no_name_is_reported_by_number():
    packets, _ = _sweep(total=12)
    packets += [as_req("x"), krb_error(99)]
    assert "error 99" in _run(packets).summary()["kdc_errors"]


# ── roasting ──────────────────────────────────────────────────────────────────

def test_a_ticket_issued_without_preauth_is_as_rep_roastable():
    """The reply itself carries material crackable offline.

    This is the configuration "do not require Kerberos pre-authentication", and
    the KDC answering a bare AS-REQ with a ticket is the proof of it.
    """
    packets = [as_req("svc_legacy"), as_rep("svc_legacy")]
    events = _run(packets).finalize()

    roast = [e for e in events if e.event_type is EventType.KERBEROS_ROASTING]
    assert len(roast) == 1
    assert roast[0].severity is Severity.CRITICAL
    assert roast[0].evidence["accounts"] == "svc_legacy"
    assert roast[0].evidence["mitre"] == krb.MITRE_ASREPROAST


def test_the_same_roastable_account_is_not_listed_twice():
    packets = [as_req("svc_legacy"), as_rep("svc_legacy"),
               as_req("svc_legacy"), as_rep("svc_legacy")]
    roast = [e for e in _run(packets).finalize()
             if e.event_type is EventType.KERBEROS_ROASTING][0]
    assert roast.evidence["accounts"] == "svc_legacy"


def test_service_tickets_for_non_krbtgt_principals_are_kerberoasting():
    packets = [tgs_req(("MSSQLSvc", "db.directory.thm:1433")),
               tgs_req(("HTTP", "web.directory.thm"))]
    roast = [e for e in _run(packets).finalize()
             if e.event_type is EventType.KERBEROS_ROASTING]
    assert len(roast) == 1
    assert roast[0].severity is Severity.HIGH          # RC4-only above
    assert "MSSQLSvc/db.directory.thm:1433" in roast[0].evidence["service_principals"]
    assert roast[0].evidence["mitre"] == krb.MITRE_KERBEROAST


def test_a_ticket_for_krbtgt_is_ordinary_business_and_not_roasting():
    """Every logon asks for krbtgt. Flagging it would flag the whole domain."""
    packets = [tgs_req(("krbtgt", REALM)) for _ in range(5)]
    assert [e for e in _run(packets).finalize()
            if e.event_type is EventType.KERBEROS_ROASTING] == []


def test_service_tickets_that_allow_aes_are_ranked_below_rc4_only_ones():
    """Asking for a service ticket is normal; forcing weak crypto is the signal."""
    packets = [tgs_req(("HTTP", "web.directory.thm"), etypes=(18, 17))]
    roast = [e for e in _run(packets).finalize()
             if e.event_type is EventType.KERBEROS_ROASTING][0]
    assert roast.severity is Severity.MEDIUM
    assert roast.evidence["rc4_forced"] == "none"


# ── encryption downgrade ──────────────────────────────────────────────────────

def test_requesting_only_rc4_is_reported_as_a_downgrade():
    """Current Windows clients offer AES. Tooling asks for RC4 on purpose."""
    events = _run([as_req("u", etypes=(23,))]).finalize()
    anomaly = [e for e in events if e.event_type is EventType.KERBEROS_ANOMALY]
    assert len(anomaly) == 1
    assert anomaly[0].evidence["rc4_only_requests"] == 1
    assert anomaly[0].evidence["mitre"] == krb.MITRE_TICKETS


def test_offering_rc4_alongside_aes_is_normal_and_not_flagged():
    """Real domain members list several etypes; the KDC picks the strongest."""
    assert [e for e in _run([as_req("u", etypes=(18, 17, 23))]).finalize()
            if e.event_type is EventType.KERBEROS_ANOMALY] == []


# ── replies without a request ─────────────────────────────────────────────────

def test_a_reply_with_no_preceding_request_is_not_attributed_to_anybody():
    """Captures start mid-conversation; a dangling reply must not invent a user."""
    acc = _run([krb_error(krb.ERR_PREAUTH_REQUIRED)])
    assert acc.summary()["valid_accounts"] == {}


def test_a_reply_from_a_host_we_never_saw_a_request_to_is_ignored():
    acc = _run([as_req("alice"),
                krb_error(krb.ERR_PREAUTH_REQUIRED, src="10.9.9.9", dst=ATTACKER)])
    assert acc.summary()["valid_accounts"] == {}


def test_an_as_rep_without_a_bare_probe_before_it_is_not_called_roastable():
    """A reply to a request that did carry pre-authentication is a normal logon."""
    acc = krb.KerberosAccumulator()
    acc._absorb(krb.KerberosMessage(1.0, ATTACKER, KDC, krb.AS_REQ,
                                    cname="alice", realm=REALM, has_preauth=True))
    acc._absorb(krb.KerberosMessage(2.0, KDC, ATTACKER, krb.AS_REP, cname="alice"))
    assert acc.clients[(ATTACKER, KDC)].asrep_roastable == []
    assert acc.clients[(ATTACKER, KDC)].confirmed == {}


# ── the summary the copilot and the report read ───────────────────────────────

def test_the_summary_states_what_was_seen_even_when_no_detector_fires():
    """"The capture contains Kerberos and here is what it says" is itself an answer.

    The copilot could not answer questions about a real AD capture because no
    Kerberos evidence reached it at all. The summary is published whether or
    not a threshold was crossed, for exactly that reason.
    """
    acc = _run([as_req("alice"), krb_error(krb.ERR_PREAUTH_REQUIRED)])
    assert acc.finalize() == []

    s = acc.summary()
    assert s["messages"] == 2
    assert s["message_types"] == {"AS-REQ": 1, "KRB-ERROR": 1}
    assert s["realms"] == [REALM]
    assert s["usernames_seen"] == ["alice"]
    assert s["valid_accounts"] == {"alice": "KDC_ERR_PREAUTH_REQUIRED"}
    assert s["kdc_errors"] == {"KDC_ERR_PREAUTH_REQUIRED": 1}
    assert s["undecodable_messages"] == 0


def test_the_summary_lists_service_principals_and_undecodable_messages():
    acc = _run([tgs_req(("HTTP", "web.directory.thm"))])
    acc.parse_failures = 2
    s = acc.summary()
    assert s["service_principals"] == ["HTTP/web.directory.thm"]
    assert s["undecodable_messages"] == 2


# ── the whole picture, as it came off the real capture ────────────────────────

def test_a_full_sweep_produces_the_enumeration_and_the_downgrade_together():
    """Shape-check against the capture this module was written from.

    There, one source probed 54 principals with RC4-only requests mixed in, and
    the tool is expected to report both the enumeration and the downgrade from
    the same client rather than collapsing them into one finding.
    """
    packets, _ = _sweep(valid_users=("djohn", "john.doe"), total=14)
    packets.append(as_req("legacy", etypes=(23,)))
    types = {e.event_type for e in _run(packets).finalize()}
    assert types == {EventType.KERBEROS_USER_ENUM, EventType.KERBEROS_ANOMALY}


def test_each_finding_carries_the_kdc_endpoint_it_came_from():
    """A responder needs to know which DC to pull logs from."""
    packets, _ = _sweep(total=12)
    for event in _run(packets).finalize():
        assert event.src_ip == ATTACKER
        assert event.dst_ip == KDC
        assert event.dst_port == 88
        assert event.protocol == "KERBEROS"


# ── reaching the analyst: the CLI section and the copilot context ─────────────
#
# The detector finding the accounts is only half of it. On the capture this was
# built from the findings table truncated the description, so "six accounts were
# confirmed" was printed while their names were not, and the copilot's context
# never mentioned Kerberos at all. Both surfaces are therefore asserted on.

def _kerberos_pcap(path):
    """Write a small but genuine Kerberos capture: a sweep that finds one account."""
    from scapy.utils import wrpcap
    packets, _ = _sweep(valid_users=("john.doe",), total=12)
    wrpcap(str(path), packets)
    return str(path)


def test_the_cli_prints_the_accounts_the_kdc_confirmed(tmp_path):
    """The names are the answer; a truncated description is not.

    This is an end-to-end run over a written capture, so it covers the parser,
    the engine pass, the detector and the rendering together.
    """
    from click.testing import CliRunner

    from packetiq.cli import main

    pcap = _kerberos_pcap(tmp_path / "kerberos_sweep.pcap")
    result = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert result.exit_code == 0, result.output
    assert "DIRECTORY SERVICES" in result.output
    assert "john.doe" in result.output
    assert "KDC_ERR_PREAUTH_REQUIRED" in result.output
    assert REALM in result.output
    # The full wordlist is what tells a responder which accounts were guessed at
    # but not found, so it has to survive to the screen too.
    assert "probe00" in result.output


def test_the_cli_abbreviates_the_wordlist_unless_full_is_asked_for(tmp_path):
    """A 54-name list is useful in a report and noise in a summary.

    Asserted on which names appear rather than on the wording of the "+N more"
    note, because the terminal renderer rewraps that line at the window width
    and a test pinned to the sentence breaks on a layout change.
    """
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main
    packets, _ = _sweep(valid_users=("john.doe",), total=30)
    pcap = str(tmp_path / "big_sweep.pcap")
    wrpcap(pcap, packets)

    brief = CliRunner().invoke(main, ["analyze", pcap])
    full = CliRunner().invoke(main, ["analyze", pcap, "--full"])
    assert brief.exit_code == 0, brief.output
    assert full.exit_code == 0, full.output

    # Sorted, the list runs john.doe, probe00 … probe28; the summary shows 20.
    assert "probe00" in brief.output
    assert "probe25" not in brief.output
    assert "probe25" in full.output


def test_the_cli_reports_service_principals_and_undecodable_messages(tmp_path, monkeypatch):
    """Both lines exist to stop a silent omission looking like a clean result."""
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main
    pcap = str(tmp_path / "tgs.pcap")
    wrpcap(pcap, [tgs_req(("MSSQLSvc", "db.directory.thm:1433"))])

    real_summary = krb.KerberosAccumulator.summary

    def with_a_fragment(self):
        self.parse_failures = self.parse_failures or 1
        return real_summary(self)

    monkeypatch.setattr(krb.KerberosAccumulator, "summary", with_a_fragment)
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "MSSQLSvc/db.directory.thm:1433" in out.output
    assert "could not be decoded" in out.output


def test_the_cli_prints_the_asrep_hash_and_the_crack_it_offline_warning(tmp_path, monkeypatch):
    """The crackable hash reaches the screen, with the account that owns it.

    It comes from an AS-REP, which scapy reads from a real capture but cannot
    rebuild into a pcap of its own, so the summary is given a hash directly
    rather than through a round-trip."""
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main
    pcap = str(tmp_path / "enum.pcap")
    packets, _ = _sweep(valid_users=("larry.doe",), total=12)
    wrpcap(pcap, packets)

    real_summary = krb.KerberosAccumulator.summary

    def with_a_hash(self):
        s = real_summary(self)
        s["asrep_hashes"] = {
            "larry.doe": "$krb5asrep$23$larry.doe@DIRECTORY.THM:" + "ab" * 16 + "$" + "cd" * 40
        }
        return s

    monkeypatch.setattr(krb.KerberosAccumulator, "summary", with_a_hash)
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "AS-REP roastable credential material" in out.output
    assert "$krb5asrep$23$larry.doe@" in out.output
    assert "cracking it offline" in out.output


def test_a_capture_without_kerberos_prints_no_directory_section(tmp_path):
    """Silence is the right output when the protocol is simply not there."""
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "plain.pcap")
    wrpcap(pcap, [IP(src=ATTACKER, dst=KDC) / TCP(dport=443) for _ in range(4)])
    out = CliRunner().invoke(main, ["analyze", pcap])

    assert out.exit_code == 0, out.output
    assert "DIRECTORY SERVICES" not in out.output


def test_the_copilot_context_states_which_accounts_exist_and_how_we_know():
    """The missing half of the original failure.

    The model was asked which accounts the attacker found and could not say,
    because its context contained no Kerberos. It now receives the accounts
    together with the KDC reply that proves each one, so an answer can cite its
    evidence instead of asserting a name.
    """
    from packetiq.copilot.context_builder import _directory_services
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run(_sweep(valid_users=("djohn", "john.doe"), total=14)[0])
    result = ExtractionResult()
    result.kerberos = acc.summary()

    text = _directory_services(result)

    assert "ACTIVE DIRECTORY / KERBEROS" in text
    assert "ACCOUNTS CONFIRMED TO EXIST (2)" in text
    assert "djohn" in text and "john.doe" in text
    assert "proved by KDC_ERR_PREAUTH_REQUIRED" in text
    assert REALM in text
    assert "AS-REQ x14" in text
    assert "Principals probed : 14 distinct" in text


def test_the_context_section_is_absent_when_the_capture_had_no_kerberos():
    """An empty heading would imply the question was asked and came back empty."""
    from packetiq.copilot.context_builder import _directory_services
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _directory_services(ExtractionResult()) == ""


def test_the_context_truncates_a_long_wordlist_but_says_how_many_it_dropped():
    """A 500-name spray must not crowd out the rest of the model's context."""
    from packetiq.copilot.context_builder import _directory_services
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run(_sweep(valid_users=(), total=60)[0])
    result = ExtractionResult()
    result.kerberos = acc.summary()

    text = _directory_services(result)
    assert "… and 20 more" in text


def test_the_context_reports_service_principals_and_undecodable_messages():
    from packetiq.copilot.context_builder import _directory_services
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run([tgs_req(("HTTP", "web.directory.thm"))])
    acc.parse_failures = 3
    result = ExtractionResult()
    result.kerberos = acc.summary()

    text = _directory_services(result)
    assert "HTTP/web.directory.thm" in text
    assert "3 message(s)" in text


# ── AS-REP roasting: the crackable hash that is the point of the attack ───────

def test_an_rc4_asrep_hash_is_formatted_for_hashcat():
    """The RC4 form is hashcat -m 18200: $krb5asrep$23$user@REALM:<check>$<rest>."""
    cipher = bytes(range(32))  # 16-byte checksum + 16-byte edata
    h = krb.format_asrep_hash("larry.doe", "directory.thm", 23, cipher)
    assert h.startswith("$krb5asrep$23$larry.doe@DIRECTORY.THM:")
    assert h == ("$krb5asrep$23$larry.doe@DIRECTORY.THM:"
                 + cipher[:16].hex() + "$" + cipher[16:].hex())


def test_an_aes_asrep_hash_puts_the_hmac_last():
    """AES (17/18) form: the trailing 12 bytes are the HMAC, split off."""
    cipher = bytes(range(40))
    h = krb.format_asrep_hash("svc", "corp.thm", 18, cipher)
    assert h == ("$krb5asrep$18$svc@CORP.THM$" + cipher[:-12].hex()
                 + "$" + cipher[-12:].hex())


def test_a_hash_is_not_produced_from_an_empty_or_unknown_cipher():
    assert krb.format_asrep_hash("u", "R", 23, b"") == ""
    assert krb.format_asrep_hash("", "R", 23, b"x" * 32) == ""
    assert krb.format_asrep_hash("u", "", 23, b"x" * 32) == ""
    # etype 1 (DES) is not a form the crackers read; no hash rather than a wrong one
    assert krb.format_asrep_hash("u", "R", 1, b"x" * 32) == ""


def _as_rep_with_cipher(user, realm, etype, cipher):
    """A real AS-REP carrying an encrypted part, built with scapy."""
    from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING
    from scapy.layers.kerberos import KRB_AS_REP, EncryptedData
    enc = EncryptedData(etype=ASN1_INTEGER(etype), cipher=ASN1_STRING(cipher))
    rep = KRB_AS_REP(crealm=ASN1_GENERAL_STRING(realm), cname=_principal(user), encPart=enc)
    return _wire_live(IP(src=KDC, dst=ATTACKER) / UDP(sport=88, dport=45000)
                      / Kerberos(root=rep))


def test_the_hash_is_pulled_from_a_real_as_rep_encrypted_part():
    from scapy.layers.kerberos import Kerberos
    cipher = bytes(range(32))
    pkt = _as_rep_with_cipher("victim", "CORP.THM", 23, cipher)
    root = pkt[Kerberos].root
    h = krb._asrep_hash_from_reply(root)
    assert h.startswith("$krb5asrep$23$victim@CORP.THM:")


def test_an_as_rep_with_no_encrypted_part_yields_no_hash():
    from scapy.layers.kerberos import KRB_AS_REP
    rep = KRB_AS_REP(crealm=ASN1_GENERAL_STRING("CORP.THM"), cname=_principal("v"))
    assert krb._asrep_hash_from_reply(rep) == ""


def test_a_roastable_account_carries_its_hash_into_the_finding_and_summary():
    """End to end: a bare AS-REQ answered by an AS-REP with crackable material."""
    from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING
    from scapy.layers.kerberos import KRB_AS_REP, EncryptedData

    cipher = bytes((i * 7) % 256 for i in range(48))
    enc = EncryptedData(etype=ASN1_INTEGER(23), cipher=ASN1_STRING(cipher))
    rep = KRB_AS_REP(crealm=ASN1_GENERAL_STRING(REALM), cname=_principal("svc_legacy"),
                     encPart=enc)
    packets = [as_req("svc_legacy"),
               _wire_live(IP(src=KDC, dst=ATTACKER) / UDP(sport=88, dport=45000)
                          / Kerberos(root=rep))]
    acc = _run(packets)

    roast = [e for e in acc.finalize() if e.event_type is EventType.KERBEROS_ROASTING][0]
    expected = "$krb5asrep$23$svc_legacy@" + REALM + ":" + cipher[:16].hex() + "$" + cipher[16:].hex()
    assert expected in roast.evidence["crackable_hashes"]
    assert acc.summary()["asrep_hashes"] == {"svc_legacy": expected}


def test_the_finding_says_the_password_comes_from_an_offline_crack():
    """The tool must not imply it recovered the password, only the hash."""
    from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING
    from scapy.layers.kerberos import KRB_AS_REP, EncryptedData

    enc = EncryptedData(etype=ASN1_INTEGER(23), cipher=ASN1_STRING(bytes(range(32))))
    rep = KRB_AS_REP(crealm=ASN1_GENERAL_STRING(REALM), cname=_principal("svc"), encPart=enc)
    acc = _run([as_req("svc"),
                _wire_live(IP(src=KDC, dst=ATTACKER) / UDP(sport=88, dport=45000)
                           / Kerberos(root=rep))])
    roast = [e for e in acc.finalize() if e.event_type is EventType.KERBEROS_ROASTING][0]
    assert "offline crack this tool does not perform" in roast.evidence["note"]


def test_two_as_reps_for_one_account_do_not_invent_a_second_account():
    """A roasting tool collects both an AES and an RC4 reply for the same user.

    The reply names its own account in cname, so both belong to that account;
    attributing each to whatever username happened to precede it on the wire
    would fabricate a roastable account that never existed. The RC4 hash, being
    the one a cracker uses, is the one kept.
    """
    from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING
    from scapy.layers.kerberos import KRB_AS_REP, EncryptedData

    def rep(etype, cipher):
        enc = EncryptedData(etype=ASN1_INTEGER(etype), cipher=ASN1_STRING(cipher))
        r = KRB_AS_REP(crealm=ASN1_GENERAL_STRING(REALM), cname=_principal("larry.doe"),
                       encPart=enc)
        return _wire_live(IP(src=KDC, dst=ATTACKER) / UDP(sport=88, dport=45000)
                          / Kerberos(root=r))

    # Two different usernames probed, two AS-REPs that both actually name larry.doe.
    packets = [as_req("someone.else"), rep(18, bytes(range(40))),
               as_req("larry.doe"), rep(23, bytes(range(32)))]
    acc = _run(packets)

    assert sorted(acc.summary()["asrep_hashes"]) == ["larry.doe"]
    assert acc.summary()["asrep_hashes"]["larry.doe"].startswith("$krb5asrep$23$")


def test_an_as_rep_whose_cipher_is_not_readable_bytes_yields_no_hash():
    """A malformed encrypted part must not raise, and must not guess a hash."""
    class Enc:
        etype = None
        cipher = None

    class Rep:
        encPart = Enc()
        cname = None
        crealm = None

    assert krb._asrep_hash_from_reply(Rep()) == ""


def test_the_copilot_context_carries_the_crackable_hash_and_forbids_a_guessed_password():
    """Q3/Q4 of a directory-forensics capture: the model is handed the hash and
    told in the same breath that the password is not in the packets."""
    from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING
    from scapy.layers.kerberos import KRB_AS_REP, EncryptedData

    from packetiq.copilot.context_builder import _directory_services
    from packetiq.extractor.data_extractor import ExtractionResult

    enc = EncryptedData(etype=ASN1_INTEGER(23), cipher=ASN1_STRING(bytes(range(40))))
    rep = KRB_AS_REP(crealm=ASN1_GENERAL_STRING(REALM), cname=_principal("larry.doe"),
                     encPart=enc)
    acc = _run([as_req("larry.doe"),
                _wire_live(IP(src=KDC, dst=ATTACKER) / UDP(sport=88, dport=45000)
                           / Kerberos(root=rep))])
    result = ExtractionResult()
    result.kerberos = acc.summary()

    text = _directory_services(result)
    assert "AS-REP ROASTABLE CREDENTIAL MATERIAL" in text
    assert "$krb5asrep$23$larry.doe@" in text
    assert "hashcat -m 18200" in text
    assert "password is NOT in this capture" in text


# ── per-host account attribution (summary["by_host"]) ─────────────────────────

def test_summary_attributes_each_host_its_own_machine_and_user_accounts():
    """`by_host` lets the asset synthesis tell a host's machine account and its
    logged-in user apart from everything else the capture saw. An AS-REQ is sent BY
    the client, so the request's source owns the identity; a client that only asked
    for a service ticket (no cname) contributes no identity and is absent."""
    acc = _run([
        as_req("DESKTOP-5OMVI3L$", src="10.11.10.147", dst="10.11.10.10"),
        as_req("edward.winslow", src="10.11.10.147", dst="10.11.10.10"),
        tgs_req(["HTTP", "dc.thm"], src="10.11.10.50", dst="10.11.10.10"),
    ])
    by_host = acc.summary()["by_host"]
    assert by_host["10.11.10.147"]["machine_accounts"] == ["DESKTOP-5OMVI3L$"]
    assert by_host["10.11.10.147"]["user_accounts"] == ["edward.winslow"]
    assert set(by_host["10.11.10.147"]["all"]) == {"DESKTOP-5OMVI3L$", "edward.winslow"}
    assert "10.11.10.50" not in by_host
