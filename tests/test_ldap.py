"""
Tests for LDAP detection.

Every request here is a real LDAP message built with scapy's own layer and
round-tripped through bytes, so the decode path under test is the one a capture
takes. The searches are the ones that actually appear in directory
reconnaissance: RootDSE discovery, a hunt for kerberoastable accounts, and a
hunt for accounts with pre-authentication disabled.
"""

from scapy.asn1.asn1 import ASN1_INTEGER, ASN1_STRING
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.ldap import (
    LDAP,
    LDAP_Authentication_simple,
    LDAP_BindRequest,
    LDAP_Filter,
    LDAP_FilterAnd,
    LDAP_FilterEqual,
    LDAP_FilterGreaterOrEqual,
    LDAP_FilterLessOrEqual,
    LDAP_FilterNot,
    LDAP_FilterOr,
    LDAP_FilterPresent,
    LDAP_SearchRequest,
)

from packetiq.detection import ldap as mod
from packetiq.detection.models import EventType, Severity

ATTACKER = "10.0.2.74"
DC = "10.0.2.75"


# ── building real messages ────────────────────────────────────────────────────

def present(attribute):
    return LDAP_Filter(filter=LDAP_FilterPresent(present=ASN1_STRING(attribute.encode())))


def equal(attribute, value):
    return LDAP_Filter(filter=LDAP_FilterEqual(
        attributeType=ASN1_STRING(attribute.encode()),
        attributeValue=ASN1_STRING(value.encode())))


def conjunction(*filters):
    return LDAP_Filter(filter=LDAP_FilterAnd(vals=list(filters)))


def _wire(pkt, port=389, src=ATTACKER, dst=DC, ts=0.0):
    out = IP(bytes(IP(src=src, dst=dst) / TCP(sport=45000, dport=port, flags="PA") / pkt))
    out.time = ts
    return out


def search(base="", filt=None, attributes=(), port=389, ts=0.0, src=ATTACKER, dst=DC):
    request = LDAP_SearchRequest(
        baseObject=ASN1_STRING(base.encode()),
        filter=filt if filt is not None else present("objectClass"),
        attributes=[ASN1_STRING(a.encode()) for a in attributes],
    )
    return _wire(LDAP(protocolOp=request), port=port, src=src, dst=dst, ts=ts)


def bind(name="CN=svc,DC=directory,DC=thm", password="hunter2", port=389, ts=0.0):
    request = LDAP_BindRequest(
        version=ASN1_INTEGER(3),
        bind_name=ASN1_STRING(name.encode()),
        authentication=LDAP_Authentication_simple(password.encode()),
    )
    return _wire(LDAP(protocolOp=request), port=port, ts=ts)


def _run(packets):
    acc = mod.LDAPAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc


# ── filter rendering ──────────────────────────────────────────────────────────

def test_a_filter_is_rendered_back_into_the_form_an_operator_typed():
    """Reported as written because that is how it is recognised.

    A responder who reads `(&(objectClass=user)(servicePrincipalName=*))` knows
    at once it was a hunt for kerberoastable accounts. "LDAP_FilterAnd with two
    children" tells them nothing.
    """
    rendered = mod.render_filter(conjunction(
        equal("objectClass", "user"), present("servicePrincipalName")))
    assert rendered == "(&(objectClass=user)(servicePrincipalName=*))"


def test_every_filter_form_this_module_meets_is_rendered():
    assert mod.render_filter(present("objectClass")) == "(objectClass=*)"
    assert mod.render_filter(equal("cn", "admin")) == "(cn=admin)"
    assert mod.render_filter(LDAP_Filter(filter=LDAP_FilterOr(vals=[
        equal("cn", "a"), equal("cn", "b")]))) == "(|(cn=a)(cn=b))"
    assert mod.render_filter(LDAP_Filter(filter=LDAP_FilterNot(
        val=equal("cn", "a")))) == "(!(cn=a))"
    assert mod.render_filter(LDAP_Filter(filter=LDAP_FilterGreaterOrEqual(
        attributeType=ASN1_STRING(b"badPwdCount"),
        attributeValue=ASN1_STRING(b"3")))) == "(badPwdCount>=3)"
    assert mod.render_filter(LDAP_Filter(filter=LDAP_FilterLessOrEqual(
        attributeType=ASN1_STRING(b"lastLogon"),
        attributeValue=ASN1_STRING(b"0")))) == "(lastLogon<=0)"


def test_an_unrecognised_filter_type_is_named_rather_than_dropped():
    class Extensibleish:
        pass

    assert mod.render_filter(Extensibleish()) == "(Extensibleish)"


def test_a_deeply_nested_filter_does_not_render_forever():
    """A filter is attacker-supplied input; nesting it is a cheap denial of service."""
    node = equal("cn", "a")
    for _ in range(40):
        node = LDAP_Filter(filter=LDAP_FilterNot(val=node))
    rendered = mod.render_filter(node)
    assert rendered.count("(") < 20


def test_an_absent_filter_renders_as_nothing():
    assert mod.render_filter(None) == ""


def test_asn1_values_are_unwrapped_to_their_value_not_their_repr():
    assert mod._text(ASN1_STRING(b"DC=directory,DC=thm")) == "DC=directory,DC=thm"
    assert mod._text(b"plain") == "plain"
    assert mod._text("already") == "already"
    assert mod._text(None) == ""


# ── intake ────────────────────────────────────────────────────────────────────

def test_non_ldap_traffic_is_ignored():
    acc = _run([IP(src=ATTACKER, dst=DC) / TCP(dport=443),
                IP(src=ATTACKER, dst=DC) / UDP(dport=53)])
    assert acc.operations == []
    assert acc.summary() == {}


def test_a_response_is_attributed_to_the_same_conversation_as_its_request():
    """Otherwise one client's session becomes two half-sessions."""
    outbound = search(ts=1.0)
    inbound = search(ts=2.0, src=DC, dst=ATTACKER, port=389)
    inbound[TCP].sport, inbound[TCP].dport = 389, 45000
    inbound = IP(bytes(inbound))
    acc = _run([outbound, inbound])
    assert len(acc.clients) == 1


def test_ldap_over_ipv6_is_read_the_same_as_over_ipv4():
    request = LDAP_SearchRequest(baseObject=ASN1_STRING(b""), filter=present("objectClass"),
                                 attributes=[])
    pkt = IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=5, dport=389, flags="PA") \
        / LDAP(protocolOp=request)
    assert len(_run([IPv6(bytes(pkt))]).operations) == 1


def test_an_ldap_message_on_a_port_we_do_not_watch_is_skipped():
    assert _run([search(port=1389)]).operations == []


def test_the_global_catalog_port_is_watched_too():
    assert len(_run([search(port=3268)]).operations) == 1


# ── enumeration ───────────────────────────────────────────────────────────────

def test_rootdse_discovery_is_recognised_for_what_it_is():
    """An empty base with (objectClass=*) is the query you run knowing nothing.

    It is how directory enumeration starts, because it returns the naming
    contexts every later search needs.
    """
    events = _run([search(ts=1.0), search(ts=2.0)]).finalize()
    enum = [e for e in events if e.event_type is EventType.LDAP_ENUMERATION]
    assert len(enum) == 1
    assert enum[0].evidence["rootdse_queries"] == 2
    assert enum[0].evidence["filters"] == "(objectClass=*)"
    assert "RootDSE discovery" in enum[0].description


def test_a_hunt_for_kerberoastable_accounts_is_ranked_higher():
    """servicePrincipalName in the filter says what the search was for."""
    packets = [
        search(base="DC=directory,DC=thm",
               filt=conjunction(equal("objectClass", "user"),
                                present("servicePrincipalName")),
               attributes=("samAccountName", "servicePrincipalName"), ts=1.0),
        search(base="DC=directory,DC=thm", ts=2.0),
    ]
    enum = [e for e in _run(packets).finalize()
            if e.event_type is EventType.LDAP_ENUMERATION][0]
    assert enum.severity is Severity.HIGH
    assert "serviceprincipalname" in enum.evidence["notable"]
    assert "kerberoastable" in enum.evidence["notable"]


def test_a_hunt_for_accounts_with_preauth_disabled_is_named_too():
    packets = [search(filt=present("userAccountControl"), ts=float(i)) for i in range(2)]
    enum = [e for e in _run(packets).finalize()
            if e.event_type is EventType.LDAP_ENUMERATION][0]
    assert "useraccountcontrol" in enum.evidence["notable"]


def test_a_single_search_is_not_called_enumeration():
    """An application that binds and reads one object is doing its job."""
    assert _run([search()]).finalize() == []


def test_the_base_object_is_reported_when_the_search_names_one():
    packets = [search(base="CN=Users,DC=directory,DC=thm", ts=float(i)) for i in range(2)]
    enum = [e for e in _run(packets).finalize()
            if e.event_type is EventType.LDAP_ENUMERATION][0]
    assert enum.evidence["base_objects"] == "CN=Users,DC=directory,DC=thm"


def test_a_session_that_upgraded_to_starttls_is_not_called_cleartext():
    from scapy.layers.ldap import LDAP_ExtendedResponse

    starttls = _wire(LDAP(protocolOp=LDAP_ExtendedResponse(
        responseName=ASN1_STRING(mod.STARTTLS_OID.encode()))), ts=0.5)
    acc = _run([starttls, search(ts=1.0), search(ts=2.0)])
    enum = [e for e in acc.finalize() if e.event_type is EventType.LDAP_ENUMERATION][0]
    assert enum.evidence["transport"] == "upgraded to TLS by StartTLS mid-session"
    assert acc.summary()["starttls"] is True


def test_ldaps_is_not_watched_because_there_is_nothing_readable_there():
    """636 is TLS from the first byte, so no finding can honestly be made.

    An earlier version of this module treated 636 as "LDAP, but encrypted" and
    had a branch for it. That branch was unreachable: the traffic never
    produces an LDAP layer to begin with. A capture of LDAPS shows that a
    connection happened and nothing whatever about what was asked.
    """
    assert 636 not in mod.LDAP_PORTS
    assert _run([search(port=636, ts=float(i)) for i in range(2)]).operations == []


def test_an_extended_operation_we_do_not_model_is_ignored_quietly():
    from scapy.layers.ldap import LDAP_ExtendedResponse

    other = _wire(LDAP(protocolOp=LDAP_ExtendedResponse(
        responseName=ASN1_STRING(b"1.2.3.4.5"))))
    assert _run([other]).operations == []


# ── cleartext binds ───────────────────────────────────────────────────────────

def test_a_simple_bind_on_a_cleartext_port_is_a_credential_disclosure():
    """A simple bind sends the password as bytes. There is no risk of exposure here, only exposure."""
    events = _run([bind()]).finalize()
    cred = [e for e in events if e.event_type is EventType.CREDENTIAL_EXPOSURE]
    assert len(cred) == 1
    assert cred[0].severity is Severity.CRITICAL
    assert cred[0].evidence["bind_dns"] == "CN=svc,DC=directory,DC=thm"
    assert cred[0].protocol == "LDAP"


def test_the_password_itself_is_never_reproduced_in_the_finding():
    """Reporting the disclosure must not repeat it into the report and the logs."""
    cred = [e for e in _run([bind(password="hunter2")]).finalize()
            if e.event_type is EventType.CREDENTIAL_EXPOSURE][0]
    assert "hunter2" not in str(cred.evidence)
    assert "hunter2" not in cred.description


def test_a_bind_on_the_ldaps_port_produces_no_finding_at_all():
    """Not "encrypted, so fine" but "unreadable, so nothing is claimed"."""
    acc = _run([bind(port=636)])
    assert acc.operations == []
    assert acc.finalize() == []


def test_a_bind_after_starttls_is_not_reported_as_exposed():
    from scapy.layers.ldap import LDAP_ExtendedResponse

    starttls = _wire(LDAP(protocolOp=LDAP_ExtendedResponse(
        responseName=ASN1_STRING(mod.STARTTLS_OID.encode()))), ts=0.5)
    assert [e for e in _run([starttls, bind(ts=1.0)]).finalize()
            if e.event_type is EventType.CREDENTIAL_EXPOSURE] == []


def test_an_anonymous_bind_is_recorded_but_is_not_a_credential_disclosure():
    """There is no password in an anonymous bind, so there is nothing exposed."""
    acc = _run([bind(name="", password="")])
    assert [e for e in acc.finalize()
            if e.event_type is EventType.CREDENTIAL_EXPOSURE] == []
    assert acc.clients[(ATTACKER, DC)].anonymous_binds == 1


def test_a_sasl_bind_is_recorded_by_its_mechanism_and_not_as_cleartext():
    from scapy.layers.ldap import LDAP_Authentication_SaslCredentials

    request = LDAP_BindRequest(
        version=ASN1_INTEGER(3), bind_name=ASN1_STRING(b""),
        authentication=LDAP_Authentication_SaslCredentials(
            mechanism=ASN1_STRING(b"GSSAPI")))
    acc = _run([_wire(LDAP(protocolOp=request))])
    assert [e for e in acc.finalize()
            if e.event_type is EventType.CREDENTIAL_EXPOSURE] == []
    assert acc.operations[0].bind_method == "SaslCredentials"


# ── the summary the copilot and the report read ───────────────────────────────

def test_the_summary_states_what_was_asked_of_the_directory():
    packets = [
        search(filt=conjunction(equal("objectClass", "user"),
                                present("servicePrincipalName")),
               attributes=("samAccountName",), base="DC=directory,DC=thm", ts=1.0),
        search(ts=2.0),
        bind(ts=3.0),
    ]
    s = _run(packets).summary()

    assert s["operations"] == 3
    assert s["searches"] == 2
    assert s["rootdse_searches"] == 1
    assert s["clients"] == [ATTACKER]
    assert s["servers"] == [DC]
    assert "(&(objectClass=user)(servicePrincipalName=*))" in s["filters"]
    assert "samAccountName" in s["attributes_requested"]
    assert "serviceprincipalname" in s["notable_attributes"]
    assert s["binds"] == ["CN=svc,DC=directory,DC=thm [simple]"]


def test_the_summary_is_empty_when_the_capture_has_no_ldap():
    assert mod.LDAPAccumulator().summary() == {}


# ── reaching the analyst ──────────────────────────────────────────────────────

def test_the_cli_prints_the_filters_as_written(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "ldap.pcap")
    wrpcap(pcap, [
        search(filt=conjunction(equal("objectClass", "user"),
                                present("servicePrincipalName")), ts=1.0),
        search(ts=2.0),
    ])
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "DIRECTORY READS" in out.output
    assert "servicePrincipalName" in out.output
    assert "RootDSE" in out.output


def test_a_capture_without_ldap_prints_no_directory_section(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "plain.pcap")
    wrpcap(pcap, [IP(src=ATTACKER, dst=DC) / TCP(dport=443) for _ in range(4)])
    out = CliRunner().invoke(main, ["analyze", pcap])

    assert out.exit_code == 0, out.output
    assert "DIRECTORY READS" not in out.output


def test_the_cli_prints_the_binds_it_saw(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "bind.pcap")
    wrpcap(pcap, [bind(ts=1.0), search(ts=2.0), search(ts=3.0)])
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "CN=svc,DC=directory,DC=thm" in out.output


def test_the_copilot_context_carries_the_filters_and_the_notable_attributes():
    from packetiq.copilot.context_builder import _directory_reads
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run([
        search(filt=conjunction(equal("objectClass", "user"),
                                present("servicePrincipalName")),
               attributes=("samAccountName",), base="DC=directory,DC=thm", ts=1.0),
        search(ts=2.0),
        bind(ts=3.0),
    ])
    result = ExtractionResult()
    result.ldap = acc.summary()

    text = _directory_reads(result)
    assert "DIRECTORY READS (LDAP)" in text
    assert "(&(objectClass=user)(servicePrincipalName=*))" in text
    assert "RootDSE queries" in text
    assert "base    DC=directory,DC=thm" in text
    assert "NOTE: serviceprincipalname" in text
    assert "samAccountName" in text
    assert "CN=svc,DC=directory,DC=thm [simple]" in text
    assert "StartTLS       : not observed" in text


def test_the_context_section_is_absent_when_there_was_no_ldap():
    from packetiq.copilot.context_builder import _directory_reads
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _directory_reads(ExtractionResult()) == ""


# ── the paths that exist so one odd packet does not end the pass ─────────────

def test_cldap_over_udp_does_not_reach_this_module_at_all():
    """scapy binds LDAP over TCP only, so connectionless LDAP never arrives.

    Worth asserting rather than assuming: the module has no "LDAP on an
    unexpected transport" guard precisely because this is true, and if a future
    scapy starts parsing CLDAP the guard will be needed again.
    """
    request = LDAP_SearchRequest(baseObject=ASN1_STRING(b""),
                                 filter=present("objectClass"), attributes=[])
    pkt = IP(bytes(IP(src=ATTACKER, dst=DC) / UDP(sport=45000, dport=389)
                   / LDAP(protocolOp=request)))
    assert not pkt.haslayer(LDAP)
    assert _run([pkt]).operations == []


def test_an_ldap_message_with_no_ip_layer_is_skipped_not_crashed():
    request = LDAP_SearchRequest(baseObject=ASN1_STRING(b""),
                                 filter=present("objectClass"), attributes=[])
    bare = TCP(sport=45000, dport=389, flags="PA") / LDAP(protocolOp=request)
    assert _run([TCP(bytes(bare))]).operations == []


def test_a_message_that_cannot_be_decoded_ends_that_packet_and_not_the_pass(monkeypatch):
    acc = mod.LDAPAccumulator()

    def truncated(*_args, **_kwargs):
        raise ValueError("ASN.1 runs past the end of this segment")

    monkeypatch.setattr(acc, "_decode", truncated)
    acc.feed(search())
    assert acc.operations == []

    # The next packet still lands: one bad message must not stop the capture.
    monkeypatch.undo()
    acc.feed(search())
    assert len(acc.operations) == 1


def test_an_ldap_operation_this_module_does_not_model_is_ignored_quietly():
    """A search *response* is half of every session and has nothing to detect.

    The real capture is full of them. Recording them as operations would double
    every count the summary reports.
    """
    from scapy.layers.ldap import LDAP_SearchResponseEntry

    entry = LDAP_SearchResponseEntry(objectName=ASN1_STRING(b"CN=x,DC=thm"), attributes=[])
    acc = _run([_wire(LDAP(protocolOp=entry))])
    assert acc.operations == []
    assert acc.finalize() == []


def test_endpoint_extraction_gives_up_quietly_on_a_packet_it_cannot_read():
    class Hostile:
        def haslayer(self, _layer):
            raise ValueError("not a packet")

    assert mod._endpoints(Hostile()) == (None, None)
    # The port falls back to 389 rather than to None: a packet that produced an
    # LDAP layer is on an LDAP port, and a finding that says "port unknown"
    # helps nobody.
    assert mod._server_port(Hostile()) == 389
