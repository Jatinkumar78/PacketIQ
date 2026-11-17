"""
Tests for DCERPC detection.

Binds are built with scapy's own DceRpc5 layer, naming real Windows interface
UUIDs, and round-tripped through bytes so the decode path under test is the one
a capture takes. A bind acknowledgement is fed live, because scapy serialises
one but does not re-dissect its own output; the bind and the bind-nak, which
carry the signal, do round-trip.

The scenarios are the RPC calls that matter in an intrusion: svcctl (the engine
inside PsExec), atsvc (remote scheduled task), drsuapi (DCSync, replicating
password hashes out of the domain), and the endpoint-mapper probing that comes
before any of them.
"""

import uuid

from scapy.layers.dcerpc import (
    DceRpc5,
    DceRpc5AbstractSyntax,
    DceRpc5BindAck,
    DceRpc5BindNak,
    DceRpc5Context,
    DceRpc5Request,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from packetiq.detection import dcerpc as mod
from packetiq.detection.models import EventType, Severity

CLIENT = "10.0.2.74"
SERVER = "10.0.2.75"

SVCCTL = "367abb81-9844-35f1-ad32-98f038001003"
ATSVC = "1ff70682-0a51-30e8-076d-740be8cee98b"
DRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
SAMR = "12345778-1234-abcd-ef00-0123456789ac"
EPMAPPER = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"


# ── building real PDUs ────────────────────────────────────────────────────────

def _wire(pdu, *, src=CLIENT, dst=SERVER, sport=50000, dport=135, ts=0.0):
    pkt = IP(bytes(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / pdu))
    pkt.time = ts
    return pkt


def _wire_live(pdu, *, src=SERVER, dst=CLIENT, sport=135, dport=50000, ts=0.0):
    """A packet fed without a bytes round-trip, for a bind ack scapy will not rebuild."""
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / pdu
    pkt.time = ts
    return pkt


def bind(interface_uuid, *, version=1, ts=0.0, dport=135, src=CLIENT, dst=SERVER):
    ctx = DceRpc5Context(abstract_syntax=DceRpc5AbstractSyntax(
        if_uuid=uuid.UUID(interface_uuid), if_version=version))
    return _wire(DceRpc5() / mod_bind(context_elem=[ctx]), ts=ts, dport=dport, src=src, dst=dst)


def mod_bind(**kw):
    from scapy.layers.dcerpc import DceRpc5Bind
    return DceRpc5Bind(**kw)


def bind_nak(ts=0.0):
    """Server -> client: the bind was refused."""
    return _wire(DceRpc5() / DceRpc5BindNak(), src=SERVER, dst=CLIENT,
                 sport=135, dport=50000, ts=ts)


def bind_ack(ts=0.0):
    """Server -> client: the bind was accepted (fed live; scapy will not rebuild it)."""
    return _wire_live(DceRpc5() / DceRpc5BindAck(), ts=ts)


def request(opnum, ts=0.0):
    return _wire(DceRpc5() / DceRpc5Request(opnum=opnum), ts=ts)


def _run(packets):
    acc = mod.DCERPCAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc


# ── intake ────────────────────────────────────────────────────────────────────

def test_non_rpc_traffic_is_ignored():
    acc = _run([IP(src=CLIENT, dst=SERVER) / TCP(dport=443),
                IP(src=CLIENT, dst=SERVER) / UDP(dport=53)])
    assert acc.binds == []
    assert acc.summary() == {}


def test_a_tcp_segment_on_an_rpc_port_that_is_not_dcerpc_is_skipped():
    """Ports 135 and 593 also carry handshakes and non-RPC bytes."""
    pkt = IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=135, flags="PA") / (b"\x00" * 32)
    assert _run([IP(bytes(pkt))]).binds == []


def test_a_short_payload_is_not_mistaken_for_a_pdu():
    pkt = IP(src=CLIENT, dst=SERVER) / TCP(sport=50000, dport=135, flags="PA") / b"\x05\x00"
    assert _run([IP(bytes(pkt))]).binds == []


def test_dcerpc_over_ipv6_is_read_the_same_as_over_ipv4():
    ctx = DceRpc5Context(abstract_syntax=DceRpc5AbstractSyntax(
        if_uuid=uuid.UUID(SVCCTL), if_version=2))
    pkt = IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=5, dport=135, flags="PA") \
        / DceRpc5() / mod_bind(context_elem=[ctx])
    assert len(_run([IPv6(bytes(pkt))]).binds) == 1


def test_a_pdu_with_no_ip_layer_is_skipped_not_crashed():
    ctx = DceRpc5Context(abstract_syntax=DceRpc5AbstractSyntax(
        if_uuid=uuid.UUID(SVCCTL), if_version=2))
    bare = TCP(sport=5, dport=135, flags="PA") / DceRpc5() / mod_bind(context_elem=[ctx])
    assert _run([TCP(bytes(bare))]).binds == []


def test_a_pdu_that_cannot_be_decoded_ends_that_packet_not_the_pass(monkeypatch):
    acc = mod.DCERPCAccumulator()

    def truncated(*_a, **_k):
        raise ValueError("truncated DCERPC PDU")

    monkeypatch.setattr(acc, "_decode", truncated)
    acc.feed(bind(SVCCTL))
    assert acc.binds == []

    monkeypatch.undo()
    acc.feed(bind(SVCCTL))
    assert len(acc.binds) == 1


# ── the interface is the signal ───────────────────────────────────────────────

def test_a_bind_to_svcctl_is_service_execution():
    """svcctl is the Service Control Manager, the engine inside PsExec."""
    events = _run([bind(SVCCTL)]).finalize()
    hit = [e for e in events if e.event_type is EventType.DCERPC_SUSPECT_BIND]
    assert len(hit) == 1
    assert hit[0].severity is Severity.HIGH
    assert hit[0].evidence["interface"] == "svcctl"
    assert hit[0].evidence["mitre"] == mod.MITRE_SVCCTL


def test_a_bind_to_drsuapi_is_a_critical_dcsync_attempt():
    """Replicating secrets out of the domain is the worst thing on this list."""
    hit = [e for e in _run([bind(DRSUAPI)]).finalize()
           if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert hit.severity is Severity.CRITICAL
    assert hit.evidence["interface"] == "drsuapi"
    assert "DCSync" in hit.evidence["meaning"]
    assert hit.evidence["mitre"] == mod.MITRE_DCSYNC


def test_a_bind_to_atsvc_is_a_scheduled_task():
    hit = [e for e in _run([bind(ATSVC)]).finalize()
           if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert hit.severity is Severity.HIGH
    assert hit.evidence["mitre"] == mod.MITRE_ATSVC


def test_a_bind_to_samr_is_discovery_not_execution():
    hit = [e for e in _run([bind(SAMR)]).finalize()
           if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert hit.severity is Severity.MEDIUM
    assert hit.evidence["category"] == "discovery"


def test_an_unknown_interface_is_reported_but_treated_as_recon():
    """A UUID this tool does not recognise is still worth noting, cautiously."""
    other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    acc = _run([bind(other)])
    # It is bound, so it is in the summary, but it does not raise an execution
    # finding on its own.
    assert any("unknown" in n for n in acc.summary()["interfaces"])
    assert [e for e in acc.finalize()
            if e.event_type is EventType.DCERPC_SUSPECT_BIND] == []


def test_a_bind_result_is_recorded_from_the_servers_reply():
    """A bind the server accepted is more serious than one it refused."""
    acc = _run([bind(SVCCTL, ts=1.0), bind_ack(ts=2.0)])
    hit = [e for e in acc.finalize() if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert hit.evidence["bind_result"] == "accepted"

    acc2 = _run([bind(SVCCTL, ts=1.0), bind_nak(ts=2.0)])
    hit2 = [e for e in acc2.finalize() if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert hit2.evidence["bind_result"] == "rejected"


def test_a_dcsync_operation_is_named_when_the_request_is_readable():
    """drsuapi opnum 3 is DRSGetNCChanges, the call DCSync makes."""
    acc = _run([bind(DRSUAPI, ts=1.0), request(3, ts=2.0)])
    hit = [e for e in acc.finalize() if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert "DRSGetNCChanges" in hit.evidence["operations"]
    assert "DCSync" in hit.description


def test_a_create_service_operation_is_named_on_svcctl():
    acc = _run([bind(SVCCTL, ts=1.0), request(12, ts=2.0)])
    hit = [e for e in acc.finalize() if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert "CreateServiceW" in hit.evidence["operations"]


def test_an_operation_number_that_is_not_notable_is_not_invented():
    acc = _run([bind(SVCCTL, ts=1.0), request(99, ts=2.0)])
    hit = [e for e in acc.finalize() if e.event_type is EventType.DCERPC_SUSPECT_BIND][0]
    assert hit.evidence["operations"] == "none in clear text"


# ── reconnaissance: what the source capture actually contains ─────────────────

def test_a_rejected_bind_is_reported_as_reconnaissance():
    """The AD capture this module was built from has exactly this: one refused
    bind on the endpoint mapper and nothing else. It is a real recon signal."""
    acc = _run([bind_nak()])
    recon = [e for e in acc.finalize() if e.event_type is EventType.DCERPC_RECON]
    assert len(recon) == 1
    assert recon[0].severity is Severity.LOW
    assert recon[0].evidence["rejected_binds"] == 1


def test_endpoint_mapper_binds_are_reconnaissance():
    acc = _run([bind(EPMAPPER)])
    recon = [e for e in acc.finalize() if e.event_type is EventType.DCERPC_RECON]
    assert len(recon) == 1
    assert recon[0].evidence["endpoint_mapper_binds"] == 1
    # The endpoint mapper itself does not raise an execution finding.
    assert [e for e in acc.finalize()
            if e.event_type is EventType.DCERPC_SUSPECT_BIND] == []


def test_a_clean_single_service_bind_raises_no_recon():
    acc = _run([bind(SVCCTL)])
    assert [e for e in acc.finalize() if e.event_type is EventType.DCERPC_RECON] == []


# ── the summary the copilot and the report read ───────────────────────────────

def test_the_summary_lists_the_interfaces_and_the_surface_mapping():
    acc = _run([bind(SVCCTL, ts=1.0), request(12, ts=2.0),
                bind(EPMAPPER, ts=3.0), bind_nak(ts=4.0)])
    s = acc.summary()
    assert "svcctl" in s["interfaces"]
    assert s["clients"] == [CLIENT]
    assert s["servers"] == [SERVER]
    assert any("CreateServiceW" in op for op in s["operations"])
    assert s["rejected_binds"] >= 1


def test_the_summary_is_empty_when_there_is_no_dcerpc():
    assert mod.DCERPCAccumulator().summary() == {}


def test_endpoint_extraction_gives_up_quietly_on_a_packet_it_cannot_read():
    class Hostile:
        def haslayer(self, _layer):
            raise ValueError("not a packet")

    assert mod._endpoints(Hostile()) == (None, None)


def test_a_bind_context_with_no_uuid_is_skipped():
    """A malformed or empty context element must not crash or invent an interface."""
    assert mod._uuid_of(object()) == ""


# ── reaching the analyst ──────────────────────────────────────────────────────

def test_the_cli_names_the_interface_and_what_it_is_for(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "rpc.pcap")
    wrpcap(pcap, [bind(DRSUAPI, ts=1.0)])
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "RPC INTERFACES" in out.output
    assert "drsuapi" in out.output
    assert "DCSync" in out.output


def test_a_capture_without_dcerpc_prints_no_rpc_section(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "plain.pcap")
    wrpcap(pcap, [IP(src=CLIENT, dst=SERVER) / TCP(dport=443) for _ in range(4)])
    out = CliRunner().invoke(main, ["analyze", pcap])

    assert out.exit_code == 0, out.output
    assert "RPC INTERFACES" not in out.output


def test_the_cli_reports_the_surface_mapping_when_binds_are_refused(tmp_path):
    from click.testing import CliRunner
    from scapy.utils import wrpcap

    from packetiq.cli import main

    pcap = str(tmp_path / "nak.pcap")
    wrpcap(pcap, [bind_nak(ts=1.0)])
    out = CliRunner().invoke(main, ["analyze", pcap, "--full"])

    assert out.exit_code == 0, out.output
    assert "reconnaissance, not execution" in out.output


def test_the_copilot_context_names_the_interfaces_and_their_meaning():
    from packetiq.copilot.context_builder import _rpc_interfaces
    from packetiq.extractor.data_extractor import ExtractionResult

    acc = _run([bind(DRSUAPI, ts=1.0), request(3, ts=2.0), bind(EPMAPPER, ts=3.0)])
    result = ExtractionResult()
    result.dcerpc = acc.summary()

    text = _rpc_interfaces(result)
    assert "RPC INTERFACES (DCERPC)" in text
    assert "drsuapi" in text
    assert "DCSync" in text
    assert "DRSGetNCChanges" in text
    assert "reconnaissance of the RPC surface" in text


def test_the_context_section_is_absent_when_there_was_no_dcerpc():
    from packetiq.copilot.context_builder import _rpc_interfaces
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _rpc_interfaces(ExtractionResult()) == ""


# ── the small internals, covered directly ─────────────────────────────────────

def test_session_duration_is_the_span_of_its_binds():
    state = mod._SessionState(first_ts=10.0, last_ts=22.5)
    assert state.duration == 12.5
    assert mod._SessionState().duration == 0.0


def test_a_single_context_element_is_handled_like_a_list_of_one():
    """scapy hands back a bare context when a bind proposes exactly one interface."""
    ctx = DceRpc5Context(abstract_syntax=DceRpc5AbstractSyntax(
        if_uuid=uuid.UUID(SVCCTL), if_version=2))
    acc = mod.DCERPCAccumulator()
    # feed a bind whose context_elem is a single object rather than a list
    from scapy.layers.dcerpc import DceRpc5Bind
    pkt = _wire(DceRpc5() / DceRpc5Bind(context_elem=ctx))
    acc.feed(pkt)
    assert "svcctl" in acc.summary().get("interfaces", {})


def test_a_bind_whose_context_carries_no_uuid_adds_no_interface():
    from scapy.layers.dcerpc import DceRpc5Bind
    acc = mod.DCERPCAccumulator()
    pkt = _wire(DceRpc5() / DceRpc5Bind(context_elem=[DceRpc5Context()]))
    acc.feed(pkt)
    assert acc.summary().get("interfaces", {}) == {}


def test_the_cli_section_lists_observed_operations():
    """The operation line is reached only when a request named a known opnum,
    rendered here from crafted data so it does not depend on a request PDU
    surviving a pcap write-and-read."""
    from packetiq.cli import _print_dcerpc_section

    class _UI:
        def __init__(self):
            self.text = []

        def print_section(self, *a, **k):
            self.text.append(" ".join(str(x) for x in a))

        def print_table(self, title, **k):
            self.text.append(title + " " + repr(k.get("rows")))

        def print_status(self, msg, *a, **k):
            self.text.append(msg)

    ui = _UI()
    _print_dcerpc_section(ui, {
        "binds": 1, "sessions": 1,
        "interfaces": {"drsuapi": "Directory Replication, DCSync"},
        "operations": ["DRSGetNCChanges (DCSync — replicating secrets out of the domain)"],
        "endpoint_mapper_requests": 0, "rejected_binds": 0,
    })
    blob = "\n".join(ui.text)
    assert "drsuapi" in blob
    assert "RPC operation observed: DRSGetNCChanges" in blob


def test_the_cli_section_is_silent_without_dcerpc():
    from packetiq.cli import _print_dcerpc_section

    seen = []

    class _UI:
        def print_section(self, *a, **k):
            seen.append(a)

    _print_dcerpc_section(_UI(), {})
    assert seen == []
