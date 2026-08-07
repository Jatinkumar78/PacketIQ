"""
Forward-compatibility guards for third-party APIs we read through.

Two deprecated call patterns were live in the parsing hot path and went unnoticed
because nothing failed — the libraries still answered, just with a warning:

  * scapy 2.5 turned DNS ``qd``/``an``/``ns``/``ar`` into PacketListFields. Reading
    ``dns.qd.qname`` kept working only through a compatibility shim that warns and
    is documented for removal; when it goes, every DNS query name in the product
    silently becomes None.
  * ``datetime.utcnow()`` is deprecated in Python 3.12 and returns a naive
    timestamp, which is exactly the bug that makes "UTC"-stamped files wrong on a
    non-UTC host.

These tests fail on the warning rather than on the eventual breakage, so the
regression is caught in the release that introduces it, not the one that removes
the shim.
"""

import datetime
import warnings

import pytest
from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

from packetiq.enrichment.update import _stamp_header
from packetiq.inspect import _dns_info
from packetiq.parser.pcap_parser import PCAPParser
from packetiq.utils.helpers import dns_first_question, dns_questions


def _dns_packet(qname="example.com", qr=0):
    pkt = (Ether() / IP(src="192.168.1.10", dst="8.8.8.8") /
           UDP(sport=40000, dport=53) / DNS(rd=1, qr=qr, qd=DNSQR(qname=qname)))
    return Ether(bytes(pkt))          # round-trip so fields parse as they do off the wire


# --------------------------------------------------------------------------- #
#  The helper itself                                                            #
# --------------------------------------------------------------------------- #

def test_questions_are_returned_as_a_plain_list():
    dns = _dns_packet("one.example.com")[DNS]
    qs = dns_questions(dns)
    assert isinstance(qs, list)
    assert len(qs) == 1
    assert qs[0].qname == b"one.example.com."


def test_every_question_is_returned_not_just_the_first():
    """The deprecated shim could only ever reach question 0."""
    raw = Ether() / IP() / UDP(dport=53) / DNS(qd=[DNSQR(qname="a.com"), DNSQR(qname="b.com")])
    dns = Ether(bytes(raw))[DNS]
    assert [q.qname for q in dns_questions(dns)] == [b"a.com.", b"b.com."]


def test_a_message_with_no_questions_yields_no_question():
    raw = Ether() / IP() / UDP(dport=53) / DNS(qr=1, qdcount=0, qd=[])
    dns = Ether(bytes(raw))[DNS]
    assert dns_questions(dns) == []
    assert dns_first_question(dns) is None


def test_a_bare_record_from_older_scapy_is_normalised():
    """Pre-2.5 scapy handed back one record, not a list. Both must work."""
    class _OldStyle:
        qd = DNSQR(qname="legacy.example.com")

    qs = dns_questions(_OldStyle())
    assert len(qs) == 1
    assert qs[0].qname == b"legacy.example.com."


def test_an_object_without_a_qd_field_is_tolerated():
    assert dns_questions(object()) == []
    assert dns_first_question(object()) is None


# --------------------------------------------------------------------------- #
#  The call sites                                                               #
# --------------------------------------------------------------------------- #

def test_parser_reads_the_query_name_without_the_deprecated_shim(tmp_path):
    pcap = tmp_path / "dns.pcap"
    wrpcap(str(pcap), [_dns_packet("tracker.example.org")])

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        records = list(PCAPParser(str(pcap)).stream())

    assert len(records) == 1
    assert records[0].has_dns is True
    assert records[0].dns_qname == "tracker.example.org"


def test_packet_inspector_reads_the_query_without_the_deprecated_shim():
    pkt = _dns_packet("evil.example.com")

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        info = _dns_info(pkt)

    assert "A evil.example.com" in info
    assert info.startswith("Standard query")


def test_inspector_labels_a_response_as_a_response():
    info = _dns_info(_dns_packet("example.com", qr=1))
    assert info.startswith("Standard query response")


def test_inspector_survives_a_dns_message_with_no_question():
    raw = Ether() / IP() / UDP(dport=53) / DNS(qr=1, qdcount=0, qd=[])
    info = _dns_info(Ether(bytes(raw)))
    assert "Standard query response" in info      # no crash, no invented name


# --------------------------------------------------------------------------- #
#  Feed refresh timestamps                                                      #
# --------------------------------------------------------------------------- #

def test_feed_header_stamp_is_timezone_aware_utc():
    """A naive utcnow() stamp reads as local time on a non-UTC host."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        header = _stamp_header("Test feed", "unit test", "one per line")

    assert "# PacketIQ feed: Test feed" in header
    assert "# Refreshed:" in header
    assert header.rstrip().endswith("are ignored.")

    stamped = [ln for ln in header.splitlines() if ln.startswith("# Refreshed:")][0]
    when = datetime.datetime.strptime(
        stamped.split(": ", 1)[1], "%Y-%m-%d %H:%M UTC"
    ).replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    assert abs((now - when).total_seconds()) < 300


@pytest.mark.parametrize("bad", ["", "   "])
def test_stamp_header_accepts_empty_metadata_without_crashing(bad):
    assert "# PacketIQ feed:" in _stamp_header(bad, bad, bad)
