"""File carving: TCP reassembly, HTTP body extraction, and hash reputation.

The reassembler is hand-rolled sequence-number arithmetic, and the three branches
that handle out-of-order, gapped and retransmitted segments were all uncovered —
exactly the cases a real download hits and a clean synthetic capture never does.
A carve that silently loses bytes produces a different SHA-256, which turns a
known-malicious file into a miss.
"""

import hashlib

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from packetiq.detection import file_carver
from packetiq.detection.models import EventType, Severity
from packetiq.enrichment.feeds import IOCHit, IOCStore

TS = 1700000000.0
PE_FILE = b"MZ" + b"\x90" * 300          # DOS header magic + filler
ELF_FILE = b"\x7fELF" + b"\x02" * 300


def _http_response(body: bytes, extra_headers: bytes = b"") -> bytes:
    return (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            + extra_headers +
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def _feed_stream(acc, data, src="185.199.108.153", dst="192.168.1.50",
                 sport=80, dport=51000, seg=200, start_seq=1000):
    for i in range(0, len(data), seg):
        pkt = (Ether() / IP(src=src, dst=dst) /
               TCP(sport=sport, dport=dport, seq=start_seq + i) / data[i:i + seg])
        pkt.time = TS
        acc.feed(pkt)


def _carve(data, **kw):
    acc = file_carver.FileCarverAccumulator()
    _feed_stream(acc, data, **kw)
    return acc.finalize()


# ── feed() filtering ─────────────────────────────────────────────────────────

def test_a_packet_with_no_ip_layer_is_ignored():
    acc = file_carver.FileCarverAccumulator()
    acc.feed(Ether() / TCP(sport=80, dport=51000) / b"MZ")
    assert acc.segments == {}


def test_a_non_tcp_packet_is_ignored():
    acc = file_carver.FileCarverAccumulator()
    acc.feed(Ether() / ARP())
    assert acc.segments == {}


def test_an_ipv6_download_is_reassembled():
    acc = file_carver.FileCarverAccumulator()
    pkt = (Ether() / IPv6(src="2606:4700::1111", dst="fd00::50") /
           TCP(sport=80, dport=51000, seq=1) / b"MZ\x90\x90")
    pkt.time = TS
    acc.feed(pkt)

    assert list(acc.segments) == [("2606:4700::1111", 80, "fd00::50", 51000)]


def test_traffic_on_a_non_file_port_is_ignored():
    """Only server ports that carry file downloads are reassembled."""
    acc = file_carver.FileCarverAccumulator()
    pkt = Ether() / IP(src="185.199.108.153", dst="192.168.1.50") / TCP(sport=443, dport=51000)
    pkt.time = TS
    acc.feed(pkt / PE_FILE)

    assert acc.segments == {}


def test_an_empty_payload_is_not_recorded():
    acc = file_carver.FileCarverAccumulator()
    pkt = Ether() / IP(src="185.199.108.153", dst="192.168.1.50") / TCP(sport=80, dport=51000)
    pkt.time = TS
    acc.feed(pkt)
    assert acc.segments == {}


def test_reassembly_stops_at_the_stream_byte_cap(monkeypatch):
    """8 MB per flow, so one huge download cannot exhaust memory.

    The cap is lowered here rather than moving 8 MB through scapy — the branch
    under test is the size check, not the constant.
    """
    monkeypatch.setattr(file_carver, "_MAX_STREAM_BYTES", 1000)
    acc = file_carver.FileCarverAccumulator()
    _feed_stream(acc, b"A" * 3000, seg=200)

    key = ("185.199.108.153", 80, "192.168.1.50", 51000)
    assert acc.sizes[key] <= 1000 + 200, "collection must stop once the cap is reached"


# ── TCP reassembly arithmetic ────────────────────────────────────────────────

def test_segments_arriving_out_of_order_are_reordered_by_sequence():
    segs = [(300, b"CCC"), (100, b"AAA"), (200, b"BBB")]
    assert file_carver._reassemble(segs) == b"AAABBBCCC"


def test_a_missing_segment_leaves_a_gap_rather_than_dropping_the_rest():
    """A capture that missed a packet still yields the bytes it did see.

    Bailing out here would throw away the tail of every download taken from a
    lossy span port.
    """
    segs = [(100, b"AAA"), (500, b"CCC")]      # 200..499 never captured
    assert file_carver._reassemble(segs) == b"AAACCC"


def test_a_retransmitted_segment_contributes_only_its_new_tail():
    """seq 100 len 6 then seq 103 len 6 overlap by 3 bytes.

    Appending the whole retransmit would duplicate three bytes and change the
    file's SHA-256 — silently defeating the hash lookup this detector exists for.
    """
    segs = [(100, b"AAABBB"), (103, b"BBBCCC")]
    assert file_carver._reassemble(segs) == b"AAABBBCCC"


def test_a_pure_duplicate_segment_adds_nothing():
    segs = [(100, b"AAABBB"), (100, b"AAABBB")]
    assert file_carver._reassemble(segs) == b"AAABBB"


def test_a_segment_entirely_inside_an_earlier_one_adds_nothing():
    segs = [(100, b"AAABBBCCC"), (103, b"BBB")]
    assert file_carver._reassemble(segs) == b"AAABBBCCC"


def test_a_stream_whose_sequence_number_wraps_is_still_ordered_correctly():
    """TCP sequence numbers are 32-bit serial values, not plain integers.

    The ISN is random, so a stream starting near 2**32 wraps through zero within
    a few kilobytes — well inside the 8 MB this carver collects. Sorting the raw
    values put the wrapped tail first and the file came out scrambled: the magic
    was no longer at offset 0, so nothing was identified, hashed or scanned.
    """
    wrap = 2 ** 32
    segs = [(wrap - 3, b"AAA"), (0, b"BBB"), (3, b"CCC")]

    assert file_carver._reassemble(segs) == b"AAABBBCCC"


def test_a_late_arriving_earlier_segment_is_not_pushed_four_gigabytes_back():
    """Offsets are signed, so a segment captured out of order sorts ahead."""
    segs = [(500, b"BBB"), (497, b"AAA"), (503, b"CCC")]

    assert file_carver._reassemble(segs) == b"AAABBBCCC"


def test_reassembling_no_segments_yields_no_bytes():
    assert file_carver._reassemble([]) == b""


def test_an_executable_download_is_carved_even_when_the_sequence_wraps():
    """End-to-end: a server choosing its ISN must not be able to hide a binary.

    A server picks its own initial sequence number, so straddling the 32-bit
    wrap was an evasion and not merely a rare mis-assembly — this exact transfer
    was reported with a normal ISN and completely invisible with a wrapping one.
    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    body = b"MZ" + b"\x90" * 300
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n") + body
    expected_sha = hashlib.sha256(body).hexdigest()

    half = len(response) // 2
    isn = 2 ** 32 - half                      # the split lands exactly on the wrap
    acc = file_carver.FileCarverAccumulator()
    for i, (chunk, seq) in enumerate((
        (response[:half], isn),
        (response[half:], 0),
    )):
        pkt = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
               / IP(src="45.33.32.156", dst="10.0.0.9")
               / TCP(sport=80, dport=40000, flags="PA", seq=seq) / Raw(load=chunk))
        pkt.time = 1700000000.0 + i
        acc.feed(pkt)

    events = acc.finalize()

    assert [e.evidence["sha256"] for e in events] == [expected_sha], (
        "the carved bytes must hash to the real file, not a scrambled stream"
    )


# ── HTTP body extraction ─────────────────────────────────────────────────────

def test_a_stream_that_is_not_an_http_response_has_no_body():
    assert file_carver._http_body(b"220 FTP server ready\r\n") is None


def test_headers_with_no_terminator_have_no_body():
    assert file_carver._http_body(b"HTTP/1.1 200 OK\r\nContent-Type: x") is None


def test_content_length_trims_a_pipelined_second_response():
    body = file_carver._http_body(_http_response(b"FIRST") + b"HTTP/1.1 200 OK\r\n\r\nSECOND")
    assert body == b"FIRST"


def test_an_unparseable_content_length_falls_back_to_the_whole_body():
    """A malformed header must not lose the payload it precedes."""
    stream = (b"HTTP/1.1 200 OK\r\nContent-Length: not-a-number\r\n\r\n" + PE_FILE)
    assert file_carver._http_body(stream) == PE_FILE


def test_a_response_with_no_content_length_keeps_everything_after_the_headers():
    stream = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + PE_FILE
    assert file_carver._http_body(stream) == PE_FILE


# ── Carving decisions ────────────────────────────────────────────────────────

def test_a_stream_too_short_to_be_a_file_is_skipped():
    assert _carve(b"HTTP/1.1 204 No Content\r\n\r\n") == []


def test_a_long_response_with_a_tiny_body_is_skipped():
    """The stream clears the minimum, the body does not.

    Both lengths are checked because a 404 page with verbose headers is a long
    stream carrying nothing worth hashing.
    """
    padding = b"X-Trace-Id: " + b"a" * 200 + b"\r\n"
    assert _carve(_http_response(b"{}", extra_headers=padding)) == []


def test_a_non_http_stream_on_an_http_port_is_skipped():
    """Something else listening on 8080 — no HTTP framing, so no body to carve."""
    assert _carve(b"SSH-2.0-OpenSSH_9.6\r\n" + b"\x00" * 200, sport=8080) == []


def test_a_body_of_an_unrecognised_type_is_not_reported():
    """No magic bytes matched — the carver does not guess at file types."""
    assert _carve(_http_response(b"plain text payload " * 20)) == []


def test_an_executable_downloaded_over_cleartext_http_is_reported():
    events = _carve(_http_response(PE_FILE))

    assert len(events) == 1
    ev = events[0]
    assert ev.event_type == EventType.MALICIOUS_FILE
    assert ev.severity == Severity.MEDIUM
    assert ev.evidence["file_type"].startswith("PE/EXE")
    assert ev.evidence["sha256"] == hashlib.sha256(PE_FILE).hexdigest()


def test_an_executable_from_an_internal_server_is_not_reported():
    """Internal software distribution is routine; only cleartext from the
    internet is worth a reviewer's time."""
    assert _carve(_http_response(PE_FILE), src="192.168.1.10") == []


def test_the_same_file_downloaded_twice_is_reported_once():
    """Deduplicated on content hash, so two clients pulling one file is one finding."""
    acc = file_carver.FileCarverAccumulator()
    _feed_stream(acc, _http_response(PE_FILE), dst="192.168.1.50")
    _feed_stream(acc, _http_response(PE_FILE), dst="192.168.1.51")

    assert len(acc.segments) == 2
    assert len(acc.finalize()) == 1


def test_a_hash_in_the_malware_feed_is_critical(monkeypatch):
    """The reputation hit outranks the generic executable heuristic."""
    sha = hashlib.sha256(PE_FILE).hexdigest()
    store = IOCStore()
    store.bad_hashes[sha] = IOCHit(indicator=sha, kind="hash", source="MalwareBazaar",
                                   label="Emotet", severity=Severity.CRITICAL)
    monkeypatch.setattr(file_carver, "_load_store", lambda: store)

    events = _carve(_http_response(PE_FILE))
    assert len(events) == 1
    assert events[0].severity == Severity.CRITICAL
    assert events[0].evidence["label"] == "Emotet"
    assert events[0].evidence["source"] == "MalwareBazaar"


def test_a_non_executable_with_a_known_bad_hash_is_still_critical(monkeypatch):
    """A malicious PDF has no executable magic — only the feed catches it."""
    pdf = b"%PDF-1.7\n" + b"0" * 300
    sha = hashlib.sha256(pdf).hexdigest()
    store = IOCStore()
    store.bad_hashes[sha] = IOCHit(indicator=sha, kind="hash", source="MalwareBazaar",
                                   label="PDF dropper", severity=Severity.CRITICAL)
    monkeypatch.setattr(file_carver, "_load_store", lambda: store)

    events = _carve(_http_response(pdf))
    assert [e.severity for e in events] == [Severity.CRITICAL]


def test_an_ftp_data_transfer_is_carved_without_http_framing():
    """Port 20 carries the file bytes raw — no headers to strip."""
    events = _carve(ELF_FILE, sport=20)
    assert len(events) == 1
    assert events[0].evidence["file_type"].startswith("ELF")


def test_a_feed_store_that_cannot_load_is_not_fatal(monkeypatch):
    """Reputation is an enrichment. Losing it must not lose the carve."""
    import packetiq.enrichment.feeds as feeds
    monkeypatch.setattr(feeds, "load_store", lambda: (_ for _ in ()).throw(OSError("no feed")))

    assert file_carver._load_store() is None
    events = _carve(_http_response(PE_FILE))
    assert len(events) == 1, "carving must still work with no reputation data"


# ── YARA arm ─────────────────────────────────────────────────────────────────

def _yara_on(monkeypatch, hits):
    from packetiq.detection import yara_scan
    monkeypatch.setattr(yara_scan, "available", lambda: True)
    monkeypatch.setattr(yara_scan, "scan_bytes", lambda data: hits)


def test_a_yara_hit_on_the_reassembled_stream_is_reported(monkeypatch):
    _yara_on(monkeypatch, [{"rule": "Emotet_Loader", "severity": "CRITICAL",
                            "description": "Emotet stage-1", "tags": ["trojan"]}])

    events = _carve(_http_response(PE_FILE))
    yara_events = [e for e in events if "yara_rule" in e.evidence]
    assert len(yara_events) == 1
    assert yara_events[0].severity == Severity.CRITICAL
    assert yara_events[0].evidence["tags"] == ["trojan"]


def test_a_yara_rule_with_an_unknown_severity_defaults_to_high(monkeypatch):
    """Rule metadata is author-supplied text; a typo must not raise mid-scan."""
    _yara_on(monkeypatch, [{"rule": "Odd_Rule", "severity": "SEVERE",
                            "description": "unknown level", "tags": []}])

    yara_events = [e for e in _carve(_http_response(PE_FILE)) if "yara_rule" in e.evidence]
    assert [e.severity for e in yara_events] == [Severity.HIGH]


def test_one_yara_rule_matching_two_streams_from_a_host_is_reported_once(monkeypatch):
    _yara_on(monkeypatch, [{"rule": "Emotet_Loader", "severity": "CRITICAL",
                            "description": "Emotet stage-1", "tags": []}])

    acc = file_carver.FileCarverAccumulator()
    _feed_stream(acc, _http_response(PE_FILE), dport=51000)
    _feed_stream(acc, _http_response(ELF_FILE), dport=51001)

    yara_events = [e for e in acc.finalize() if "yara_rule" in e.evidence]
    assert len(yara_events) == 1, "same rule, same host pair — one finding"


# ── File-level entry point ───────────────────────────────────────────────────

def test_analyze_carves_from_a_real_pcap(tmp_path):
    from scapy.utils import wrpcap

    data = _http_response(PE_FILE)
    pkts = []
    for i in range(0, len(data), 200):
        p = (Ether() / IP(src="185.199.108.153", dst="192.168.1.50") /
             TCP(sport=80, dport=51000, seq=1000 + i) / data[i:i + 200])
        p.time = TS
        pkts.append(p)
    path = tmp_path / "download.pcap"
    wrpcap(str(path), pkts)

    events = file_carver.analyze(str(path))
    assert len(events) == 1
    assert events[0].evidence["sha256"] == hashlib.sha256(PE_FILE).hexdigest()


def test_an_unreadable_capture_yields_no_findings(tmp_path):
    bad = tmp_path / "broken.pcap"
    bad.write_bytes(b"definitely not a pcap")
    assert file_carver.analyze(str(bad)) == []


def test_the_number_of_carved_flows_is_bounded(monkeypatch):
    """Bytes were capped per flow at 8 MB, but the flow count was not.

    Measured at ~740 bytes of bookkeeping per flow with minimal payloads, so a
    ~100 MB capture of a million tiny packets on an HTTP port cost roughly
    705 MB before any file content was held. New flows past the cap are
    declined and counted; the ones already being reassembled continue.
    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    from packetiq.detection import file_carver as mod

    monkeypatch.setattr(mod, "_MAX_FLOWS", 10)
    acc = mod.FileCarverAccumulator()

    def _pkt(client, sport):
        p = (Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
             / IP(src="45.33.32.156", dst=client)
             / TCP(sport=80, dport=sport, flags="PA", seq=1)
             / Raw(load=b"MZ" + b"\x90" * 80))
        p.time = 1700000000.0
        return p

    for i in range(100):
        acc.feed(_pkt(f"10.0.1.{i}", 40000 + i))

    assert len(acc.segments) == 10
    assert acc.skipped_flows == 90
    assert len(acc.sizes) == 10, "a declined flow must not leave a size entry behind"


# ── Full hash set, embedded strings, and document/image metadata ──────────────

def test_a_carved_file_gets_md5_sha1_and_sha256():
    body = b"MZ" + b"\x00" * 200
    h = file_carver._file_hashes(body)
    assert len(h["md5"]) == 32 and len(h["sha1"]) == 40 and len(h["sha256"]) == 64
    assert h["sha256"] == hashlib.sha256(body).hexdigest()


def test_notable_strings_pulls_urls_and_flags_from_a_file():
    body = (b"%PDF-1.4 see http://pentestmonkey.net/tool for details "
            b"and the flag is THM{inside_the_file} end.")
    strings = file_carver._notable_strings(body)
    assert "http://pentestmonkey.net/tool" in strings
    assert "THM{inside_the_file}" in strings


def test_notable_strings_is_empty_when_there_is_nothing():
    assert file_carver._notable_strings(b"MZ" + b"\x00" * 100) == []


def test_pdf_title_and_author_metadata_is_extracted():
    body = b"%PDF-1.5\n<< /Title (Quarterly Secrets) /Author (mallory) >>\n"
    meta = file_carver._file_metadata(body, "PDF")
    assert meta["title"] == "Quarterly Secrets"
    assert meta["author"] == "mallory"


def test_png_text_chunk_metadata_is_extracted():
    body = b"\x89PNG\r\n\x1a\n" + b"....tEXtComment\x00flag THM{png_text}" + b"\x00" * 10
    meta = file_carver._file_metadata(body, "PNG image")
    assert "Comment" in meta["text"] and "THM{png_text}" in meta["text"]


def test_jpeg_comment_metadata_is_extracted():
    comment = b"hidden THM{jpeg_com}"
    length = (len(comment) + 2).to_bytes(2, "big")
    body = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\xff\xfe" + length + comment + b"\xff\xd9"
    meta = file_carver._file_metadata(body, "JPEG image")
    assert meta["comment"] == "hidden THM{jpeg_com}"


def test_metadata_is_empty_for_a_file_without_it():
    assert file_carver._file_metadata(b"MZ" + b"\x00" * 50, "PE/EXE (Windows)") == {}
    assert file_carver._file_metadata(b"%PDF-1.4 no info here", "PDF") == {}
    assert file_carver._file_metadata(b"\x89PNG\r\n\x1a\n no text", "PNG image") == {}
    assert file_carver._file_metadata(b"\xff\xd8\xff no comment marker", "JPEG image") == {}


def test_file_artifacts_combines_strings_and_metadata():
    body = b"%PDF-1.4 /Title (Report) grab http://evil.test/x THM{both}"
    art = file_carver._file_artifacts(body, "PDF")
    assert "http://evil.test/x" in art["strings"] and "THM{both}" in art["strings"]
    assert art["metadata"]["title"] == "Report"
    assert file_carver._file_artifacts(b"MZ" + b"\x00" * 40, "PE/EXE (Windows)") == {}
