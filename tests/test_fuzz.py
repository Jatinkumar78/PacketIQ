"""
Robustness / fuzz tests — malformed and truncated captures must never crash the
parser or the pipeline; they should degrade gracefully.
"""

import random
import struct

import pytest

from packetiq.detection.engine import DetectionEngine
from packetiq.extractor.data_extractor import DataExtractor
from packetiq.parser.pcap_parser import PCAPParser


def _pcap_global_header() -> bytes:
    # classic pcap global header, LINKTYPE_ETHERNET
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def test_truncated_file_does_not_crash(tmp_path):
    p = tmp_path / "trunc.pcap"
    p.write_bytes(_pcap_global_header() + b"\x00\x01\x02")  # bogus partial record
    parser = PCAPParser(str(p))
    records = list(parser.stream())   # must not raise
    assert isinstance(records, list)


def test_random_garbage_records(tmp_path):
    random.seed(0)
    body = _pcap_global_header()
    for _ in range(50):
        payload = bytes(random.randint(0, 255) for _ in range(random.randint(0, 80)))
        ts_sec, ts_usec = 1700000000, 0
        body += struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)) + payload
    p = tmp_path / "garbage.pcap"
    p.write_bytes(body)

    parser = PCAPParser(str(p))
    extractor = DataExtractor()
    for rec in parser.stream():       # must not raise on malformed frames
        extractor.feed(rec)
    result = extractor.finalize()
    # full detection pipeline must also survive garbage input
    events, risk, fps = DetectionEngine().run(result, str(p))
    assert isinstance(events, list)
    assert 0 <= risk.score <= 100


def test_empty_pcap(tmp_path):
    p = tmp_path / "empty.pcap"
    p.write_bytes(_pcap_global_header())
    parser = PCAPParser(str(p))
    assert list(parser.stream()) == []


def test_nonexistent_file_raises():
    with pytest.raises(FileNotFoundError):
        PCAPParser("/no/such/file.pcap")
