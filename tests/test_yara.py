"""Tests for YARA scanning (bundled example rules).

The fixtures here are the things the bundled rules detect — the EICAR test
string and PHP webshell markers — and writing them out verbatim turned this file
into something desktop anti-virus quarantines. Microsoft Defender flagged the
repository download as `Backdoor:PHP/Remoteshell.F` and removed the whole zip,
naming this file: a PHP open tag sitting directly in front of an `eval` of
request data matched a webshell signature — which it is, in the sense that any
test of a webshell detector has to contain one.

So each fixture is written with `~` at a couple of points and assembled by
`_fixture()` below. The scanner under test receives byte-identical input — the
assertions are unchanged and still fail if a rule stops matching — while nothing
in the repository is a contiguous copy of a signature. `tests/test_repo_hygiene.py`
holds that line for every tracked file, so a fixture pasted in verbatim later
fails the build rather than a stranger's download.
"""

import pytest

from packetiq.detection import yara_scan

pytest.importorskip("yara")


def _fixture(text: str) -> bytes:
    """The fixture bytes, with the `~` split markers removed.

    `~` appears in none of these payloads, so removing it is lossless and the
    string stays readable to a human reviewing the test.
    """
    return text.replace("~", "").encode()


EICAR = _fixture(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EIC~AR-STANDARD-ANTIVIRUS-TE~ST-FILE!$H+H*")
WEBSHELL = _fixture("<?php ev~al($_POST['x']); ?>")
WEBSHELL_CMD = _fixture("<?php sys~tem($_REQUEST['cmd']); ev~al($_POST['x']); ?>")


def test_the_fixtures_are_the_bytes_they_claim_to_be():
    """A mistyped split marker would silently change what is under test, and every
    assertion below would then be exercising a different payload.

    Pinned by digest rather than by spelling the payload out a second time —
    writing the expected value as a literal would put back exactly the string
    this file exists to avoid. The EICAR digest is the published one for
    EICAR.COM, so that fixture is checked against a value from outside this
    repository rather than against itself.
    """
    import hashlib

    assert len(EICAR) == 68
    assert hashlib.sha256(EICAR).hexdigest() == \
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert hashlib.sha256(WEBSHELL).hexdigest() == \
        "60d88584dd42d70e232ff3526dc6356dcce06795419fd726a41f7935bdb3f478"
    assert hashlib.sha256(WEBSHELL_CMD).hexdigest() == \
        "ba31b9ce1fc07f8f90ef21aca0502c6112c4b3a9fbb044d56144892aa98b7f0f"


def test_yara_available_with_bundled_rules():
    assert yara_scan.available(), "bundled YARA rules should compile"


def test_eicar_match():
    hits = yara_scan.scan_bytes(EICAR)
    assert any(h["rule"] == "EICAR_Test_File" for h in hits)


def test_webshell_marker_match():
    hits = yara_scan.scan_bytes(WEBSHELL)
    assert any("Webshell" in h["rule"] for h in hits)


def test_clean_data_no_match():
    assert yara_scan.scan_bytes(b"just some normal text content here") == []


def test_carver_emits_yara_event(tmp_path):
    """A webshell delivered over HTTP should produce a YARA-tagged finding."""
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    from packetiq.detection import file_carver
    from packetiq.detection.models import EventType

    body = WEBSHELL_CMD + b"A" * 200
    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    p = Ether() / IP(src="45.33.32.156", dst="192.168.1.50") / \
        TCP(sport=80, dport=51000, seq=1000, flags="A") / Raw(load=resp)
    p.time = 1700000000.0
    pcap = tmp_path / "shell.pcap"
    wrpcap(str(pcap), [p])

    events = file_carver.analyze(str(pcap))
    assert any(e.event_type == EventType.MALICIOUS_FILE and e.evidence.get("yara_rule")
               for e in events), [e.description for e in events]
