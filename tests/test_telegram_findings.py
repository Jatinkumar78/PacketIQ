"""The Telegram 'Notify' message must be a professional SOC brief (risk, severity
breakdown, top talkers, attack chains with MITRE, and the key findings with
evidence) — not the old two-line list — built from the serialised result dict.
"""

import re

from packetiq.alerts import formatter

_RES = {
    "meta": {"filename": "jay2.pcapng", "total_packets": 1234, "bytes_fmt": "1.2 MB",
             "duration": "42s", "external_ips": 9},
    "risk": {"score": 13, "tier": "LOW", "summary": "Low-risk capture with DNS tunneling indicators.",
             "breakdown": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 1, "LOW": 0}},
    "top_src_ips": [{"ip": "172.20.10.3", "count": 500}, {"ip": "172.20.10.1", "count": 400}],
    "events": [
        {"event_type": "DNS_TUNNELING", "severity": "HIGH", "src_ip": "172.20.10.3",
         "dst_ip": "172.20.10.1", "dst_port": 53, "confidence": 82,
         "description": "High-entropy DNS queries consistent with tunnelling over port 53."},
        {"event_type": "SUSPICIOUS_FLAGS", "severity": "MEDIUM", "src_ip": "10.0.0.9",
         "dst_ip": "10.0.0.5", "dst_port": 445, "confidence": 55, "description": "Unusual TCP flags."},
    ],
    "chains": [
        {"name": "DNS Exfiltration Channel", "severity": "HIGH", "confidence": 78,
         "attacker_ips": ["172.20.10.3"], "target_ips": ["172.20.10.1"],
         "phases": ["Command & Control"], "mitre": [{"id": "T1071.004", "name": "DNS"}]},
    ],
}


def test_message_has_professional_sections():
    msg = formatter.format_webapp_findings(_RES)
    assert "PacketIQ Security Report" in msg
    assert "jay2.pcapng" in msg
    assert "13/100 [LOW]" in msg
    assert "Findings:" in msg and "Key findings:" in msg
    assert "Attack chain" in msg
    assert "T1071.004" in msg                      # MITRE surfaced
    assert "DNS TUNNELING" in msg
    assert "82%" in msg                            # confidence surfaced
    assert "PDF" in msg                            # points at the attached report


def test_message_includes_top_talkers_and_context():
    msg = formatter.format_webapp_findings(_RES)
    assert "172.20.10.3" in msg
    assert "external IPs" in msg


def test_message_is_valid_telegram_html_and_strips_cleanly():
    msg = formatter.format_webapp_findings(_RES)
    # Tags must be balanced enough that a naive strip yields readable text
    plain = re.sub(r"<[^>]+>", "", msg)
    assert "<" not in plain and ">" not in plain
    assert "DNS TUNNELING" in plain


def test_empty_findings_still_renders():
    res = {"meta": {"filename": "clean.pcap"}, "risk": {"score": 0, "tier": "LOW", "breakdown": {}},
           "events": [], "chains": []}
    msg = formatter.format_webapp_findings(res)
    assert "clean.pcap" in msg
    assert "Findings:" in msg
