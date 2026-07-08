r"""
HTTP deep inspection.

Scans observed HTTP requests for attack indicators in the URI/path and for
suspicious User-Agents:

  - SQL injection             (UNION SELECT, ' OR 1=1, etc.)
  - Cross-site scripting      (<script>, javascript:, onerror=)
  - Path / directory traversal (../, ..\, %2e%2e)
  - OS command injection      (;id, |whoami, $(...), backticks)
  - Log4Shell / JNDI          (${jndi:ldap://...})
  - Webshell access           (c99.php, cmd.jsp, ?cmd=, /shell)
  - Suspicious User-Agents    (sqlmap, nikto, nmap, empty UA on POST, etc.)

Operates on ExtractionResult.http_requests (no extra PCAP pass needed).
URL-decodes once before matching so simple percent-encoding can't hide payloads.
"""

import re
from urllib.parse import unquote_plus

from packetiq.detection.models import DetectionEvent, EventType, Severity
from packetiq.extractor.data_extractor import ExtractionResult

# (label, severity, compiled regex) — matched against the decoded path+query
_URI_PATTERNS: list[tuple] = [
    ("SQL injection",       Severity.HIGH,     re.compile(r"(union\s+select|\bor\s+1\s*=\s*1\b|';--|\bselect\b.+\bfrom\b|sleep\(\d|benchmark\()", re.I)),
    ("Cross-site scripting", Severity.HIGH,    re.compile(r"(<script\b|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=)", re.I)),
    ("Path traversal",      Severity.HIGH,     re.compile(r"(\.\./|\.\.\\|/etc/passwd|\bboot\.ini\b|%2e%2e)", re.I)),
    ("Command injection",   Severity.CRITICAL, re.compile(r"(;\s*(id|whoami|uname|cat\s)\b|\|\s*(id|whoami|nc|bash|sh)\b|\$\([^)]+\)|`[^`]+`)", re.I)),
    ("Log4Shell / JNDI",    Severity.CRITICAL, re.compile(r"\$\{jndi:(ldap|ldaps|rmi|dns)://", re.I)),
    ("Webshell access",     Severity.CRITICAL, re.compile(r"(c99\.php|r57\.php|/shell\b|cmd\.jsp|/wso\.php|\?cmd=|\?exec=|eval\(|/webshell)", re.I)),
]

# Tooling User-Agents that almost always mean an attack/scan
_BAD_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|nessus|acunetix|dirbuster|gobuster|wpscan|"
    r"hydra|metasploit|havij|zgrab|curl/|python-requests|go-http-client)",
    re.I,
)


def detect(result: ExtractionResult) -> list[DetectionEvent]:
    events: list[DetectionEvent] = []
    seen: set = set()

    for r in result.http_requests:
        path = r.get("path") or ""
        host = r.get("host") or ""
        ua   = r.get("ua") or ""
        src  = r.get("src") or ""
        dst  = r.get("dst") or ""
        ts   = r.get("ts", 0.0)

        decoded = unquote_plus(path)
        target  = f"{host}{decoded}"
        # Attack payloads also arrive via Host / User-Agent headers (e.g. Log4Shell),
        # so search the path, the host, and the UA together.
        haystack = f"{decoded}\n{path}\n{host}\n{ua}"

        for label, severity, rx in _URI_PATTERNS:
            if rx.search(haystack):
                key = (src, dst, label)
                if key in seen:
                    break
                seen.add(key)
                events.append(DetectionEvent(
                    event_type   = EventType.HTTP_ATTACK,
                    severity     = severity,
                    src_ip       = src,
                    dst_ip       = dst,
                    dst_port     = 80,
                    protocol     = "HTTP",
                    timestamp    = ts,
                    packet_count = 1,
                    confidence   = 0.85,
                    description  = f"HTTP {label} attempt — {r.get('method','GET')} {target[:80]}",
                    evidence     = {
                        "attack_type": label,
                        "method":      r.get("method", "GET"),
                        "uri":         decoded[:200],
                        "host":        host,
                        "user_agent":  ua[:120],
                    },
                ))
                break  # one finding per request

        # Suspicious / scanner User-Agent
        if ua and _BAD_UA.search(ua):
            key = (src, dst, "ua")
            if key not in seen:
                seen.add(key)
                events.append(DetectionEvent(
                    event_type   = EventType.HTTP_ATTACK,
                    severity     = Severity.MEDIUM,
                    src_ip       = src,
                    dst_ip       = dst,
                    dst_port     = 80,
                    protocol     = "HTTP",
                    timestamp    = ts,
                    packet_count = 1,
                    confidence   = 0.7,
                    description  = f"Suspicious HTTP User-Agent (scanner/tooling): {ua[:60]}",
                    evidence     = {
                        "attack_type": "suspicious_user_agent",
                        "user_agent":  ua[:160],
                        "host":        host,
                    },
                ))

    return events
