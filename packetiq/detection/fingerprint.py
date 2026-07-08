"""
Passive OS / Device Fingerprinting.

Infers the operating system of each observed source IP purely from
TCP/IP stack behavior — no packets sent, fully passive.

Signals used:
  - IP TTL (Linux=64, Windows=128, Cisco/BSD=255)
  - Heuristic: observed TTL normalized to nearest power-of-2 milestone

Returns a list of Fingerprint objects (informational, not DetectionEvents).
"""

from dataclasses import dataclass

from packetiq.extractor.data_extractor import ExtractionResult
from packetiq.utils.helpers import is_private_ip

# TTL milestone → (initial_ttl, os_label, icon)
_TTL_MAP: list[tuple[int, int, str, str]] = [
    # (max_observed, initial_ttl, os_label, icon)
    (64,  64,  "Linux / Android / macOS",    "🐧"),
    (128, 128, "Windows",                    "🪟"),
    (200, 255, "BSD / Solaris",              "🔱"),
    (255, 255, "Network Device (Cisco/HP)",  "📡"),
]


@dataclass
class Fingerprint:
    src_ip:       str
    observed_ttl: int
    initial_ttl:  int
    os_guess:     str
    os_icon:      str
    hops:         int
    is_external:  bool


def detect(result: ExtractionResult) -> list[Fingerprint]:
    """Return a passive OS fingerprint for every observed source IP."""
    prints: list[Fingerprint] = []

    for src_ip, ttl in result.src_ip_ttl.items():
        initial, label, icon = _infer(ttl)
        prints.append(Fingerprint(
            src_ip       = src_ip,
            observed_ttl = ttl,
            initial_ttl  = initial,
            os_guess     = label,
            os_icon      = icon,
            hops         = max(0, initial - ttl),
            is_external  = not is_private_ip(src_ip),
        ))

    return sorted(prints, key=lambda f: f.src_ip)


def _infer(ttl: int) -> tuple[int, str, str]:
    for max_obs, initial, label, icon in _TTL_MAP:
        if ttl <= max_obs:
            return initial, label, icon
    return 255, "Network Device (Cisco/HP)", "📡"
