"""
The offline recovery as one step, so the CLI and the copilot share it.

`recover()` runs the whole opt-in chain in one call: extract the AS-REP roast the
capture carries, crack it against a wordlist, and decrypt the WinRM session the
recovered password unlocks. It returns a structured result the `crack` command
prints and the copilot context carries, so the AI can answer "what was the
password / what commands ran / what is the flag" from recovered fact instead of
saying it is encrypted.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass
class OfflineRecovery:
    roasts: int = 0                                            # AS-REP roasts found
    credentials: dict[str, str] = field(default_factory=dict)  # account -> password
    commands: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    exfiltrated_files: list[str] = field(default_factory=list)
    sessions: int = 0
    command_sessions: list[list[str]] = field(default_factory=list)  # commands per shell

    def __bool__(self) -> bool:
        return bool(self.credentials or self.commands or self.flags)

    def to_dict(self) -> dict:
        return {
            "roasts": self.roasts,
            "credentials": dict(self.credentials),
            "commands": list(self.commands),
            "flags": list(self.flags),
            "exfiltrated_files": list(self.exfiltrated_files),
            "sessions": self.sessions,
            "command_sessions": [list(s) for s in self.command_sessions],
        }


def _asrep_hashes(pcap_path: str) -> dict[str, str]:
    from scapy.all import PcapReader

    from packetiq.detection import kerberos as kerb

    acc = kerb.KerberosAccumulator()
    with contextlib.suppress(Exception), PcapReader(pcap_path) as reader:
        for pkt in reader:
            acc.feed(pkt)
        acc.finalize()
    return acc.summary().get("asrep_hashes", {})


def recover(pcap_path: str, wordlist: str | None = None) -> OfflineRecovery:
    """Crack the AS-REP roast(s) in a capture and decrypt the WinRM session(s)."""
    from packetiq.offline import asrep, winrm

    result = OfflineRecovery()
    hashes = _asrep_hashes(pcap_path)
    result.roasts = len(hashes)
    if not hashes:
        return result

    def candidates() -> Iterator[str]:
        return asrep.iter_wordlist(wordlist) if wordlist else asrep.bundled_wordlist()

    for account, hash_string in hashes.items():
        password = asrep.crack(hash_string, candidates())
        if password:
            result.credentials[account] = password

    for password in dict.fromkeys(result.credentials.values()):
        session = winrm.decrypt_capture(pcap_path, password)
        result.sessions += session.sessions
        result.command_sessions.extend(session.command_sessions)
        for command in session.commands:
            if command not in result.commands:
                result.commands.append(command)
        for flag in session.flags:
            if flag not in result.flags:
                result.flags.append(flag)
        for path in session.exfiltrated_files:
            if path not in result.exfiltrated_files:
                result.exfiltrated_files.append(path)
    return result
