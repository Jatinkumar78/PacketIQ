"""Host identity evidence — the name and OS a host announces for itself.

Why this module exists
----------------------
"Which host is this, and what is it called?" is the first question of almost
every incident, and a Windows host answers it out loud: it broadcasts its
computer name in NetBIOS Browser host announcements and gives it again in its
DHCP requests. PacketIQ extracted the MAC↔IP bindings for the device inventory
but never read those name announcements, so the copilot had the victim's IP and
MAC and still could not give its host name — it reached instead for the domain
controller's name, which was prominent in DNS.

What is read here
-----------------
  * NetBIOS Browser host / local-master announcements (UDP 138): the ServerName,
    OS version and role flags a host broadcasts for itself. One announcement ties
    a host's MAC, IP and name together, which is why exercise authors point
    analysts straight at ``browser.response_computer_name``.
  * DHCP option 12 (Host Name) and option 81 (Client FQDN): the name a host
    gives when it asks for its lease.

Everything is read straight from the packets and attributed to the MAC/IP that
sent it; nothing is inferred. This module emits no DetectionEvent — an asset
knowing its own name is not an alert — it only contributes the identity evidence
the copilot and the asset inventory consume.
"""

from __future__ import annotations

import contextlib

# The NetBIOS Browser announcement rides in an SMB mailslot that scapy exposes
# only as an opaque buffer (``haslayer(BRWS_HostAnnouncement)`` is False), so the
# fixed-layout body after this marker is read by hand. Layout (MS-BRWS §2.2.1):
# OpCode(1) UpdateCount(1) Periodicity(4) ServerName(16, NUL-padded)
# OSVersionMajor(1) OSVersionMinor(1) ServerType(4, little-endian) …
_BROWSE_MARK = b"\\MAILSLOT\\BROWSE\x00"
_HOST_ANNOUNCE_OPS = frozenset({0x01, 0x0F})  # HostAnnouncement, LocalMasterAnnouncement
_BROWSE_MIN_LEN = 28

# NetBIOS Browser ServerType role flags (MS-BRWS). Only the ones that change how
# a host is classified are named; the rest are left to the raw flag string.
_ROLE_FLAGS: list[tuple[int, str]] = [
    (0x00000001, "workstation"),
    (0x00000002, "server"),
    (0x00000008, "domain controller"),
    (0x00000010, "backup domain controller"),
    (0x00000020, "time source"),
    (0x00010000, "domain master browser"),
    (0x00000100, "master browser"),
]

# Windows NT version (major, minor) → the OS families that announce it. Phrased as
# a range because one NT version covers several products; the host name usually
# disambiguates workstation from server.
_OS_NAMES: dict[tuple[int, int], str] = {
    (10, 0): "Windows 10/11 or Server 2016+",
    (6, 3):  "Windows 8.1 or Server 2012 R2",
    (6, 2):  "Windows 8 or Server 2012",
    (6, 1):  "Windows 7 or Server 2008 R2",
    (6, 0):  "Windows Vista or Server 2008",
    (5, 2):  "Windows Server 2003 / XP x64",
    (5, 1):  "Windows XP",
}


class HostNameAccumulator:
    """Collects self-announced host names over one PCAP pass.

    ``feed(pkt)`` filters internally so this can ride the engine's existing
    raw-packet loop. Results are keyed by IP where the packet had one, and by MAC
    otherwise (a DHCP request sent from 0.0.0.0), for the synthesiser to resolve.
    """

    def __init__(self) -> None:
        self.by_ip: dict[str, dict] = {}
        self.by_mac: dict[str, dict] = {}

    # ── collection ──────────────────────────────────────────────────────────

    def feed(self, pkt) -> None:
        # Each parse is isolated: a malformed announcement is one packet's loss,
        # not a reason to abandon the shared capture pass for every detector.
        with contextlib.suppress(Exception):
            self._feed_browser(pkt)
        with contextlib.suppress(Exception):
            self._feed_dhcp(pkt)

    def _store(self, ip: str, mac: str, **vals) -> None:
        """Fold one observation into the by-IP map, or the by-MAC map when the
        packet carried no usable source IP."""
        usable_ip = bool(ip) and ip != "0.0.0.0"  # nosec B104 # sentinel compare, not a bind address
        key_store, key = (self.by_ip, ip) if usable_ip else (self.by_mac, mac)
        if not key:
            return
        rec = key_store.setdefault(
            key, {"name": "", "fqdn": "", "os": "", "mac": "", "role": "", "sources": []}
        )
        for field_name, value in vals.items():
            if field_name == "source":
                if value and value not in rec["sources"]:
                    rec["sources"].append(value)
            elif value and not rec.get(field_name):
                rec[field_name] = value
        if mac and not rec["mac"]:
            rec["mac"] = mac

    def _feed_browser(self, pkt) -> None:
        from scapy.layers.inet import UDP

        if not pkt.haslayer(UDP):
            return
        udp = pkt[UDP]
        if 138 not in (int(udp.sport), int(udp.dport)):
            return
        raw = bytes(udp.payload)
        idx = raw.find(_BROWSE_MARK)
        if idx == -1:
            return
        body = raw[idx + len(_BROWSE_MARK):]
        # Only host/local-master announcements carry the host's own name; a domain
        # announcement names the domain, which must not be recorded as a host.
        if len(body) < _BROWSE_MIN_LEN or body[0] not in _HOST_ANNOUNCE_OPS:
            return

        name = _text(body[6:22].split(b"\x00")[0])
        if not name:
            return
        os_name = _os_label(body[22], body[23])
        role = _role(int.from_bytes(body[24:28], "little"))
        self._store(_ip_src(pkt), _eth_src(pkt),
                    name=name, os=os_name, role=role, source="NetBIOS Browser")

    def _feed_dhcp(self, pkt) -> None:
        from scapy.layers.dhcp import DHCP

        if not pkt.haslayer(DHCP):
            return
        name = fqdn = ""
        for opt in pkt[DHCP].options:
            if not isinstance(opt, tuple) or len(opt) < 2:
                continue
            if opt[0] == "hostname":
                name = _text(opt[1])
            elif opt[0] == "client_FQDN":
                fqdn = _fqdn(opt[1])
        if not name and not fqdn:
            return
        self._store(_ip_src(pkt), _eth_src(pkt),
                    name=name, fqdn=fqdn, source="DHCP")

    # ── reporting ───────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Host-name evidence for the synthesiser, keyed by IP and by MAC.

        Empty when the capture carried no Browser or DHCP name announcements.
        """
        if not self.by_ip and not self.by_mac:
            return {}
        return {"by_ip": self.by_ip, "by_mac": self.by_mac}


# ── helpers ──────────────────────────────────────────────────────────────────

def _text(value) -> str:
    """A scapy string/bytes field as a clean str, trailing NULs stripped."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("latin-1", "replace")
    return str(value).strip().strip("\x00").strip()


def _fqdn(value) -> str:
    """The host FQDN out of a DHCP option-81 Client-FQDN value.

    The option always begins with three control bytes (flags, RCODE1, RCODE2)
    before the name, so they are dropped unconditionally; a flags-only option
    (``\\x00\\xff\\xff``) then leaves nothing. What remains is reduced to the
    ASCII characters a DNS name can hold, which also discards the stray high
    bytes a flags-only value would otherwise smuggle through as letters.
    """
    if isinstance(value, (bytes, bytearray)):
        text = bytes(value)[3:].decode("latin-1", "replace")
    else:
        text = str(value)
    cleaned = "".join(
        ch for ch in text.strip().strip("\x00")
        if ch.isascii() and (ch.isalnum() or ch in ".-_")
    )
    return cleaned if any(ch.isalnum() for ch in cleaned) else ""


def _os_label(major, minor) -> str:
    """A readable OS family from the announced NT version, or '' if unknown."""
    try:
        key = (int(major), int(minor))
    except (TypeError, ValueError):
        return ""
    return _OS_NAMES.get(key, "")


def _role(server_type) -> str:
    """The host roles decoded from the Browser ServerType bitmask."""
    try:
        flags = int(server_type)
    except (TypeError, ValueError):
        return ""
    roles = [label for bit, label in _ROLE_FLAGS if flags & bit]
    return ", ".join(roles)


def _eth_src(pkt) -> str:
    from scapy.layers.l2 import Ether
    if pkt.haslayer(Ether):
        return str(pkt[Ether].src)
    return ""


def _ip_src(pkt) -> str:
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    if pkt.haslayer(IP):
        return str(pkt[IP].src)
    if pkt.haslayer(IPv6):
        return str(pkt[IPv6].src)
    return ""
