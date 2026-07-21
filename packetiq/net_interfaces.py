"""
Cross-platform network-interface enumeration for live capture.

Wireshark shows a *live* list of capture interfaces with friendly names and a
link-status indicator, and it re-scans continuously so a NIC you plug in appears
without a restart. This module gives PacketIQ the same raw material: for every
interface currently visible to the OS it returns a small record with a friendly
label, IPv4 address, MAC, link/up state and a "kind" classification, sorted so
the interface a user most likely wants to capture on comes first.

Everything here is strictly best-effort. Each enrichment source (scapy, the
macOS ``networksetup``/``ifconfig`` tools, the Linux ``sysfs`` operstate file)
is optional and any failure degrades to *less* metadata — never an exception —
so the web UI and CLI always get at least the bare interface names.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess  # nosec B404 - only fixed, argument-list OS queries below (no shell)
import sys
import threading

# Serialises scapy's ``conf.ifaces.reload()`` (a clear-then-repopulate on a shared
# dict) so concurrent web-poll threads can't observe a half-rebuilt list.
_RELOAD_LOCK = threading.Lock()

# Interface-name prefixes → coarse "kind". Used for the icon/label and to rank
# real NICs above virtual/system plumbing when nothing better is known.
_KIND_PREFIXES = (
    ("lo", "loopback"),
    ("eth", "ethernet"),
    ("en", "ethernet"),      # macOS Wi-Fi is also enX; friendly name refines this
    ("wl", "wifi"),          # Linux wlan0 / wlp*
    ("ww", "wwan"),
    ("utun", "vpn"), ("tun", "vpn"), ("tap", "vpn"), ("ppp", "vpn"),
    ("ipsec", "vpn"), ("wg", "vpn"),
    ("bridge", "bridge"), ("br-", "bridge"), ("br", "bridge"),
    ("awdl", "system"), ("llw", "system"), ("anpi", "system"),
    ("ap", "system"), ("gif", "system"), ("stf", "system"),
    ("vmnet", "virtual"), ("vboxnet", "virtual"), ("docker", "virtual"),
    ("veth", "virtual"), ("vnic", "virtual"),
)


def _run(cmd: list, timeout: float = 4.0) -> str:
    """Run a fixed OS query command and return stdout, or '' on any problem.

    The binary is resolved with ``shutil.which`` so we pass an absolute path and
    never invoke a shell; ``cmd`` is a constant argument list with no user input.
    """
    exe = shutil.which(cmd[0])
    if not exe:
        return ""
    try:
        out = subprocess.run(  # nosec B603 - resolved absolute path, constant args, no shell, no user input
            [exe, *cmd[1:]], capture_output=True, text=True, timeout=timeout
        )
        return out.stdout or ""
    except Exception:
        return ""


def _kind_for(name: str, friendly: str = "") -> str:
    """Best-effort classification from the friendly name, then the OS name."""
    f = (friendly or "").lower()
    if "wi-fi" in f or "wifi" in f or "airport" in f or "wireless" in f:
        return "wifi"
    if "thunderbolt" in f or "bridge" in f:
        return "bridge"
    if "bluetooth" in f:
        return "system"
    if "ethernet" in f or "lan" in f or "usb" in f:
        return "ethernet"
    n = name.lower()
    for prefix, kind in _KIND_PREFIXES:
        if n == prefix or n.startswith(prefix):
            return kind
    return "other"


def _macos_friendly_names() -> dict:
    """device (enX) -> friendly hardware-port name, via ``networksetup``."""
    names: dict = {}
    out = _run(["networksetup", "-listallhardwareports"])
    port = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and port:
            dev = line.split(":", 1)[1].strip()
            if dev:
                names[dev] = port
            port = None
    return names


def _macos_link_status() -> dict:
    """device -> True/False (active link), parsed from a single ``ifconfig`` call.

    Interfaces without a ``status:`` line (many virtual ones) are simply absent
    from the map, which callers read as "unknown".
    """
    status: dict = {}
    out = _run(["ifconfig"])
    cur = None
    for line in out.splitlines():
        if line and not line[0].isspace():
            cur = line.split(":", 1)[0].strip()
        elif cur and "status:" in line:
            status[cur] = "status: active" in line
    return status


def _linux_link_up(dev: str) -> bool | None:
    """Read /sys/class/net/<dev>/operstate. None when it can't be determined."""
    try:
        with open(f"/sys/class/net/{dev}/operstate", encoding="ascii") as fh:
            state = fh.read().strip().lower()
    except OSError:
        return None
    if state == "up":
        return True
    if state in ("down", "lowerlayerdown"):
        return False
    return None  # "unknown" (e.g. loopback, or driver doesn't report)


def _rescan_scapy(conf) -> None:
    """Force scapy to re-enumerate the OS interfaces (Wireshark-style live scan).

    scapy populates ``conf.ifaces`` once and then caches it, so an interface that
    appears *after* import — e.g. a USB LAN adapter plugged in while the web app
    is already running — is invisible to ``get_if_list()`` until a reload. That is
    exactly why Wireshark (which re-scans the OS every time) shows such a NIC while
    a long-running PacketIQ process does not.

    This triggers the reload, but only where it can *only help*:
      * reload only when a provider is registered — a half-initialised ``conf``
        has none, and ``reload()`` would then *clear* the interface list;
      * under a lock, so concurrent web polls don't race on the shared dict;
      * any failure is swallowed, leaving the existing cached list intact.
    """
    with contextlib.suppress(Exception):
        ifaces = getattr(conf, "ifaces", None)
        if ifaces is not None and getattr(ifaces, "providers", None):
            with _RELOAD_LOCK:
                ifaces.reload()


def _scapy_metadata() -> tuple:
    """(name->{ip,mac,flags,description}, names_list, default_name). Best effort.

    Every step degrades to partial data (explicit ``return``/``continue``) rather
    than raising, so a quirk in one interface's record never blanks the whole list.
    """
    meta: dict = {}
    names: list = []
    try:
        from scapy.all import get_if_list
        from scapy.config import conf
        # The first call also forces scapy's lazy init + provider registration,
        # so we always have a valid name list even if the re-scan below fails.
        names = list(get_if_list())
    except Exception:
        return meta, names, None  # scapy unavailable → caller still gets bare names elsewhere

    # Re-scan the live OS interface table so a NIC attached after this process
    # started (the reason a USB LAN can show in Wireshark but not here) appears.
    _rescan_scapy(conf)
    with contextlib.suppress(Exception):
        names = list(get_if_list())

    default = str(conf.iface) if getattr(conf, "iface", None) else None
    data = getattr(getattr(conf, "ifaces", None), "data", None) or {}
    unspecified = "0.0.0.0"  # nosec B104 - the no-IP value we FILTER OUT, never a bind target
    for key, iface in list(data.items()):
        with contextlib.suppress(Exception):  # a quirk in one record must not blank the list
            nm = getattr(iface, "name", None) or key
            ip = getattr(iface, "ip", None)
            meta[nm] = {
                "ip": ip if ip and ip != unspecified else "",
                "mac": (getattr(iface, "mac", None) or "").strip(),
                "flags": str(getattr(iface, "flags", "") or ""),
                "description": (getattr(iface, "description", None) or "").strip(),
            }
    return meta, names, default


def _score(rec: dict) -> tuple:
    """Sort key (higher first): live NICs with an IP win, system plumbing loses."""
    s = 0
    if rec["up"] is True:
        s += 100
    if rec["ip"]:
        s += 50
    if rec["is_default"]:
        s += 40
    kind = rec["kind"]
    if kind in ("ethernet", "wifi"):
        s += 20
    elif kind == "bridge":
        s += 5
    elif kind == "loopback":
        s -= 10
    elif kind == "vpn":
        s -= 5
    elif kind in ("system", "virtual"):
        s -= 20
    if rec["up"] is False:
        s -= 15
    # Negate score for ascending sort, tiebreak on name for stability.
    return (-s, rec["name"])


def list_interfaces() -> list:
    """Return rich, best-first interface records for the live-capture picker.

    Each record: ``{name, label, ip, mac, kind, up, is_default, recommended}``
    where ``up`` is ``True``/``False``/``None`` (unknown). Exactly one record is
    flagged ``recommended`` when a sensible default exists.
    """
    meta, names, default = _scapy_metadata()

    plat = "mac" if sys.platform == "darwin" else (
        "linux" if sys.platform.startswith("linux") else (
            "windows" if sys.platform == "win32" else "other"))

    friendly_map: dict = {}
    link_map: dict = {}
    if plat == "mac":
        friendly_map = _macos_friendly_names()
        link_map = _macos_link_status()

    records = []
    for name in names:
        m = meta.get(name, {})
        friendly = friendly_map.get(name) or m.get("description") or ""
        # scapy on macOS sets description == name (useless); treat that as blank.
        if friendly == name:
            friendly = friendly_map.get(name, "")

        if plat == "mac":
            up = link_map.get(name)             # True/False, or None if no status line
        elif plat == "linux":
            up = _linux_link_up(name)
        else:
            up = None
        if up is None and "RUNNING" in m.get("flags", "") and m.get("ip"):
            up = True  # has an address and the driver is running → treat as up

        kind = _kind_for(name, friendly)
        label = friendly or ("Loopback" if kind == "loopback" else name)

        records.append({
            "name": name,
            "label": label,
            "ip": m.get("ip", ""),
            "mac": m.get("mac", ""),
            "kind": kind,
            "up": up,
            "is_default": name == default,
            "recommended": False,
        })

    records.sort(key=_score)

    # Recommend the first interface that is up *and* has an IP; otherwise the
    # scapy default; otherwise the top-ranked entry. Loopback is never auto-picked.
    pick = next((r for r in records
                 if r["up"] is True and r["ip"] and r["kind"] != "loopback"), None)
    if pick is None:
        pick = next((r for r in records if r["is_default"]), None)
    if pick is None:
        pick = next((r for r in records if r["kind"] != "loopback"), None)
    if pick is None and records:
        pick = records[0]
    if pick is not None:
        pick["recommended"] = True

    return records
