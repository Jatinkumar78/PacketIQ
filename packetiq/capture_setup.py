"""
One-time live-capture privilege setup.

Raw packet capture requires elevated rights on every OS. Rather than making the
user run the whole app with sudo on every launch, this performs the *standard,
one-time* OS setup so capture then works as a normal user:

  - macOS  : install a ChmodBPF launch daemon (the same approach Wireshark uses)
             that grants the `access_bpf` group access to /dev/bpf*, and add the
             current user to that group. Uses one GUI admin-password prompt.
  - Linux  : grant CAP_NET_RAW/CAP_NET_ADMIN to the Python interpreter via setcap
             (one sudo prompt).
  - Windows: capture is provided by Npcap; report whether it's installed and how
             to enable non-admin capture.

`status()` reports whether capture already works (no changes made).
`setup()` performs the one-time grant.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


def platform_name() -> str:
    if sys.platform == "darwin":
        return "mac"
    if os.name == "nt":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return "other"


# ── status ────────────────────────────────────────────────────────────────────

def _mac_capture_ok() -> bool:
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True
        import grp
        gids = set(os.getgroups())
        for g in grp.getgrall():
            if g.gr_name == "access_bpf" and g.gr_gid in gids:
                # group membership AND a readable bpf device
                for i in range(4):
                    dev = f"/dev/bpf{i}"
                    if os.path.exists(dev) and os.access(dev, os.R_OK):
                        return True
                return True   # in group; perms applied on next bpf device
    except Exception:
        pass
    return False


def _linux_capture_ok() -> bool:
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return True
        py = os.path.realpath(sys.executable)
        out = subprocess.run(["getcap", py], capture_output=True, text=True, timeout=5)
        return "cap_net_raw" in (out.stdout or "")
    except Exception:
        return False


def _windows_capture_ok() -> bool:
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
    except Exception:
        pass
    # Npcap installed?  (non-admin capture is possible if installed that way)
    return _npcap_installed()


def _npcap_installed() -> bool:
    for p in (r"C:\Windows\System32\Npcap", r"C:\Windows\SysWOW64\Npcap",
              r"C:\Program Files\Npcap"):
        if Path(p).exists():
            return True
    return False


def status() -> tuple[bool, str, str]:
    """Return (capture_ok, platform, human_detail) — makes no changes."""
    plat = platform_name()
    if plat == "mac":
        ok = _mac_capture_ok()
        return ok, plat, ("Live capture is enabled (you're in the access_bpf group)."
                          if ok else "Live capture not yet enabled.")
    if plat == "linux":
        ok = _linux_capture_ok()
        return ok, plat, ("Python has CAP_NET_RAW — live capture is enabled."
                          if ok else "Live capture not yet enabled.")
    if plat == "windows":
        ok = _windows_capture_ok()
        return ok, plat, ("Npcap present / running as Administrator."
                          if ok else "Npcap not detected.")
    return False, plat, "Unsupported platform for live capture."


# ── setup ───────────────────────────────────────────────────────────────────

_CHMODBPF = """#!/bin/sh
# PacketIQ ChmodBPF — grant the access_bpf group access to the BPF capture devices.
syslog -s -l notice "PacketIQ ChmodBPF: setting permissions on /dev/bpf*"
if ! /usr/bin/dscl . -read /Groups/access_bpf >/dev/null 2>&1; then
  /usr/sbin/dseditgroup -q -o create access_bpf
fi
/usr/sbin/chown :access_bpf /dev/bpf* 2>/dev/null || true
/bin/chmod g+rw /dev/bpf* 2>/dev/null || true
"""

_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>org.packetiq.ChmodBPF</string>
  <key>RunAtLoad</key><true/>
  <key>Program</key><string>/Library/Application Support/PacketIQ/ChmodBPF/ChmodBPF</string>
</dict></plist>
"""


def _mac_setup() -> tuple[bool, str]:
    import re
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    # The username is interpolated into a shell script run with administrator
    # privileges; reject anything outside a safe charset to prevent command
    # injection via a tampered $USER/$LOGNAME (CWE-78, defence in depth).
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", user):
        return False, "Could not determine a safe username for capture setup."
    support = "/Library/Application Support/PacketIQ/ChmodBPF"
    plist = "/Library/LaunchDaemons/org.packetiq.ChmodBPF.plist"
    # Build a privileged shell script and run it once via a GUI admin prompt.
    script = f"""
set -e
mkdir -p '{support}'
cat > '{support}/ChmodBPF' <<'EOS'
{_CHMODBPF}EOS
chmod 755 '{support}/ChmodBPF'
cat > '{plist}' <<'EOS'
{_PLIST}EOS
chmod 644 '{plist}'
launchctl unload '{plist}' 2>/dev/null || true
launchctl load '{plist}'
'{support}/ChmodBPF'
dseditgroup -o edit -a '{user}' -t user access_bpf 2>/dev/null || true
"""
    # osascript shows a native admin-password dialog (no terminal needed)
    osa = ('do shell script "' + script.replace("\\", "\\\\").replace('"', '\\"')
           + '" with administrator privileges')
    try:
        r = subprocess.run(["osascript", "-e", osa], capture_output=True, text=True, timeout=120)
    except Exception as e:  # noqa: BLE001
        return False, f"Setup failed to launch: {e}"
    if r.returncode != 0:
        err = (r.stderr or "").strip()
        if "User canceled" in err or "-128" in err:
            return False, "Cancelled — no changes made."
        return False, f"Setup failed: {err[:200]}"
    return True, ("✓ Live capture enabled via ChmodBPF. You may need to log out/in once "
                  "for group membership to take full effect; new captures work immediately.")


def _linux_setup() -> tuple[bool, str]:
    py = os.path.realpath(sys.executable)
    if not shutil.which("setcap"):
        return False, ("`setcap` not found. Install libcap (e.g. `sudo apt install libcap2-bin`), "
                       "then re-run `packetiq setup-capture`.")
    cmd = ["setcap", "cap_net_raw,cap_net_admin+eip", py]
    runner = ["sudo"] if shutil.which("sudo") else []
    try:
        r = subprocess.run(runner + cmd, capture_output=True, text=True, timeout=120)
    except Exception as e:  # noqa: BLE001
        return False, f"setcap failed: {e}"
    if r.returncode != 0:
        return False, f"setcap failed: {(r.stderr or '').strip()[:200]}"
    return True, f"✓ Granted CAP_NET_RAW to {py}. Live capture now works without sudo."


def setup() -> tuple[bool, str]:
    """Perform the one-time capture-privilege setup for the current OS."""
    ok, plat, _ = status()
    if ok:
        return True, "Live capture is already enabled — nothing to do."
    if plat == "mac":
        return _mac_setup()
    if plat == "linux":
        return _linux_setup()
    if plat == "windows":
        if _npcap_installed():
            return False, ("Npcap is installed. For non-admin capture, reinstall Npcap with the "
                           "'Restrict to Administrators' option UNCHECKED, or run PacketIQ as Administrator.")
        return False, ("Install Npcap from https://npcap.com (enable 'Support raw 802.11' is optional). "
                       "Then run PacketIQ as Administrator, or reinstall Npcap allowing non-admin capture.")
    return False, "Live capture isn't supported on this platform."
