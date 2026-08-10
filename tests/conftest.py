"""
Shared pytest fixtures for PacketIQ tests.

Builds a deterministic synthetic attack PCAP that exercises every detector,
then runs the full analysis pipeline once and exposes the results.

Two of the guards below have to be installed here, at import, rather than as
fixtures: `rich` freezes a console's width when it builds one, which the display
module does at import; and pytest creates session-scoped fixtures *before* any
function-scoped autouse fixture, so the attack PCAP would otherwise be built
with the guards still off.
"""

import os
import random
import socket
import threading

# Rendered width, before anything can construct a `rich` console. See
# `fixed_terminal_width`.
os.environ["COLUMNS"] = "80"
os.environ["LINES"] = "25"

import pytest  # noqa: E402
from scapy.all import ICMP, IP, TCP, UDP, Ether, Raw, wrpcap  # noqa: E402
from scapy.config import conf as _scapy_conf  # noqa: E402
from scapy.fields import MACField as _MACField  # noqa: E402
from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.l2 import SourceMACField as _SourceMACField  # noqa: E402

from packetiq.correlation.engine import CorrelationEngine  # noqa: E402
from packetiq.detection.engine import DetectionEngine  # noqa: E402
from packetiq.extractor.data_extractor import DataExtractor  # noqa: E402
from packetiq.parser.pcap_parser import PCAPParser  # noqa: E402

# The MAC every frame is built with when the test did not specify one. The `02`
# in the first octet marks it locally administered, so it can never collide with
# a real vendor prefix and can never be mistaken for a device that exists.
FIXED_SOURCE_MAC = "02:00:00:00:00:01"
BROADCAST_MAC    = "ff:ff:ff:ff:ff:ff"

_scapy_conf.neighbor.__class__.resolve = (            # destination
    lambda self, l2inst, l3inst: BROADCAST_MAC)
_SourceMACField.i2h = (                               # source
    lambda self, pkt, x: _MACField.i2h(self, pkt, FIXED_SOURCE_MAC if x is None else x))

ATTACKER = "45.33.32.156"      # external
VICTIM   = "192.168.1.50"      # internal
C2       = "185.199.108.153"   # external
FTP_SRV  = "193.122.6.168"     # external
ICMP_DST = "188.114.96.3"      # external
RESOLVER = "8.8.8.8"


@pytest.fixture(autouse=True)
def isolate_analysis_history(tmp_path, monkeypatch):
    """Give every test its own analysis-history database.

    `storage._db_path()` falls back to ``~/.packetiq/history.db``, so any test that
    recorded an analysis without overriding ``PACKETIQ_DB`` wrote into the developer's
    real history — a full run added six fixture rows named `attack.pcap` to it. The
    same leak made coverage irreproducible: the web app renders a different branch once
    history is non-empty, so `webapp/app.py` swung by 14 statements between consecutive
    runs depending on what the previous run had left behind.

    Isolation is the default now rather than something each test has to remember. Tests
    that need a specific path still just set ``PACKETIQ_DB`` themselves; monkeypatch
    applies theirs after this one.
    """
    monkeypatch.setenv("PACKETIQ_DB", str(tmp_path / "history.db"))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Turn any use of a network service into a failed test.

    Deleting ``TELEGRAM_BOT_TOKEN`` from the environment does not unconfigure
    alerting: ``telegram.load_credentials`` also scans ``./.env`` and ``../.env``,
    so the "does not send without configuration" test found the developer's real
    bot token and POSTed the findings to a real chat on every local run. Nothing
    failed, because sending worked. The same silence made the coverage number
    machine-dependent — that request was the only thing exercising the alert
    formatter's MITRE block, which is why CI came up short.

    Loopback was originally left open, and that turned out to be the same trap one
    layer down. ``MultiProviderClient.available()`` and ``_ollama_probe()`` ask
    127.0.0.1:11434 whether a model is there, so on a workstation running
    ``ollama serve`` the suite silently took the *provider is available* branch of
    `packetiq chat` and really fired the web app's model warm-up. A CI runner has
    nothing listening, took the other branch, and came up 16 statements short.
    Nothing under test legitimately needs a listening service, so loopback is now
    blocked too and each of those paths is driven with a stub.

    Blocking at ``connect`` rather than at ``requests`` catches every client
    (requests, httpx, urllib, raw sockets) and every credential source. AF_UNIX
    stays open for anything that talks to a socket file.

    One exception, and it is the operating system rather than a client: Windows
    has no AF_UNIX socketpair, so ``socket.socketpair()`` there is emulated by
    binding a listener on 127.0.0.1 and connecting to it. Every asyncio event
    loop builds its self-pipe that way, which meant *starting a loop at all* —
    `asyncio.run`, every FastAPI `TestClient` — tripped this guard and failed 190
    tests on the Windows runner alone. The pair is allowed while, and only while,
    `socket.socketpair()` is running on this thread; it can never let a client
    request through.
    """
    real_connect = socket.socket.connect
    real_socketpair = socket.socketpair
    inside = threading.local()

    def guarded_connect(self, address, *args, **kwargs):
        if getattr(inside, "socketpair", False):
            return real_connect(self, address, *args, **kwargs)
        if self.family != getattr(socket, "AF_UNIX", object()):
            host = address[0] if isinstance(address, tuple) else address
            raise AssertionError(
                f"test attempted a network connection to {host!r}; stub the client "
                "at its boundary instead"
            )
        return real_connect(self, address, *args, **kwargs)

    def guarded_socketpair(*args, **kwargs):
        inside.socketpair = True
        try:
            return real_socketpair(*args, **kwargs)
        finally:
            inside.socketpair = False

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "socketpair", guarded_socketpair)


@pytest.fixture(autouse=True)
def no_real_packet_capture(monkeypatch):
    """Make opening a real capture socket a failed test.

    Whether a line is covered must not depend on whether the machine running the
    suite is allowed to capture. It did: this developer's Mac has been through
    ``packetiq setup-capture``, so the live-session tests started genuine loopback
    captures and covered the whole ``/api/live/*`` lifecycle for free. The Linux
    runner has no CAP_NET_RAW, the sniffer thread dies on the first read, and 20
    statements that look tested here were never executed there.

    Denying the socket makes that impossible to reintroduce: a live-capture test
    now has to supply its own sniffer, which is the only way its coverage can mean
    the same thing on every host. Everything else in the suite reads packets from
    a file and never comes near this.

    Only the *listening* sockets are denied. ``conf.L2socket``/``L3socket`` are the
    sending pair, and scapy reaches for them while merely building a packet — a BSD
    route lookup for an IPv6 destination opens one to ask the kernel which interface
    it would use — so blocking those breaks ordinary offline packet construction
    rather than any capture. What that construction actually needs is an answer to
    "which MAC is that address on?", and `fixed_link_layer_resolution` below supplies
    one without a socket.
    """
    from scapy.config import conf

    def denied(*args, **kwargs):
        raise AssertionError(
            "test attempted to open a real packet-capture socket; supply a fake "
            "sniffer instead so the result does not depend on capture privileges"
        )

    for attr in ("L2listen", "L3listen"):
        monkeypatch.setattr(conf, attr, denied, raising=False)


@pytest.fixture(autouse=True)
def fixed_link_layer_resolution(monkeypatch):
    """Answer "which MAC is that address on?" without asking the network.

    ``Ether()`` leaves its destination unset, and scapy fills it in while *building*
    the packet by resolving the layer-3 destination for real: an ARP request for
    IPv4, a neighbour solicitation for IPv6. That is a transmission on a live
    interface, from a test that never meant to send anything. This Mac has been
    through ``packetiq setup-capture`` so the account is in `access_bpf`, the
    solicitation went out on the LAN and the tests passed; the GitHub macOS runner
    cannot open /dev/bpf0, so building the very same packet raised Scapy_Exception
    and three IPv6 tests failed there and only there. Three, because scapy catches
    the failure for IPv4 and falls back to broadcast with a warning, and does not
    catch it for IPv6 — so the count of failures was never the count of frames
    being resolved on the wire.

    Pinning the answer to the broadcast address keeps construction offline and
    identical on every host. Broadcast is not an invention: it is exactly what scapy
    itself falls back to when resolution finds nothing, so it is what the Linux
    runners — which have no capture rights either — have been building all along.

    The *source* MAC is pinned for the same reason and is worse than host-dependent:
    scapy fills an unset `Ether().src` with the hardware address of `conf.iface`, so
    every frame the suite builds — and every fixture PCAP it writes — carried this
    machine's real MAC. On the Windows runner, where scapy has no usable interface
    without Npcap, that same lookup raises `ValueError: Interface ... not found` and
    took out five tests.

    Only packets whose MACs were left unspecified are affected; an explicit
    ``Ether(src=..., dst=...)`` never reaches a resolver, and neither does a packet read
    from a capture file, which carries the addresses that were actually on the wire.

    Both pins are installed at import (top of this file) because the session-scoped
    `attack_pcap` is built before any function-scoped fixture runs. Re-applying them
    per test is what undoes a test that patched scapy's fields for its own purposes.
    """
    monkeypatch.setattr(
        type(_scapy_conf.neighbor), "resolve", lambda self, l2inst, l3inst: BROADCAST_MAC
    )
    monkeypatch.setattr(
        _SourceMACField, "i2h",
        lambda self, pkt, x: _MACField.i2h(self, pkt, FIXED_SOURCE_MAC if x is None else x),
    )


@pytest.fixture(autouse=True)
def fixed_terminal_width(monkeypatch):
    """Render every table at the same width, whatever console the host has.

    `rich` sizes its tables from `os.get_terminal_size()`, so the terminal the
    suite happens to run in decides where a column wraps. A CI runner with no tty
    falls back to 80 columns; the Windows runner has a console attached and
    reports its own, which wrapped `PROTOCOL MISUSE` across two lines and failed
    two CLI tests that look for it. 80x25 is what the Linux and macOS legs have
    been rendering at all along, so pinning it changes nothing except who agrees.
    """
    monkeypatch.setenv("COLUMNS", "80")
    monkeypatch.setenv("LINES", "25")


# The interface list every test sees, in place of whatever NICs this machine has.
# One name per classification `_kind_for` can return, all suffixed `99` so none of
# them can collide with a real adapter (and therefore with scapy's `conf.iface`,
# which decides the `is_default` flag).
FIXED_INTERFACES = (
    "lo99",       # loopback
    "eth99",      # ethernet
    "wl99",       # wifi
    "ww99",       # wwan
    "utun99",     # vpn
    "bridge99",   # bridge
    "awdl99",     # system
    "docker99",   # virtual
    "zzz99",      # other — matches no prefix
)


@pytest.fixture(autouse=True)
def fixed_interface_table(monkeypatch):
    """Enumerate a fixed interface list instead of the machine's real NICs.

    `net_interfaces.list_interfaces()` ranks whatever the OS reports, so which of
    its branches run is decided by the hardware. This Mac has four bridge-kind
    adapters (bridge0 plus the Thunderbolt members), so the `bridge` arm of
    `_score` ran on every local run; a Linux runner has `lo` and `eth0` and never
    reached it. The suite looked complete and CI stopped one statement short.

    Pinning the list keeps every ranking, labelling and classification branch
    reachable on any host, and keeps it reachable for the same reason everywhere.
    Only the *names* are fixed: the metadata lookup, the macOS `networksetup` /
    `ifconfig` helpers and the Linux `sysfs` read still run for real and simply
    find nothing for these names, which is itself the same on every machine.

    Tests that need a particular table still stub `_scapy_metadata` (or
    `list_interfaces`) directly; monkeypatch applies theirs after this one.
    """
    import scapy.all as scapy_all

    monkeypatch.setattr(scapy_all, "get_if_list", lambda: list(FIXED_INTERFACES))


def _build_attack_pcap(path: str):
    random.seed(7)
    pkts = []
    t = 1700000000.0

    def add(p, ts):
        p.time = ts
        pkts.append(p)

    # SSH brute force
    for i in range(40):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + i, dport=22, flags="S"), t + i)
    t += 70
    # Vertical port scan
    for i, port in enumerate(range(1, 70)):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=50000 + i, dport=port, flags="S"), t + i * 0.1)
    t += 30
    # Horizontal host scan on 445
    for i in range(25):
        add(Ether() / IP(src=ATTACKER, dst=f"192.168.1.{100 + i}") / TCP(sport=51000 + i, dport=445, flags="S"), t + i * 0.1)
    t += 30
    # XMAS scan (FIN+PSH+URG)
    for i in range(3):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=54000 + i, dport=81 + i, flags="FPU"), t + i * 0.1)
    t += 10
    # C2 beacon to external every 30s
    for i in range(16):
        add(Ether() / IP(src=VICTIM, dst=C2) / TCP(sport=52000, dport=443, flags="S"), t + i * 30 + random.uniform(-0.3, 0.3))
    t += 16 * 30 + 10
    # DNS tunneling (oversized names)
    for i in range(6):
        label = "".join(random.choice("0123456789abcdef") for _ in range(60))
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=33000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example-evil.xyz")), t + i * 2)
    t += 20
    # Normal DNS (must not be flagged as DGA)
    for d in ("google.com", "github.com", "cloudflare.com"):
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=35000, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=d)), t)
        t += 1
    # ICMP tunneling
    for i in range(130):
        add(Ether() / IP(src=VICTIM, dst=ICMP_DST) / ICMP() / Raw(load=b"X" * 1000), t + i * 0.2)
    t += 30
    # Cleartext FTP creds to external
    add(Ether() / IP(src=VICTIM, dst=FTP_SRV) / TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"), t); t += 1
    add(Ether() / IP(src=VICTIM, dst=FTP_SRV) / TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"PASS hunter2\r\n"), t); t += 1

    wrpcap(path, pkts)
    return path


@pytest.fixture(scope="session")
def attack_pcap(tmp_path_factory):
    path = tmp_path_factory.mktemp("pcaps") / "attack.pcap"
    return _build_attack_pcap(str(path))


@pytest.fixture(scope="session")
def pipeline(attack_pcap):
    """Run the full pipeline once and return (result, events, risk, chains)."""
    parser = PCAPParser(attack_pcap)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    result = extractor.finalize()
    events, risk, fps = DetectionEngine().run(result, attack_pcap)
    chains = CorrelationEngine().correlate(events)
    return {"result": result, "events": events, "risk": risk, "chains": chains, "fps": fps}
