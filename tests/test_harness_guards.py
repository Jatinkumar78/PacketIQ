"""The conftest guards, asserted rather than assumed.

Each guard exists because something about the machine — a real bot token,
capture rights, a running Ollama, a Thunderbolt bridge, a NIC's hardware
address, the width of a terminal — quietly changed what the suite did, and the
difference only showed up as a CI failure hours later. A guard that silently
stops applying recreates exactly that situation, and on the machine where it
matters least: the workstation that has the privilege in the first place.

So the guards are tested here. These assertions cost nothing and fail loudly on
any host where a guard has been removed, reordered out of effect, or broken by a
scapy or rich upgrade.
"""

import asyncio
import os
import socket

import pytest
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from .conftest import FIXED_INTERFACES, FIXED_SOURCE_MAC


def test_each_test_gets_its_own_history_database(tmp_path):
    """`isolate_analysis_history`: no test writes into the developer's history."""
    assert os.environ["PACKETIQ_DB"] == str(tmp_path / "history.db")


def test_an_outbound_connection_is_refused():
    """`no_network`: no credential source, no provider probe, no real request."""
    with pytest.raises(AssertionError, match="network connection"):
        socket.socket().connect(("192.0.2.1", 80))


def test_an_event_loop_can_still_start():
    """`no_network` again, from the other side: the guard must not block asyncio.

    Windows has no AF_UNIX socketpair, so every event loop's self-pipe is a real
    127.0.0.1 connection. Refusing it took out 190 tests on that runner — every
    `asyncio.run` and every `TestClient` — without a single one of them going
    anywhere near a network.
    """
    assert asyncio.run(asyncio.sleep(0, result="loop started")) == "loop started"


def test_opening_a_capture_socket_is_refused():
    """`no_real_packet_capture`: coverage must not depend on capture rights."""
    from scapy.config import conf

    for attr in ("L2listen", "L3listen"):
        with pytest.raises(AssertionError, match="packet-capture socket"):
            getattr(conf, attr)()


def test_the_interface_table_is_the_fixed_one():
    """`fixed_interface_table`: ranking branches must not depend on the hardware."""
    from scapy.all import get_if_list

    assert tuple(get_if_list()) == FIXED_INTERFACES


def test_building_a_packet_resolves_no_address_on_the_network():
    """`fixed_link_layer_resolution`: an unset destination MAC comes from nowhere.

    Left to itself scapy answers this with an ARP request or a neighbour
    solicitation on a live interface. The bytes below must be produced with the
    machine's network stack untouched, which is what makes them the same bytes on
    a runner that is not allowed to transmit at all.
    """
    from scapy.config import conf

    pkt = Ether() / IPv6(src="fd00::1", dst="fd00::50")
    # The resolver itself, and not merely its effect: unguarded it answers `None`
    # after a solicitation times out, which the broadcast fallback then hides. On a
    # host that may not transmit at all it does not answer — it raises, and that is
    # the shape this took on the macOS runner.
    assert conf.neighbor.resolve(pkt, pkt.payload) == "ff:ff:ff:ff:ff:ff"
    assert bytes(pkt)[:6] == b"\xff" * 6


def test_a_frame_carries_the_fixed_source_mac():
    """`fixed_link_layer_resolution`: and the source address comes from nowhere too.

    Unguarded, scapy fills an unset `Ether().src` from `conf.iface`, so every
    frame the suite builds — and every fixture capture it writes — carried the
    hardware address of whichever machine ran it.
    """
    frame = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2"))
    assert ":".join(f"{b:02x}" for b in frame[6:12]) == FIXED_SOURCE_MAC


def test_tables_render_at_a_fixed_width():
    """`fixed_terminal_width`: a wrapped column must not depend on the console.

    The width is frozen when `rich` builds a console, which the display module
    does at import, so this asserts the console the CLI actually renders through
    rather than one built here.
    """
    from packetiq.display import terminal

    assert terminal.console.size.width == 80
