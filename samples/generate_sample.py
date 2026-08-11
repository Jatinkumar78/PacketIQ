#!/usr/bin/env python3
"""
Generate a realistic demo PCAP for PacketIQ.

This builds a *synthetic* capture (no real traffic is sent anywhere, and no
real hardware address is ever read from this machine) that deliberately
contains the behaviours PacketIQ detects, so you can try the tool immediately:

    python samples/generate_sample.py
    packetiq analyze samples/demo_attack.pcap
    packetiq webapp           # then upload samples/demo_attack.pcap

The scenario: an external attacker (45.33.32.156) recons and brute-forces an
internal host (192.168.1.50), which then beacons to an external C2, tunnels
data out over DNS/ICMP, and leaks FTP credentials in cleartext.

Vantage point
-------------
The capture is taken *inside* the 192.168.1.0/24 LAN, on a span port of the
access switch. That single choice decides every Ethernet header here:

  • A host on the monitored segment transmits from its own NIC, so its frames
    carry its own MAC.
  • Every off-LAN address is reached through the router, so all external
    traffic — the attacker, the C2, the resolver — carries the router's MAC.
    PacketIQ is expected to notice one NIC fronting many addresses and call it
    a gateway; that is the correct forensic reading of this segment.
  • The horizontal SMB sweep probes 25 addresses. Two of them answer and are
    therefore real devices; the other 23 never transmit, so no MAC is ever
    learned for them and PacketIQ must not draw them as hosts. Frames to those
    addresses carry the broadcast destination rather than an invented NIC.

Both directions of every conversation are present, because a capture in which
40 SSH SYNs draw no response and 130 ICMP echo requests draw no reply is not a
capture of anything real — and the return frames are what prove which hosts
exist and which ports are genuinely open.

Addresses
---------
All IP addresses are written only into the capture file — nothing is
transmitted over the network. Every MAC address is locally administered (the
first octet's 0x02 bit is set), which is the one range the IEEE guarantees is
never assigned to a manufacturer: these frames cannot collide with, or imply
anything about, any real vendor's hardware. PacketIQ's own OUI lookup declines
to name a vendor for them, which is the honest result for synthetic data.
"""

import os
import random

from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR

random.seed(1337)  # deterministic output

# Public (non-reserved) addresses used purely as labels inside the pcap.
ATTACKER = "45.33.32.156"
VICTIM   = "192.168.1.50"
C2       = "185.199.108.153"
FTP_SRV  = "193.122.6.168"
ICMP_DST = "188.114.96.3"
RESOLVER = "8.8.8.8"
WEB_SRV  = "93.184.216.34"

# The monitored segment, and the two swept addresses that actually answer.
LAN      = "192.168.1."
GATEWAY  = "192.168.1.1"
FILE_SRV = "192.168.1.100"
PRINTER  = "192.168.1.110"

# Locally administered MACs (0x02 bit set) — never a real vendor's OUI. The
# last octets echo each host's final IP octet so the inventory reads clearly.
BROADCAST = "ff:ff:ff:ff:ff:ff"
NIC = {
    GATEWAY:  "02:00:00:00:00:01",
    VICTIM:   "02:00:00:00:00:50",
    FILE_SRV: "02:00:00:00:01:00",
    PRINTER:  "02:00:00:00:01:10",
}

OUT = os.path.join(os.path.dirname(__file__), "demo_attack.pcap")


def mac_of(ip: str) -> str:
    """The MAC that carries this address's frames on the monitored segment.

    A host on the segment uses its own NIC. Anything off-LAN is reached through
    the router, so it inherits the router's MAC. A LAN address that never
    transmitted has no learned MAC at all, so frames to it go to the broadcast
    destination — an address that was only ever probed must not be handed a
    hardware identity it never proved it had.
    """
    if ip in NIC:
        return NIC[ip]
    return BROADCAST if ip.startswith(LAN) else NIC[GATEWAY]


def eth(src_ip: str, dst_ip: str) -> Ether:
    """An Ethernet header addressed the way this segment would really carry it."""
    return Ether(src=mac_of(src_ip), dst=mac_of(dst_ip))


def build():
    pkts = []
    t = 1700000000.0

    def add(pkt, ts):
        pkt.time = ts
        pkts.append(pkt)

    def ip_pkt(src, dst, payload, ts):
        add(eth(src, dst) / IP(src=src, dst=dst) / payload, ts)

    # 1) SSH brute force: 40 rapid SYNs to victim:22, each answered — port 22 is
    #    open, which is why the attacker keeps hammering it.
    for i in range(40):
        ip_pkt(ATTACKER, VICTIM, TCP(sport=40000 + i, dport=22, flags="S"), t + i)
        ip_pkt(VICTIM, ATTACKER, TCP(sport=22, dport=40000 + i, flags="SA", ack=1), t + i + 0.002)
    t += 70

    # 2) Vertical port scan: attacker -> victim, many ports. The victim refuses
    #    every closed port and completes the handshake on the two that are open,
    #    so the scan result is proven rather than assumed from the port number.
    open_ports = {21, 22}
    for i, port in enumerate(range(1, 70)):
        ts = t + i * 0.1
        ip_pkt(ATTACKER, VICTIM, TCP(sport=50000 + i, dport=port, flags="S"), ts)
        flags = "SA" if port in open_ports else "RA"
        ip_pkt(VICTIM, ATTACKER, TCP(sport=port, dport=50000 + i, flags=flags, ack=1), ts + 0.002)
    t += 30

    # 3) Horizontal host scan: attacker -> 25 hosts on SMB/445. Two answer; the
    #    remaining 23 addresses never transmit a frame in this capture and are
    #    therefore not devices, however many times they were asked about.
    for i in range(25):
        host = f"192.168.1.{100 + i}"
        ts = t + i * 0.1
        ip_pkt(ATTACKER, host, TCP(sport=51000 + i, dport=445, flags="S"), ts)
        if host in (FILE_SRV, PRINTER):
            ip_pkt(host, ATTACKER, TCP(sport=445, dport=51000 + i, flags="SA", ack=1), ts + 0.002)
    t += 30

    # 4) XMAS scan packets (FIN+PSH+URG) attacker -> victim, on closed ports.
    for i in range(3):
        ts = t + i * 0.1
        ip_pkt(ATTACKER, VICTIM, TCP(sport=54000 + i, dport=81 + i, flags="FPU"), ts)
        ip_pkt(VICTIM, ATTACKER, TCP(sport=81 + i, dport=54000 + i, flags="RA", ack=1), ts + 0.002)
    t += 10

    # 5) C2 beacon: victim -> external C2 every ~30s, low jitter, answered.
    for i in range(16):
        ts = t + i * 30 + random.uniform(-0.4, 0.4)  # nosec B311 - synthetic demo-capture jitter, not cryptographic
        ip_pkt(VICTIM, C2, TCP(sport=52000, dport=443, flags="S"), ts)
        ip_pkt(C2, VICTIM, TCP(sport=443, dport=52000, flags="SA", ack=1), ts + 0.03)
    t += 16 * 30 + 10

    # 6) DNS tunneling: oversized query names from victim, answered by the
    #    tunnel's authoritative server.
    for i in range(6):
        label = "".join(random.choice("0123456789abcdef") for _ in range(60))  # nosec B311 - synthetic demo-capture data, not cryptographic
        qname = f"{label}.exfil.example-evil.xyz"
        qid = 0x4000 + i
        ip_pkt(VICTIM, RESOLVER, UDP(sport=33000 + i, dport=53) /
               DNS(id=qid, rd=1, qd=DNSQR(qname=qname)), t + i * 2)
        ip_pkt(RESOLVER, VICTIM, UDP(sport=53, dport=33000 + i) /
               DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=qname),
                   an=DNSRR(rrname=qname, ttl=60, rdata="203.0.113.7")), t + i * 2 + 0.01)
    t += 20

    # 7) DGA-style domains from victim (high-entropy second-level labels). Most
    #    of a DGA's guesses are unregistered, so the resolver says NXDOMAIN.
    for i in range(5):
        label = "".join(random.choice("bcdfghjklmnpqrstvwxyz0123456789") for _ in range(18))  # nosec B311 - synthetic demo-capture data, not cryptographic
        qname = f"{label}.top"
        qid = 0x5000 + i
        ip_pkt(VICTIM, RESOLVER, UDP(sport=34000 + i, dport=53) /
               DNS(id=qid, rd=1, qd=DNSQR(qname=qname)), t + i * 2)
        ip_pkt(RESOLVER, VICTIM, UDP(sport=53, dport=34000 + i) /
               DNS(id=qid, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=qname)), t + i * 2 + 0.01)
    t += 20

    # 8) Normal DNS (should NOT be flagged)
    benign = {"google.com": "142.250.72.206", "github.com": "140.82.121.4",
              "cloudflare.com": "104.16.132.229", "microsoft.com": "20.70.246.20"}
    for i, (d, answer) in enumerate(benign.items()):
        qid = 0x6000 + i
        ip_pkt(VICTIM, RESOLVER, UDP(sport=35000, dport=53) /
               DNS(id=qid, rd=1, qd=DNSQR(qname=d)), t)
        ip_pkt(RESOLVER, VICTIM, UDP(sport=53, dport=35000) /
               DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=d),
                   an=DNSRR(rrname=d, ttl=300, rdata=answer)), t + 0.01)
        t += 1

    # 9) ICMP tunneling: large ICMP volume victim -> external, echoed back.
    for i in range(130):
        ts = t + i * 0.2
        payload = Raw(load=b"X" * 1000)
        ip_pkt(VICTIM, ICMP_DST, ICMP(type=8, id=0x1337, seq=i) / payload, ts)
        ip_pkt(ICMP_DST, VICTIM, ICMP(type=0, id=0x1337, seq=i) / payload, ts + 0.02)
    t += 30

    # 10) Cleartext FTP credentials victim -> external FTP server, with the
    #     server's replies — the 230 is what proves the stolen login worked.
    #     The handshake comes first, as it must: the side that sends the opening
    #     SYN is the client, and that is how the session's direction is known.
    ip_pkt(VICTIM, FTP_SRV, TCP(sport=53500, dport=21, flags="S"), t); t += 0.05
    ip_pkt(FTP_SRV, VICTIM, TCP(sport=21, dport=53500, flags="SA", ack=1), t); t += 0.05
    ip_pkt(VICTIM, FTP_SRV, TCP(sport=53500, dport=21, flags="A", ack=1), t); t += 0.9
    ip_pkt(FTP_SRV, VICTIM, TCP(sport=21, dport=53500, flags="PA") /
           Raw(load=b"220 (vsFTPd 3.0.3)\r\n"), t); t += 1
    ip_pkt(VICTIM, FTP_SRV, TCP(sport=53500, dport=21, flags="PA") /
           Raw(load=b"USER admin\r\n"), t); t += 1
    ip_pkt(FTP_SRV, VICTIM, TCP(sport=21, dport=53500, flags="PA") /
           Raw(load=b"331 Please specify the password.\r\n"), t); t += 1
    ip_pkt(VICTIM, FTP_SRV, TCP(sport=53500, dport=21, flags="PA") /
           Raw(load=b"PASS S3cr3tP@ss!\r\n"), t); t += 1
    ip_pkt(FTP_SRV, VICTIM, TCP(sport=21, dport=53500, flags="PA") /
           Raw(load=b"230 Login successful.\r\n"), t); t += 1

    # 11) A little benign HTTP for context
    ip_pkt(VICTIM, WEB_SRV, TCP(sport=55000, dport=80, flags="S"), t); t += 0.05
    ip_pkt(WEB_SRV, VICTIM, TCP(sport=80, dport=55000, flags="SA", ack=1), t); t += 0.05
    ip_pkt(VICTIM, WEB_SRV, TCP(sport=55000, dport=80, flags="A", ack=1), t); t += 0.9
    ip_pkt(VICTIM, WEB_SRV, TCP(sport=55000, dport=80, flags="PA") /
           Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), t); t += 1
    ip_pkt(WEB_SRV, VICTIM, TCP(sport=80, dport=55000, flags="PA") /
           Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    b"Content-Length: 13\r\n\r\nhello, world\n"), t); t += 1

    # A real capture is chronological; responses were appended beside their
    # requests, so put the file back in wire order before writing it.
    pkts.sort(key=lambda p: p.time)
    return pkts


def main():
    pkts = build()
    wrpcap(OUT, pkts)
    print(f"Wrote {len(pkts)} packets → {OUT}")
    print("Try it:")
    print(f"  packetiq analyze {OUT}")
    print(f"  packetiq sigma   {OUT}")
    print(f"  packetiq webapp                 # then upload {os.path.basename(OUT)}")


if __name__ == "__main__":
    main()
