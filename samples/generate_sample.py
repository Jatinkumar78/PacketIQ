#!/usr/bin/env python3
"""
Generate a realistic demo PCAP for PacketIQ.

This builds a *synthetic* capture (no real traffic is sent anywhere) that
deliberately contains the behaviours PacketIQ detects, so you can try the
tool immediately:

    python samples/generate_sample.py
    packetiq analyze samples/demo_attack.pcap
    packetiq webapp           # then upload samples/demo_attack.pcap

The scenario: an external attacker (45.33.32.156) recons and brute-forces an
internal host (192.168.1.50), which then beacons to an external C2, tunnels
data out over DNS/ICMP, and leaks FTP credentials in cleartext.

All IP addresses are written only into the capture file — nothing is
transmitted over the network.
"""

import os
import random

from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS, DNSQR

random.seed(1337)  # deterministic output

# Public (non-reserved) addresses used purely as labels inside the pcap.
ATTACKER = "45.33.32.156"
VICTIM   = "192.168.1.50"
C2       = "185.199.108.153"
FTP_SRV  = "193.122.6.168"
ICMP_DST = "188.114.96.3"
RESOLVER = "8.8.8.8"

OUT = os.path.join(os.path.dirname(__file__), "demo_attack.pcap")


def build():
    pkts = []
    t = 1700000000.0

    def add(pkt, ts):
        pkt.time = ts
        pkts.append(pkt)

    # 1) SSH brute force: 40 rapid SYNs to victim:22
    for i in range(40):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + i, dport=22, flags="S"), t + i)
    t += 70

    # 2) Vertical port scan: attacker -> victim, many ports
    for i, port in enumerate(range(1, 70)):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=50000 + i, dport=port, flags="S"), t + i * 0.1)
    t += 30

    # 3) Horizontal host scan: attacker -> many hosts on SMB/445
    for i in range(25):
        add(Ether() / IP(src=ATTACKER, dst=f"192.168.1.{100 + i}") / TCP(sport=51000 + i, dport=445, flags="S"), t + i * 0.1)
    t += 30

    # 4) XMAS scan packets (FIN+PSH+URG) attacker -> victim
    for i in range(3):
        add(Ether() / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=54000 + i, dport=81 + i, flags="FPU"), t + i * 0.1)
    t += 10

    # 5) C2 beacon: victim -> external C2 every ~30s, low jitter
    for i in range(16):
        add(Ether() / IP(src=VICTIM, dst=C2) / TCP(sport=52000, dport=443, flags="S"), t + i * 30 + random.uniform(-0.4, 0.4))
    t += 16 * 30 + 10

    # 6) DNS tunneling: oversized query names from victim
    for i in range(6):
        label = "".join(random.choice("0123456789abcdef") for _ in range(60))
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=33000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"{label}.exfil.example-evil.xyz")), t + i * 2)
    t += 20

    # 7) DGA-style domains from victim (high-entropy second-level labels)
    for i in range(5):
        label = "".join(random.choice("bcdfghjklmnpqrstvwxyz0123456789") for _ in range(18))
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=34000 + i, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=f"{label}.top")), t + i * 2)
    t += 20

    # 8) Normal DNS (should NOT be flagged)
    for d in ("google.com", "github.com", "cloudflare.com", "microsoft.com"):
        add(Ether() / IP(src=VICTIM, dst=RESOLVER) / UDP(sport=35000, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=d)), t)
        t += 1

    # 9) ICMP tunneling: large ICMP volume victim -> external
    for i in range(130):
        add(Ether() / IP(src=VICTIM, dst=ICMP_DST) / ICMP() / Raw(load=b"X" * 1000), t + i * 0.2)
    t += 30

    # 10) Cleartext FTP credentials victim -> external FTP server
    add(Ether() / IP(src=VICTIM, dst=FTP_SRV) / TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"), t); t += 1
    add(Ether() / IP(src=VICTIM, dst=FTP_SRV) / TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"PASS S3cr3tP@ss!\r\n"), t); t += 1

    # 11) A little benign HTTP for context
    add(Ether() / IP(src=VICTIM, dst="93.184.216.34") / TCP(sport=55000, dport=80, flags="PA") /
        Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), t); t += 1

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
