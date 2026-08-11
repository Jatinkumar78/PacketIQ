#!/usr/bin/env python3
"""
Throughput benchmark for the PacketIQ analysis pipeline.

Measures how fast PacketIQ turns raw packets into detections — parse → extract →
detect — and reports packets/s, MB/s, per-stage timing and peak memory. These are
*real* measured numbers on your machine, not estimates.

Usage
-----
  # Reproducible, no download — generate a large synthetic capture and time it:
  python tools/benchmark.py --demo --packets 200000

  # Benchmark a real capture (or a directory of them):
  python tools/benchmark.py --pcap datasets/real/pcaps/rbot-dos-icmp.pcap
  python tools/benchmark.py --dir datasets/real/pcaps --markdown reports/performance.md

The pipeline timed here is exactly the one used by the CLI, the web app and the
validation harness (PCAPParser → DataExtractor → DetectionEngine).
"""
from __future__ import annotations

import argparse
import ctypes
import gc
import os
import sys
import time
from pathlib import Path

try:
    import resource  # POSIX only — Windows has no getrusage(2)
except ImportError:
    resource = None            # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packetiq.detection.engine import DetectionEngine  # noqa: E402
from packetiq.extractor.data_extractor import DataExtractor  # noqa: E402
from packetiq.parser.pcap_parser import PCAPParser  # noqa: E402


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    """psapi.h — only the PeakWorkingSetSize field is read."""
    _fields_ = [("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t)]


def _peak_rss_mb() -> float:
    """Peak resident set size in MB, on every platform PacketIQ supports.

    `resource.getrusage` is POSIX-only and does not exist on Windows, where the
    equivalent is GetProcessMemoryInfo's PeakWorkingSetSize. Reporting 0 there
    instead would put a made-up number in the benchmark table.
    """
    if resource is not None:
        ru = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # ru_maxrss is bytes on macOS, kilobytes on Linux.
        return ru / (1024 * 1024) if sys.platform == "darwin" else ru / 1024
    counters = _PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    handle = ctypes.windll.kernel32.GetCurrentProcess()      # type: ignore[attr-defined]
    ctypes.windll.psapi.GetProcessMemoryInfo(                # type: ignore[attr-defined]
        handle, ctypes.byref(counters), counters.cb)
    return counters.PeakWorkingSetSize / (1024 * 1024)


def bench_one(path: str) -> dict:
    size_mb = os.path.getsize(path) / (1024 * 1024)

    gc.collect()
    t0 = time.perf_counter()
    parser = PCAPParser(path)
    extractor = DataExtractor()
    n = 0
    for rec in parser.stream():
        extractor.feed(rec)
        n += 1
    result = extractor.finalize()
    t_parse = time.perf_counter() - t0

    t1 = time.perf_counter()
    events, risk, _fps = DetectionEngine().run(result, path)
    t_detect = time.perf_counter() - t1

    total = t_parse + t_detect
    return {
        "file": os.path.basename(path),
        "packets": n,
        "size_mb": size_mb,
        "t_parse": t_parse,
        "t_detect": t_detect,
        "t_total": total,
        "pps": n / total if total else 0.0,
        "mbps": size_mb / total if total else 0.0,
        "events": len(events),
        "risk": risk.score,
        "peak_rss_mb": _peak_rss_mb(),
    }


def _fmt_row(r: dict) -> str:
    return (f"{r['file']:<26} {r['packets']:>9,} {r['size_mb']:>8.1f} "
            f"{r['t_total']:>8.2f} {r['pps']:>11,.0f} {r['mbps']:>8.1f} "
            f"{r['peak_rss_mb']:>8.0f}")


def _print_table(rows: list) -> None:
    print(f"\n{'capture':<26} {'packets':>9} {'MB':>8} {'sec':>8} "
          f"{'pkts/s':>11} {'MB/s':>8} {'RSS MB':>8}")
    print("-" * 84)
    for r in rows:
        print(_fmt_row(r))
    if len(rows) > 1:
        tot_p = sum(r["packets"] for r in rows)
        tot_mb = sum(r["size_mb"] for r in rows)
        tot_t = sum(r["t_total"] for r in rows)
        print("-" * 84)
        print(f"{'TOTAL / weighted':<26} {tot_p:>9,} {tot_mb:>8.1f} {tot_t:>8.2f} "
              f"{tot_p / tot_t if tot_t else 0:>11,.0f} "
              f"{tot_mb / tot_t if tot_t else 0:>8.1f} "
              f"{max(r['peak_rss_mb'] for r in rows):>8.0f}")


def _to_markdown(rows: list) -> str:
    import platform
    from datetime import date

    from packetiq import __version__
    tot_p = sum(r["packets"] for r in rows)
    tot_mb = sum(r["size_mb"] for r in rows)
    tot_t = sum(r["t_total"] for r in rows)
    agg_pps = tot_p / tot_t if tot_t else 0.0
    agg_mbps = tot_mb / tot_t if tot_t else 0.0
    out = [
        "# PacketIQ Performance — Pipeline Throughput", "",
        # Throughput is meaningless without the date and the build it was taken on —
        # both the hardware and the detectors move.
        f"Measured **{date.today().isoformat()}** on **{platform.platform()}**, "
        f"Python {platform.python_version()}, PacketIQ v{__version__}. "
        "The timed pipeline (parse → extract → detect) is the same one used by the "
        "CLI, web app and validation harness. Numbers are real measurements on this "
        "machine, single-threaded.", "",
        f"**Aggregate: {agg_pps:,.0f} packets/s, {agg_mbps:.1f} MB/s** across "
        f"{len(rows)} capture(s) ({tot_p:,} packets, {tot_mb:.1f} MB in {tot_t:.2f}s).",
        "",
        "| Capture | Packets | Size (MB) | Parse (s) | Detect (s) | Total (s) | "
        "Packets/s | MB/s | Peak RSS (MB) |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    for r in rows:
        out.append(
            f"| {r['file']} | {r['packets']:,} | {r['size_mb']:.1f} | "
            f"{r['t_parse']:.2f} | {r['t_detect']:.2f} | {r['t_total']:.2f} | "
            f"{r['pps']:,.0f} | {r['mbps']:.1f} | {r['peak_rss_mb']:.0f} |")
    out += [
        "",
        "*Parse* streams packets through the scapy-based reader and the feature "
        "extractor; *detect* runs every detector over the extracted session state. "
        "Because parsing is streaming, memory grows far more slowly than capture "
        "size rather than loading the whole PCAP into RAM.", "",
        "**Reading the RSS column.** It is `getrusage`'s *peak* for the whole "
        "process, which never decreases, so when several captures are benchmarked "
        "in one run each row inherits the high-water mark of every row above it. "
        "Read the column as the running maximum up to that point, not as the cost "
        "of that capture alone. For a per-capture figure, benchmark that capture on "
        "its own (`--pcap`), which starts a fresh process.", "",
    ]
    return "\n".join(out)


def _build_demo(path: Path, n_packets: int) -> None:
    """Generate a large, varied synthetic capture for a reproducible benchmark."""
    import random

    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    from scapy.layers.dns import DNS, DNSQR

    random.seed(1)
    eth = {"src": "00:11:22:33:44:55", "dst": "66:77:88:99:aa:bb"}  # explicit → no MAC lookup
    pkts = []
    t = 1700000000.0
    hosts = [f"192.168.1.{i}" for i in range(10, 40)]
    ext = [f"93.184.216.{i}" for i in range(1, 60)]
    for i in range(n_packets):
        r = i % 10
        src = random.choice(hosts)  # nosec B311 - synthetic benchmark traffic, not cryptographic
        if r < 6:      # HTTPS-ish
            dst = random.choice(ext)  # nosec B311 - synthetic benchmark traffic, not cryptographic
            p = Ether(**eth) / IP(src=src, dst=dst) / \
                TCP(sport=40000 + (i % 20000), dport=443, flags="S")
        elif r < 8:    # DNS
            p = Ether(**eth) / IP(src=src, dst="8.8.8.8") / \
                UDP(sport=33000 + (i % 1000), dport=53) / \
                DNS(rd=1, qd=DNSQR(qname=f"host{i % 500}.example.com"))
        else:          # small HTTP payload
            dst = random.choice(ext)  # nosec B311 - synthetic benchmark traffic, not cryptographic
            p = Ether(**eth) / IP(src=src, dst=dst) / \
                TCP(sport=50000 + (i % 10000), dport=80, flags="PA") / \
                Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        p.time = t + i * 0.001
        pkts.append(p)
        if len(pkts) >= 50000:              # write in batches to bound memory
            wrpcap(str(path), pkts, append=path.exists())
            pkts = []
    if pkts:
        wrpcap(str(path), pkts, append=path.exists())


def main() -> int:
    ap = argparse.ArgumentParser(description="PacketIQ pipeline throughput benchmark")
    ap.add_argument("--pcap", help="Benchmark a single PCAP file")
    ap.add_argument("--dir", help="Benchmark every .pcap in this directory")
    ap.add_argument("--demo", action="store_true",
                    help="Generate a synthetic capture and benchmark it (no download)")
    ap.add_argument("--packets", type=int, default=200000,
                    help="Number of packets for --demo (default 200000)")
    ap.add_argument("--markdown", dest="md_out", help="Write a Markdown report here")
    args = ap.parse_args()

    paths: list = []
    tmp = None
    if args.demo:
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="packetiq_bench_"))
        demo = tmp / "synthetic.pcap"
        print(f"Generating {args.packets:,}-packet synthetic capture …")
        _build_demo(demo, args.packets)
        paths.append(str(demo))
    if args.pcap:
        paths.append(args.pcap)
    if args.dir:
        paths += sorted(str(p) for p in Path(args.dir).glob("*.pcap"))
    if not paths:
        ap.error("provide --demo, --pcap PATH, or --dir DIR")

    rows = []
    for p in paths:
        if not os.path.isfile(p):
            print(f"skip (missing): {p}")
            continue
        print(f"benchmarking {os.path.basename(p)} …", flush=True)
        rows.append(bench_one(p))

    if not rows:
        print("Nothing benchmarked.")
        return 1
    _print_table(rows)

    if args.md_out:
        Path(args.md_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md_out).write_text(_to_markdown(rows))
        print(f"\nMarkdown report written to {args.md_out}")

    if tmp:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
