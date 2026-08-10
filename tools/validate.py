#!/usr/bin/env python3
"""
Detector validation harness.

Runs the full PacketIQ pipeline over a *labeled* set of PCAPs and reports real
precision / recall / F1 — the numbers you can honestly put in a README.

Usage
-----
  # Validate against your own labeled dataset described by a JSON manifest:
  python tools/validate.py --manifest dataset/labels.json

  # Quick self-check on a generated benign/malicious pair (no data needed):
  python tools/validate.py --demo

Manifest format (JSON)
----------------------
{
  "base_dir": "pcaps",              # optional; paths are relative to this
  "severity_threshold": "HIGH",     # a capture counts as "flagged" at >= this
  "captures": [
    {"file": "qakbot.pcap",  "malicious": true,  "expect": ["IOC_MATCH", "C2_BEACON"]},
    {"file": "browsing.pcap","malicious": false}
  ]
}

`malicious` drives the binary precision/recall. Optional `expect` lists the
event types that *should* fire, used for a per-detector recall breakdown.

Good public sources of labeled captures: malware-traffic-analysis.net,
the Stratosphere IPS dataset, and CIC-IDS2017.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# allow running from a source checkout without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packetiq.detection.engine import DetectionEngine  # noqa: E402
from packetiq.detection.models import Severity  # noqa: E402
from packetiq.extractor.data_extractor import DataExtractor  # noqa: E402
from packetiq.parser.pcap_parser import PCAPParser  # noqa: E402

_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def _analyze(path: str):
    parser = PCAPParser(path)
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    result = extractor.finalize()
    events, risk, _fps = DetectionEngine().run(result, path)
    return events, risk


def _flagged(events, threshold: Severity) -> bool:
    bar = _SEV_ORDER[threshold]
    return any(_SEV_ORDER.get(e.severity, 9) <= bar for e in events)


def run(manifest: dict, base_dir: Path, md_out: str = None, gates: dict = None) -> int:
    threshold = Severity[manifest.get("severity_threshold", "HIGH").upper()]
    captures = manifest.get("captures", [])
    if not captures:
        print("No captures in manifest.")
        return 1

    tp = fp = tn = fn = 0
    per_type_recall: dict = defaultdict(lambda: [0, 0])  # type -> [hit, total]
    rows: list = []  # (file, truth, pred, outcome, risk, n_events) for the report

    print(f"{'capture':<40} {'truth':<8} {'pred':<8} result")
    print("-" * 70)
    for cap in captures:
        path = base_dir / cap["file"]
        if not path.is_file():
            print(f"{cap['file']:<40} MISSING (skipped)")
            continue
        truth = bool(cap.get("malicious", False))
        try:
            events, risk = _analyze(str(path))
        except Exception as exc:  # noqa: BLE001
            print(f"{cap['file']:<40} ERROR: {exc}")
            continue
        pred = _flagged(events, threshold)

        if truth and pred:
            tp += 1; outcome = "TP"
        elif truth and not pred:
            fn += 1; outcome = "FN (missed)"
        elif not truth and pred:
            fp += 1; outcome = "FP (false alarm)"
        else:
            tn += 1; outcome = "TN"

        present = {e.event_type.value for e in events}
        for et in cap.get("expect", []):
            per_type_recall[et][1] += 1
            if et in present:
                per_type_recall[et][0] += 1

        rows.append((cap["file"], truth, pred, outcome, risk.score, len(events)))
        print(f"{cap['file']:<40} {str(truth):<8} {str(pred):<8} {outcome}  "
              f"[risk {risk.score}/100, {len(events)} events]")

    # ── Metrics ──────────────────────────────────────────────────────────────
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0

    print("\n" + "=" * 70)
    print("BINARY CLASSIFICATION (malicious vs benign, threshold "
          f"{threshold.value})")
    print("-" * 70)
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print(f"  Precision : {precision:.1%}")
    print(f"  Recall    : {recall:.1%}")
    print(f"  F1        : {f1:.1%}")
    print(f"  Accuracy  : {accuracy:.1%}")

    if per_type_recall:
        print("\nPER-DETECTOR RECALL (where ground-truth event types were given)")
        print("-" * 70)
        for et, (hit, total) in sorted(per_type_recall.items()):
            print(f"  {et:<22} {hit}/{total}  ({(hit/total if total else 0):.0%})")

    metrics = {
        "threshold": threshold.value,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
        "per_type_recall": {k: v for k, v in per_type_recall.items()},
        "rows": rows,
        "dataset": manifest.get("dataset_name", ""),
    }
    if md_out:
        Path(md_out).write_text(_to_markdown(metrics), encoding="utf-8")
        print(f"\nMarkdown report written to {md_out}")

    # Optional CI gate: exit non-zero if metrics fall below required floors. This
    # turns the synthetic suite into a standing regression check (recall/precision
    # must not drop) that GitHub Actions can enforce on every push.
    if gates:
        checks = [("recall", recall), ("precision", precision), ("f1", f1)]
        failures = [f"{name} {val:.1%} < required {gates[name]:.1%}"
                    for name, val in checks
                    if gates.get(name) is not None and val + 1e-9 < gates[name]]
        if failures:
            print("\nGATE FAILED: " + "; ".join(failures))
            return 1
        if any(gates.get(k) is not None for k in ("recall", "precision", "f1")):
            print("\nGATE PASSED.")
    return 0


def _to_markdown(m: dict) -> str:
    name = m.get("dataset") or "labeled dataset"
    out = [f"# PacketIQ Detection Accuracy — {name}", "",
           f"Binary classification (malicious vs benign) at severity threshold "
           f"**{m['threshold']}+**. Metrics computed by running the real detection "
           f"pipeline over each labeled capture.", "",
           "| Metric | Value |", "|---|---|",
           f"| True positives | {m['tp']} |",
           f"| False positives | {m['fp']} |",
           f"| True negatives | {m['tn']} |",
           f"| False negatives | {m['fn']} |",
           f"| **Precision** | **{m['precision']:.1%}** |",
           f"| **Recall** | **{m['recall']:.1%}** |",
           f"| **F1** | **{m['f1']:.1%}** |",
           f"| **Accuracy** | **{m['accuracy']:.1%}** |", ""]
    if m["per_type_recall"]:
        out += ["## Per-detector recall", "",
                "| Detector (event type) | Detected | Recall |", "|---|--:|--:|"]
        for et, (hit, total) in sorted(m["per_type_recall"].items()):
            out.append(f"| {et} | {hit}/{total} | {(hit/total if total else 0):.0%} |")
        out.append("")
    out += ["## Per-capture results", "",
            "| Capture | Label | Flagged | Outcome | Risk | Events |", "|---|---|---|---|--:|--:|"]
    for f, truth, pred, outcome, risk, n in m["rows"]:
        out.append(f"| {f} | {'malicious' if truth else 'benign'} | "
                   f"{'yes' if pred else 'no'} | {outcome} | {risk}/100 | {n} |")
    return "\n".join(out) + "\n"


def _build_demo(tmp: Path) -> dict:
    """Generate a benign and a malicious capture and a manifest pointing at them."""
    import random

    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    from scapy.layers.dns import DNS, DNSQR

    random.seed(11)

    # Benign: normal browsing-ish traffic
    benign = []
    t = 1700000000.0
    for d in ("google.com", "github.com", "cloudflare.com", "wikipedia.org"):
        benign.append(Ether() / IP(src="192.168.1.10", dst="8.8.8.8") /
                      UDP(sport=33000, dport=53) / DNS(rd=1, qd=DNSQR(qname=d)))
    for i in range(20):
        benign.append(Ether() / IP(src="192.168.1.10", dst="93.184.216.34") /
                      TCP(sport=40000 + i, dport=443, flags="S"))
    for i, p in enumerate(benign):
        p.time = t + i
    wrpcap(str(tmp / "benign.pcap"), benign)

    # Malicious: SSH brute force + cleartext FTP creds to an external host
    mal = []
    t = 1700001000.0
    for i in range(40):
        mal.append(Ether() / IP(src="45.33.32.156", dst="192.168.1.50") /
                   TCP(sport=50000 + i, dport=22, flags="S"))
    mal.append(Ether() / IP(src="192.168.1.50", dst="193.122.6.168") /
               TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"))
    mal.append(Ether() / IP(src="192.168.1.50", dst="193.122.6.168") /
               TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"PASS s3cr3t\r\n"))
    for i, p in enumerate(mal):
        p.time = t + i
    wrpcap(str(tmp / "malicious.pcap"), mal)

    return {
        "base_dir": str(tmp),
        "severity_threshold": "HIGH",
        "captures": [
            {"file": "benign.pcap", "malicious": False},
            {"file": "malicious.pcap", "malicious": True,
             "expect": ["BRUTE_FORCE", "CREDENTIAL_EXPOSURE"]},
        ],
    }


def _build_suite(tmp: Path) -> dict:
    """Build a labeled *synthetic* fixture suite — crafted traffic with known
    ground truth that exercises each detector, so `validate.py` produces a real
    precision/recall/F1 table with no external data to download.

    These are synthetic fixtures (honestly labeled as such), not a public dataset.
    To measure against real-world captures, point --manifest at malware-traffic-
    analysis.net / CIC-IDS2017 / the Stratosphere IPS dataset (see datasets/README).
    """
    import random

    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    from scapy.layers.dns import DNS, DNSQR

    random.seed(7)
    eth = {"src": "00:11:22:33:44:55", "dst": "66:77:88:99:aa:bb"}  # explicit → no MAC lookup

    def save(name: str, pkts: list, t0: float, step: float = 1.0):
        for i, p in enumerate(pkts):
            p.time = t0 + i * step
        wrpcap(str(tmp / name), pkts)

    internal = "192.168.1.10"
    victim = "192.168.1.50"

    # ── Benign 1: normal web browsing (DNS + HTTPS) ──────────────────────────
    p = []
    for d in ("google.com", "github.com", "cloudflare.com", "wikipedia.org", "apple.com"):
        p.append(Ether(**eth) / IP(src=internal, dst="8.8.8.8") /
                 UDP(sport=33000, dport=53) / DNS(rd=1, qd=DNSQR(qname=d)))
    for i in range(20):
        p.append(Ether(**eth) / IP(src=internal, dst="93.184.216.34") /
                 TCP(sport=40000 + i, dport=443, flags="S"))
    save("benign_web.pcap", p, 1700000000.0)

    # ── Benign 2: a couple of internal hosts doing DNS + HTTPS ───────────────
    p = []
    for i, d in enumerate(("microsoft.com", "ubuntu.com", "python.org", "mozilla.org")):
        p.append(Ether(**eth) / IP(src=f"192.168.1.{20 + i}", dst="1.1.1.1") /
                 UDP(sport=34000 + i, dport=53) / DNS(rd=1, qd=DNSQR(qname=d)))
    for i in range(12):
        p.append(Ether(**eth) / IP(src="192.168.1.21", dst="140.82.113.4") /
                 TCP(sport=41000 + i, dport=443, flags="S"))
    save("benign_office.pcap", p, 1700010000.0)

    # ── Malicious: port scan (1 src → many dports) ───────────────────────────
    p = [Ether(**eth) / IP(src="45.33.32.156", dst=victim) /
         TCP(sport=55000, dport=port, flags="S")
         for port in range(1, 200)]
    save("port_scan.pcap", p, 1700020000.0, step=0.05)

    # ── Malicious: SSH brute force ───────────────────────────────────────────
    p = [Ether(**eth) / IP(src="45.33.32.156", dst=victim) /
         TCP(sport=50000 + i, dport=22, flags="S") for i in range(60)]
    save("ssh_brute.pcap", p, 1700030000.0, step=0.2)

    # ── Malicious: XMAS scan (FIN+PSH+URG) ───────────────────────────────────
    p = [Ether(**eth) / IP(src="45.33.32.156", dst=victim) /
         TCP(sport=56000 + i, dport=(80 + i), flags="FPU") for i in range(30)]
    save("xmas_scan.pcap", p, 1700040000.0, step=0.1)

    # ── Malicious: cleartext FTP credentials ─────────────────────────────────
    p = [
        Ether(**eth) / IP(src=victim, dst="193.122.6.168") /
        TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"),
        Ether(**eth) / IP(src=victim, dst="193.122.6.168") /
        TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"PASS s3cr3t\r\n"),
    ]
    save("cleartext_ftp.pcap", p, 1700050000.0)

    # ── Malicious: HTTP attack (SQLi + traversal + scanner UA) ───────────────
    reqs = [
        b"GET /login.php?user=admin'%20OR%20'1'='1 HTTP/1.1\r\nHost: h\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
        b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: h\r\nUser-Agent: Nikto\r\n\r\n",
    ]
    p = [Ether(**eth) / IP(src="45.33.32.156", dst=victim) /
         TCP(sport=51000 + i, dport=80, flags="PA") / Raw(load=r) for i, r in enumerate(reqs)]
    save("http_attack.pcap", p, 1700060000.0)

    # ── Malicious: DNS tunneling (long random labels to one parent domain) ───
    p = []
    for i in range(60):
        label = "".join(random.choice("0123456789abcdef") for _ in range(40))  # nosec B311 - synthetic validation fixture, not cryptographic
        p.append(Ether(**eth) / IP(src=victim, dst="45.33.32.156") /
                 UDP(sport=35000 + i, dport=53) /
                 DNS(rd=1, qd=DNSQR(qname=f"{label}.tunnel.evil-c2.com")))
    save("dns_tunnel.pcap", p, 1700070000.0, step=0.5)

    # ── Malicious: C2 beacon (regular fixed-interval callbacks) ──────────────
    p = [Ether(**eth) / IP(src=victim, dst="185.220.101.50") /
         TCP(sport=45000, dport=443, flags="S") for _ in range(40)]
    save("c2_beacon.pcap", p, 1700080000.0, step=60.0)  # exactly 60s apart

    return {
        "dataset_name": "PacketIQ synthetic fixture suite",
        "base_dir": str(tmp),
        "severity_threshold": "MEDIUM",
        "captures": [
            {"file": "benign_web.pcap",    "malicious": False},
            {"file": "benign_office.pcap", "malicious": False},
            {"file": "port_scan.pcap",     "malicious": True, "expect": ["PORT_SCAN"]},
            {"file": "ssh_brute.pcap",      "malicious": True, "expect": ["BRUTE_FORCE"]},
            {"file": "xmas_scan.pcap",      "malicious": True, "expect": ["SUSPICIOUS_FLAGS"]},
            {"file": "cleartext_ftp.pcap",  "malicious": True, "expect": ["CREDENTIAL_EXPOSURE"]},
            {"file": "http_attack.pcap",    "malicious": True, "expect": ["HTTP_ATTACK"]},
            {"file": "dns_tunnel.pcap",     "malicious": True, "expect": ["DNS_TUNNELING"]},
            {"file": "c2_beacon.pcap",      "malicious": True, "expect": ["C2_BEACON"]},
        ],
    }


def main():
    ap = argparse.ArgumentParser(description="PacketIQ detector validation harness")
    ap.add_argument("--manifest", help="Path to a JSON labels manifest")
    ap.add_argument("--demo", action="store_true", help="Quick built-in benign/malicious self-check")
    ap.add_argument("--suite", action="store_true",
                    help="Run the built-in synthetic labeled fixture suite (9 captures, all detectors)")
    ap.add_argument("--markdown", dest="md_out", help="Write a Markdown accuracy report to this path")
    ap.add_argument("--keep", metavar="DIR", help="Copy generated fixtures to DIR (for --demo/--suite)")
    ap.add_argument("--min-recall", type=float, metavar="R",
                    help="CI gate: exit non-zero if recall < R (0.0–1.0)")
    ap.add_argument("--min-precision", type=float, metavar="P",
                    help="CI gate: exit non-zero if precision < P (0.0–1.0)")
    ap.add_argument("--min-f1", type=float, metavar="F",
                    help="CI gate: exit non-zero if F1 < F (0.0–1.0)")
    args = ap.parse_args()
    gates = {"recall": args.min_recall, "precision": args.min_precision, "f1": args.min_f1}

    if args.demo or args.suite:
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="packetiq_validate_"))
        manifest = _build_suite(tmp) if args.suite else _build_demo(tmp)
        rc = run(manifest, tmp, md_out=args.md_out, gates=gates)
        if args.keep:
            import shutil
            dest = Path(args.keep)
            dest.mkdir(parents=True, exist_ok=True)
            for f in tmp.glob("*.pcap"):
                shutil.copy2(f, dest / f.name)
            print(f"Fixtures copied to {dest}")
        return rc

    if not args.manifest:
        ap.error("provide --manifest PATH, --demo, or --suite")

    manifest = json.loads(Path(args.manifest).read_text())
    base_dir = Path(manifest.get("base_dir", Path(args.manifest).parent))
    if not base_dir.is_absolute():
        base_dir = Path(args.manifest).parent / base_dir
    return run(manifest, base_dir, md_out=args.md_out, gates=gates)


if __name__ == "__main__":
    raise SystemExit(main())
