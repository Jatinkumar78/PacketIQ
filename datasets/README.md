# Detection validation datasets

PacketIQ's detection accuracy is measured with `tools/validate.py`, which runs
the **real** detection pipeline over a set of *labeled* captures and reports
precision / recall / F1 — the numbers you can honestly cite.

There are two ways to run it.

## 1. Built-in synthetic fixture suite (no download)

```bash
python tools/validate.py --suite --markdown reports/detection_synthetic.md
```

This crafts 9 small captures (2 benign, 7 malicious) with **known ground truth**,
one per detector, and prints precision / recall / F1 plus a per-detector recall
table. It downloads nothing.

> **What this proves — and what it doesn't.** These are *synthetic* fixtures:
> textbook examples of each attack, plus clean benign traffic. A high score here
> shows the detectors fire on the behaviour they target and stay quiet on clean
> traffic — a sanity/regression check. It is **not** a claim of real-world
> accuracy. For that, run against public captures (below).

## 2. Real public datasets (recommended for the dissertation)

The same harness runs on any captures you provide, described by a JSON manifest
(`--manifest`). Good, well-labeled public sources:

| Dataset | What it is | Link |
|---|---|---|
| **malware-traffic-analysis.net** | Real malware PCAPs (Qakbot, IcedID, etc.), dated & described | https://www.malware-traffic-analysis.net |
| **CIC-IDS2017** | Labeled IDS benchmark (brute force, DoS, portscan, web attacks, botnet) | https://www.unb.ca/cic/datasets/ids-2017.html |
| **Stratosphere IPS** | Labeled malware + normal captures (CTU-13 and others) | https://www.stratosphereips.org/datasets-overview |

These are large and often licensed for research use — **download them yourself**
(they are not bundled here). Then drop the `.pcap` files somewhere and point a
manifest at them.

### Manifest format

```json
{
  "dataset_name": "malware-traffic-analysis sample",
  "base_dir": "pcaps",
  "severity_threshold": "MEDIUM",
  "captures": [
    {"file": "2023-09-12-Qakbot.pcap", "malicious": true,  "expect": ["IOC_MATCH", "C2_BEACON"]},
    {"file": "2023-08-01-normal.pcap",  "malicious": false}
  ]
}
```

- `malicious` drives the binary precision/recall.
- `expect` (optional) lists the detector event types that *should* fire for that
  capture — used for the per-detector recall breakdown.
- `severity_threshold` — a capture counts as "flagged" when it produces an event
  at this severity or higher (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`).

Then:

```bash
python tools/validate.py --manifest datasets/my_manifest.json --markdown reports/detection_real.md
```

See `sample_manifest.json` in this folder for a starting point.
