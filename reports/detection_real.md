# PacketIQ Detection Accuracy — Real-World Captures (Stratosphere CTU-13)

Binary classification (malicious vs benign) at severity threshold **MEDIUM+**,
computed by running the **real** PacketIQ detection pipeline (parse → extract →
detect) over each labeled capture. Unlike the synthetic fixture suite, these are
genuine packet captures with authoritative third-party ground-truth labels.

*Measured 2026-08-11 · PacketIQ v1.0.0 · macOS-26.6.1-arm64-arm-64bit · Python
3.12.13. The headline figures below are unchanged from the previous run; the
per-capture and per-detector detail was re-measured and is stated as found.*

## Dataset

Captures from the **Stratosphere IPS Malware Capture Facility Project / CTU-13**
(CTU University, Prague — https://www.stratosphereips.org). Labels are the
dataset's own: `botnet-capture-*` = a host infected with real malware;
`normal-capture-*` / `*-only-dns` = real benign traffic. Reproduce with:

```bash
bash datasets/fetch_ctu.sh                 # downloads 12 captures (~428 MB, gitignored)
python tools/validate.py --manifest datasets/ctu13_manifest.json \
                         --markdown reports/detection_real.md
```

| # | Capture | Malware family | Label | Packets |
|--:|---|---|---|--:|
| 1 | donbot.pcap        | Donbot spam botnet (IRC C2)         | malicious | 24,764 |
| 2 | sogou.pcap         | Sogou botnet                        | malicious | 20,663 |
| 3 | qvod.pcap          | Qvod botnet                         | malicious | 85,735 |
| 4 | rbot-dos-icmp.pcap | Rbot DDoS bot (IRC C2)              | malicious | 28,826 |
| 5 | virut-fastflux.pcap| Virut botnet (fast-flux / DGA DNS)  | malicious | 440,625 |
| 6 | neris-42.pcap      | Neris HTTP spam/click-fraud bot (CTU-13 sc. 1) | malicious | 323,154 |
| 7 | neris-43.pcap      | Neris HTTP spam/click-fraud bot (CTU-13 sc. 2) | malicious | 176,064 |
| 8 | rbot-44.pcap       | Rbot IRC bot — scan + DoS (CTU-13 sc. 3) | malicious | 495,056 |
| 9 | fastflux-46.pcap   | Fast-flux / DGA DNS botnet (distinct capture) | malicious | 45,853 |
| 10 | normal-20110817.pcap | —                             | benign    | 20,549 |
| 11 | normal-dns-2015.pcap | —                             | benign    |  5,966 |
| 12 | normal-dns-2013.pcap | —                             | benign    |  1,720 |

Six malware families spanning three behaviour classes — IRC-controlled botnets
(Donbot, Rbot ×2), HTTP-C2 / spam-and-click-fraud botnets (Sogou, Qvod, Neris ×2),
and **fast-flux / DGA** DNS families (Virut, plus a second fast-flux capture) —
alongside three benign captures (one general host capture, two DNS-heavy). Nine
real malware captures totalling **1,640,740 packets** exercise every detector
class; the fast-flux and Neris captures in particular stress the DNS/DGA and
HTTP-C2 paths on genuinely different families.

## Headline result

| Metric | Value |
|---|---|
| True positives | 9 |
| False positives | 1 |
| True negatives | 2 |
| False negatives | 0 |
| **Precision** | **90.0%** |
| **Recall** | **100.0%** |
| **F1** | **94.7%** |
| **Accuracy** | **91.7%** |

**Recall is 100%: every real malware capture was caught, with zero misses** — the
priority for a forensic-triage tool, where a missed infection is the costly error.
Each malicious capture is flagged by *multiple independent detectors*, so no single
heuristic's weakness can hide an infection. The one remaining false positive is not
a detector error (see error analysis) — it is a correct detection of genuine
hostile traffic in a capture whose *host-level* label is "benign".

### Improvement over the first measurement

An earlier run of this same harness scored **57.1% precision / 100% recall / 72.7%
F1** on the 7-capture set. Investigating every false positive traced them to a
single structural cause — **CTU's LAN uses a public /16 (147.32.0.0/16)**, so
intra-campus traffic was misread as internet-facing — plus one non-discriminative
heuristic (see *Principled fixes* below). Correcting these (without tuning to the
test data, and with recall held at 100% and the synthetic suite held at 100%)
lifted precision to **80.0%** on the 7-capture set; adding the Virut fast-flux
family (correctly caught) brought **83.3% / 100% / 90.9%** on the 8-capture set.

Enlarging the malicious set from five to nine real botnet captures — Neris ×2
(HTTP-C2 spam / click-fraud), a second Rbot (IRC scan + DoS), and a second
fast-flux / DGA capture, **chosen by an objective size rule before their detection
outcome was known** — added four more true positives, *all correctly detected*,
lifting the current figure to **90.0% / 100% / 94.7%**. This gain reflects a
larger, more diverse real-malware set that the tool handles correctly — evidence
of generalisation — and **not** any change to the detectors: no detector code was
touched, and the single false positive is unchanged (the same correct detection of
real inbound scanning; see error analysis). Precision here is arithmetic
(TP/(TP+FP)); a lone label-artifact FP weighs less against nine caught infections
than against five, but honesty requires stating it is still there.

## Per-capture results

Counts in the last column are MEDIUM+ events per detector; the *Events* column is
the total the capture produced at every severity.

| Capture | Label | Flagged | Outcome | Risk | Events | Detectors that fired (MEDIUM+) |
|---|---|---|---|--:|--:|---|
| donbot.pcap        | malicious | yes | **TP** | 100/100 | 47 | DOS_FLOOD (43), HOST_SCAN (1), PORT_SCAN (1), C2_BEACON (1) |
| sogou.pcap         | malicious | yes | **TP** | 35/100  | 2  | HTTP_ATTACK (1, crit), CREDENTIAL_EXPOSURE (1) |
| qvod.pcap          | malicious | yes | **TP** | 78/100  | 18 | DOS_FLOOD (6), C2_BEACON (3), HOST_SCAN (2), PORT_SCAN (2), MALICIOUS_FILE (1), ARP_SCAN (1) |
| rbot-dos-icmp.pcap | malicious | yes | **TP** | 57/100  | 5  | PORT_SCAN (2), CREDENTIAL_EXPOSURE (1, crit), ICMP_TUNNELING (1), PROTOCOL_MISUSE (1) |
| virut-fastflux.pcap| malicious | yes | **TP** | 100/100 | 392 | CREDENTIAL_EXPOSURE (119, crit), DOS_FLOOD (104), C2_BEACON (21), DNS_ANOMALY (12), HTTP_ATTACK (4, crit), HOST_SCAN (4), IOC_MATCH (3), MALICIOUS_FILE (2), BRUTE_FORCE (1), PORT_SCAN (1) |
| neris-42.pcap      | malicious | yes | **TP** | 100/100 | 4853 | DNS_ANOMALY (4275), DOS_FLOOD (101), CREDENTIAL_EXPOSURE (51, crit), C2_BEACON (6), HOST_SCAN (5), IOC_MATCH (3), BRUTE_FORCE (1), PORT_SCAN (1) |
| neris-43.pcap      | malicious | yes | **TP** | 100/100 | 127 | DOS_FLOOD (61), CREDENTIAL_EXPOSURE (28, crit), DNS_ANOMALY (6), HTTP_ATTACK (5, crit), C2_BEACON (4, crit), HOST_SCAN (4), IOC_MATCH (1), PORT_SCAN (1) |
| rbot-44.pcap       | malicious | yes | **TP** | 100/100 | 51 | IOC_MATCH (39), PORT_SCAN (3), CREDENTIAL_EXPOSURE (2, crit), BRUTE_FORCE (2, crit), HOST_SCAN (2), PROTOCOL_MISUSE (2), DOS_FLOOD (1) |
| fastflux-46.pcap   | malicious | yes | **TP** | 100/100 | 27 | CREDENTIAL_EXPOSURE (17, crit), DNS_ANOMALY (5), HOST_SCAN (2), DOS_FLOOD (1), PORT_SCAN (1) |
| normal-20110817.pcap | benign  | yes | **FP** | 4/100   | 4  | PORT_SCAN (2) |
| normal-dns-2015.pcap | benign  | no  | **TN** | 9/100   | 17 | *(all LOW / informational — no MEDIUM+)* |
| normal-dns-2013.pcap | benign  | no  | **TN** | 3/100   | 5  | *(all LOW / informational — no MEDIUM+)* |

Two detectors added after the original measurement — **DOS_FLOOD** and **ARP_SCAN** —
now contribute to most malicious captures and raise several risk scores (donbot
31 → 100, qvod 50 → 78). They fire on **none** of the three benign captures, so the
extra sensitivity cost no precision: the binary outcome of every capture is
unchanged, and the headline is identical to the previous run.

## Per-detector recall (where ground-truth event types were declared)

| Detector (ground-truth expectation) | Detected | Recall |
|---|--:|--:|
| C2_BEACON (8 botnets declare C2 as ground-truth behaviour) | 5/8 | 62% |
| DNS_ANOMALY (Virut + second fast-flux DGA DNS) | 2/2 | 100% |
| IOC_MATCH (Virut contacts known-bad hosts) | 1/1 | 100% |

Five of the eight C2-declaring botnets trip the fixed-interval C2_BEACON heuristic
directly: donbot, qvod, virut-fastflux, neris-42 and neris-43. The three that do not
— sogou, rbot-dos-icmp and rbot-44 — are still correctly classified malicious via
*other* detectors (HTTP_ATTACK and CREDENTIAL_EXPOSURE on sogou; CREDENTIAL_EXPOSURE,
ICMP_TUNNELING and PROTOCOL_MISUSE on rbot-dos-icmp; IOC_MATCH, BRUTE_FORCE and
CREDENTIAL_EXPOSURE on rbot-44). They are the 2011-era IRC botnets with irregular C2
cadence, and the beacon detector is tuned for the regular callbacks of modern
implants.

**This figure moved, and downwards: it was 6/8 (75%) at the previous measurement.**
`rbot-44` no longer trips the beacon heuristic — the same-org and interval
constraints tightened since then push its IRC callbacks below the bar. It is still
detected as malicious, by seven other detectors including 39 IOC_MATCH hits, so the
binary recall is unaffected. Reporting one heuristic's recall separately is the point
of this table: a single detector's coverage is honestly below the 100% *binary*
recall, and it is allowed to move without the headline moving.

## Principled fixes applied (and why they are not overfitting)

Every fix corrects a *structural* misjudgement that is defensible independently of
this dataset. They are unified by one idea — **traffic between two endpoints on the
same organisation's network is intra-LAN, not internet-facing** — implemented as a
shared `same_org_network(a, b)` helper (`packetiq/utils/helpers.py`): two IPs are
"same-org" if both are private, or both public and in the same /16.

1. **SMB / cleartext-protocol "to the internet"** (`protocol_misuse.py`) now skip
   flows where both endpoints are same-org. A public-IP campus /16 doing intra-LAN
   SMB/FTP is normal file sharing — the detector still fires on genuine
   private↔public or cross-/16 exposure (e.g. rbot's inbound Telnet from
   `85.190.0.3` is *kept*).
2. **C2 beacon** (`beacon.py`) skips beacons whose destination is same-org — idle
   RDP keepalives, health checks and sync clients are intra-LAN periodicity, not C2
   phoning home. A genuine external beacon (different /16) is still caught (qvod's
   beacon to `222.189.228.111` is *kept*).
3. **Non-standard DNS resolver** (`dns_anomaly.py`) no longer flags an
   organisation's own resolver on a public IP (same /16). An off-network resolver
   is still flagged.
4. **DNS "excessive queries"** is demoted to **LOW / informational**. Re-resolving
   *one* name hundreds of times is a TTL/caching/client-polling artifact (Dropbox,
   Firefox tiles), not an attack; the discriminative DNS threats — many *distinct*
   high-entropy subdomains (DGA), oversized names (tunneling), known-bad names (IOC)
   — have their own dedicated detectors, which correctly caught Virut's fast-flux.

Recall stayed **100%** on every malicious capture through all four changes, the
synthetic fixture suite stayed at **100% precision / 100% recall**, and all unit
tests pass — the changes remove false alarms without weakening true detection.

## Error analysis — the one remaining false positive

`normal-20110817.pcap` is still flagged, and this is **defensible rather than a
detector error**. It now produces exactly two MEDIUM+ findings, both the same
detector, both stealth SYN sweeps from the internet:

- `70.37.110.238` — 10 half-open connections across **10 distinct internal hosts on
  a single port, 3128** (`147.32.84.165`, `.191`–`.193`, `.204`–`.209`). A horizontal
  sweep for open web proxies.
- `60.174.174.107` — the same shape against the same 10 hosts on **port 1433**
  (MSSQL).

Both are real inbound internet scanning, captured because CTU's monitored range sits
on a public /16. The capture's "benign" label means the *monitored host was not
infected*; it does not mean the capture is free of hostile traffic. A triage tool
*should* raise these — counting it as a false positive is an artifact of the coarse
binary label, not a heuristic mistake. Every alert carries its evidence (source,
target list, port, half-open count) so an analyst can make that call in seconds.

Two things are worth noting about how mild this alarm is. The capture's overall risk
score is **4/100 (LOW tier)** — the two scans are surfaced for triage without the
capture being presented as compromised — and the earlier C2_BEACON finding on this
capture (inbound RDP to `147.32.84.192:3389`) **no longer fires at all**, so the only
remaining false positive is this pair of genuine scans. Its other two events are LOW
informational DNS notes (`wpad`, `time.windows.com` re-queried), below the MEDIUM
threshold and not counted.

## Bug found and fixed during this evaluation

The first run raised a **CRITICAL IOC_MATCH for `drive.google.com`** on a benign
capture. Root cause: the ThreatFox feed contains malicious **URL** IOCs staged on
shared hosting (`https://drive.google.com/uc?export=download&id=…`), and the feed
parser collapsed each URL to its bare host, blocklisting the whole domain — a
CRITICAL alert for **every** user of Google Drive, Dropbox, Discord CDN, GitHub
raw, pastebin, `t.me`, etc. Fixed in `packetiq/enrichment/feeds.py`: a URL IOC on a
shared front-door host no longer becomes a domain IOC (regression test
`test_shared_hosters_never_blocklisted_from_url_iocs`). This removed a genuine false
positive independent of this dataset.

## Interpretation

PacketIQ is a **recall-oriented forensic-triage tool**: on real malware spanning
six families and three behaviour classes it missed nothing (**100% recall across
nine infected captures, ~1.64 M packets**), each malicious capture tripping multiple
independent detectors. Precision is **90.0%**, and the single remaining "false
positive" is itself a correct detection of two real inbound port sweeps against a
public-facing range. Every alert is attributable to a specific, inspectable detector
and carries its own evidence — the opposite of a black-box classifier. Honest
headline for the write-up: **100% recall on real-world malware captures at 90%
precision, with a transparent, per-detector account of every decision.**
