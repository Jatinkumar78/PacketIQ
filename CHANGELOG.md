# Changelog

All notable changes to PacketIQ are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0]

### Reliable AI provider selection & a reproducible local copilot

**Fixed**
- **Gemini could not be used at all on projects with no free-tier allowance.**
  Google grants free-tier quota *per model and per project*, not per key: a valid
  key answers `429 … limit: 0` for the default `gemini-2.0-flash` while newer
  models reply normally, so issuing a fresh key changed nothing. PacketIQ now
  tells a model-scoped failure apart from a dead provider — it marks that model
  unusable, silently retries the same provider on its next candidate model
  (`_MODEL_CANDIDATES`), and only benches the provider once every candidate is
  exhausted. Verified against the live API on both the streaming chat path and
  the non-streaming explain/report path.

**Added**
- **`GEMINI_MODEL` / `GROQ_MODEL` / `ANTHROPIC_MODEL` overrides.** Previously the
  model was hard-coded, so there was no way to move off a model whose quota
  Google had zeroed without editing the source.
- **The local copilot is now reproducible.** Ollama seeds its sampler randomly, so
  the same capture was reworded on every run — indefensible for prose that goes
  into a forensic report. `OLLAMA_SEED` (default `42`) pins it; `random` opts out.

**Changed**
- **Faithfulness figures re-measured on `donbot.pcap` and corrected.** The
  previously published raw-model numbers do not reproduce on current code, and the
  built-in `--demo` capture turns out to be too small to expose hallucination at
  all (the raw model scores 100% on it). Measured on evidence-rich traffic with
  the seed pinned: raw `qwen2.5:7b-instruct` 62.5% (9 hallucinated claims) →
  100% / 0 guarded; across three local models, 47 raw hallucinations → 0 guarded.
  `reports/` and `docs/ollama_integration.md` now carry these numbers, and note
  that guarded faithfulness is a safety measure rather than a quality one.

### Professional AI packet analysis, richer Telegram alerts + PDF & a faster local LLM

**Added**
- **All three reports rebuilt to one professional house style.** A new
  `packetiq/export/report_style.py` is the single source of truth for the report's identity,
  its twelve numbered sections, its palette and its assurance statements — shared by the PDF,
  the HTML export and the AI-written report.
  The **PDF** (`export/pdf_report.py`) is now a print-ready document: a cover page with the
  risk verdict band and a document-details block (report reference, evidence SHA-256,
  classification), running headers, `Page X of Y` footers, and twelve numbered sections —
  Executive Summary, Scope & Methodology, Capture Overview, Risk Assessment, Detection
  Findings, Finding Details, Attack Chain Analysis, MITRE ATT&CK Coverage, Network Activity,
  Indicators of Compromise, Recommended Actions, and Limitations & Assurance.
  The **HTML export** gained the same cover block, self-numbering sections, and the shared
  limitations statement, with print rules that keep headings with their tables.
  The **AI-written report** (`/report`) now follows the identical twelve-section structure and
  is told to write "Not observed in this capture." rather than pad an empty section. A test
  locks all three surfaces to the same section list.

**Fixed**
- **Reports named the wrong evidence file.** For an uploaded PCAP the chain-of-custody block
  cited the internal temporary filename (a UUID) instead of the file the analyst submitted,
  because `PCAPParser.file_summary()` reports the name on disk. The report now always cites the
  submitted filename. This mattered: a forensics report that misnames its evidence is unusable.

- **Professional per-packet AI analysis, rendered as a triage card.** The "Explain this
  packet" copilot now reads a **decoded analyst fact sheet** (`inspect.analyst_facts` /
  `analyst_brief`) instead of a raw scapy field dump — so it reasons like a senior
  analyst: host roles (internal vs external), **TTL → OS fingerprint** and hop distance,
  **port direction** (client vs server, service vs ephemeral, shown as *numbers* — no
  more obscure aliases like `ifsf_hb_port`), TCP flags / handshake state, **payload
  Shannon entropy** (encrypted vs plaintext), and decoded app-layer (**TLS SNI**, HTTP
  request line, DNS query).
  The model now answers in **plain labelled sections** (Verdict · What this packet is ·
  Where it comes from · Is it suspicious? · Recommended action), which the web UI renders
  as a **styled triage card**: a colour-coded verdict badge with its one-line reason,
  headed prose sections, a **bulleted "Key points"** list, and a separate
  **"Evidence from the packet"** panel built from the deterministic facts — not from the
  model. Previously the panel printed the model's raw Markdown as a wall of text (literal
  `**Verdict**`). A server-side parser now strips stray Markdown, understands alternate
  and bare headings, splits the verdict from its reason, and falls back to cleanly
  formatted prose if the model ignores the format; the evidence panel is omitted rather
  than rendering `undefined` when facts are missing. 20 new tests.
- **Detailed Telegram findings + full PDF report.** The **📣 Send report + PDF** button
  now sends a proper SOC brief (risk, severity breakdown, top talkers, attack chains
  with MITRE, and every key finding with one-line evidence) instead of a two-line list,
  and attaches a **professional multi-section PDF report** (`export.build_pdf`, ReportLab,
  offline). Slack/e-mail get the same content as plain text. 10 new tests.

**Changed**
- **Faster, more accurate local LLM (Ollama).** The offline copilot now keeps the model
  **resident between requests** (`keep_alive`, default 30 min — no more multi-second cold
  reloads), **sizes the context window to the prompt** so large grounded PCAP context is
  no longer silently truncated (a real accuracy fix), caps output tokens per task
  (a single-packet explanation no longer generates up to 2048 tokens), and **pre-loads
  the model** in the background when it's the active provider so the first query is fast.
  Tunable via `OLLAMA_KEEP_ALIVE` / `OLLAMA_NUM_CTX`. 5 new tests.

### Wireshark-accurate packets, 1-click Telegram & a faster pipeline

**Fixed**
- **Packet protocol labels now match Wireshark.** The Packets browser used to call
  *every* segment on port 80 "HTTP" and *every* segment on port 443 "TCP/443"
  (TLS was never recognised because scapy's TLS layer isn't loaded). Labels are now
  decided by **payload inspection, exactly like Wireshark's Protocol column**: a TCP
  segment is only "HTTP"/"TLS" when it actually carries that protocol, so handshake /
  ACK / keep-alive segments correctly read "TCP", TLS records read "TLS", and HTTP or
  TLS on non-standard ports is still detected. The Info column is now Wireshark-style
  too (`51000 → 80 [SYN] Seq=0 Win=8192 Len=0`, `GET /path HTTP/1.1`,
  `TLS 1.2 Client Hello`, `Standard query 0x1a2b A example.com`). 8 regression tests added.

**Added**
- **One-click Telegram alerts — no file editing.** A guided **✈️ Connect Telegram**
  panel in the web app takes a @BotFather token, **auto-detects your chat ID** (it
  reads the bot's recent messages so you never hunt for a numeric ID), and sends a
  live test message. Applies instantly and, unless you opt out, is saved to `.env`;
  removable from the UI. New endpoints `GET/POST/DELETE /api/notify/telegram` and
  `POST /api/notify/telegram/detect`; 4 isolated tests.

**Changed**
- **~40 % faster analysis, identical results.** The capture was being parsed **5
  times** (extraction + credential + JA3 + TLS-cert + file-carving). Detectors that
  consume the same record type now **share one pass** (credential + JA3) and the raw-
  packet detectors share another (TLS-cert + file-carving), cutting it to **3 passes**;
  the per-packet parser also stopped building the TCP/UDP payload twice and dropped an
  unused layer-list allocation. On a 20 MB capture end-to-end analysis dropped from
  ~90 s to ~55 s (profiled). Detection output is **byte-for-byte identical** — verified
  on 5 real captures (same event SHAs), so precision/recall are unchanged.

### Offline-first web app & in-app AI keys

**Added**
- **Fully offline web app.** Chart.js and marked are now **bundled and served
  locally** (`/static/vendor/…`) instead of from a CDN, so the browser UI works
  with no internet at all. The core analysis was already offline (bundled
  threat-intel snapshots, local detectors); this closes the last online dependency.
- **Enter API keys in the app — no `.env` editing, no restart.** A **⚙ Keys**
  panel in the copilot lets you paste a Gemini / Groq / Anthropic key; it applies
  immediately (`POST /api/ai/key` sets it in-process) and, unless you opt out, is
  saved to `.env` so it persists. Keys can be removed from the UI too. The no-key
  banner is now an actionable "Add an API key" button instead of instructions to
  edit a file and restart.
- **Local-LLM (Ollama) status surfaced.** The settings panel shows whether the
  local daemon is running and which models are installed — the copilot runs fully
  offline and private with no key. Ollama is only ever contacted on `localhost`.

**Fixed**
- Six new tests cover offline asset serving (no CDN, path-traversal-safe) and the
  key set/clear/persist flow (isolated from the real `.env`).

### Web-app parity, richer reports & CI fixes

**Added**
- **NetFlow / IPFIX analysis from the web app.** A raw NetFlow v5 / v9 / IPFIX
  export can now be uploaded and analysed in the browser through the same
  upload → detect → report pipeline a PCAP uses — closing the last CLI-only gap.
  Exports are routed by extension (`.netflow` / `.nfcapd` / `.ipfix` / …) **or** by
  their version word (first two bytes), so an unfamiliar extension still works and
  a PCAP is never misclassified. Two web-path tests were added.
- **Substantially richer downloadable report.** The self-contained HTML / court-ready
  PDF report gained traffic-composition (protocol mix, throughput, TCP-handshake
  completion), top-talkers with passive OS hints, top conversations, service/port
  usage, DNS and HTTP activity, observed software banners, threat-actor TTP-overlap
  (clearly labelled *not* attribution), a consolidated analyst action list, and a
  methodology note. Every section is deterministic and derived only from the
  captured evidence — no value is inferred by a model.

**Fixed**
- **CI Python 3.9 job.** Root cause was the non-existent dependency pins above; with
  the corrected floors a clean 3.9 install and the full test suite pass. Bumped
  `actions/checkout@v5` and `actions/setup-python@v6` (Node 24) to clear the
  deprecation warnings.
- **Documentation accuracy pass.** Corrected stale/overstated metadata: the real
  test count (217), "15 detection types across 12 modules" (was "20+ detectors"),
  and OSINT feeds described as dated, refreshable **snapshots** rather than "live".

### Detection accuracy, flow inputs & CI hardening

**Added**
- **NetFlow / IPFIX ingestion** (`packetiq/inputs/netflow.py`, `packetiq netflow`).
  Parses Cisco **NetFlow v5**, **NetFlow v9**, and **IPFIX (v10)** export files —
  template-based decoding of the IANA Information Elements — into the same
  `ExtractionResult` the PCAP path produces, so every flow-based detector
  (port/host scan, beacon, ICMP volume, SMB / cleartext misuse) and IOC enrichment
  runs on flow telemetry at collector scale with no raw capture. Eight new tests
  cover v5, v9, IPFIX, multi-datagram streams and graceful degradation.
- **Real-world detection accuracy re-measured and enlarged.** The CTU-13 harness
  now spans **five malware families** (added Virut fast-flux / DGA) plus benign
  captures: **100% recall · 83.3% precision · 90.9% F1** (up from 57% precision),
  every decision attributable to a specific detector — see `reports/detection_real.md`.
- **CI eval gates.** `tools/validate.py` gained `--min-recall / --min-precision /
  --min-f1` (exit non-zero below the floor). CI now enforces the synthetic suite at
  100% recall/precision, runs the deterministic guardrail invariant, a throughput
  benchmark smoke, and a `pip-audit` dependency-CVE scan on every push.

**Changed / Fixed**
- **False-positive precision fixes (principled, recall preserved).** A shared
  `same_org_network()` helper stops the SMB, cleartext-protocol, C2-beacon and
  non-standard-resolver detectors from misreading **intra-LAN traffic on a
  public-IP network** (e.g. a university /16) as internet-facing. The DNS
  "excessive-query" signal — re-resolving one name, a caching/polling artifact — is
  demoted to LOW/informational; DGA, tunneling and IOC remain the discriminative
  DNS threats. Recall held at 100% on real malware and the synthetic suite held 100%.
- **Dependency pins corrected to versions that exist on PyPI.** The former
  `setup.py` pinned floors that do not exist (`python-multipart>=0.0.31`,
  `requests>=2.33.0`, `urllib3>=2.7.0`, `python-dotenv>=1.2.2`), which broke a clean
  `pip install`. `pyproject.toml` and `requirements.txt` now carry the real
  security-patched floors — `python-multipart>=0.0.18` (CVE-2024-53981),
  `requests>=2.32.4` (CVE-2024-47081), `urllib3>=2.6.0`, `cryptography>=44.0.1` —
  kept in lockstep.

### Added — local AI copilot & evaluation
- **Local-LLM copilot (Ollama) — offline, private, no API key.** The AI copilot
  can now run entirely on the analyst's machine via a local Ollama model, so
  sensitive PCAPs never leave the host and there are no rate limits. It is
  auto-detected when the Ollama daemon is reachable (not gated on a key) and
  slots into the existing provider system as a fallback *after* any configured
  cloud key — so cloud wins when present, local covers you when it isn't. Pick
  **"Local (Ollama)"** in the web AI selector, or let Auto fall through to it.
  Env: `OLLAMA_MODEL` (default `qwen2.5:7b-instruct`), `OLLAMA_HOST`,
  `PACKETIQ_ENABLE_OLLAMA=0` to disable. Applies to chat, Explain-with-AI and
  AI reports through the same streaming path as the cloud providers.
- **CLI copilot is now multi-provider too.** `packetiq chat` and `packetiq
  report` previously required an Anthropic key; they now route through the same
  provider layer as the web app (Gemini → Groq → Anthropic → local Ollama) via a
  small adapter, so they work with any free cloud key *or* fully offline with a
  local model — and the interactive REPL can't be killed by a transient provider
  error (it switches or reports gracefully).
- **Copilot grounding (anti-hallucination).** The web and CLI system prompts now
  carry explicit *grounding rules* — answer only from the capture evidence, never
  invent an IP/domain/port/technique/CVE/hash, copy IDs verbatim (don't pad a
  list from prior knowledge), and say "That is not present in this capture" when
  there is no supporting evidence. Sampling temperature was lowered to **0.15**
  across all providers (`PACKETIQ_AI_TEMPERATURE`). The detectors — not the LLM —
  remain the sole source of truth for findings; the AI only explains what they
  already found.
- **Grounding guardrail — a hard guarantee, not just a prompt.** On top of the
  prompt rules, a deterministic post-filter now sits on the copilot's output
  stream (`_stream_ai`, so it covers chat, Explain-with-AI, AI reports and the
  CLI alike). Every specific claim the model emits — IP address, MITRE technique
  ID, CVE, **domain and file hash (MD5/SHA-1/SHA-256)** — is checked against the
  exact evidence it was given (the analysis context plus the analyst's own
  question); anything ungrounded is redacted before it reaches the user, and a
  wholly-invented list item is dropped. Domains are matched behind a real-TLD gate
  so file names (`app.py`), field references (`tcp.port`) and version strings are
  never touched, and naming the registrable parent of an observed FQDN is allowed
  while an invented sibling subdomain is not. It can
  only ever *remove* an invented entity, never add or alter a real one, so a
  faithful answer passes through byte-for-byte. This is what lets even a small
  local model reach **0 hallucinations**: on the built-in evaluation, raw
  `qwen2.5:7b-instruct` scores ~45–75% faithful (it varies run-to-run — LLMs are
  non-deterministic), and a deterministic **100.0%** with the guardrail on. On by
  default; `PACKETIQ_GROUNDING_GUARD=0` disables it (used to measure the
  raw model in the harness). The evaluation harness quantifies both so the effect
  is visible, not asserted.
- **Copilot faithfulness evaluation harness** (`tools/eval_copilot.py`) — a
  quantitative, human-free measure of copilot groundedness: it runs the real
  copilot path over labeled captures and computes **faithfulness** (the share of
  the model's specific claims — IPs, MITRE technique IDs, CVE IDs — that are
  actually present in the evidence it was given), flagging any invented entity as
  a hallucination. Runs fully offline against a local Ollama model; emits JSON /
  Markdown for reporting.
- **Detection precision/recall harness + table** — `tools/validate.py` gained a
  built-in **synthetic labeled fixture suite** (`--suite`, one crafted capture per
  detector plus benign traffic) that produces a real precision/recall/F1 and
  per-detector recall table with nothing to download, plus **`--markdown`** report
  output. `datasets/README.md` documents pointing the same harness at real public
  captures (malware-traffic-analysis.net, CIC-IDS2017, Stratosphere IPS). Synthetic
  numbers are labeled as such — they are a regression/sanity check, not a
  real-world accuracy claim.
- **Real-world detection validation (Stratosphere CTU-13).** `datasets/fetch_ctu.sh`
  pulls a small, balanced set of genuine labeled captures (real malware botnets +
  real benign traffic) and `datasets/ctu13_manifest.json` runs the same harness
  over them. Measured result: **100% recall (every real malware capture caught,
  zero misses)** with a transparent, per-detector account of the precision
  trade-off (`reports/detection_real.md`). Captures are gitignored (large +
  malware); the manifest and fetch script are versioned so the run is reproducible.
- **Multi-model faithfulness ablation** (`tools/ablation.py`) — runs the copilot
  faithfulness eval across several local Ollama models (e.g. `qwen2.5:7b`,
  `llama3.1:8b`, `llama3.2:3b`) with the guardrail off vs on, showing the
  guardrail reaches a deterministic 100% on *every* model, not just one.
- **Pipeline throughput benchmark** (`tools/benchmark.py`) — measures real
  packets/s, MB/s, per-stage timing and peak memory through the exact
  parse→extract→detect pipeline, on a synthetic capture (`--demo`, no download) or
  real captures (`--dir`/`--pcap`). Confirms streaming keeps memory roughly flat
  with capture size (`reports/performance.md`).

### Fixed
- **IOC false positive: shared-hosting domains no longer blocklisted from URL
  indicators.** ThreatFox lists malicious *URLs* staged on multi-tenant services
  (e.g. `https://drive.google.com/uc?...` — malware on Google Drive). The feed
  parser collapsed each URL to its bare host, so `drive.google.com` (and Dropbox,
  Discord CDN, GitHub raw, pastebin, `t.me`, …) became CRITICAL "malicious
  domains" — a critical false alarm for every legitimate user. A URL IOC on a
  shared front-door host is no longer promoted to a domain IOC
  (`packetiq/enrichment/feeds.py`; regression test in `tests/test_enrichment.py`).
  Found while validating against real benign traffic.

### Added — analyst experience & assurance
- **Per-finding explainability + precision grading** (`packetiq/triage.py`). Every
  detection now carries a plain-English *what / why / recommended action*, the
  concrete evidence behind it, its MITRE technique and kill-chain phase, and a
  **precision grade** (Confirmed / High / Probable / Tentative) — Confirmed being
  reserved for evidence-backed findings (real feed hits, cleartext credentials,
  malware-hash matches). Surfaced as an expandable "Why was this flagged?" row in
  the web Events panel and in the report.
- **False-positive reduction (precision-first).** A conservative triage stage
  applies an optional, config-driven **allow-list** (`[allowlist]` IPs/CIDRs/
  domains/JA3 in `packetiq.toml`) and an optional **confidence floor**
  (`[triage] min_confidence`) before risk scoring. Defaults change nothing
  (recall preserved); the layer exists to suppress *known-good* noise on demand.
  No detector is claimed to be false-positive-free — findings are graded and
  explained instead.
- **Visual kill-chain pipeline** in the web Attack Chains panel — each correlated
  chain renders as a Reconnaissance→…→Actions-on-Objectives flow that highlights
  the phases actually reached.
- **MITRE ATT&CK coverage matrix** (in-GUI heatmap, by tactic, coloured by peak
  severity) plus a real **ATT&CK Navigator layer export** (`packetiq navigator`,
  web `GET /api/navigator/{job}`, and an Exports button) openable in the official
  Navigator.
- **Court-ready report.** The HTML report gained a chain-of-custody header
  (capture filename/size/**SHA-256**, capture window, analysis time, tool
  version), an executive summary, the ATT&CK coverage matrix, per-finding
  explainability, and a **print stylesheet** — a one-click **"Save court-ready
  PDF"** opens it paginated and light-on-white for printing/PDF.

### Added — threat intelligence
- **Vulnerability assessment (NVD CPE + CVSS + CISA KEV)** — the deep version of
  the CVE lookup. Each host's observed software is resolved to an official **CPE**
  and matched to NVD CVEs for that *exact version* (not a fuzzy keyword search),
  scored by **CVSS**, and cross-referenced against **CISA's Known Exploited
  Vulnerabilities** catalogue (live, cached) to flag what's *actively exploited*
  and used in ransomware. Observed **exploit attempts are correlated against the
  target's real software** (attack-seen + target-vulnerable). Surfaced as
  `packetiq vulns`, the web **Vulnerabilities** panel (per-host attack surface +
  vuln risk score), `GET /api/vulns/{job}`, and an optional report section
  (`packetiq html --vulns`). All data from NVD + CISA; nothing is invented.
- **Dynamic per-PCAP Threat Intel** — the Threat-Intel panel now shows the
  indicators that actually matched *this* capture (IOC IPs/domains, malicious
  JA3, known-malware hashes) grouped by feed and affected host, synced to the
  analysed PCAP, above the loaded-feed inventory (`threat_intel_matches` in the
  results).
- **NVD CVE lookup** — reads the *real* software banners observed in a capture
  (HTTP `Server` response headers and `User-Agent` request headers) and queries
  NIST's official NVD REST API 2.0 for matching CVEs, with CVSS scores, severities
  and links. Available as `packetiq cve <pcap>`, the web `GET /api/cve/{job}`
  endpoint, and a one-click **CVEs** panel in the GUI. Optional `NVD_API_KEY`
  raises the rate limit (~5 → ~50 req/30s). Nothing is invented — CVE data comes
  straight from NVD, and captures with no plaintext banners (e.g. all-HTTPS) report
  nothing to look up.
- **IOC enrichment** against real OSINT feeds (abuse.ch Feodo Tracker, ThreatFox,
  MalwareBazaar; the Tor exit list; Spamhaus DROP). Observed IPs, CIDRs and
  domains are matched against bundled real snapshots and emitted as `IOC_MATCH`
  findings. Refresh with `packetiq feeds update`; inspect with `packetiq feeds status`.
- **JA4** (FoxIO) TLS client fingerprinting alongside JA3, surfaced in evidence.
- **TLS certificate inspection** — flags self-signed, expired/not-yet-valid and
  abnormally long-validity server certificates (`TLS_ANOMALY`).
- **YARA scanning** over reassembled streams / carved files (bundled example
  rules + `PACKETIQ_YARA_RULES`; optional `yara-python`).
- **HTTP deep inspection** — SQLi / XSS / path-traversal / command-injection /
  Log4Shell / webshell URI patterns and scanner User-Agents (`HTTP_ATTACK`).
- **Jitter-tolerant beaconing** — periodicity check that catches jittered C2 a
  pure coefficient-of-variation test would miss.

### Added — workflow & integrations
- **One-time live-capture setup** (`packetiq setup-capture`, web `POST /api/live/setup-capture`,
  and a **"🔓 Enable live capture (one-time)"** button in the Live Monitor) so live
  capture works without per-run `sudo`. macOS installs **ChmodBPF** (the same
  approach Wireshark uses) via a single native admin-password prompt; Linux grants
  **CAP_NET_RAW** to the Python interpreter with `setcap`; Windows detects **Npcap**
  and explains how to enable non-admin capture. A single `capture_setup.status()`
  is now the source of truth for the GUI's capture-privilege banner.
- **STIX 2.1 export** (`packetiq stix`, web `/api/stix/{job}`) and an IOC bundle
  computed during every web analysis.
- **MISP push** (`packetiq misp`) — build a MISP Event from IOCs and push via REST.
- **pySigma-valid rules** — SIGMA output now parses with the real SIGMA toolkit
  (validated in CI); legacy inline aggregations moved to rule descriptions.
- **Packet inspector (Wireshark-style, friendly)** — a web **Packets** browser
  showing every packet with search, a per-packet layer/field tree + hex view, and
  **"Explain with AI"**. Endpoints: `/api/packets/{job}`, `/api/packets/{job}/{i}`,
  `/api/packets/{job}/{i}/explain`.
- **Cross-platform + responsive** — temp/upload paths use the OS temp dir (no more
  hardcoded `/tmp`, so Windows works); capture-privilege detection is OS-aware
  (root / macOS `access_bpf` / Windows Administrator+Npcap) with tailored guidance;
  double-click launchers for macOS/Linux (`PacketIQ.command`) and Windows
  (`PacketIQ.bat`). The web UI is fully responsive (verified desktop + mobile):
  sidebar collapses to icons, grids stack, stats reflow, tables stay swipeable.
- **Live capture fixed on real interfaces (macOS)** — scapy's native BPF couldn't
  set promiscuous mode (`BIOCPROMISC` → "Operation not supported"), which silently
  killed the sniffer on `en0`/Wi-Fi so only `lo0` (localhost) ever showed traffic.
  Promiscuous mode is now disabled (not needed to see the host's traffic), so all
  interfaces capture. The picker also defaults to the active NIC instead of `lo0`,
  and reports whether capture is permitted (root / macOS `access_bpf` group).
- **Live capture, fully wired** — records to a PCAP, streams **every packet** (not
  just findings), **Download PCAP**, **Stop & Analyze** to run the full report so it
  populates every section, plus privilege/zero-packet health hints. **Clear history**
  added. Endpoints: `/api/live/{sid}/packets`, `/api/live/{sid}/pcap`,
  `/api/live/{sid}/analyze`, `DELETE /api/history`.
- **Interactive connection graph** — dependency-free force-directed graph in the
  web Network panel (plus the SVG graph in the HTML report).
- **100% GUI parity** — every CLI capability is driveable from the web app:
  multi-capture **campaign/fuse** (drag in 2+ captures), Zeek upload, live capture,
  HTML / **AI markdown** / SIGMA / STIX / MISP exports, evidence-PCAP carving,
  threat-intel feed status/update, history, and **notifications** (test + send
  findings to Slack / email / webhook / Telegram). New endpoints: `/api/fuse`,
  `/api/notify/*`, `/api/report/{job}/ai`, `/api/feeds/*`, `/api/misp/{job}`,
  `/api/evidence/{job}`, `/api/live/*`. Plus **double-click launchers**
  (`PacketIQ.command` / `PacketIQ.bat`) for zero-terminal startup.
- **Evidence PCAP slicing** (`packetiq slice`) to carve the packets for a finding.
- **REST API** `POST /api/analyze` for scripts / CI (synchronous JSON).
- **Alert channels** — Slack, generic webhook and SMTP email (`packetiq notify`),
  in addition to Telegram.
- **Zeek `conn.log` ingestion** — analyze flow logs without a PCAP.
- **Live capture mode** — sliding-window detection on a NIC, available both in the
  CLI (`packetiq live`) and as a **Live Monitor panel in the web GUI** (interface
  picker + real-time findings; web endpoints `/api/live/*`).
- **Tunable configuration** via `packetiq.toml` (detector thresholds).
- **Detector validation harness** (`tools/validate.py`) — precision/recall over
  labeled PCAP datasets.

### Security
- Removed real Gemini/Groq API keys that had been committed to `.env.example`
  (placeholders only now). **Keys present in earlier git history must be rotated.**
- **Full security audit + hardening** (SAST, dependency CVE scan, secret scan,
  and manual review — see `docs/reports/PacketIQ_Security_Audit_Report.pdf`). Fixed:
  **path-traversal / arbitrary file write** in the evidence export (the `ip`
  filter is validated and never reaches the output path); **DNS-rebinding** and
  **CSRF** on the local web server (new middleware validates the Host header and
  blocks cross-origin state-changing requests — e.g. a malicious page can no
  longer trigger the privileged capture-setup prompt); **upload memory-exhaustion
  DoS** (uploads stream to disk with an early size abort; default cap 2 GB via
  `PACKETIQ_MAX_UPLOAD_MB`); oversized HTTP buffer / long keep-alive reduced;
  **command-injection hardening** of the privileged macOS capture-setup (strict
  `$USER` validation); world-readable upload/history dirs tightened to `0700`; a
  security warning is printed when binding to a non-loopback address. Dependencies
  bumped to patched versions (`python_requires` raised to 3.10 for the fixed
  `requests`/`python-multipart`/`urllib3`). MD5-in-JA3 annotated (`usedforsecurity=
  False`) — it is the JA3 spec, not a security control. bandit High/Medium: 0.

### Fixed
- **"Explain with AI" (and AI report) now fall back across providers.** They
  previously used only the first configured key, so a Gemini free-tier `429`
  quota error surfaced as a hard error. They now auto-fall-back Gemini → Groq →
  Anthropic (matching the chat panel) and return a clear message only if *all*
  providers are exhausted or none is configured.
- **Smart, sticky AI auto-switch.** When a provider is rate-limited it's now put
  on a short cooldown (parsed from the API's own retry hint), so the *next*
  request goes straight to a healthy provider instead of wasting a retry on the
  dead one. Added a GUI provider selector (Auto / Gemini / Groq / Anthropic) that
  shows the active provider and live cooldowns, backed by `GET /api/ai/status`
  and `POST /api/ai/provider`. Applies across chat, Explain-with-AI and reports.
- **JA3 threat database** replaced fabricated hashes with the real abuse.ch SSLBL
  JA3 feed (bundled + refreshable). No fingerprints are invented.
- **Attribution** reframed as *behavioural TTP overlap* (an investigative lead),
  not confirmed attribution, with disclaimers across CLI and web UIs.
- **XMAS / suspicious-flag detection** — fixed a flag-ordering bug that prevented
  XMAS (FIN+PSH+URG) scans from ever being detected.
- **SIGMA generator** — produces valid YAML (quoted titles, real dates, correct
  evidence keys).
- README accuracy pass (risk 0–100 not 0–10, sequential pipeline, JA3 wording,
  WhatsApp marked planned, indicative-only performance figures).

### Project
- Added `LICENSE` (MIT), `pyproject.toml`, `MANIFEST.in`, `CHANGELOG.md`,
  `quickstart.sh`, Dockerfile + docker-compose, GitHub Actions CI, and a
  pytest suite covering the parser, detectors, enrichment, TLS, export and config.
