# Changelog

All notable changes to PacketIQ are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0]

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
