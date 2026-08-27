# Changelog

All notable changes to PacketIQ are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] — 2026-08-11

First stable release. PacketIQ is a defensive network-forensics platform that turns
a packet capture, a Zeek `conn.log`, a NetFlow/IPFIX export or a live interface into
an evidence-backed analysis: 18 detection types across 12 detector modules, real
threat-intel enrichment, MITRE ATT&CK and kill-chain correlation, deployable SIGMA /
STIX / MISP output, and an optional AI copilot whose every claim is checked against
the capture before it reaches the screen. The core pipeline runs fully offline.

**State of the release, as measured on 2026-08-11** (macOS 26.6.1 arm64,
CPython 3.12.13) rather than asserted:

| | |
|---|---|
| Tests | **1,843 passing**, **100.00%** line coverage of **10,050** statements |
| Coverage gate | 100% floor enforced in CI on **Python 3.9, 3.10, 3.11, 3.12** |
| Platforms | Linux, macOS and Windows each run the suite in CI |
| Lint / types | `ruff` clean · `mypy` clean across **83** source files |
| Static security | `bandit` at its strictest setting: **no issues at any severity** over **17,196** lines |
| Dependencies | runtime closure: **zero** known advisories (blocking gate) |
| Detection (real) | **100%** recall · **90.0%** precision · **94.7%** F1 on Stratosphere CTU-13 |
| Detection (synthetic) | 100% recall · 100% precision, gated on every push |
| Throughput | **4,005 packets/s** aggregate over 12 captures (1,668,975 packets, 427.7 MB) |
| Threat intel | **8,398** bundled indicators (8,301 feed entries + 97 JA3 fingerprints) |
| Interfaces | **24** CLI commands · FastAPI web app · local dashboard |

Precision is an honest **90.0%**, not a rounded-up 100%: one benign-labelled capture
raises a MEDIUM finding, and that finding is itself a correct detection of real
inbound internet scanning. It is
[documented and analysed openly](reports/detection_real.md) rather than suppressed.

Everything below is the development record, newest first — the defects found, what
each one actually broke, and how it was verified fixed.

### The source download was being deleted by anti-virus

Microsoft Defender quarantined `PacketIQ-main.zip`, downloaded straight from
codeload.github.com, as `Backdoor:PHP/Remoteshell.F`. Not a warning — the archive
was removed. On a managed university or corporate machine that happens silently
and there is no obvious way past it.

**Fixed**
- **`tests/test_yara.py` shipped two complete PHP webshells and the EICAR
  string.** They were inert Python byte-literals, never executed, feeding
  PacketIQ's *own* webshell detector so the test could assert it fires — which is
  the only way to test a webshell detector, and also precisely what a signature
  matches. The fixtures are now assembled at runtime from fragments split with a
  visible `~`; the scanner under test receives byte-identical input and every
  assertion is unchanged. A round-trip test pins the bytes **by digest** rather
  than by writing the payload out a second time, and the EICAR digest it checks
  against is the published one for EICAR.COM — a value from outside this
  repository.
- **The bundled YARA rules carried the EICAR string as a quoted literal.** Every
  anti-virus product detects EICAR; that is its entire purpose. It is now written
  as a hex byte sequence, which matches the same 68 bytes and leaves nothing for a
  scanner to lift out of the rule file. The webshell and cradle patterns were
  already fragments (`eval($_POST` with no `<?php`) and stay that way — better
  detection, and not a runnable anything.

**Added**
- **`tests/test_repo_hygiene.py`**, which scans the *tracked* file set — what
  GitHub actually serves, not the working tree — for a contiguous EICAR string or
  a PHP open tag sitting near an exec sink. It caught one immediately: a line in
  the new test's own docstring that quoted the offending string while explaining
  it. A fourth test proves the pattern has teeth by matching the exact literal
  Defender flagged, and proves it does not fire on the detection fragments that
  must stay in the rule file.

**Verified** — built the archive with `git archive` and confirmed both signatures
are present at HEAD (reproducing what was quarantined), then staged the working
tree the same way and confirmed both are gone from all 255 shipped files. The
generated demo capture was checked too and carries no EICAR, no webshell, no PE
header: it is synthetic attack *behaviour*, not malware bytes. YARA still matches
both fixtures, so detection is unchanged. Suite **1,843 passing** at 100.00%
coverage on Python 3.9 and 3.12, natively and under the Windows simulation.

### The Windows leg, fixed and then actually run

CI came back with one job red — `test (windows-latest, py3.12)` — on a single
line, and behind it a second failure that had never had the chance to happen.

**Fixed**
- **`os.sysconf` does not exist on Windows, and typeshed knows it.** The RAM
  probe added for the local-model picker calls it inside a `contextlib.suppress`,
  which is correct at runtime on every platform — but mypy targeting Windows
  reports `Module has no attribute "sysconf"  [attr-defined]`, so the type gate
  failed there and only there. Fixed with the ignore this project already uses
  for POSIX-only symbols, deliberately *not* an `if sys.platform` guard: mypy
  reads such a guard as unreachable on Linux, which is the leg that measures
  coverage.
- **Three tests would have failed on Windows the moment mypy stopped failing
  first.** `monkeypatch.setattr(os, "sysconf", …)` raises `AttributeError` where
  the attribute does not exist, and because the Windows job died at the type
  check, its test step had never run — the defect was queued behind the one that
  was visible. All three now pass `raising=False`, which is what the
  capture-privilege tests already do for `os.geteuid`/`grp`: supply the symbol
  rather than skip the test, so the POSIX branch stays *measured* on Windows
  instead of silently unmeasured.

**Added**
- **A test for the shape Windows actually has** — the attribute missing rather
  than failing — so the fall-through to `GlobalMemoryStatusEx` is exercised the
  way the Windows runner will exercise it.
- **A layout assertion for `MEMORYSTATUSEX`.** `GlobalMemoryStatusEx` fills the
  struct *by offset*, so a reordered or mistyped field would not raise — it would
  return a different number, silently, on the one platform that cannot be run
  here. The field order and the DWORD/DWORDLONG split are asserted instead.

**Verified** — reproduced the failure from this Mac with `mypy --platform win32`
before changing anything, then rebuilt the Windows simulation described in the
cross-platform notes (a pytest plugin: `sys.platform = "win32"`, the POSIX `os`
attributes deleted, `grp`/`pwd`/`resource`/`fcntl` unimportable). Under it the
whole suite is **1,843 passing at 100.00% coverage** — coverage holding on the
simulated platform is the real result, because it means no branch quietly stops
being measured there. Confirmed the simulation has teeth by removing
`raising=False` again and watching exactly those three tests fail. mypy is clean
on **all three target platforms** (`--platform win32`, `linux`, `darwin`) under
mypy 1.19.1 and 2.3.1 alike, and the suite passes on Python 3.9 and 3.12, both
natively and under the simulation. The one Groq-era lesson repeated itself
usefully: `anthropic` had moved on again, to **1.1.0**, and the capability probe
picked it up with no change.

### Provider SDKs and model lists, checked against the providers rather than remembered

CI went red on four of five legs, and chasing it down turned up three more
defects of the same shape: a name or a signature written into the source once,
believed thereafter, and wrong.

**Fixed**
- **`anthropic` 1.0.0 removed `temperature` from the Messages API, and PacketIQ
  still sent it.** The methods take no `**kwargs`, so the parameter is not
  ignored — it raises `TypeError` and the provider stops answering. mypy caught
  it in `copilot/client.py` and could not see it in `webapp/app.py`, where the
  client is annotated `Any` because one name is rebound to four SDKs in that
  function; that half would have reached users as a runtime failure on the first
  question after a clean install. Both call sites now ask the installed SDK
  whether it takes the parameter and send it only where it does, so 0.x and 1.x
  both work and neither is pinned. Where it is gone the request runs at the API
  default temperature — that changes how varied the prose is, not whether it is
  grounded, because the deterministic guardrail does not depend on sampling.
- **Groq retired `llama-3.3-70b-versatile`, this file's declared Groq default.**
  Every request for it returns `404 - The model does not exist or you do not have
  access to it`. Verified against the live API, replaced with
  `openai/gpt-oss-120b` — measured answering the same analysis question in 0.7s
  with clean prose, where `qwen/qwen3.6-27b` leaks `<think>` blocks into the
  answer and `groq/compound` took 6.4s.
- **A Groq 413 was not recognised as a rate limit, so the provider was never
  benched.** Groq's free tier allows 8,000 tokens per minute and a grounded PCAP
  context is around 11,000, so it answers `413 … 'code': 'rate_limit_exceeded'`
  — no `429`, no `quota`, and `rate_limit` spelled with an underscore rather
  than a space. It matched none of the markers, so the sticky cooldown never
  fired and every subsequent message paid another full failing round trip before
  switching. The fallback itself worked correctly throughout; it was just doing
  it the expensive way.
- **The Gemini catalogue came back empty because its pager outlived its client.**
  Written as `for m in Client(key).models.list()`, the client is released the
  moment the expression ends and the lazy pager dies with "Cannot send a request,
  as the client has been closed" — which surfaces as "this key has no models".
  Found by running it against the real API rather than a stub.

**Added**
- **Model lists loaded from the providers themselves.** `POST /api/ai/models/refresh`
  asks Google's, Groq's or Anthropic's models endpoint what the configured key
  can actually call, and the picker shows exactly that — id, the provider's own
  display name, and its context window. Measured on one real setup: **37 Gemini
  models, 9 Groq, 3 local**. Entries the provider marks as something other than
  text-to-text (Whisper transcription, Orpheus speech) are dropped because they
  cannot answer a chat request; nothing else is filtered and nothing is invented.
  Cached 15 minutes, reloaded on demand or when a key changes, and a failure is
  shown as the provider's own message. Where no list has been fetched the built-in
  names are used and **labelled built-in**, and a hand-typed model is labelled
  `unverified`, so a compiled-in guess never looks like a confirmed fact.
- **A contract test binding every provider call to the installed SDK.** The
  suite stubs each SDK, which is what makes it fast and offline — and is what let
  the Anthropic break through: the stubs take `**kwargs` and accepted a parameter
  the real SDK had deleted, so 1,843 tests stayed green against a provider that
  would have raised on the first question.
  `tests/test_provider_sdk_contract.py` binds the exact keyword set each call
  site sends to the real `Signature`, for Anthropic (sync, single-shot and the
  web app's async arm), Groq and Gemini. A dropped or renamed parameter now fails
  pytest on every platform instead of mypy on one — and covers the arm mypy
  cannot see at all.

**Verified** — reproduced the CI failure locally in a clean environment first,
then ran the whole gate on three closures: Python 3.9 (mypy 1.19.1, anthropic
0.125.0 — the only leg that was green, and only because 1.0.0 requires >=3.10),
Python 3.12 with anthropic 0.116.0, and Python 3.12 with anthropic 1.0.0 and
mypy 2.3.1, which is the combination CI installs. All three: **1,843 passing**,
**100.00%** coverage, `ruff` and `mypy` clean. The Gemini pager fix was confirmed
by reverting it and watching the new test fail with the real error message.

### The copilot's model is now a choice, not a lottery

Reported against the AI Copilot: with several models pulled, the local runtime
answered through a different one from run to run, and sometimes through one large
enough to make the machine crawl. There was no way to say which model to use short
of editing `.env` and restarting.

**Fixed**
- **The local model was picked by list order, so pulling anything changed which
  one answered.** `_ollama_model()` preferred the tuned default when it was
  installed and otherwise fell through to `models[0]` — the first entry of
  Ollama's `/api/tags`, which is ordered by modification time. Pull a new model
  and the copilot silently switched to it. On a machine with modest RAM that could
  be a model several times too large, and an oversized model does not fail
  cleanly: it loads, swaps, and answers minutes later. The pick is now
  deterministic and sized against the machine's real memory — the tuned default if
  it is installed *and* fits the RAM budget, else the largest installed model that
  fits, else the smallest installed, with ties broken by name so two equal-sized
  models cannot trade places between runs. Erring small is deliberate: an
  undersized model is less eloquent, not less accurate, because the grounding
  guardrail closes its indicator vocabulary to the evidence either way.
- **Nothing in the product let a user choose the model.** `<PROVIDER>_MODEL` was
  read from `.env` but only settable by hand, and only applied on restart —
  precisely the workflow the in-app key entry had already replaced for API keys.
  `POST /api/ai/model` now pins (or clears) a model for any provider, applies
  immediately, and persists to `.env` unless asked not to. The AI Copilot panel
  renders it as a dropdown beside the provider selector and inside *Keys*, and
  `packetiq chat|report` gained `--provider` / `--model` so the CLI sets the same
  pin. An Ollama model that is not pulled is refused with the `ollama pull`
  command that would fix it, instead of being accepted and 404-ing on the first
  question.

**Added**
- **Real numbers to choose against.** The daemon probe now keeps each model's
  `size` and `details.parameter_size` alongside its name, and the picker shows
  them — `llama3.2:3b · 2.0 GB · 3.2B` — beside this machine's physical RAM and
  the 60% budget a resident model plus its KV cache can reasonably occupy. RAM is
  read from the OS (`sysconf` on Linux and macOS, `GlobalMemoryStatusEx` on
  Windows), never estimated; where the platform will not report it, no fit claim
  is made anywhere in the UI.
- **A conftest guard for host RAM.** The picker's branch now depends on physical
  memory, which is exactly the kind of host fact that has made this project's
  coverage differ between two green runs before (the network, capture and
  interface guards each exist for the same reason). Every test now sees a fixed
  16 GiB.

**Verified** — 44 new tests covering both halves; suite **1,843 passing** at
**100.00%** coverage of **10,050** statements; `ruff` and `mypy` clean. End to end
against a real daemon: pinning `llama3.2:3b` in the web UI moved
`/api/chat/{job}/status` to that model, and the copilot answered the demo capture
through it. The pinned choice reached the daemon — Ollama's `/api/ps` showed the
selected model loaded, not the previously auto-picked one.

### Documentation re-measured against the code, not re-read

Every document in the repository checked claim by claim against what the code and
the captures actually do. Where a number could be re-measured, it was.

**Fixed**
- **The "synthetic" demo capture carried a real hardware address and only ever
  spoke in one direction.** `samples/generate_sample.py` built every frame as a
  bare `Ether()`, which scapy fills from the *generating machine's* NIC and
  default gateway — so a file whose docstring promises nothing real embedded the
  author's own MAC and their router's, and `random.seed(1337)  # deterministic
  output` was untrue: the file differed on every machine, and on macOS between
  runs as the private Wi-Fi address rotated. Every host also shared that one
  address, so the device inventory correctly collapsed all 301 packets to a
  single NIC and the connection graph drew **one node and no edges** — the panel
  working exactly as designed and looking broken. The capture is now addressed
  the way its own vantage point implies: locally administered MACs (the range
  the IEEE guarantees is never assigned to a manufacturer, so no real vendor's
  hardware is implied and PacketIQ's OUI lookup honestly declines to name one),
  one NIC per host on the monitored segment, and every off-LAN address behind
  the router's MAC — which PacketIQ then classifies as a Gateway/Router from the
  six addresses fronting it, unprompted. Both directions of every conversation
  are present, because a capture where 40 SSH SYNs draw no reply and 130 ICMP
  echo requests draw no echo is not a capture of anything real. It is now
  byte-identical on every machine and every run. **The headline figures did not
  move** — 39 events, 5 chains, risk 100/100 — and the two that did are both
  corrections: the half-open count fell from 94 to 23 (only genuinely unanswered
  SYNs are half-open now that 69 ports and 2 hosts answer), and the forecast rose
  from 4 predictions to 7, because SSH, FTP and SMB can finally be *proven*
  listening rather than merely probed. `quickstart.sh` only writes the file when
  it is missing, so an existing checkout keeps the old one until
  `samples/demo_attack.pcap` is deleted or `samples/generate_sample.py` re-run.
- **Two detector defects that only bidirectional traffic could expose.** Making
  the demo capture realistic immediately surfaced both. First, the parser read a
  qname off *every* DNS packet without checking the QR bit — but a reply echoes
  the question section verbatim, so every response was recorded as a query made
  by the *resolver*. That doubled every query count in any real capture and
  handed the tunnelling, DGA and suspicious-TLD detectors a second source to
  accuse: `8.8.8.8` reported as the origin of a DNS tunnel it had merely
  resolved. Queries are now counted as queries. Second, the graph sized a
  scanner's fan-out badge from `sample_targets` alone — a list the detectors
  deliberately truncate — and never read `sample_hosts` at all, so a horizontal
  sweep contributed *nothing* to its own scanner's badge and the count was capped
  at the sample length: a 40-host sweep reported as 10. The badge now takes the
  larger of the hosts it can name and the number the detector actually counted,
  and stays a floor by construction — it may sit under the truth when the sample
  is short, never above it. Both have regression tests that fail on the old code.
- **The README's screenshots were a month behind the app, and two of its
  descriptions had become false.** Every image was recaptured from the running web
  app at the release commit. The drift they were hiding was not cosmetic: the whole
  **Possible Attacks** panel and its dashboard card did not exist when the old images
  were taken, nor did the per-finding evidence-PCAP download in the events table, and
  the protocol breakdown still showed everything as bare TCP/UDP/ICMP rather than
  naming SSH, FTP, SMB, SMTP and Telnet. Worse, the README described the connection
  graph as "colour-coded internal / external / flagged" when it had been rebuilt as a
  **device-level** graph — one node per NIC that actually transmitted, coloured
  attacker / target / internal / gateway — and never mentioned the Assets panel at
  all. Both are now documented, and the tour covers twelve panels instead of eight.
  Eleven tiles are the bundled demo capture; the device *inventory* is shot on
  `donbot.pcap`, a real Stratosphere CTU-13 botnet capture, and labelled as such,
  because OUI vendor lookup can only be demonstrated on real hardware addresses —
  the demo capture's MACs are locally administered precisely so that they name no
  manufacturer. One further claim was simply untrue: the README told Docker users
  the demo capture is "created for you on first launch", but only `quickstart.sh`
  ever writes it and the image does not ship it.
- **A documented command that did not exist — resolved in the code, not the prose.**
  `docs/RELEASE.md` told the reader to verify an install with `packetiq --version`,
  which exited with `Error: No such option '--version'`. The first pass corrected the
  document to the real subcommand, `packetiq version`. On review that was the wrong
  fix: `--version` is the form scripts, packagers and examiners reach for first, and
  answering "no such option" is a wrong answer rather than a missing feature. The flag
  now exists (`--version` / `-V`), printing the bare `PacketIQ 1.0.0` line, while
  `packetiq version` keeps the banner and full build block. Both read the single
  source of truth in `packetiq.__version__`, so neither can drift from the packaged
  metadata, and `tests/test_cli_commands.py` asserts both forms.
- **The paper contradicted itself and the implementation.** `docs/paper/` totalled
  the ablation's hallucinated entities as **95** in its conclusion and **47** in its
  abstract, table and source data (9 + 17 + 21 = 47). It also described redaction as
  replacing an ungrounded entity "with a redaction marker", while `_GroundingFilter`
  deletes it and substitutes nothing — the opposite of what the soundness argument in
  §4 needs. Its limitations section still called a cloud-model contrast "future
  work" after that contrast had been measured.
- **Six stale line-number citations.** `docs/ollama_integration.md` pinned the three
  LLM call sites and the three outbound HTTP calls to `app.py` line numbers; all six
  had drifted by 300–450 lines. They now cite function names, which do not drift.
- **An offline claim that was too strong to be true.** The same document stated the
  web app "makes exactly three outbound HTTP calls in its entire codebase, and all
  three target `_ollama_host()`". The cloud providers reach the network too — through
  their vendor SDKs, when a key is set. The claim now says what is actually true and
  is the stronger point anyway: with no cloud key configured, the copilot's only
  network destination is loopback.
- **`SECURITY.md` understated the upload cap by 5×** (2 GB; the code defaults to
  10240 MB) and summarised outbound traffic as three feeds. It now carries the
  complete destination table — feeds, NVD/KEV, all four alert channels, MISP, AI
  providers — and states that nothing is contacted unless invoked.
- **A stale coverage gate in the release guide** (`--cov-fail-under=65`; the gate has
  been 100 for some time), and a CI description that predated the macOS and Windows
  legs, the ruff/mypy gates and the four-way split of the security job.
- **`reports/detection_real.md` had drifted in its detail while its headline held.**
  Re-measuring all 12 CTU-13 captures reproduces 9 TP / 1 FP / 2 TN / 0 FN —
  precision 90.0%, recall 100.0%, F1 94.7% — exactly. But the per-capture table was
  written before DOS_FLOOD and ARP_SCAN existed (donbot 31 → 100 risk, 4 → 47
  events; qvod 50 → 78), the C2_BEACON heuristic's own recall has fallen from 6/8 to
  **5/8** because `rbot-44` no longer trips it, and the error analysis described a
  C2_BEACON finding on the false-positive capture that **no longer fires**. That
  false positive is now two stealth SYN sweeps and nothing else — `70.37.110.238`
  across 10 hosts on port 3128 and `60.174.174.107` across the same 10 on 1433 — at
  an overall risk of 4/100. All of it is now stated as measured.
- **A dangling documentation link.** `reports/*` is git-ignored with per-file
  exceptions, and `reports/ollama_tuning.md` had none — so a document cited by
  `docs/ollama_integration.md` was absent from every clone. Un-ignored, along with
  `copilot_faithfulness_comparison.md`, which was tracked only by the accident of
  predating the ignore rule.
- **The README understated its own threat-intel corpus.** "7,600+ indicators" against
  a measured **8,398** shipped (8,301 feed entries + 97 JA3 fingerprints). It now
  states that exact figure rather than a floor, because it is quoted beside a
  screenshot of the feeds panel and a reader can count it. Its description of them as
  "live" is now accurate about being a bundled snapshot that `packetiq feeds update`
  refreshes. `tests/test_project_metadata_sync.py` accepts either form and still fails
  in the one direction that matters — a claim the shipped feeds cannot back.
- **A footgun in the dataset guide.** `datasets/README.md` told users to point their
  own validation run at `reports/detection_real.md`, which `--markdown` overwrites
  wholesale. It also never said that a manifest's `base_dir` resolves relative to the
  manifest file rather than the shell's working directory.
- **The shipped bandit output contradicted the security policy.**
  `docs/security_audit/bandit.txt` still recorded **53 Low-severity findings** over
  15,718 lines — the state before those findings were worked through — while
  `SECURITY.md` and the CI comment both describe the scan as clean. Re-running the
  exact blocking CI command reports **no issues at any severity** over 16,864 lines.
  The file now carries that dated output, an itemised account of all fourteen
  `# nosec BXXX` suppressions (B404 ×2, B603 ×4, B607 ×2, B112 ×4, B104 ×2) and the
  confirmation that no line is exempted from scanning wholesale.
- **A performance table measured on an interpreter the project no longer uses.** The
  README quoted **~1,660 packets/s** over three captures on Python 3.9. Re-measured
  on the current reference build over all twelve, throughput is **4,005 packets/s**
  aggregate (1,668,975 packets, 427.7 MB, 416.77 s) — the old figure understated it
  by 2.4×.
- **A memory claim the numbers do not support.** "Memory stays roughly flat
  (~100–150 MB) regardless of capture size" was written before the large captures
  were added. Benchmarked alone in its own process, the largest (122.6 MB, 495,056
  packets) peaks at **226 MB** against the smallest's 112 MB. Streaming still makes
  growth strongly sublinear — 24× the capture for ~2× the memory — so the README now
  says that instead, with both measured endpoints.
- **Four overstated dataset figures.** `virut-fastflux.pcap` was quoted as "~430,000"
  packets (actually **440,625**); the nine malicious captures as "~1.7 million"
  (actually **1,640,740** — the benign three were being counted in); and the CTU-13
  download as "~435 MB" in three places (actually **~428 MB**).
- **A misreadable column in every multi-capture benchmark.** `Peak RSS` is
  `getrusage`'s process high-water mark, which never decreases, so in a 12-capture
  run each row silently inherits the maximum of every row above it — the last row's
  243 MB is not what that capture cost. `tools/benchmark.py` now says so in the
  report it generates, and points at `--pcap` for a per-capture figure.

**Added**
- **Provenance on every generated report.** `tools/validate.py` and
  `tools/benchmark.py` now stamp each Markdown report with the date, PacketIQ
  version, platform and interpreter it was measured on. A results table with no date
  cannot be told apart from a current one six months later.
- **`datasets/README.md` now documents the CTU-13 path that already shipped** —
  `fetch_ctu.sh` and `ctu13_manifest.json` were sitting in that folder while the
  document told the reader to go and source real captures themselves.

**Changed**
- `reports/detection_synthetic.md` and `reports/performance.md` regenerated from real
  runs. The synthetic suite still measures 100% precision and recall over its 9
  fixtures; one row (`ssh_brute`) had drifted to a second event and a risk of 26.
  `detection_synthetic.md` is now tracked alongside `detection_real.md` rather than
  git-ignored, so the file the changelog and README refer to is actually in the repo.
- **Both dependency closures re-audited from freshly built virtualenvs**, and the
  result recorded in `docs/security_audit/pip_audit.txt`: the runtime closure reports
  **no known vulnerabilities**, the dev closure the same single unfixable `diskcache`
  advisory. Worth writing down because auditing the *developer's* venv on the same
  day reported 7 findings across 4 packages — that venv had drifted behind current
  releases, and three of the four packages are in neither closure. An audit of a
  developer machine is not an audit of what users install; the file now says so.
- **`SECURITY.md` now dates its own claims** and marks the one figure in the
  2026-07-15 audit PDF that has been superseded (its `Low: 53` bandit line), rather
  than leaving a reader to assume a point-in-time report is current. The PDF itself is
  left as written on its date.
- **The CI comment justifying the blocking `pip-audit` step** cited 2026-08-10 while
  the audit log recorded a fresh 2026-08-11 re-verification of that same closure. It
  now cites the later run, and carries the reason the distinction matters: audit a
  freshly built closure, never a long-lived developer venv.

### Full-project audit: the claims, the container, and the code nothing calls

A sweep over every feature, file and stated number, checking each against what
the code actually does rather than what it says.

**Fixed**
- **`docker build` could not work.** The Dockerfile copied `setup.py`, which
  stopped existing when packaging moved to pyproject-only, so the build died on
  its first `COPY` — on exactly the path the README hands a new user. It now
  copies `pyproject.toml`, and installs non-editable, because an editable install
  is silently skipped by some Python 3.12+ builds and leaves the image without the
  entry point its `ENTRYPOINT` invokes. Verified by installing the exact file set
  the Dockerfile copies into a clean Python 3.9 environment: entry point runs,
  bundled feeds/templates/vendor JS all present, and a real capture analyses to 39
  events.
- **`docker compose up` failed before it started.** `env_file: .env` is required
  by default and `.env` is git-ignored, so a fresh clone had no such file. It is
  now declared optional.
- **The web UI stated numbers it had been told, not numbers it counted.** The
  landing page read "15 Detection Types" while 18 event types are emitted, and
  carried a hand-typed version label. Both are now rendered from
  `len(EventType)`, `len(THREAT_ACTORS)` and `__version__`, the same way the
  upload cap already was.
- **Three detectors were missing from the README's capability table** — ARP scan,
  ARP spoofing and the DoS-flood detector — so a reader would conclude the tool
  does not have them. Added with their real thresholds, MITRE techniques and
  severity ranges, and the headline count corrected from 15 to 18.
- **`SECURITY.md` said `pip-audit` covers "Python 3.9–3.12"; the job only ran
  3.12.** Rather than trim the claim, CI now audits the oldest supported
  interpreter too. It is advisory-only and deliberately so: `pillow`,
  `python-dotenv` and `python-multipart` have all moved past 3.9, so a 3.9 install
  resolves to the newest 3.9-compatible release of each — some carrying published
  advisories with no version to upgrade to. That residual is now visible in every
  run's log, and SECURITY.md states it plainly.

**Removed**
- Four helpers with no caller anywhere in `packetiq/` or `tools/`, kept alive
  only by tests: `pdf_report.build_pdf_bytes`, `pcap_slicer.filter_for_event`,
  `nvd.keyword_for` (a second, subtly different copy of the keyword logic
  `lookup_banners` already does inline) and `feeds._feed_paths`. 32 statements,
  and with them the illusion that their coverage meant anything. The PDF tests now
  render through `build_pdf` — the entry point the web app and the Telegram sender
  actually call.

**Added**
- Tests that hold the documentation to the code: the README's detection-type
  count must equal `len(EventType)`, every emitted type must appear in the
  capability table, the detector-module count must match the package, and the
  indicator figure may never exceed what the feeds actually hold. Plus: every path
  the Dockerfile copies must exist, and the container may not install editable.
  Each of these guards a drift that had already happened.

### Windows and macOS are supported in fact, not in principle

The package metadata said `Operating System :: OS Independent` and the repository
shipped a `PacketIQ.bat`, but every test had only ever run on Linux and on one
Mac. Auditing the OS-dependent surface found real defects on both of the
platforms that were never exercised, so CI now runs the whole suite on
`ubuntu-latest` (all four interpreters), `macos-latest` and `windows-latest`. The
coverage gate stays on the Linux legs: coverage of the platform branches is
necessarily different on each OS, and one number measured three ways would be
three different claims.

**Fixed**
- **The CLI crashed instead of printing whenever stdout was not UTF-8.** The
  tables are drawn with box characters no legacy 8-bit code page can encode, so
  `packetiq analyze capture.pcap > report.txt` died part-way through the first
  table with a `UnicodeEncodeError` — the default for redirected output on
  Windows, and reproducible on macOS and Linux under `LC_ALL=C`. The streams are
  now switched to UTF-8 with `errors="replace"`, so the report completes either
  way. Reproduced before the fix and re-run after it.
- **Fourteen places left the text codec to the platform.** `.env` scanning in four
  modules, the web app's key persistence, the validation report writer and four
  subprocess calls all took whatever the locale offered, which is UTF-8 on macOS
  and Linux and the ANSI code page on Windows. A capture from a machine with a
  non-ASCII hostname was enough to raise `UnicodeDecodeError` while merely
  looking for an API key. All are now explicit.
- **`tools/benchmark.py` could not start on Windows.** It imported `resource`,
  which is POSIX-only, at module scope — so the benchmark CI step would have
  failed on import. Peak memory now comes from `GetProcessMemoryInfo` there
  rather than being reported as zero.
- **Four tests could not run on Windows at all.** They monkeypatched
  `os.geteuid` / `os.getgroups` and imported `grp`, none of which exist there.
  They now supply the POSIX identity as a fixture, which keeps the macOS
  privilege branch measured on every platform instead of skipped wherever it is
  not the host OS.
- **Line endings are pinned.** A `.gitattributes` normalises text to LF and marks
  the captures and images binary. Without it a clone with `core.autocrlf` on
  hands back `PacketIQ.command` with CRLF, which then fails on a Mac with `bad
  interpreter: /bin/bash^M`, and could rewrite bytes inside a fixture PCAP.
  `PacketIQ.bat` is the one file kept at CRLF, because `cmd.exe` mis-parses a
  LF-only batch file.
- **The Windows launcher installed differently from the macOS one.**
  `PacketIQ.bat` used `pip install -e .`; `PacketIQ.command` deliberately does
  not, because editable installs are silently skipped by some Python 3.12+ builds
  and the `packetiq` command then breaks outside the repository folder.

Verified by simulating a Windows host on this workstation — `sys.platform` set to
`win32`, `os.geteuid`/`getgroups` removed, `grp`/`pwd`/`resource`/`fcntl` made
unimportable, and the Unix tools unresolvable. The suite passes under it apart
from four e-mail tests, whose failure is the simulation itself: CPython's `ssl`
module imports `enum_certificates` only when `sys.platform == "win32"` at import
time, and that symbol exists only in a Windows build of `_ssl`.

### The Windows leg, once it got as far as running the suite

Fixing the type gate let the Windows runner reach the tests for the first time,
and it found four more things the suite had been taking from whatever host ran
it. Every one is the same defect as the round before in a different disguise,
and none of them is in shipped code.

**Fixed**
- **Starting an event loop counted as a network connection.** Windows has no
  AF_UNIX socketpair, so asyncio builds every loop's self-pipe by connecting to
  127.0.0.1, and the outbound-network guard refused it. 190 tests failed there
  without one of them going near a network — every `asyncio.run`, every FastAPI
  `TestClient`. The guard now allows a connection while, and only while,
  `socket.socketpair()` is running on that thread, which no client can be inside.
- **Every frame was stamped with the host's own MAC address.** scapy fills an
  unset `Ether().src` from `conf.iface`, so the fixture captures the suite writes
  carried the hardware address of the machine that built them. On the Windows
  runner, which has no usable scapy interface without Npcap, that same lookup
  raised `ValueError: Interface 'Microsoft Loopback Adapter' not found` and took
  out five tests. Source addresses are now pinned to a locally-administered
  `02:00:00:00:00:01`, alongside the destination pinned in the previous round.
- **Tables were as wide as whatever console the suite ran in.** `rich` freezes a
  console's width when it builds one, from `os.get_terminal_size()`. A runner
  with no tty gets 80 columns; the Windows runner has a console and reported its
  own, which wrapped `PROTOCOL MISUSE` across two lines and failed the two CLI
  tests that look for it. 80x25 is now pinned before anything can construct a
  console — the width the Linux and macOS legs had been rendering at all along.
  `COLUMNS` alone did not settle it: rich deducts the legacy-Windows column
  *twice*, once building the console and again reading its size, so that runner
  rendered at 78 while every other host rendered at 80 — and drew its boxes in
  ASCII besides. The legacy detection is pinned off with the width, which is what
  makes rendered output one thing rather than two.
- **A capture-privilege test asked the runner whether it was an administrator.**
  It is, so `_windows_capture_ok()` returned True whatever the Npcap probe said —
  and that probe was the entire point of the test. Stubbing the elevation check
  makes the fallback the thing under test on every OS, rather than only on the
  ones where `ctypes.windll` happens not to exist.

**Added**
- Four more assertions in `tests/test_harness_guards.py`: the isolated history
  database, the event loop that must still be allowed to start, the pinned source
  MAC, and the rendered width.

Verified by simulating the Windows runner's networking on this Mac — asyncio's
loopback socketpair, and a scapy that cannot resolve any interface — where the
whole suite of 1,753 passes; by re-running the two CLI tests under a deliberately
narrow console; and by re-measuring coverage at 100.00% on 3.9, 3.11 and 3.12,
since pinning the source MAC changes the bytes every fixture capture is built
from.

### What the first macOS and Windows runs caught

Both new legs failed the first time they ran, which is the entire reason for
adding them. Neither failure was visible from Linux or from this workstation.

**Fixed**
- **The suite transmitted real ARP and neighbour-solicitation packets.** `Ether()`
  leaves the destination MAC unset, and scapy fills it in while *building* the
  frame by resolving the layer-3 destination on a live interface. This Mac has
  been through `packetiq setup-capture`, so its account is in `access_bpf`, the
  solicitation went out on the LAN and everything passed; the macOS runner cannot
  open `/dev/bpf0`, so building the same frame raised `Scapy_Exception` and three
  IPv6 tests failed there and only there. Only three, because scapy catches the
  failure for IPv4 and warns before falling back to broadcast, and does not catch
  it for IPv6 — the asymmetry is why hundreds of frames were being resolved on the
  wire while exactly three tests reported it. A fourth guard in `tests/conftest.py`
  now answers the resolution with the broadcast address — which is what scapy
  itself falls back to when it finds nothing, and therefore what the Linux legs
  had been building all along. No shipped code path is affected: a packet read
  from a capture file carries the address that was on the wire, so nothing in
  `packetiq/` ever asks for one.
- **`mypy` failed on Windows over two POSIX-only calls.** `os.getgroups` and
  `grp.getgrall` are absent from typeshed when the target platform is Windows, so
  the type gate failed on a helper that only ever runs on macOS. Suppressing the
  two lookups is the whole fix; guarding the block on `sys.platform` instead would
  have made mypy treat it as unreachable on Linux as well, and Linux is where its
  coverage is measured.

**Changed**
- `tools/validate.py --demo` now gives its generated frames explicit MAC
  addresses, which the `--suite` and benchmark generators already did. Leaving
  them unset meant writing the capture sent an ARP request for every destination
  it had not already cached — recoverable everywhere (scapy warns and uses
  broadcast) but still real traffic from whoever ran the tool, and two warning
  lines per packet in the output.

**Added**
- `tests/test_harness_guards.py` — four tests asserting the four conftest guards
  are still in effect: outbound connections refused, capture sockets refused, the
  interface table fixed, link-layer resolution answered offline. A guard that
  quietly stops applying recreates the exact failure it was written to prevent,
  and does so on the machine least able to notice.

Verified by denying `/dev/bpf*` on this Mac, which reproduces the runner's
failure exactly: the three tests fail before the change and the whole suite of
1,749 passes after it. Coverage re-measured at 100.00% on 3.9, 3.11 and 3.12,
and `mypy` re-run for all three target platforms on both the 1.x and 2.x majors
the matrix installs.

### Host-dependent coverage, round three — and what Python 3.9 had been reporting

One line, and the same cause a third time: `net_interfaces._score`'s `bridge`
arm. This developer's Mac has four bridge-kind adapters (`bridge0` plus the
Thunderbolt members), a Linux runner has none, so the branch ran on every local
run and never in CI. `tests/conftest.py` now pins the interface list to a fixed
table with one adapter of every kind it can classify — a third guard alongside
the socket and capture-device ones — and the ranking weights have direct unit
tests, since driving them through `list_interfaces` only ever proved the ordering
of whatever adapters that host happened to have.

**The 3.9 leg was not a measurement limitation, and the previous entry in this
file was wrong to call it one.** The twelve `continue`/`break` lines it reported
as unhit were twelve real gaps. CPython 3.9 threads the conditional jump for each
operand of a short-circuit guard directly to the loop header, past the `continue`
that follows it, so the line is recorded only when the *last* operand is the one
that fires — verified from the bytecode, where `POP_JUMP_IF_FALSE` targets the
loop head at offset 62 rather than the `continue` at 116. Each unhit line
therefore named a guard whose second half nothing exercised; 3.10 and later
record the line whichever operand fired and reported all twelve as covered.

**The gaps that were hiding behind it**
- A Zeek `conn.log` record with an originator but no responder (the suite tested
  a record missing both).
- A `Server:` banner naming a product with no version — the case where a keyword
  search would return CVEs for releases the host may never have run.
- A commented-out assignment in `.env`, which is how a stale Telegram chat id is
  usually parked.
- A NetFlow v9 flowset with a reserved id (2–255) and a perfectly legal length.
- A NetFlow template whose fields declare zero width, which consumes no bytes and
  would otherwise re-read the same record for as long as the process lived.
- Four graph cases across the web app and the HTML report: an attacker address
  that never transmitted a frame, and a device holding an IP that did not make
  the node budget.

Two small product changes came out of it. `parse_netflow`'s version dispatch now
reads `if parsed_any: break` before the `raise` instead of after it — the `break`
was previously reachable only by a jump, so on 3.9 it could never be recorded at
all. And the DNS multicast guard collapses its four `startswith` calls into one:
`ff0`/`ff2` was an incomplete spelling of `ff00::/8` (it missed `ff1e::`/`ff3e::`)
and `ff2` is not a flag combination RFC 4291 permits.

The floor is now **100 on every interpreter, 3.9 included**.

### Host-dependent coverage, round two: tests that asked the host and took either answer

The same gate failed again on the same three legs, in a different module. The
first round was the platform switches, and the fix for those held. This round was
harder to see, because the tests involved looked careful rather than careless:
each one asked the machine a question and accepted whichever answer it got.
`/api/live/start` was allowed to return 403 and the test simply `return`ed;
`packetiq chat` was handed no API keys and trusted that to mean no provider. Both
read as defensive. On a Mac that has been through `setup-capture`, with
`ollama serve` listening on loopback, both take the long branch — and 34
statements that are covered on this workstation are never executed on a runner.

Measured, not inferred: GitHub's logs need admin auth this project does not have,
so the suite was run under four simulated runner environments (Linux dispatch,
denied capture socket, no local model, no external tools resolvable) against a
clean `git worktree` checkout with a `.[dev]`-only virtualenv and an empty `HOME`.
All four agreed on the same 34 lines — `cli.py` 720-735 and 27 in
`webapp/app.py` — on both 3.11 and 3.12.

**Fixed**
- **The live-capture lifecycle was covered by capture privileges, not by tests.**
  Start, poll, the rolling packet list, the pcap download and stop are now driven
  through a stand-in sniffer, so the whole `/api/live/*` block is exercised on a
  host that cannot capture at all. The two tests it replaces started genuine
  loopback captures and wrote the developer's own traffic to a pcap.
- **`packetiq chat` was covered by whatever provider the machine happened to
  offer.** Clearing the API-key variables does not leave the copilot
  unconfigured: `MultiProviderClient.available()` also reads `.env` and probes a
  local Ollama daemon. The test now states which branch it is testing; the
  unconfigured case keeps its own separate test.
- **The model warm-up was only ever executed against a real daemon.** The unit
  test replaced `threading.Thread` and never ran the target, so the request body
  ran only where `ollama serve` was listening. It now runs against a stubbed
  transport and asserts the payload — the keep-alive and `num_predict: 1` that
  are the entire point of preloading.
- **A refused live capture left an empty pcap behind every time.** The recording
  file is created before it is known whether the capture will work, so each
  failed "Start capture" left a zero-byte file in the shared upload directory.
  They accumulate, and an empty recording is not something a user can analyse or
  download. A session that captured nothing now removes its own file.
- **An upload test asserted over a directory it did not own.** "No small pcap
  exists anywhere in `UPLOAD_DIR`" is a claim about every other test, about
  previous runs, and about the user's own web app. It now compares the directory
  before and after, so it tests the refused upload and nothing else.

**Added — two standing guards in `tests/conftest.py`**
- No test may open a socket. The previous guard allowed loopback, which is
  precisely how the local model went unnoticed; nothing under test legitimately
  needs a listening service.
- No test may open a real packet-capture device. A path that depends on capture
  privileges now has to supply its own sniffer, which is the only way its coverage
  can mean the same thing on every host. Only the *listening* sockets are denied:
  scapy reaches for the sending pair while merely building a packet, since a BSD
  route lookup for an IPv6 destination asks the kernel which interface it would
  use.

**Verified** — 1,729 tests. 100.00% of 9,882 statements under every one of the
four simulated environments on 3.11 and 3.12; 99.88% on real CPython 3.9, whose
12 remaining lines are all `continue`/`break` (3.9 also parses to 5 fewer
statements than 3.11/3.12, which is why its total differs). Detection is
unchanged: 90.0% precision, 100% recall on the real CTU-13 corpus.

### Security — the dependency audit now distinguishes what ships from what does not

`pip-audit` over the closure a user actually installs is **blocking**, and clean:
"No known vulnerabilities found", verified 2026-08-10. The dev extra is audited as
a separate, advisory step. It reports one finding — pySigma pins
`diskcache>=5.6.3,<6.0.0`, and 5.6.3 is simultaneously the newest release in
existence and the one carrying PYSEC-2026-2447 / CVE-2025-69872 (pickle
deserialisation; CVSS 4.0 `AV:L`, requiring an attacker who can already write to
the cache directory). There is no version to upgrade to, PacketIQ imports neither
package, and neither reaches a user's install — so it is reported rather than
allowed to wedge the pipeline. Previously a single non-blocking step covered both,
which meant a genuine regression in a shipped dependency would have scrolled past
in a green log.

### Coverage made a property of the suite rather than of the machine

The 100% gate passed on the workstation it was written on and failed on all three
Linux legs of CI (3.10, 3.11, 3.12; 3.9 sits at a 99% floor and stayed green,
which is what made the split hard to read). Reproduced two ways before anything
was changed — the platform dispatch forced to Linux on this host, and a clean
checkout run against a `.[dev]`-only environment with an empty `HOME` — and the
two reproductions found six lines and one outright test failure between them.

**Fixed**
- **The test suite was sending real Telegram alerts.** The CLI test named
  "analyze with alerts does not send without configuration" cleared
  `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` and considered alerting
  unconfigured. It is not:
  `telegram.load_credentials` also scans `./.env` and `../.env`, so on a machine
  with a populated `.env` the test found a real bot token and chat id and POSTed
  the findings to a real chat. Confirmed from the coverage contexts, which show
  that test executing `telegram.py`'s `requests.post` to `api.telegram.org`.
  Nothing ever failed, because sending worked — and the same silence is why the
  chain formatter's MITRE block was covered here and missing in CI. The test now
  runs from an empty directory where no `.env` is discoverable, and treats any
  outbound request as a failure.
- **The TOML backport test failed wherever the backport is not installed.**
  `tomli` is a conditional dependency (`python_version < '3.11'`), so on 3.11 and
  3.12 it is genuinely absent. The test hid `tomllib` and imported the real
  `tomli`, which raised, landed in `except Exception: return {}`, and asserted
  against a default value. Both `tomllib` and `tomli` are now bound to a stand-in
  that delegates to whichever parser the interpreter does have, so the fallback
  wiring is what is measured. This also closed the last non-`continue`/`break`
  gap on 3.9, taking that leg from 99.84% to **99.88%**.
- **A test ran the privileged capture fix for real.** `setup-capture`'s
  smoke test invoked the unstubbed command; where capture is not already enabled
  that goes on to call `setcap` on the interpreter, and CI runners grant
  passwordless sudo. The probe still runs for real; the fix no longer does.

**Fixed — measurement**
- **Six lines were covered by the machine rather than by a test** — green here,
  red in CI. Four turned on the operating system: `_run`'s success path (its only
  callers are the two macOS interface helpers, which `list_interfaces` skips off
  darwin), the `/dev/bpf` branch of the macOS privilege check, and the CLI's
  "capture is already enabled, nothing to do" branch — the last two reachable
  only on a machine that had already been through `setup-capture`. The other two
  turned on which packages happened to be installed: the `tomli` arm of
  `_load_toml`. All six are now driven with an explicit stub, so the same lines
  execute on every matrix leg. The suite grew from 1,716 tests to **1,723**.

**Added**
- **An autouse guard in `tests/conftest.py` that fails any test which opens an
  outbound connection.** It sits at `socket.connect`, so it catches every client
  and every credential source rather than one library's `post`; loopback stays
  open for the local Ollama endpoint, and AF_UNIX for socket files. This is the
  standing form of the Telegram fix above — the suite can no longer touch the
  outside world without saying so.

### 100% line coverage, and four real defects it uncovered

Coverage went from a reported 87.49% to **100.00%** — every one of the 9,879
statements in `packetiq/` is now executed by the suite, which grew from 724 tests
to **1,716**. The CI floor moved from 85% to 100%.

The point was never the number. Driving it there ran code that had never
executed before, and four of those lines were broken.

**Fixed**
- **`packetiq chat` crashed on the first question.** `_print_thinking_prefix`
  called Rich's `Console.print(..., flush=True)`, and Rich's `print` takes no
  `flush` argument — so every question raised `TypeError` before a single token
  arrived. The interactive REPL loop had zero coverage, which is exactly why a
  crash on its most common path survived. The prefix now flushes the underlying
  stream directly.
- **One failed AI turn broke the rest of the chat session.** On an API error the
  REPL correctly rolled the user message back out of the history, then appended
  an assistant turn anyway — leaving a conversation that opened with the
  assistant, which the API rejects. Every subsequent question in that session
  failed. `_stream_response` now returns `None` on failure and the caller skips
  the append.
- **A failed web analysis reported no reason on reconnect.** `_jobs[id]["error"]`
  was initialised to `None` and never written; the worker only pushed the reason
  onto the WebSocket queue. A browser that connected *after* the failure received
  `{"type": "error", "message": null}`. The reason is now recorded on the job, so
  both the socket and `GET /api/results/{id}` report it.
- **One corrupt frame could fail the whole packet list.** `summarize()` called
  `len(pkt)`, which re-serialises the packet and raises on a frame from a
  truncated capture. Since the packet browser renders every row through
  `summarize`, one bad frame took down the entire list — and it also made
  `dissect()`'s own "unbuildable packet" fallback unreachable. Frame length now
  degrades to 0 and the rest of the row still renders.

**Fixed — measurement**
- **The coverage number was overstated, and the config was hiding code.** The
  `exclude_also` list carried a bare `\.\.\.` pattern, intended for `...`
  Protocol stubs. It matched any line containing three dots anywhere — including
  `File(...)` in a FastAPI signature and every `"Parsing packets..."` progress
  string. coverage.py drops the *whole body* when the matching line opens a
  block, so `/api/upload`, `/api/fuse` and `/api/analyze` plus 32 statements of
  `cli.py` were absent from the denominator: 96 statements the gate could never
  fail on. The pattern is now anchored (`^\s*\.\.\.\s*$`). Re-measuring on the
  honest denominator put the real starting figure at 87.45%.

**Changed**
- **Unreachable code deleted rather than excluded.** Seven guards could not fire
  on any input and were removed with the reason recorded in place: a `_TTL_MAP`
  row duplicated by its own fallback; a bounds check in the JA3 ClientHello
  parser already guaranteed by the 43-byte minimum above it; a `ValueError`
  handler around `ipaddress` calls that a width check makes impossible; a
  `try/except` around `int(arp.op)`, which scapy has already dissected as an
  integer by the time it is read; a dedup pass over a `set`; a second
  `len(combined) < 1` after a check that already proved the list non-empty; and a
  chain-collection sweep that could never append. Excluding them would have
  hidden the same dead code behind a green number.
- **CI coverage gate raised from 85% to 100%** on Python 3.10–3.12, so a line
  that ships untested fails the commit that introduced it. The 3.9 leg is held at
  99% for two measurement reasons, neither a test gap: `tomllib` does not exist
  there (3.9 runs the `tomli` backport branch instead, and both branches are
  covered — since closed outright, see the section above), and CPython 3.9 emits
  no trace event for about a dozen `continue`/`break` statements that 3.10+
  records. The latter was verified directly rather than assumed — the Zeek
  endpoint guard demonstrably skips the record on 3.9 (one of two flows kept,
  test green) while coverage still reports
  the line unhit.

**Added**
- Twenty-nine new test modules covering the surfaces that had none: the interactive
  copilot REPL, TLS certificate carving (driven with real X.509 certificates),
  file carving and TCP reassembly, the JA3/JA4 ClientHello parser, malformed
  NetFlow/IPFIX exports, live capture and interface enumeration (with the Linux
  and Windows paths stubbed so they run on macOS too), every AI provider's
  streaming arm and the cross-provider fallback loop, and the web app's
  rejection paths, worker-thread failures and grounding redactor.

**Fixed — test hygiene**
- A new CLI test set `PACKETIQ_ALLOWED_HOSTS=*` and leaked it into the
  DNS-rebinding and CSRF guards, failing them. `monkeypatch.delenv` records
  nothing for a variable that was never set, so it restores nothing; the test now
  seeds the variable with `setenv` first.

### Type-check gate fixed on Python 3.9, and packaging promises made enforceable

**Fixed**
- **The CI type-check gate failed on Python 3.9 only.** mypy 2.x requires Python
  >=3.10, so the 3.9 matrix leg resolves to mypy 1.x — and the two majors disagree on
  a default: `ignore_missing_imports` covers a module mypy cannot find, but only 2.x
  extends that to a module which *is* installed and simply carries no types. mypy 1.x
  reports the latter as `import-untyped`, so the six modules importing `requests`
  failed the gate on 3.9 while 3.10–3.12 stayed green. Fixed by shipping the real
  `types-requests` stubs in the `dev` extra rather than suppressing the diagnostic, so
  `requests` call sites are genuinely type-checked on every leg. Verified against both
  mypy 1.19.1 and 2.3.0. Because the gate failed first, every later step on that leg —
  the test suite, the coverage floor, the guardrail and detection gates, the benchmark
  — was skipped and had never actually run on 3.9; all of them have now been executed
  end to end on a real 3.9.25 interpreter and pass, at 87.29% coverage.

- **MANIFEST.in shipped a rule pattern that matched nothing.** It listed
  `*.yar *.yara` under `yara_rules/` while `[tool.setuptools.package-data]` listed
  `yara_rules/*`; only `.yar` files exist, so every sdist build printed
  `warning: no files found matching '*.yara'`, and the two manifests disagreed about
  what a rules directory contains. Both now say "everything in that directory", so a
  rule added with either extension ships.
- **The test suite wrote into the developer's real analysis history.**
  `storage._db_path()` falls back to `~/.packetiq/history.db`, and overriding
  `PACKETIQ_DB` was left to each test to remember. Tests that forgot recorded fixture
  rows named `attack.pcap` into the real database — a full run added six, and they had
  been accumulating. `tests/conftest.py` now points the database at a per-test
  temporary file for every test automatically; a test that wants a specific path still
  just sets the variable itself.
- **Coverage was not reproducible.** Two runs of an unchanged tree reported anywhere
  between 87.34% and 87.49%. Two causes, both now closed: the history-database leak
  above (the web app renders a different branch once history exists), and a live-capture
  test that starts a genuine interface capture — whether the sniffer callback ever ran
  depended on whether traffic happened to arrive inside the test window, so fourteen
  statements in `_LiveSession._cb` were covered by luck. That callback is now driven
  directly with synthetic IPv4 and IPv6 packets, making it an assertion rather than a
  coincidence. Five consecutive runs now report exactly 87.49%.
- **A live-capture test could sniff a physical interface.** It preferred loopback but
  fell back to the first interface in the list, so on a host without a loopback entry
  running the suite would capture the developer's own network traffic into an
  upload-directory pcap. It is loopback-only now, and skips when there is none.
- **A module-level fixture asserted an attribute that tests remove.**
  `test_yara_and_channels.py` cleared the memoised rule set in teardown via
  `_rules.cache_clear()`, which does not exist while a test has `_rules` replaced with a
  stub. Whether that mattered depended on fixture ordering elsewhere in the session; it
  now looks the attribute up instead of assuming it.
- **Deprecated license metadata.** `license = { file = "LICENSE" }` and the
  `License :: OSI Approved` classifier each raised a `SetuptoolsDeprecationWarning` on
  every build. Replaced with the PEP 639 form (`license = "MIT"` plus
  `license-files`), which builds clean and emits `License-Expression: MIT` in the
  wheel metadata with LICENSE still shipped in `dist-info`.

**Changed**
- The CI `test` job no longer installs `ruff` and `mypy` a second time on top of
  `pip install ".[dev]"`. The extra already provides both, and the duplicate line was
  a second place for the tool list to drift.
- Build backend floor raised to `setuptools>=77`, the first release that understands
  PEP 639. This is a build-time requirement resolved in pip's isolated build
  environment; it does not change what the installed package runs on, and the 3.9 leg
  was re-run end to end to confirm it.

**Added**
- `tests/test_project_metadata_sync.py` — turns three packaging promises that existed
  only as prose comments into failing tests: that `requirements.txt` really does stay
  in lockstep with `[project.dependencies]` (names, version floors, and environment
  markers alike), that the advertised Python classifiers and `requires-python` floor
  match the versions CI actually tests, and that every tool the workflow invokes comes
  from the `dev` extra. Each guard was mutation-checked to confirm it fails on the
  drift it claims to catch. Ten tests in total across this entry and the live-capture
  callback above, taking the suite to **724** at a reproducible **87.49%**.

### Machine-readable output, deprecated APIs, and a coverage sweep

**Fixed**
- **`--json` output was not valid JSON.** Every document-producing command printed
  through the rich console, which soft-wraps at the terminal width — inserting raw
  newlines *inside* JSON string literals — and interprets square-bracketed text as
  style markup. A CVE description was therefore both unparseable and silently
  missing characters. Documents are now written to stdout verbatim; the banner and
  status lines move to stderr for those runs, so `packetiq cve x.pcap --json | jq`
  works. Affected `cve --json`, `vulns --json`, `stix`, `navigator`, `sigma`, and
  `misp --dry-run`.
- **`cve --json` / `vulns --json` returned prose, not JSON, when a capture exposed
  no software banners** — the common case for all-encrypted traffic. Both now emit
  a valid document on every path.
- **Deprecated third-party APIs that were one release from breaking.** DNS query
  names were read through scapy's `qd.qname` compatibility shim (removed in a
  future release, which would have silently turned every query name into `None`);
  feed refresh timestamps used `datetime.utcnow()`, deprecated in Python 3.12 and
  naive, so "UTC"-stamped files were wrong on a non-UTC host. The suite now runs
  with zero warnings.
- **`DELETE /api/history/{id}` reported success for an id that never existed.**
  `storage.delete()` now returns whether a row was actually removed.
- **Evidence slicing raised on a capture that had gone away**, aborting the whole
  request when the web UI slices several captures at once. A missing or unreadable
  source now yields no evidence instead of an exception.
- **`CRED_PORTS` was decorative.** The credential detector's documented port table
  was never read — the dispatch carried its own hardcoded lists, and the two had
  already drifted (port 8000 was inspected but unlisted). The table is now the
  single source of truth.
- The terminal banner had **v1.0.0 hardcoded**; it now reads the package version,
  so it cannot drift from what is installed.

**Changed**
- Test suite grown from **375 to 714 tests**; line coverage from **73.7% to 87%**,
  measured over the whole package with nothing excluded. Three modules that were at
  **0%** — the standalone dashboard server, the OSINT feed refresher, and the GeoIP
  loader — are now covered, along with the CLI (17% → 78%), JA3/JA4 fingerprinting
  (41% → 96%), credential exposure (47% → 94%) and capture-privilege setup
  (45% → 92%). The CI coverage floor rises from 65% to **85%**.
- `geoip.reset()` added so a database configured after first use is picked up; the
  reader cache previously froze the answer for the life of the process.
- README test-count and coverage figures corrected to the measured values.

### HTTP is identified by its bytes, not by its port

**Fixed**
- **HTTP served on any port other than TCP 80 or 8080 was not recognised at all.**
  Scapy binds its HTTP dissector to those two ports and nothing else, so
  byte-identical HTTP on 8000 / 8888 / 3128 / 81 parsed as anonymous TCP:
  `has_http` stayed `False` and the method, path, `Host`, `User-Agent`, `Server`
  and status fields were all `None`. Everything downstream went blind with them —
  HTTP inspection, HTTP-based beaconing evidence, and server-banner CVE
  matching — on exactly the ports C2 traffic prefers.

  The parser now reads the request line or status line off the wire, so the port
  number is no longer part of the decision. It sets nothing unless the payload
  genuinely opens with an HTTP/1.x start line, so a non-HTTP service on a
  web-looking port is never relabelled on a guess: TLS, SSH, SMTP, gzip, the
  HTTP/2 preface, a request line appearing inside a body, and binary payloads
  that happen to start with `0x47` are all left as TCP.

  Recovered on the real CTU-13 corpus, none of it visible before: a malware
  config fetch on **3389** (`GET /tool/train/q.txt`, `User-Agent: VBTagEdit`),
  botnet C2 polling on **179**, and `.exe` payload downloads on **88** — 4,586
  additional HTTP messages across five captures.
- Header lookup reads the full TCP payload rather than the 512-byte
  `raw_payload` cap, so a `Host` pushed past 512 bytes by long preceding headers
  is still found, and it stops at the blank line so a body containing `Host:`
  cannot be misread as a header.
- **A request target containing unencoded spaces lost everything after the first
  one** — including on port 80, where Scapy's `Path` field truncates there. A
  crude scanner sending `GET /index.php?id=1' OR 1=1-- HTTP/1.1` had its
  injection discarded before any detector saw it. The start line is now split on
  its first and last space, so the full request-target is kept and the parse is
  identical on every port.
- **Only the header packets of an off-port HTTP session read as HTTP.** Segments
  continuing a message carry no start line, so the port table named them by port
  instead — 28,681 of the 32,000 packets in `qvod.pcap`'s malware HTTP session on
  3389 were labelled "RDP". A flow proven to carry HTTP now keeps that name for
  its data segments, as Wireshark does, with bare ACKs staying "TCP". That moves
  11,979 of those packets to HTTP. The rest are the ones that precede the first
  start line in their flow: a single streaming pass cannot label a packet from
  evidence that arrives after it, and guessing by port is the behaviour being
  removed. The flow memo is capped at 50,000 entries so a capture of many
  short-lived flows cannot grow it without bound.
- **HTTP findings quoted port 80 regardless of the port observed.**
  `http_inspect` hardcoded `dst_port = 80` and `beacon` grouped HTTP beacons
  under port 80. That was almost always right while only 80/8080 were dissected
  and is wrong now, so `ExtractionResult.http_requests` / `.http_responses`
  carry the real server port and both detectors report it. Beacons to the same
  host on different ports are also no longer merged into one channel.

**Changed**
- The seven modules that compared against the `0.0.0.0` / `::` unspecified
  sentinels now share `UNSPECIFIED_IPV4` / `UNSPECIFIED_IPV6` from
  `packetiq.utils.helpers` instead of repeating the literal. This removes all 11
  `# nosec B104` suppressions: bandit flags every bare `"0.0.0.0"` string, and it
  emits a spurious "nosec encountered, but no failed test" warning once per
  *other* string literal sharing a suppressed line. Naming the sentinel once
  removes both the duplication and the noise.
- `yara_scan._rules()` had its per-file retry extracted into
  `_compile_valid_only()`. Behaviour is unchanged; the nested `try` inside an
  `except` handler was what made bandit misreport its `# nosec B112`.
- Dropped the `B607` id from the `setcap` suppression in `capture_setup.py`: the
  argv there is built at runtime, so that test never fired. `B603` still applies.
- Bandit now scans completely clean — 0 findings **and** 0 warnings.

### CI type gate, and the crash it had been reporting

**Fixed**
- **`packetiq fuse` crashed with `AttributeError` on any capture that matched a
  threat actor.** The `icon` field was removed from `AttributionMatch` during the
  emoji cleanup while `cli.py` still read it. mypy had been reporting this the
  whole time — the CI step ran as `mypy packetiq || true`, so nobody saw it.
- **The mypy step is now blocking**, and the 35 pre-existing errors it had
  accumulated across 8 modules are all resolved (`Success: no issues found in 83
  source files`). Two were latent defects rather than annotation noise:
  `Copilot single_message()` indexed `response.content[0]` without checking for an
  empty or non-text first block, and `attack_navigator._sev_value()` returned
  `None` for a severity whose `.value` was itself `None`.
- **The Python 3.9 floor was going unverified.** mypy 2.x refuses to target
  anything below 3.10, so `python_version = "3.9"` was silently ignored while it
  checked 3.10 semantics. `tests/test_python39_compat.py` now enforces the floor
  directly: every module must parse under the 3.9 grammar, and no annotation that
  Python evaluates at import time may use a PEP 604 `X | Y` union.
- **`# nosec` comments used ` - ` before their explanation**, which bandit parses
  as a list of test IDs — every scan emitted a warning per prose word. Switched to
  the ` # ` separator, keeping the explanations. Bandit reports 0 issues at every
  severity, unchanged.

**Changed**
- CI workflow hardened: `timeout-minutes` on both jobs, a `concurrency` group so a
  newer push supersedes an in-flight run, least-privilege `permissions: contents:
  read`, and `workflow_dispatch` so a run lost to a runner/infrastructure fault can
  be restarted without an empty commit.
- Bandit now runs as a blocking CI gate alongside pip-audit. First-party code
  scans clean, so any new finding is a regression rather than pre-existing debt.
- `InteractiveChat` takes a `CopilotLike` protocol instead of naming
  `CopilotClient` concretely; the CLI passes `MultiProviderClient` there, which
  the old annotation had been misdeclaring.
- The `fuse` TTP-overlap row moved into `_attribution_line()` so it is reachable
  from a test. Covered by `tests/test_attribution_render.py`, which renders real
  `AttributionEngine` output.

### Evidence-proven threat forecast and a real network boundary

**Fixed**
- **The threat forecast no longer invents attacks on a benign capture.** It
  listed the same generic set every run, and predicted attacks against ports the
  packets *prove* are shut. Two rules now govern it:
  - **Proven-open only.** The extractor resolves every `host:port` to `open`
    (a SYN-ACK came from it, or a UDP service answered), `closed` (it refused a
    SYN with RST) or `filtered` (probed, never answered) — new
    `ExtractionResult.service_exposure`. Only `open` is attack surface. Previously
    a host answering `RST` on 1433/21/22 still produced "Database compromise",
    "FTP brute force" and "SSH brute force" forecasts.
  - **Your network only.** An internal client browsing an external web server no
    longer makes that server your exposed HTTP surface — the *serving* host must
    be inside the monitored network.

  Measured on the real corpus: the benign `normal-dns-2013` / `normal-dns-2015`
  captures now yield **0 predictions** (previously non-empty), and
  `normal-20110817` drops from **9 to 3** — the three that remain are genuine
  (RDP open and reached from off-net, two real inbound scans, NetBIOS-SSN open to
  10 clients). Each prediction now quotes the concrete evidence from *that*
  capture, so the panel is different for every file.
- **"Internal vs external" is now derived from the packets, not from RFC1918.**
  New `helpers.monitored_network()` finds the monitored segment from link-layer
  evidence: hosts on the segment send frames from their own NIC, while everything
  behind a router shares the router's MAC. RFC1918 is only a proxy and broke both
  ways — a publicly addressed LAN (e.g. CTU's `147.32.0.0/16`) read as internet
  peers, and a browsed web server read as ours. Used by the forecast, the beacon
  detector, the connection graph, the HTML report and the copilot's evidence.
- **A phantom "C2 beacon" on inbound RDP.** External hosts repeatedly connecting
  to a local host's open 3389 were reported as C2 beacons, because the
  "destination is internal" guard used RFC1918 and the LAN was publicly
  addressed. Beacons toward a host on the monitored network are now correctly
  suppressed — that is an inbound session, not an implant phoning out. This
  removed 3 mislabelled events across the corpus and dropped the benign
  capture's risk score from 17 to 4. Binary precision is unchanged at **90.0%**
  with **100% recall**; per-detector `C2_BEACON` recall is honestly restated
  **6/8 → 5/8**, because two of the old "hits" were these inbound RDP sessions
  rather than real C2 (rbot-44's actual IRC C2 was never caught — it is still
  flagged malicious by other detectors).
- **The connection graph could silently drop the attacker.** The 60-node budget
  truncated an unordered set, so which hosts survived was arbitrary; nodes are
  now filled by priority (flagged hosts first, then by volume). An IPv6-only host
  was also mis-drawn as an address-less NIC — the device's own address list is
  now used instead of guessing from the id's punctuation. Same fix in the report's
  SVG graph.
- `0.0.0.0` (the DHCP "unspecified" sentinel a host sends from before it has an
  address) is no longer listed as a top talker or given an OS fingerprint.
- Four pre-existing type errors in `helpers.format_bytes` and the HTML report
  (mypy clean on all touched modules now).

**Changed**
- **All remaining decorative emoji removed from product output** — Telegram
  alerts, the CLI (OS fingerprints, exploit notices, interface list), the
  timeline renderer, threat-actor profiles, the legacy `packetiq dashboard`, and
  the web app. Severity now reads as a text tag (`[HIGH]`). The `os_icon` and
  actor `icon` fields, which existed only to carry an emoji, were removed.
- The Possible Attacks card no longer prints the same evidence twice; it
  separates "Evidence in this capture" from "Why this leads to the attack above".

**Verification** — 352 tests pass (13 new: threat-forecast exposure rules and the
network-boundary logic, all built from real packets via scapy rather than hand-made
fixtures), ruff clean, mypy clean on every touched module, bandit 0 issues, and
throughput unchanged (4,301 vs 4,314 pkts/s on `neris-43.pcap`).

### Local copilot accuracy, same-chassis inference, and a professional UI

**Fixed**
- **The AI copilot context no longer starves the model on busy captures.** An
  evidence-rich capture (e.g. `donbot.pcap`) enumerated *every* external IP —
  1,555 of them, listed twice — ballooning the context to ~82,000 chars, which
  overflowed the local model's window so Ollama truncated the detections, attack
  chains and MITRE mappings and left only a wall of IPs. On the real capture the
  local model went from **0 grounded claims** ("you gave me a list of IP
  addresses") to **65+ grounded claims with 0 hallucinations (100% faithful)**.
  Long IP enumerations are now capped to the top 30 by volume with an "… and N
  more" line (`context_builder.py`); the local context-window cap rose to 16,384
  tokens so evidence-rich captures fit without truncation. Verified on real
  captures with `tools/eval_copilot.py` — see `reports/ollama_tuning.md`.

**Added**
- **Same-chassis inference in the device inventory.** Two NICs on one OUI where
  one is switch infrastructure (a managed switch's STP control-plane MAC + its
  DHCP management interface, e.g. Cisco `c7:4b:89` + `c7:4b:c0`) are flagged as
  *likely one physical device* — shown in the Assets panel, the HTML report and
  the CLI. They are **never merged**: the packets prove two distinct MACs, so it
  is stated as an explicit inference. New `chassis_groups` on the extractor
  result + 2 regression tests.

**Changed**
- **Professional UI — decorative emoji removed** across the dashboard, Possible
  Attacks, Attack Chains, Live Monitor, Export, Threat-Intel, CVE, Alerts and AI
  Copilot surfaces. Metric-card and interface icons are now clean inline SVG /
  text; kill-chain and CVE-pipeline steps are numbered. Conventional status marks
  (✓ ✗ ⚠ ℹ) are kept.

**Investigated and rejected (documented in `reports/ollama_tuning.md`)**
- A few-shot Ollama Modelfile (`packetiq-soc`) trained on real capture data was
  built and measured, but it **memorised the examples' indicators** and emitted
  them into unrelated captures (named Donbot's IPs while analysing a benign DNS
  capture — 0% faithful). It was **not shipped**; the accuracy win came from the
  context fix above, which helps every provider (cloud and local).

### Network graph shows only real devices (no phantom hosts)

**Fixed**
- **The network connection graph no longer invents hosts.** It was drawing one
  node for every IP an ARP sweep *probed* (e.g. `.101`–`.109`, the AWS metadata
  IP `169.254.169.254`) — but being asked about in a who-has is not evidence a
  device exists. A capture with 4 real machines rendered 16 nodes. A host is now
  drawn **only with evidence it transmitted** (it sent a frame or answered ARP);
  probed-but-silent addresses are never nodes.
- **A host's IPv4 and IPv6 addresses now collapse to one device.** Each machine
  appeared twice (its `192.168.x` and its `fe80::` link-local were separate dots).
  The graph is now keyed on the physical NIC (MAC), so one machine is one node.
- **A scanner's fan-out is shown as a count, not phantom dots.** The attacker node
  carries a **"scanned N · M live"** badge instead of a spray of edges to hosts
  that never responded.

**Added**
- **Device inventory in the extractor** (`transmitted_ips`, `ip_to_mac`,
  `mac_to_ips`, `devices`, `ip_to_device`), reconstructed from the frame source
  MAC now captured by the parser (`eth_src`/`eth_dst`). It classifies each NIC as
  endpoint / gateway / infrastructure and never collapses a router's many IPs.
- **The graph now shows the *complete* real device inventory.** Infrastructure
  NICs that carry no IP (a switch broadcasting STP/CDP, a host booting over DHCP)
  are drawn as distinct teal squares, and when exactly one switch is present its
  members are linked by faint dotted **"L2 segment"** edges — so the graph reads
  as a real switched topology (switch at the hub) instead of a few floating dots.
- **Device Inventory table** in the Assets panel, the HTML report, and the CLI
  `analyze` output: one row per transmitting NIC with **vendor (from the MAC OUI)**,
  MAC, IP address(es), role and packet count. New `oui_vendor()` helper (a curated,
  partial OUI map — returns "" when unknown rather than guessing).
- Regression tests (`tests/test_device_graph.py`) proving no phantom nodes,
  IPv4+IPv6 merge, fan-out-as-count, switch/infra + L2-segment rendering, and the
  same-chassis inference (grouped switch MACs; no false grouping of real hosts).

### Accurate composition, coordinated-recon detection, real network graph & a Possible-Attacks panel

**Added**
- **Dedicated "Possible Attacks" panel.** The Threat Forecast is now its own
  left-nav section (with a count badge) alongside Threat Events / Attack Chains,
  and every predicted attack shows an explicit **"Why we predict this"** reason
  tied to the concrete observed evidence. A compact summary also appears on the
  Dashboard.
- **Coordinated-recon detection.** A host that ARP-sweeps the subnet and then
  sends TCP SYN probes to several services is now flagged as a scan even when the
  probe count is far below the standalone vertical/horizontal thresholds (the case
  a vantage-limited pentest capture produces). Low false-positive — it requires the
  ARP-sweep context. These recon phases also correlate into a **"Reconnaissance
  campaign"** attack chain.
- 5 tests (`tests/test_composition_recon.py`).

**Fixed**
- **Traffic composition now matches Wireshark.** The parser was collapsing
  link-layer control frames into "802.3"/"Ethernet" and every UDP application into
  "UDP". It now names them: **STP, CDP, DTP, LLC, LOOP** and **DHCP, mDNS, NBNS,
  NBT-DGM, LLMNR, SSDP, NTP, SNMP** (a new `display_protocol` used only for the
  composition — `protocol` stays TCP/UDP for detector logic). e.g. a lab capture
  that read "802.3 18.8% / UDP 6.2%" now reads "STP 16.2% / DHCP 5.4% / mDNS 0.7% …".
- **DNS activity distinguishes mDNS / LLMNR / unicast DNS** and notes when a
  capture contains only local service discovery (no external name resolution).
- **Real host-to-host network graph** (replaces the top-talker chart). Nodes are
  tagged with a role — **attacker / target / internal / external** — edges are the
  actual conversations *plus* attacker→target scan/attack edges reconstructed from
  detections (dashed red, arrowed), so the attack topology is visible. Web canvas
  and report SVG both updated; the report section is now "Network connection graph".
- **Indicators of Compromise now include internal hosts of interest** (the
  attacker/scanner source IPs and ARP MACs), so an internal pentest is no longer
  reported as "no IOCs".

### Threat-forecast prediction, full-suite protocols & SYN-flood detection

**Added**
- **Threat Forecast — grounded attack prediction (`packetiq/prediction.py`).**
  After analysing a capture, PacketIQ now forecasts the attacks it is *exposed to
  next*, from two evidence sources only: the **services actually observed** (mapped
  to the concrete attacks that target them — e.g. SMB → EternalBlue/ransomware
  lateral movement; FTP/Telnet → credential sniffing; RDP → BlueKeep/brute force;
  Redis/Mongo/Docker → unauth RCE/takeover; chargen → UDP amplification), and the
  **behavioural trajectory** of what was detected (a scan → targeted exploitation
  of what it found; an ARP sweep → MITM/lateral staging; a C2 beacon → exfiltration).
  Each prediction cites the exact evidence, a likelihood (High/Medium/Low), impact
  severity, MITRE technique and remediation. It is framed as *possible* attacks
  given exposure — never a confirmed event — and surfaced on the web Dashboard
  ("🔮 Threat Forecast"), in the CLI (`THREAT FORECAST` section) and in the HTML/PDF
  report. 7 tests (`tests/test_prediction.py`).
- **Comprehensive Internet-Protocol-Suite recognition.** `utils/helpers.py` now
  maps the core transport/internet-layer protocols (TCP, UDP, ICMP/ICMPv6, IGMP,
  SCTP, GRE, ESP/AH, OSPF, EIGRP, VRRP, L2TP, …) and ~135 application-layer
  services — including the legacy inetd services a scan reveals (echo, discard,
  daytime, qotd, chargen), Windows services (MSRPC, NetBIOS, SMB, WinRM, Kerberos),
  databases, ICS/SCADA (Modbus, S7), and management planes (IPMI, Docker, VMware).
  This feeds richer composition tables and the threat-forecast reasoning.
- **SYN-flood / connection-exhaustion detection (`packetiq/detection/dos_flood.py`).**
  A high volume of *unanswered* SYNs concentrated on a single host:port (a flood,
  not a scan) is now flagged — a real gap: a lab capture with 308 unanswered SYNs
  to one target previously produced zero findings. MITRE **T1499.002**, tiered by
  volume/rate, and verified to add no false positives on benign captures. 4 tests
  (`tests/test_dos_flood.py`).

### Layer-2 attack detection, a cleaner graph & a zero-finding security scan

**Added**
- **ARP scan & spoofing detection (`packetiq/detection/arp_scan.py`).** PacketIQ
  now parses ARP frames instead of discarding them, and detects two layer-2
  attack patterns that IP-layer detectors are blind to:
  - **ARP host-discovery sweep** — one host ARP-requesting many distinct targets
    (how `nmap -sn` / `arp-scan` enumerate a subnet). MITRE **T1018**. Tiered
    MEDIUM (≥20 targets) / HIGH (≥50), scaled by breadth.
  - **ARP cache poisoning** — a single IP announced by multiple MACs (an
    adversary-in-the-middle signature). MITRE **T1557.002**.
  This closes a real gap: a full-subnet ARP sweep (789 requests to 253 hosts) that
  previously produced **zero findings** now surfaces as a clear HIGH event naming
  the scanner. ARP is also a first-class protocol in the composition table now
  (it was silently lumped into "Ethernet"). 6 new tests (`tests/test_arp_scan.py`).

**Fixed**
- **A successful attack reading as "0 findings / LOW".** In addition to the ARP
  gap above, the aggregate risk **tier could read lower than the worst single
  finding warranted** — a capture containing a HIGH indicator could still be
  summarised "LOW — no action". The tier is now floored (a HIGH finding ⇒ tier at
  least MEDIUM, a CRITICAL ⇒ at least HIGH); the numeric score is unchanged.
- **Connection graph cluttered / mis-sized.** The graph plotted broadcast,
  multicast and unspecified pseudo-addresses (`0.0.0.0`, `255.255.255.255`,
  `224–239.x.x.x`, `x.x.x.255`, `ff00::/8`) as if they were hosts, so DHCP/mDNS
  noise dwarfed the real talkers. It now shows only real endpoints. The canvas is
  also sized correctly (it was laid out at a fixed width while its panel was
  hidden, then CSS-stretched — causing blur), redraws when the Network panel
  becomes visible and on window resize, labels every node when few are present,
  and no longer leaks a window event listener per redraw.
- **The previous capture's data lingering after a new upload.** A new analysis now
  clears all per-capture panels (packets, CVE, graph) **up-front** when it starts,
  not only when the next render lands, so no state bleeds between captures.
- **All 56 Bandit findings resolved (was 0 High / 0 Medium / 53 Low → now 0/0/0).**
  43 best-effort `try/except: pass` blocks became idiomatic `contextlib.suppress`;
  the remaining intentional patterns (fixed-argv, no-shell system calls; skip-and-
  continue loops; `"0.0.0.0"` sentinel comparisons) carry scoped, justified
  `# nosec` annotations. No behaviour change; the full suite stays green.
- **Editable install permanently robust to macOS `UF_HIDDEN`.** The earlier
  `chflags` clear was only temporary (a background service re-hides `.venv`). A
  `sitecustomize.py` in the venv now re-adds the repo root to `sys.path`; Python
  imports it even when hidden (unlike `.pth` files, which `site.py` skips), so the
  `packetiq` command resolves from any directory and live edits keep working.
  `quickstart.sh` writes it automatically on macOS.

### Dynamic, Wireshark-style Live Monitor & reliable editable installs

**Added**
- **Live, self-refreshing capture-interface picker.** The Live Monitor no longer
  shows a static, cryptic `en0/en3/…` list. A new `packetiq/net_interfaces.py`
  enumerates interfaces with **friendly names** (macOS `networksetup` hardware
  ports — "Wi-Fi", "Ethernet Adapter (en3)", "Thunderbolt Bridge"), **IPv4**,
  **link status** (● up / ○ down), and a **kind** icon, ranked best-first with the
  active NIC **★ recommended**. The web picker **re-scans every 3 s** (and on a new
  🔄 button), so an adapter you plug in **appears on its own without reloading** —
  just like Wireshark — while preserving your current selection.
- **`packetiq live --list`** prints the same interface table in the terminal, and
  running `packetiq live` with no `-i` now lists the available interfaces.
- 10 new tests (`tests/test_net_interfaces.py`) covering classification, the macOS
  `networksetup`/`ifconfig` parsers, ranking, the live re-scan and graceful
  degradation.

**Fixed**
- **A hot-plugged NIC (e.g. a USB LAN adapter) never appearing in the Live
  Monitor while it was visible in Wireshark.** Root cause: scapy caches its
  interface table (`conf.ifaces`) at first use and `get_if_list()` only reads that
  cache, so an interface attached *after* the web app started stayed invisible —
  even though the picker re-polled every 3 s (it was re-rendering a stale list).
  Wireshark, by contrast, re-scans the OS on every open. `net_interfaces.py` now
  forces a live re-scan (`conf.ifaces.reload()`) on each enumeration — guarded so
  it only fires when a scapy provider is registered (otherwise `reload()` would
  clear the list), serialised with a lock against concurrent web polls, and
  failure-tolerant (a failed re-scan leaves the cached list intact). A plugged-in
  adapter now shows up within one 3 s tick, matching Wireshark.
- **Editable installs (`pip install -e .`) silently doing nothing on macOS.**
  Root cause: when the `.venv` tree carries the macOS `UF_HIDDEN` flag, pip writes
  the editable `.pth` hidden, and CPython's `site.py` **deliberately skips hidden
  `.pth` files** — so `import packetiq` / the `packetiq` command failed outside the
  repo and source edits never took effect. `quickstart.sh` now clears the flag on
  macOS (`chflags -R nohidden .venv`), and `docs/RELEASE.md` documents the one-time
  fix plus the `--config-settings editable_mode=compat` editable-dev install. With
  the flag cleared, editable installs work reliably: edits to `packetiq/` take
  effect immediately **and** the console script resolves from any directory.

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
  now spans **six malware families** across nine real infected captures (~1.64 M
  packets — Donbot, Sogou, Qvod, Rbot ×2, Virut + a second fast-flux, Neris ×2)
  plus benign captures: **100% recall · 90.0% precision · 94.7% F1** (up from 57%
  precision; the lift from 83.3% comes from correctly detecting four more real
  botnet captures, detectors untouched), every decision attributable to a specific
  detector — see `reports/detection_real.md`.
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
  (placeholders only now). The keys present in earlier git history have since been
  **revoked by the owner (2026-07-12)**, so the leaked values no longer authenticate;
  an optional history scrub before any public push is all that remains.
- **Full security audit + hardening** (SAST, dependency CVE scan, secret scan,
  and manual review — see `docs/reports/PacketIQ_Security_Audit_Report.pdf`). Fixed:
  **path-traversal / arbitrary file write** in the evidence export (the `ip`
  filter is validated and never reaches the output path); **DNS-rebinding** and
  **CSRF** on the local web server (new middleware validates the Host header and
  blocks cross-origin state-changing requests — e.g. a malicious page can no
  longer trigger the privileged capture-setup prompt); **upload memory-exhaustion
  DoS** (uploads stream to disk with an early size abort; default cap 10 GB via
  `PACKETIQ_MAX_UPLOAD_MB`); oversized HTTP buffer / long keep-alive reduced;
  **command-injection hardening** of the privileged macOS capture-setup (strict
  `$USER` validation); world-readable upload/history dirs tightened to `0700`; a
  security warning is printed when binding to a non-loopback address. MD5-in-JA3
  annotated (`usedforsecurity=False`) — it is the JA3 spec, not a security control.
  bandit High/Medium: 0.
- **Dependency posture.** Runtime pins sit at security-patched floors in
  `pyproject.toml` / `requirements.txt`. The **reference/dev environment now runs on
  Python 3.12.13**, where these resolve to fully-patched releases and `pip-audit`
  reports zero advisories in the runtime dependency set (one dev-only transitive,
  `diskcache` via the `dev`-extra `pySigma`, has no upstream fix yet — not shipped to
  runtime users). The still-supported Python 3.9 (end-of-life since Oct 2025)
  installs each package at its newest 3.9-compatible version, so a few upstream
  advisories are only fixed on 3.10+ — **Python 3.10+ is recommended**. Re-checked
  by `pip-audit` in CI.
- **Re-audit (2026-07-15)** confirmed no new code-level issues; added a root
  [`SECURITY.md`](SECURITY.md) policy and refreshed the audit report + raw
  `bandit`/`pip-audit` evidence in `docs/security_audit/`. Also fixed a web-app
  display gap: the drop-zone hint and client-side size guard were hard-coded and
  could drift from the server's real limit — both now read the actual
  `MAX_UPLOAD_MB` injected at page load, so they always match the backend (and
  track `PACKETIQ_MAX_UPLOAD_MB` overrides). The default cap is **10 GB**: uploads
  stream to disk in 1 MiB chunks and captures are analysed packet-by-packet via a
  streaming `PcapReader`, so a full 10 GB file is handled in bounded memory
  (limit is free disk, not RAM); documented in `.env.example`.
- **Test-coverage measurement** — added `pytest-cov` (dev dependency) with a
  `[tool.coverage]` config that measures the **whole** package (nothing omitted to
  inflate the number). Line coverage is **~70%**; CI now enforces a **65% floor**
  on every push (Python 3.9–3.12) so it cannot silently regress. Bandit's B311
  "weak-random" findings in the synthetic capture/benchmark/fixture generators are
  annotated `# nosec B311` (deterministic sample data, never cryptographic); the
  audit's Low count is now 53.
- **Migrated the reference environment to Python 3.12.13.** The dev `.venv` was
  rebuilt on a standalone (uv-managed) CPython 3.12.13 — no system change, no code
  change (`requires-python` stays `>=3.9`). The full suite (304 tests, ~70% coverage
  gate, ruff, detection gate 100%) passes on 3.12, and the security-floor
  dependencies resolve to their fully-patched releases (`python-multipart`
  0.0.20→0.0.32, `starlette` 0.49→1.3.1, `urllib3` 2.6.3→2.7.0, `requests`
  2.32.5→2.34.2, `click` 8.1.8→8.4.2, `python-dotenv` 1.2.1→1.2.2), clearing the
  3.9-ceiling advisories. `PacketIQ.command` / `quickstart.sh` now auto-prefer the
  newest installed CI-tested interpreter (3.12 → 3.10) for a fresh `.venv`, falling
  back to `python3` (3.9 still supported); an upgrade runbook is in
  [`docs/RELEASE.md`](docs/RELEASE.md).

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
