# Deterministic Output-Grounding for a SOC Copilot

*A methods note on how PacketIQ guarantees its AI copilot never surfaces an
ungrounded indicator — regardless of which language model produces the prose.*

## 1. Problem

An LLM copilot in a security-operations context is held to a higher bar than a
chatbot. If it states an IP address, a MITRE ATT&CK technique ID, a CVE, a domain
or a file hash, an analyst may pivot on it — block it, hunt for it, escalate on
it. A single **hallucinated indicator** — a plausible-looking IP or CVE the model
invented — is therefore not a cosmetic error but a false lead that wastes analyst
time and can misdirect a response.

Small local models (the ones you can run offline on an analyst's laptop, which
PacketIQ supports for privacy) are especially prone to this. Asked to list the
MITRE techniques in a capture, a 3B–8B model will often **pad** the list with
techniques it "expects" to see, or append a well-known CVE (e.g. Log4Shell) that
was never in the evidence. Measured on PacketIQ's own faithfulness harness, a raw
local model lands well below 100% (see §6).

Prompting helps but does not *guarantee*. "Only use entities from the evidence"
is an instruction the model may or may not follow on any given generation, and its
compliance is non-deterministic. For a tool that wants to make a hard claim —
*"the copilot will never show you an indicator that isn't in your capture"* — a
prompt is not enough.

## 2. Key insight

PacketIQ's architecture separates **evidence** from **explanation**:

- The **evidence** — every detection, IP, port, domain, CVE, hash, risk score — is
  produced by the deterministic detection pipeline (`parser → extractor →
  detection → correlation`). It never comes from the LLM.
- The **explanation** — the readable prose that summarises and interprets that
  evidence — is the only thing the LLM produces.

So the only place a hallucinated indicator can enter is the model's prose. And the
set of indicators that are *legitimately* mentionable is known exactly ahead of
time: it is the set of entities in the evidence the model was given (plus the
analyst's own question, since referring to what you were asked about is
legitimate). This turns "detect hallucination" — hard, semantic, model-dependent —
into "check membership in a known set" — trivial, syntactic, deterministic.

## 3. Method

A **deterministic streaming post-filter** sits on the copilot's output stream, at
the single choke point (`_stream_ai`) through which *all* copilot text flows — web
chat, Explain-with-AI, AI reports, and the CLI. It is not a second model; it adds
no network call and negligible latency.

**Allowed set.** Before generation, extract every entity of each tracked type from
the evidence context ∪ the user's messages:

| Type | Extraction | Grounding rule |
|---|---|---|
| IPv4/IPv6 | regex + `ipaddress` validation (rejects dotted non-IPs like `v1.2.3.4`) | exact membership |
| MITRE technique | `T####(.###)?` | exact (case-insensitive) |
| CVE | `CVE-####-####+` | exact (case-insensitive) |
| Domain | hostname regex behind a **real-TLD gate** | exact, or the registrable **parent** of an observed FQDN |
| File hash | MD5 / SHA-1 / SHA-256 hex | exact (case-insensitive) |

The TLD gate is what makes domain-checking safe: a dotted token is only treated as
a domain when its last label is a real TLD, so `app.py`, `index.html`, `tcp.port`,
`session.id`, `e.g.` and version strings are never redacted. The parent rule lets
the model name `evil-c2.top` when the evidence observed `cdn.evil-c2.top` (a
legitimate generalisation) but not invent a more specific `admin.evil-c2.top`.

**Streaming redaction.** The filter buffers the token stream and flushes on line
boundaries (entities never span a newline; a safety valve flushes very long lines
at the last whitespace so the stream never stalls). For each completed line it
redacts any token of a tracked type that is not in the allowed set. Cleanup then
tidies the artefacts of removal (double spaces, empty parentheses, a space left
before punctuation).

**List-item rule.** If a bulleted/numbered line's *every* specific claim was
invented, the whole item is dropped (that is the "padded MITRE list" case). But if
a grounded entity survives the redaction, the item is kept — the filter never hides
real evidence to remove an invented neighbour.

## 4. Formal properties

Let `A` be the allowed set and `f` the filter. For any model output `o`:

- **Soundness (never fabricates or alters).** `f` only ever *deletes* substrings
  that match a tracked-entity pattern and are ∉ `A`. It never inserts or rewrites
  an entity. Therefore every entity in `f(o)` was present in `o`, and every
  *grounded* entity in `o` is preserved. A fully faithful answer is returned
  **byte-for-byte unchanged**.
- **Completeness (over tracked types).** After `f`, no IP / technique / CVE /
  domain / hash outside `A` remains. Faithfulness over the tracked entity types is
  therefore **1.0 by construction**, independent of the model.
- **Determinism / stream-invariance.** The output depends only on `o` and `A`, not
  on how `o` was chunked by the network. The test suite asserts this directly:
  across 200 random chunk boundaries (and character-by-character) the reassembled
  output is identical every time.

## 5. Why not the alternatives

| Approach | Guarantee? | Cost | Model-agnostic? |
|---|---|---|---|
| Prompt "stay grounded" | No (best-effort) | free | no — compliance varies |
| Lower temperature | No (reduces, not removes) | free | no |
| Second-model verifier | No (verifier can also err) | +1 model / latency | no |
| RAG with citations | Partial (still free-form prose) | retrieval infra | no |
| **Deterministic post-filter (this)** | **Yes, for tracked entity types** | **~0** | **yes** |

The trade-off is scope (below), bought in exchange for a *hard, cheap,
model-independent* guarantee — the right trade for indicators, which are exactly
the claims an analyst acts on.

## 6. Evaluation

Faithfulness is measured by `tools/eval_copilot.py`: it runs the real copilot path
over labeled captures and computes the share of the model's specific claims that
are present in the evidence, counting any invented entity as a hallucination. The
guardrail is toggled with `PACKETIQ_GROUNDING_GUARD` so raw vs guarded is directly
comparable, and `tools/ablation.py` sweeps several local models. The consistent
finding: raw local models score below 100% and wobble run-to-run (they pad lists
and occasionally invent a CVE); with the guardrail on, **every** model is a
deterministic 100% with zero hallucinated claims. See
`reports/faithfulness_ablation.md` (multi-model) and
`reports/copilot_faithfulness_comparison.md` (local-raw vs local-guarded vs cloud).

## 7. Limitations (stated honestly)

- **Scope is the tracked entity types.** The guarantee covers IPs, MITRE
  techniques, CVEs, domains and file hashes — the actionable indicators. It does
  **not** vet free-text claims ("the attacker deployed ransomware"): a model could
  still mischaracterise behaviour in prose that contains no ungrounded indicator.
  The prompt rules and low temperature address that softer surface; the guardrail
  hard-guarantees only the indicators.
- **Grounding is not relational correctness.** The filter guarantees every shown
  indicator *appears in the evidence*, not that the model *related them correctly*
  (e.g. attributing a grounded IP to the wrong host). It removes fabrication, not
  misinterpretation.
- **Domain recall is TLD-bounded.** To avoid ever mangling non-domain prose, an
  invented domain on an unusual TLD outside the curated set could pass; invented
  C2s almost always use a common gTLD, which is covered. This is a deliberate
  precision-over-recall choice for the *filter itself*.
- **Redaction can leave a seam.** Removing an ungrounded token from mid-sentence
  can leave slightly awkward phrasing; cleanup minimises but does not always
  eliminate this. A visible seam is preferable to a confident false indicator.

## 8. Contribution

The novel element is not any single regex but the **framing**: because a
well-architected analysis tool already computes its indicators deterministically,
the LLM's indicator vocabulary can be *closed* to that evidence with a
deterministic, model-agnostic, near-zero-cost post-filter — converting "please
don't hallucinate" from a hope into a checkable property. It lets PacketIQ run a
small, private, offline model and still make the hard claim a SOC tool needs:
*the copilot will never show you an indicator that isn't in your capture.*
