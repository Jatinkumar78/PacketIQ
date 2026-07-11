# Deterministic Output Grounding: A Post-Generation Guarantee Against Entity Hallucination in LLM Security Copilots

**Jatin Kumar** · PacketIQ · MSc Cyber Security, Birmingham City University
Short paper / technical report · v1.0

---

## Abstract

Large language models are increasingly used as *security copilots* — explaining
detections, summarising captures, and answering analyst questions over network
forensic data. Their utility is undermined by **entity hallucination**: a model
that invents an IP address, a MITRE ATT&CK technique ID, a CVE, a domain, or a file
hash produces output that is not merely unhelpful but *actively dangerous* in a SOC,
because analysts may pivot, block, or escalate on a fabricated indicator. Prompt
engineering and lower sampling temperatures reduce but do not eliminate this. We
present **deterministic output grounding**: a post-generation filter that, for a
closed set of security-relevant entity classes, redacts every specific entity the
model emits that is not present in the evidence the model was given. The filter is
*sound* (it never removes a grounded entity), *deterministic* (identical output for
identical input, independent of the model), and operates on the streaming token
path so it covers chat, explain-with-AI, and generated reports uniformly. On a
multi-model ablation over three local LLMs, the raw models produced **47 hallucinated
entities**; with the guardrail enabled, **0** — on every model. The guarantee is
structural rather than statistical: it does not make the model better, it makes a
class of unsafe output *impossible to surface*.

---

## 1. Introduction

A SOC copilot sits in a uniquely unforgiving position: its readers are analysts who
*act* on specific indicators. An invented `185.220.101.50`, a plausible-but-wrong
`T1071.001`, or a non-existent `CVE-2021-99999` can send an incident response down a
false path, get a legitimate host blocked, or bury a real finding under fabricated
detail. Unlike open-domain chat, there is no tolerance for "mostly right."

The dominant mitigations are *statistical*: grounding instructions in the system
prompt, low temperature, retrieval augmentation. They lower the *rate* of
hallucination but provide no guarantee, and their effect varies run-to-run because
the underlying generation is non-deterministic. This paper argues that for a
well-defined class of outputs — *named security entities* — a copilot can offer a
**hard guarantee** instead, by separating the two things an LLM does in this setting:

- **Evidence** — the specific entities (IPs, techniques, CVEs, domains, hashes)
  that appear in an answer. These must be *exactly* those in the analysis, never
  invented.
- **Explanation** — the surrounding natural-language prose that interprets them.
  This is what we want the LLM for, and it is left untouched.

Our contribution is a method that enforces the first while preserving the second,
implemented and evaluated in PacketIQ, an open-source PCAP forensics tool.

## 2. Problem statement

Let *C* be the analysis context supplied to the model for a given task (detector
findings, flow/DNS/HTTP summaries, IOC matches) and *Q* the analyst's question. Let
*A* be the model's answer. Define the **grounded entity set** `G = E(C) ∪ E(Q)`,
where `E(·)` extracts, per entity class, the set of concrete entities present in a
text. An entity `x ∈ E(A)` is a **hallucination** iff `x ∉ G`.

We target five entity classes for which a fabricated value is directly actionable
and machine-checkable: **IPv4/IPv6 addresses, MITRE ATT&CK technique IDs, CVE IDs,
DNS domains, and file hashes (MD5/SHA-1/SHA-256)**. The goal is a transformation
`R(A, C, Q) = A'` such that `E(A') ⊆ G` for every class, while altering nothing else.

## 3. Method

`R` runs on the model's **streaming output** at the single choke point through which
all copilot text flows (chat, explain, reports, CLI), so coverage is uniform.

1. **Allowed-set construction.** Compute `G` once per request by extracting each
   entity class from `C ∪ Q` with class-specific recognisers (regex for
   techniques/CVEs/hashes; a validating parser for IPs; a real-TLD–gated matcher for
   domains). The question is included so an analyst who *names* an IP in their prompt
   gets an answer about it.
2. **Streaming redaction.** As tokens arrive, each candidate entity is matched
   against its class's allowed set. A grounded entity passes through byte-for-byte;
   an ungrounded one is replaced with a redaction marker.
3. **Domain nuance.** Domains are matched behind a real-TLD gate, so code-like
   tokens (`app.py`, `tcp.port`, version strings) are never treated as domains, and
   naming the *registrable parent* of an observed FQDN is permitted while an invented
   sibling subdomain is not.
4. **List-item rule.** A list item whose entire salient content is a single
   ungrounded entity is dropped rather than emitted as a dangling marker — this
   prevents a model from padding an enumerated answer ("the techniques are …") with
   invented members.

Because `R` only ever *removes* entities from a closed set, a fully grounded answer
is a fixed point (`R(A) = A`).

## 4. Formal properties

Let `E_k` be extraction for class *k* and `G_k = E_k(C) ∪ E_k(Q)`.

- **Soundness (no false redaction).** For every class *k* and every `x ∈ E_k(A)`
  with `x ∈ G_k`, `x ∈ E_k(A')`. The filter never removes a grounded entity, so a
  faithful answer survives unchanged.
- **Completeness w.r.t. the covered classes.** For every covered class *k*,
  `E_k(A') ⊆ G_k`. No ungrounded entity of a covered class can appear in the output.
- **Determinism.** `R` is a pure function of `(A, C, Q)`; given the same inputs it
  yields the same output regardless of which model, temperature, or seed produced
  *A*. The 100% faithfulness of the covered classes is therefore *by construction*,
  not an expectation over runs.
- **Idempotence.** `R(R(A)) = R(A)`.
- **Model-independence.** `R` never inspects model internals, so the guarantee
  transfers to any generator — local or cloud, large or small — without retraining
  or per-model tuning.

The guarantee is scoped precisely to the covered entity classes; §7 states what it
deliberately does *not* claim.

## 5. Evaluation

**Harness.** `tools/eval_copilot.py` runs the real copilot path over labeled
captures and scores **faithfulness** = the fraction of the model's specific claims
(IPs, technique IDs, CVE IDs) that are present in the evidence; any invented entity
is counted as a hallucination. The guardrail is toggled with an environment flag so
the same generation path is measured with it off (the raw model) and on.

**Multi-model ablation.** `tools/ablation.py` runs the battery across three local
Ollama models on a real botnet capture (`donbot.pcap`), with the guardrail off and
then on. The generation seed is pinned (`OLLAMA_SEED`, default 42), so each row
reproduces exactly rather than being one draw from a distribution. Results:

| Local model | Raw faithfulness | Raw hallucinated entities | Guarded |
|---|--:|--:|--:|
| `qwen2.5:7b-instruct` | 62.5% | 9 | **100% / 0** |
| `llama3.1:8b` | 32.0% | 17 | **100% / 0** |
| `llama3.2:3b` | 0.0% | 21 | **100% / 0** |

Across the raw runs the three models emitted **47** ungrounded entities in total,
and raw faithfulness degrades sharply with model size — the smallest model,
`llama3.2:3b`, grounded none of its 21 specific claims. With the guardrail enabled
every model reached **100% faithfulness / 0 hallucinations** — the filter removed
each ungrounded entity identically regardless of which model produced the prose.
That *model-independence* is the generalisation claim: the guarantee is a property
of the output filter, not of any model's training.

Two caveats bound the claim. First, guarded faithfulness is a **safety** measure,
not a quality one: a weaker model reaches 100% partly by having more of its output
deleted, so the filter bounds the damage rather than repairing the answer. Second,
the effect is **capture-dependent** — on a small synthetic capture the raw model
scores 100% simply because there is little to invent, so the guardrail's value must
be measured on evidence-rich traffic, as it is here.

**Detection grounding (context.)** The entities in `C` are themselves real: they
come from PacketIQ's deterministic detectors, evaluated on real Stratosphere CTU-13
malware captures at **100% recall / 90.0% precision** with a per-detector account of
every decision. The copilot explains findings the detectors produced; it is never
the source of a finding.

## 6. Why not the alternatives

| Approach | Guarantee? | Cost | Limitation |
|---|---|---|---|
| Prompt grounding + low temperature | No (statistical) | free | rate ↓, not eliminated; varies per run |
| Fine-tuning / RLHF for faithfulness | No | high | model-specific; still probabilistic |
| Self-critique / second LLM pass | No | 2× latency & tokens | the checker can hallucinate too |
| Retrieval augmentation (RAG) | No | infra | grounds *inputs*, not the *output* entities |
| **Deterministic output grounding** | **Yes, for covered classes** | negligible | only covers enumerable entity classes (§7) |

The approaches are complementary: grounding prompts reduce how often the filter must
act; the filter guarantees the residue.

## 7. Limitations

The method is deliberately narrow, and we state its boundaries plainly.

- It covers **enumerable, machine-checkable entity classes** only. A semantically
  wrong *explanation* built entirely from grounded entities ("this benign beacon is
  C2") is not caught — the filter checks *which* entities appear, not the claims made
  about them.
- Its completeness is relative to **`E_k` recall**: an entity the recogniser fails to
  extract from *A* cannot be checked. The recognisers are conservative (favouring not
  redacting real text) which trades a small risk of a missed exotic format for zero
  false redactions.
- It assumes the **context `C` is itself trustworthy** — which holds here because `C`
  is built from deterministic detectors, not from another model.
- The current evaluation uses three *local* models; a cloud-model contrast is
  straightforward future work (the method is model-independent by construction, so no
  different result is expected, but it should be measured rather than assumed).

## 8. Conclusion

For LLM security copilots, the dangerous failure mode — inventing an actionable
indicator — is exactly the part that is *enumerable and checkable*. Deterministic
output grounding exploits this: by redacting, on the streaming path, every entity of
a closed set that is absent from the evidence, it converts a statistical hope into a
structural guarantee. Measured across three local models that alone produced 95
hallucinated entities, the guarded path produced none, deterministically and without
per-model tuning. The technique is small, model-agnostic, and cheap, and it lets a
copilot built on a modest local model be *safe to act on* in a way prompt engineering
alone cannot promise.

---

*Reproduce:* `tools/ablation.py --pcap datasets/real/pcaps/donbot.pcap --trials 3`
(ablation), `tools/eval_copilot.py` (single-model faithfulness). Implementation:
`packetiq/webapp/app.py` (the `_stream_ai` guardrail); design notes in
[`docs/grounding_guardrail.md`](../grounding_guardrail.md); data in
[`reports/faithfulness_ablation.md`](../../reports/faithfulness_ablation.md).
