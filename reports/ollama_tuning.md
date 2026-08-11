# Tuning the local (Ollama) copilot for PacketIQ — what actually moved the needle

**Goal:** make the offline local model give its best, fully-grounded answers on
real captures. **Measured with** `tools/eval_copilot.py` (deterministic entity
grounding, seed pinned) on real captures from `datasets/real/pcaps/`.

*Faithfulness* = share of the model's specific claims (IPs, MITRE technique IDs,
CVE IDs) that appear verbatim in the evidence it was given. *Grounded claims* =
how many correct specifics it actually produced (a proxy for usefulness — a model
that says nothing scores 100% faithful but is useless).

Every number below is reproducible: `OLLAMA_SEED=42`, base model
`qwen2.5:7b-instruct`.

---

## The real problem: the local model was being starved, not under-trained

On an evidence-rich capture the copilot context is large. `context_builder.py`
used to enumerate **every** external IP — twice (in the topology section and the
IOC summary). On `donbot.pcap` that is **1,555 external IPs listed twice** plus a
full destination-IP table, ballooning the context to **~82,000 characters
(~20,500 tokens)**. That overflowed the local model's context window, and Ollama
truncates from the front — so the **detections, attack chains and MITRE mappings
at the top were dropped**, leaving the model only the tail (a wall of IPs).

The symptom, from the raw eval, was unmistakable — the model replied:

> "Based on the provided list, it appears that you have a list of IP addresses
> rather than a capture file… we would need to analyze the network traffic data."

It literally never saw the findings.

### The fix (helps every provider, cloud and local)

- `packetiq/copilot/context_builder.py`: cap every long IP enumeration to the
  **top 30 by traffic volume** with an "… and N more" line (external contacts,
  attacker IPs, target IPs). The long tail only buried the findings.
- `packetiq/webapp/app.py`: raise the local context-window cap from 8,192 to
  **16,384** tokens so an evidence-rich capture fits without truncation (still
  laptop-sized for a 7B model; override with `OLLAMA_NUM_CTX`).

`donbot.pcap` context dropped from **82,000 → 33,700 chars**, and now contains the
detections, chains, MITRE IDs and the real attacker IP.

### Before → after (base `qwen2.5:7b-instruct`, guardrail OFF, raw)

| Capture | Grounded claims | Hallucinated | Raw faithfulness |
|---|--:|--:|--:|
| `donbot.pcap` — **before** the fix | **0** (generic non-answers) | 0 | 100%* |
| `donbot.pcap` — **after** the fix | **67** | **0** | **100%** |

\* trivially 100% because the model made no specific claim at all — it could not
see the evidence.

### Held-out confirmation (the fix generalises, not just donbot)

| Capture | Config | Grounded | Hallucinated | Faithfulness |
|---|---|--:|--:|--:|
| `donbot.pcap` | guardrail **ON** (shipped) | 65 | 0 | **100%** |
| `qvod.pcap` (never used in tuning) | guardrail OFF | 48 | 0 | **100%** |
| `normal-dns-2013.pcap` (benign) | guardrail OFF | grounded, correctly abstains on CVEs | 0 | **100%** |

The local model now produces **dozens of correct, grounded indicators per capture
with zero hallucinations** — the best result the metric allows.

---

## What we tried and rejected: a few-shot Modelfile ("packetiq-soc")

Ollama has no weight-fine-tune CLI; you specialise via a Modelfile (system prompt
+ sampling params + few-shot `MESSAGE` examples). We built `packetiq-soc` from
`qwen2.5:7b-instruct` with few-shot examples drawn from the **real** Donbot
analysis, and measured it honestly on a **held-out benign capture**:

| Model | Capture | Hallucinated | Faithfulness |
|---|---|--:|--:|
| base `qwen2.5:7b-instruct` | `normal-dns-2013.pcap` | 0 | **100%** |
| `packetiq-soc` (few-shot) | `normal-dns-2013.pcap` | **12** | **0%** |

The 7B model **memorised the examples' indicators** and emitted Donbot's IPs
(`147.32.84.165`, `91.212.135.158`, `90.177.113.3`) and MITRE IDs
(`T1046`, `T1071.001`, `T1499.002`) while analysing an unrelated benign DNS
capture. Removing the few-shot (system-prompt + params only) stopped the IP leak
but the model still invented MITRE IDs (81.8%) where base scored 100%.

**Conclusion:** a specialised Modelfile is *no better than the base model in the
PacketIQ pipeline, and slightly worse* — the app already injects the optimal
evidence-only system prompt and reproducible sampling on every request, so a
custom model only adds variance and leakage risk. We therefore **did not ship it**
and kept `qwen2.5:7b-instruct` as the default. This is the honest outcome: the
accuracy win came from fixing the evidence pipeline, not from fine-tuning.

The deterministic **grounding guardrail** remains the hard guarantee — it strips
any indicator not present in the evidence, so guarded faithfulness is 100%
regardless of model. See `docs/ollama_integration.md` §6 and
`docs/grounding_guardrail.md`.

### Reproduce

```bash
PCAP=datasets/real/pcaps/donbot.pcap
# raw (guardrail off) and shipped (guardrail on)
PACKETIQ_GROUNDING_GUARD=0 OLLAMA_SEED=42 python tools/eval_copilot.py --pcap $PCAP --provider ollama
OLLAMA_SEED=42 python tools/eval_copilot.py --pcap $PCAP --provider ollama
```
