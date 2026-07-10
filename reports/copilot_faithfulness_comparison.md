# PacketIQ Copilot Faithfulness — Local vs Cloud, with the Grounding Guardrail

Same rich multi-attack capture (`datasets/real/pcaps/donbot.pcap`), same
5-question battery, scored identically. **Faithfulness** = share of the
copilot's specific claims (IP addresses, MITRE technique IDs, CVE IDs) that are
present in the evidence it was given. A hallucination is any invented entity.

The local rows are **reproducible**: PacketIQ pins the Ollama sampling seed
(`OLLAMA_SEED`, default 42), so re-running the commands below reproduces these
numbers exactly. Set `OLLAMA_SEED=random` to observe run-to-run variance.

| Configuration | Model | Faithfulness | Hallucination-free | Hallucinated claims |
|---|---|--:|--:|--:|
| Local — guardrail OFF (raw model) | `ollama:qwen2.5:7b-instruct` | 62.5% | 3/5 | 9 |
| Local — guardrail ON (shipped) | `ollama:qwen2.5:7b-instruct` | 100.0% | 5/5 | 0 |
| Cloud — Gemini (guardrail ON) | `gemini:gemini-flash-lite-latest` | 100.0% | 5/5 | 0 |

The raw local model invented seven MITRE technique IDs (`T1046`, `T1071`,
`T1075`, `T1089`, `T1098`, `T1210`, `T1543`) that appear nowhere in the evidence,
and cited two RFC 5737 documentation addresses (`192.0.2.1`, `198.51.100.1`) as
though they were observed hosts. The guardrail removes exactly those.

> The Gemini row's model was selected automatically. This Google project has no
> free-tier allowance for the default `gemini-2.0-flash` (the API answers
> `limit: 0`), so PacketIQ's per-model fallback advanced to
> `gemini-flash-lite-latest`, which served the run. The provider label stored in
> the JSON records the *first-choice* model, not the one that answered.

**What this shows.** The copilot's *evidence* (detections, IPs, CVEs) is
deterministic and real — it never comes from the LLM. The only place a
hallucination could enter is the model's prose. A capable cloud model is
already ~100% faithful; a small local model, left raw, pads MITRE lists and
invents addresses. The **grounding guardrail** — a deterministic post-filter
that redacts any ungrounded IP/technique/CVE from the output — closes that gap,
taking the local model to **0 hallucinations** without any cloud dependency. It
can only remove an invented entity, never add or change a real one, so a
faithful answer is unchanged.

Faithfulness is **capture-dependent**: on the small built-in `--demo` capture the
raw local model already scores 100%, because there is little to invent. The gap
only opens on evidence-rich captures like this one, which is why these numbers
are measured on `donbot.pcap` rather than on the demo.

Reproduce with:

```bash
# raw local model (guardrail off):
PACKETIQ_GROUNDING_GUARD=0 python tools/eval_copilot.py \
    --pcap datasets/real/pcaps/donbot.pcap --provider ollama
# shipped (guardrail on):
python tools/eval_copilot.py --pcap datasets/real/pcaps/donbot.pcap --provider ollama
# cloud comparison:
python tools/eval_copilot.py --pcap datasets/real/pcaps/donbot.pcap --provider gemini
```
