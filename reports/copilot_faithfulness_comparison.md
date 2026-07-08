# PacketIQ Copilot Faithfulness — Local vs Cloud, with the Grounding Guardrail

Same rich multi-attack capture, same 5-question battery, scored identically.
**Faithfulness** = share of the copilot's specific claims (IP addresses, MITRE
technique IDs, CVE IDs) that are present in the evidence it was given. A
hallucination is any invented entity. Numbers are single-run (LLMs are
non-deterministic) and reproducible with `tools/eval_copilot.py`.

| Configuration | Model | Faithfulness | Hallucination-free | Hallucinated claims |
|---|---|--:|--:|--:|
| Local — guardrail OFF (raw model) | `ollama:qwen2.5:7b-instruct` | 42.9% | 4/5 | 16 |
| Local — guardrail ON (shipped) | `ollama:qwen2.5:7b-instruct` | 100.0% | 5/5 | 0 |
| Cloud — Gemini (guardrail ON) | `gemini:gemini-2.0-flash` | 100.0% | 5/5 | 0 |

**What this shows.** The copilot's *evidence* (detections, IPs, CVEs) is
deterministic and real — it never comes from the LLM. The only place a
hallucination could enter is the model's prose. A capable cloud model is
already ~100% faithful; a small local model, left raw, pads MITRE lists and
invents the occasional CVE. The **grounding guardrail** — a deterministic
post-filter that redacts any ungrounded IP/technique/CVE from the output —
closes that gap, taking the local model to **0 hallucinations** without any
cloud dependency. It can only remove an invented entity, never add or change a
real one, so a faithful answer is unchanged. Reproduce with:

```bash
# raw local model (guardrail off):
PACKETIQ_GROUNDING_GUARD=0 python tools/eval_copilot.py --demo --provider ollama
# shipped (guardrail on):
python tools/eval_copilot.py --demo --provider ollama
```
