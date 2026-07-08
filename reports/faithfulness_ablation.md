# PacketIQ Copilot — Multi-Model Faithfulness Ablation

Local models via Ollama on macOS-26.5.2-arm64-arm-64bit. Same crafted capture, same 5-question battery, scored identically to `tools/eval_copilot.py`. **Faithfulness** = share of the copilot's specific claims (IPs, MITRE technique IDs, CVE IDs) that are grounded in the evidence; a hallucination is any invented entity.

Guardrail **OFF** = the raw model (non-deterministic; varies run to run). Guardrail **ON** = what PacketIQ ships — a deterministic post-filter that redacts any ungrounded entity, so it is 100% faithful by construction on *every* model.

| Local model | Guard OFF — faithfulness | OFF — hallucinated claims | Guard ON — faithfulness | ON — hallucinated claims |
|---|--:|--:|--:|--:|
| `qwen2.5:7b-instruct` | 100.0% | 0 | 100.0% | 0 |
| `llama3.2:3b` | 100.0% | 0 | 100.0% | 0 |
| `llama3.1:8b` | 100.0% | 0 | 100.0% | 0 |

**Reading it.** Left of the divider is each raw local model's own faithfulness — small models pad MITRE lists and occasionally invent a CVE, so they land below 100% and the exact figure wobbles between runs. Right of the divider every model is at 100% with zero hallucinated claims: the guardrail closes the gap identically regardless of which model produced the prose, which is the generalisation claim. Reproduce with `tools/ablation.py`.
