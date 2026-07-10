# PacketIQ Copilot — Multi-Model Faithfulness Ablation

Capture: `donbot.pcap` · 5-question battery · 1 raw trial(s) per model · Ollama on macOS-26.5.2-arm64-arm-64bit. Scored identically to `tools/eval_copilot.py`: **faithfulness** = share of the copilot's specific claims (IPs, MITRE technique IDs, CVE IDs) grounded in the evidence; a hallucination is any invented entity.

Guardrail **OFF** = the raw model (the raw column shows the min–max faithfulness across the trials). Guardrail **ON** = what PacketIQ ships: a deterministic post-filter that redacts any ungrounded entity, so it is 100% faithful by construction on *every* model.

PacketIQ pins the Ollama sampling seed (`OLLAMA_SEED`, default 42), so repeated trials of the same model reproduce exactly. Set `OLLAMA_SEED=random` to sample the raw model's run-to-run variance instead.

| Local model | Raw faithfulness (min–max) | Raw hallucinated claims | Guarded faithfulness | Guarded hallucinated |
|---|--:|--:|--:|--:|
| `qwen2.5:7b-instruct` | 62.5% | 9 | 100.0% | 0 |
| `llama3.1:8b` | 32.0% | 17 | 100.0% | 0 |
| `llama3.2:3b` | 0.0% | 21 | 100.0% | 0 |

**Reading it.** Across the raw trials the local models produced **47 hallucinated claim(s)** in total — invented MITRE techniques or CVEs not in the evidence — and the count grows sharply as the model gets smaller. With the guardrail on, every model is at 100% with **0** hallucinated claims: the filter removes each ungrounded entity identically regardless of which model produced the prose. That model-independence is the generalisation claim.

Reproduce with `tools/ablation.py`.
