# PacketIQ Copilot — Multi-Model Faithfulness Ablation

Capture: `donbot.pcap` · 5-question battery · 3 raw trial(s) per model · Ollama on macOS-26.5.2-arm64-arm-64bit. Scored identically to `tools/eval_copilot.py`: **faithfulness** = share of the copilot's specific claims (IPs, MITRE technique IDs, CVE IDs) grounded in the evidence; a hallucination is any invented entity.

Guardrail **OFF** = the raw model (non-deterministic — the raw column shows the min–max faithfulness across the trials). Guardrail **ON** = what PacketIQ ships: a deterministic post-filter that redacts any ungrounded entity, so it is 100% faithful by construction on *every* model.

| Local model | Raw faithfulness (min–max) | Raw hallucinated claims | Guarded faithfulness | Guarded hallucinated |
|---|--:|--:|--:|--:|
| `llama3.1:8b` | 69.0–93.3% | 26 | 100.0% | 0 |
| `llama3.2:3b` | 15.0–20.0% | 55 | 100.0% | 0 |
| `qwen2.5:7b-instruct` | 33.3–94.9% | 14 | 100.0% | 0 |

**Reading it.** Across the raw trials the local models produced **95 hallucinated claim(s)** in total — invented MITRE techniques or CVEs not in the evidence — and the exact count wobbles between runs because the models are non-deterministic. With the guardrail on, every model is at 100% with **0** hallucinated claims: the filter removes each ungrounded entity identically regardless of which model produced the prose. That model-independence is the generalisation claim.

Reproduce with `tools/ablation.py`.
