#!/usr/bin/env python3
"""
Copilot faithfulness / hallucination evaluation harness.

PacketIQ's *evidence* (detections, IPs, CVEs, IOCs) is deterministic and real —
it comes from the detectors, NVD and the threat-intel feeds, never from the LLM.
The AI copilot is only an *explanation layer* on top of that evidence. The one
place a hallucination could enter is the copilot's prose. This harness measures
exactly that, quantitatively and without a human judge:

    faithfulness = fraction of the specific factual claims the copilot makes
                   (IP addresses, MITRE technique IDs, CVE IDs) that are actually
                   present in the analysis context it was given.

Any claimed entity that is NOT in the context is counted as a hallucination.
The metric is deterministic (regex entity extraction against the exact context
string the model saw) so the numbers are honest and reproducible — the kind of
groundedness evaluation a dissertation examiner asks for.

It runs the *real* copilot code path: the same context builder the CLI uses and
the same provider fallback (`_collect_ai_with_fallback`) the web app uses, so it
measures the shipping product, not a mock. Point it at a local Ollama model to
run the whole evaluation offline.

Usage
-----
  # Built-in synthetic capture (crafted traffic with known ground truth):
  python tools/eval_copilot.py --demo

  # A capture of your own, or a whole labeled manifest (same format as validate.py):
  python tools/eval_copilot.py --pcap suspicious.pcap
  python tools/eval_copilot.py --manifest dataset/labels.json

  # Pin the provider (default: whatever is configured, cloud key or local Ollama):
  python tools/eval_copilot.py --demo --provider ollama
  python tools/eval_copilot.py --demo --json results.json --markdown eval.md

Scoring covers IPs, MITRE technique IDs and CVE IDs — unambiguous entity types
where a hallucination is clear-cut. Free-text domains are deliberately excluded
from scoring because natural-language tokenisation makes them noisy to attribute.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# allow running from a source checkout without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from packetiq.copilot.context_builder import build_context  # noqa: E402
from packetiq.correlation.engine import CorrelationEngine  # noqa: E402
from packetiq.detection.engine import DetectionEngine  # noqa: E402
from packetiq.extractor.data_extractor import DataExtractor  # noqa: E402
from packetiq.parser.pcap_parser import PCAPParser  # noqa: E402

# ── Entity extraction (the "specific factual claims" we score) ───────────────
_IP_RE   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_CVE_RE  = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _ips(text: str) -> set:
    out = set()
    for m in _IP_RE.findall(text or ""):
        try:
            ipaddress.ip_address(m)   # drop dotted numbers that aren't valid IPs (octet > 255)
            out.add(m)
        except ValueError:
            pass
    return out


def _techs(text: str) -> set:
    return {t.upper() for t in _TECH_RE.findall(text or "")}


def _cves(text: str) -> set:
    return {c.upper() for c in _CVE_RE.findall(text or "")}


def extract_entities(text: str) -> dict:
    """Pull the scored entity types out of any text (context or answer)."""
    return {"ips": _ips(text), "techniques": _techs(text), "cves": _cves(text)}


# ── Scoring ──────────────────────────────────────────────────────────────────
_KINDS = ("ips", "techniques", "cves")


def score_answer(context_entities: dict, answer: str, question_entities: dict = None) -> dict:
    """Score one answer's faithfulness. An entity in the answer is *grounded* if it
    appears in the analysis context OR in the analyst's question (the model may
    legitimately reference what it was given or asked about). A *hallucination* is a
    specific entity the model introduced that appears in neither — genuinely invented."""
    claimed = extract_entities(answer)
    question_entities = question_entities or {}
    detail: dict = {}
    hallucinations: dict = {}
    claimed_total = grounded_total = 0
    for k in _KINDS:
        c = claimed[k]
        allowed = context_entities.get(k, set()) | question_entities.get(k, set())
        halluc = sorted(c - allowed)
        grounded = len(c) - len(halluc)
        detail[k] = {"claimed": len(c), "grounded": grounded, "hallucinated": len(halluc)}
        hallucinations[k] = halluc
        claimed_total += len(c)
        grounded_total += grounded
    # No specific claim ⇒ nothing to hallucinate ⇒ trivially faithful (1.0).
    faithfulness = (grounded_total / claimed_total) if claimed_total else 1.0
    return {
        "faithfulness":  faithfulness,
        "claimed":       claimed_total,
        "grounded":      grounded_total,
        "hallucinated":  sum(len(v) for v in hallucinations.values()),
        "detail":        detail,
        "hallucinations": {k: v for k, v in hallucinations.items() if v},
    }


# ── The fixed question battery (deterministic, reproducible) ─────────────────
# The last item is an abstention probe: it asks for CVEs without naming one, so a
# faithful model names none when the evidence has no CVE, and any CVE it emits is
# its own invention — caught as a hallucination.
QUESTIONS = [
    ("summary", "Give a concise executive summary of the threats found in this capture."),
    ("iocs",    "List every indicator of compromise (attacker IP addresses and ports) "
                "found in this capture."),
    ("mitre",   "List the MITRE ATT&CK technique IDs (Txxxx) that are evidenced in this capture."),
    ("actors",  "Which external IP addresses are the attackers here, and what is each doing?"),
    # Non-seeding abstention probe: names no specific CVE, so any CVE the model
    # emits is its own invention unless the evidence genuinely supports it.
    ("probe_cve", "List any CVEs that the evidence in this capture proves are being "
                  "exploited. If the evidence does not establish a specific CVE, say so "
                  "and name none."),
]


# ── Analysis (the real pipeline → the real copilot context) ──────────────────
@dataclass
class CaptureCtx:
    name:    str
    context: str
    events:  list = field(default_factory=list)
    risk_score: int = 0
    risk_tier:  str = "UNKNOWN"


def analyze(pcap_path: str) -> CaptureCtx:
    """Parse → extract → detect → correlate → build the exact copilot context."""
    parser = PCAPParser(str(pcap_path))
    extractor = DataExtractor()
    for rec in parser.stream():
        extractor.feed(rec)
    result = extractor.finalize()
    events, risk, _fps = DetectionEngine().run(result, str(pcap_path))
    chains = CorrelationEngine().correlate(events)
    file_meta = parser.file_summary()
    context = build_context(file_meta, result, events, chains, risk.score, risk.tier)
    return CaptureCtx(Path(pcap_path).name, context, events, risk.score, risk.tier)


# ── Provider wiring (reuse the shipping copilot path) ────────────────────────
def make_answer_fn(provider: str = "auto"):
    """Return (answer_fn, provider_name) using the web app's real fallback path.
    Raises RuntimeError if no provider is available."""
    import asyncio

    from packetiq.webapp import app as webapp

    if provider and provider not in ("auto", ""):
        webapp._AI_FORCED["provider"] = provider
    active = webapp._detect_provider()
    if not active["provider"]:
        raise RuntimeError(
            "No AI provider available. Set GEMINI_API_KEY/GROQ_API_KEY, or run a "
            "local model with Ollama (`ollama serve` after `ollama pull llama3.1:8b`)."
        )

    system = webapp._CHAT_SYSTEM

    def answer(context: str, question: str) -> str:
        return asyncio.run(webapp._collect_ai_with_fallback(
            system, context, [{"role": "user", "content": question}]))

    return answer, f"{active['provider']}:{active['model']}"


# ── Evaluation loop ──────────────────────────────────────────────────────────
def evaluate(captures: list, answer_fn, questions=QUESTIONS, verbose: bool = False) -> dict:
    rows = []
    for cap in captures:
        ctx_ent = extract_entities(cap.context)
        for qid, q in questions:
            try:
                ans = answer_fn(cap.context, q)
            except Exception as exc:  # noqa: BLE001
                print(f"  ! {cap.name}/{qid}: answer failed: {exc}", file=sys.stderr)
                continue
            s = score_answer(ctx_ent, ans, extract_entities(q))
            s.update(capture=cap.name, question=qid, answer=ans)
            rows.append(s)
            if verbose and s["hallucinated"]:
                print(f"  ⚠ {cap.name}/{qid}: hallucinated {s['hallucinations']}", file=sys.stderr)

    claimed = sum(r["claimed"] for r in rows)
    grounded = sum(r["grounded"] for r in rows)
    hallucinated = sum(r["hallucinated"] for r in rows)
    overall = (grounded / claimed) if claimed else 1.0
    clean = sum(1 for r in rows if r["hallucinated"] == 0)
    return {
        "rows": rows,
        "summary": {
            "answers":          len(rows),
            "clean_answers":    clean,
            "claims_total":     claimed,
            "claims_grounded":  grounded,
            "claims_hallucinated": hallucinated,
            "faithfulness":     overall,
        },
    }


# ── Reporting ────────────────────────────────────────────────────────────────
def print_report(result: dict, provider: str) -> None:
    rows = result["rows"]
    s = result["summary"]
    print(f"\nProvider: {provider}")
    print(f"{'capture':<24} {'question':<10} {'claims':>6} {'grnd':>5} {'hall':>5} {'faithful':>9}")
    print("-" * 66)
    for r in rows:
        print(f"{r['capture'][:23]:<24} {r['question']:<10} "
              f"{r['claimed']:>6} {r['grounded']:>5} {r['hallucinated']:>5} "
              f"{r['faithfulness']*100:>8.1f}%")
    print("-" * 66)
    print("AGGREGATE")
    print(f"  Answers evaluated     : {s['answers']}")
    print(f"  Hallucination-free    : {s['clean_answers']}/{s['answers']} "
          f"({(s['clean_answers']/s['answers']*100 if s['answers'] else 100):.0f}%)")
    print(f"  Specific claims       : {s['claims_total']} "
          f"({s['claims_grounded']} grounded, {s['claims_hallucinated']} hallucinated)")
    print(f"  FAITHFULNESS          : {s['faithfulness']*100:.1f}%")
    if s["claims_hallucinated"]:
        print("\n  Hallucinated claims (not in evidence):")
        for r in rows:
            if r["hallucinated"]:
                print(f"    {r['capture']}/{r['question']}: {r['hallucinations']}")


def to_markdown(result: dict, provider: str) -> str:
    s = result["summary"]
    out = ["# PacketIQ Copilot — Faithfulness Evaluation", "",
           f"**Provider:** `{provider}`  ",
           f"**Answers evaluated:** {s['answers']}  ",
           f"**Hallucination-free answers:** {s['clean_answers']}/{s['answers']}  ",
           f"**Specific claims:** {s['claims_total']} "
           f"({s['claims_grounded']} grounded, {s['claims_hallucinated']} hallucinated)  ",
           f"**Faithfulness:** {s['faithfulness']*100:.1f}%", "",
           "Faithfulness = share of the copilot's specific claims (IPs, MITRE "
           "technique IDs, CVE IDs) that are present in the evidence it was given. "
           "Higher is better; a hallucination is any claimed entity absent from the "
           "analysis context.", "",
           "| Capture | Question | Claims | Grounded | Hallucinated | Faithfulness |",
           "|---|---|--:|--:|--:|--:|"]
    for r in result["rows"]:
        out.append(f"| {r['capture']} | {r['question']} | {r['claimed']} | "
                   f"{r['grounded']} | {r['hallucinated']} | {r['faithfulness']*100:.1f}% |")
    return "\n".join(out) + "\n"


# ── Demo capture (crafted traffic, known ground truth) ───────────────────────
def build_demo_capture(tmp: Path) -> Path:
    """A small malicious capture with real, verifiable indicators: an external
    SSH brute-force, an HTTP SQL-injection attempt, and cleartext FTP creds.
    Deliberately contains NO Log4Shell, so the probe_cve question is a genuine
    absent-entity test."""
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    eth = {"src": "00:11:22:33:44:55", "dst": "66:77:88:99:aa:bb"}  # explicit → no MAC lookup
    pkts = []
    t = 1700000000.0
    attacker = "45.33.32.156"
    victim = "192.168.1.50"
    # SSH brute force: many SYNs to :22 from one external host
    for i in range(40):
        pkts.append(Ether(**eth) / IP(src=attacker, dst=victim) /
                    TCP(sport=50000 + i, dport=22, flags="S"))
    # HTTP SQL injection attempt (HTTP_ATTACK)
    sqli = (b"GET /login.php?user=admin'%20OR%20'1'='1 HTTP/1.1\r\n"
            b"Host: 192.168.1.50\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
    pkts.append(Ether(**eth) / IP(src=attacker, dst=victim) /
                TCP(sport=51000, dport=80, flags="PA") / Raw(load=sqli))
    # Cleartext FTP credentials (CREDENTIAL_EXPOSURE)
    pkts.append(Ether(**eth) / IP(src=victim, dst="193.122.6.168") /
                TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"USER admin\r\n"))
    pkts.append(Ether(**eth) / IP(src=victim, dst="193.122.6.168") /
                TCP(sport=53500, dport=21, flags="PA") / Raw(load=b"PASS s3cr3t\r\n"))
    for i, p in enumerate(pkts):
        p.time = t + i
    out = tmp / "demo_malicious.pcap"
    wrpcap(str(out), pkts)
    return out


def _captures_from_args(args) -> list:
    if args.demo:
        import tempfile
        tmp = Path(tempfile.mkdtemp(prefix="packetiq_evalcopilot_"))
        return [analyze(str(build_demo_capture(tmp)))]
    if args.pcap:
        return [analyze(args.pcap)]
    if args.manifest:
        man = json.loads(Path(args.manifest).read_text())
        base = Path(man.get("base_dir", Path(args.manifest).parent))
        if not base.is_absolute():
            base = Path(args.manifest).parent / base
        caps = []
        for c in man.get("captures", []):
            p = base / c["file"]
            if p.is_file():
                caps.append(analyze(str(p)))
            else:
                print(f"  (missing, skipped) {c['file']}", file=sys.stderr)
        return caps
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description="PacketIQ copilot faithfulness evaluation")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--demo", action="store_true", help="Use a built-in crafted capture")
    src.add_argument("--pcap", help="Evaluate on a single PCAP")
    src.add_argument("--manifest", help="Evaluate on a labeled manifest (validate.py format)")
    ap.add_argument("--provider", default="auto",
                    help="auto | gemini | groq | anthropic | ollama (default: auto)")
    ap.add_argument("--json", dest="json_out", help="Write full results to a JSON file")
    ap.add_argument("--markdown", dest="md_out", help="Write a Markdown table")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    try:
        answer_fn, provider = make_answer_fn(args.provider)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    captures = _captures_from_args(args)
    if not captures:
        print("No captures to evaluate.", file=sys.stderr)
        return 1

    print(f"Evaluating {len(captures)} capture(s) × {len(QUESTIONS)} questions "
          f"via {provider} …", file=sys.stderr)
    result = evaluate(captures, answer_fn, verbose=args.verbose)
    print_report(result, provider)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"provider": provider, **result}, indent=2))
        print(f"\nJSON written to {args.json_out}", file=sys.stderr)
    if args.md_out:
        Path(args.md_out).write_text(to_markdown(result, provider))
        print(f"Markdown written to {args.md_out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
