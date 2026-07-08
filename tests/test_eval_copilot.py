"""The copilot faithfulness harness (tools/eval_copilot.py): entity extraction,
scoring, question-echo handling, and the real analysis path — all offline, no LLM."""

import sys
import tempfile
from pathlib import Path

# tools/ isn't a package; make eval_copilot importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import eval_copilot as ec  # noqa: E402

# ── entity extraction ────────────────────────────────────────────────────────

def test_extract_entities():
    e = ec.extract_entities("Attacker 45.33.32.156 used T1110 and CVE-2021-44228 on 192.168.1.50.")
    assert e["ips"] == {"45.33.32.156", "192.168.1.50"}
    assert e["techniques"] == {"T1110"}
    assert e["cves"] == {"CVE-2021-44228"}


def test_extract_ignores_non_ip_dotted_numbers():
    # version-like tokens with an octet > 255 must not be read as IPs
    e = ec.extract_entities("Running nginx 1.999.0.1 build 300.1.1.1")
    assert "300.1.1.1" not in e["ips"]


# ── scoring ──────────────────────────────────────────────────────────────────

def test_grounded_answer_scores_full():
    ctx = ec.extract_entities("Host 45.33.32.156 -> 192.168.1.50, technique T1110.")
    s = ec.score_answer(ctx, "The attacker 45.33.32.156 performed T1110 brute force.")
    assert s["faithfulness"] == 1.0
    assert s["hallucinated"] == 0


def test_hallucinated_entities_are_caught():
    ctx = ec.extract_entities("Host 45.33.32.156 -> 192.168.1.50.")
    s = ec.score_answer(ctx, "Attacker 8.8.8.8 exploited CVE-2021-44228 via T1499.")
    assert s["hallucinated"] == 3
    assert s["faithfulness"] == 0.0
    assert "8.8.8.8" in s["hallucinations"]["ips"]
    assert "CVE-2021-44228" in s["hallucinations"]["cves"]


def test_question_echo_is_not_a_hallucination():
    # If the analyst's question names an entity, echoing it (e.g. to deny it) is
    # not an invention — it must not be scored as a hallucination.
    ctx = ec.extract_entities("Only FTP creds and SSH brute force here.")
    q = ec.extract_entities("Is there evidence of CVE-2021-44228?")
    s = ec.score_answer(ctx, "No, CVE-2021-44228 is not present in this capture.", q)
    assert s["hallucinated"] == 0
    assert s["faithfulness"] == 1.0


def test_no_claims_is_trivially_faithful():
    ctx = ec.extract_entities("Host 45.33.32.156.")
    s = ec.score_answer(ctx, "No specific indicators were established by the evidence.")
    assert s["faithfulness"] == 1.0
    assert s["claimed"] == 0


# ── real analysis path (deterministic, no LLM) ───────────────────────────────

def test_analyze_demo_capture_grounds_real_entities():
    tmp = Path(tempfile.mkdtemp(prefix="eval_test_"))
    pcap = ec.build_demo_capture(tmp)
    cap = ec.analyze(str(pcap))
    ent = ec.extract_entities(cap.context)
    # the crafted attacker IP and at least one MITRE technique must be in context
    assert "45.33.32.156" in ent["ips"]
    assert any(t.startswith("T11") for t in ent["techniques"])
    # demo deliberately has no CVE evidence → CVE probe can't be grounded by invention
    assert cap.context  # non-empty context built by the real context_builder


def test_evaluate_with_injected_answer_fn():
    tmp = Path(tempfile.mkdtemp(prefix="eval_test2_"))
    cap = ec.analyze(str(ec.build_demo_capture(tmp)))
    ip = "45.33.32.156"

    def fake_answer(context, question):
        # a faithful answer that only references a real in-context IP
        return f"The attacker {ip} is the source of the activity."

    res = ec.evaluate([cap], fake_answer, questions=[("q", "who is the attacker?")])
    assert res["summary"]["faithfulness"] == 1.0
    assert res["summary"]["claims_hallucinated"] == 0
