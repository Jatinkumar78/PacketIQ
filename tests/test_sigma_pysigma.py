"""
Validate that generated SIGMA rules parse with pySigma (the real SIGMA toolkit),
not just as YAML. Skips gracefully if pySigma isn't installed.
"""

import pytest

from packetiq.sigma.generator import SigmaGenerator

pysigma = pytest.importorskip("sigma.collection")


def test_generated_rules_parse_with_pysigma(pipeline):
    from sigma.collection import SigmaCollection

    rules = SigmaGenerator().generate(pipeline["events"], pipeline["chains"])
    assert rules, "expected at least one SIGMA rule"
    failures = []
    for r in rules:
        try:
            coll = SigmaCollection.from_yaml(r.raw_yaml)
            assert len(coll.rules) == 1
        except Exception as exc:  # noqa: BLE001
            failures.append((r.title, str(exc)[:160]))
    assert not failures, "pySigma rejected rules:\n" + "\n".join(f"  {t}: {e}" for t, e in failures)
