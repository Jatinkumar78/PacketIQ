"""The detection precision/recall harness (tools/validate.py): the synthetic
fixture suite must trigger each targeted detector and keep benign traffic clean."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import validate as v  # noqa: E402


def _events(path):
    events, _risk = v._analyze(str(path))
    return {e.event_type.value for e in events}


def test_suite_detectors_fire_and_benign_is_clean():
    tmp = Path(tempfile.mkdtemp(prefix="validate_suite_test_"))
    manifest = v._build_suite(tmp)
    by_file = {c["file"]: c for c in manifest["captures"]}

    # each malicious fixture must produce its expected detector event type
    for fname, cap in by_file.items():
        for expected in cap.get("expect", []):
            assert expected in _events(tmp / fname), f"{expected} not fired on {fname}"

    # benign fixtures must not cross the MEDIUM flag threshold
    from packetiq.detection.models import Severity
    for fname, cap in by_file.items():
        if cap.get("malicious"):
            continue
        events, _ = v._analyze(str(tmp / fname))
        assert not v._flagged(events, Severity.MEDIUM), f"false positive on {fname}"


def test_markdown_report_is_written():
    tmp = Path(tempfile.mkdtemp(prefix="validate_md_test_"))
    manifest = v._build_suite(tmp)
    md = tmp / "report.md"
    rc = v.run(manifest, tmp, md_out=str(md))
    assert rc == 0
    text = md.read_text()
    assert "Precision" in text and "Recall" in text and "Per-detector recall" in text
