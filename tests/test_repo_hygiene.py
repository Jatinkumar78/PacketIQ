"""No file that ships may be a contiguous copy of a malware signature.

Microsoft Defender quarantined the GitHub source download —
`PacketIQ-main.zip`, straight from codeload.github.com — as
`Backdoor:PHP/Remoteshell.F`, naming `tests/test_yara.py`. It was a false
positive in the strict sense (a Python byte-literal that is never executed,
feeding PacketIQ's *own* webshell detector) and completely fatal in the
practical one: the archive was removed before anyone could unzip it, and on a
managed university or corporate machine that outcome is silent and final.

A defensive tool has an unavoidable amount of this: rules must contain what they
detect, and their tests must contain what the rules match. What is avoidable is
the *contiguous* form. The rule patterns are fragments (`eval($_POST` with no
`<?php`) or hex byte sequences; the test fixtures are assembled at runtime. Both
detect and test exactly what they did before.

This is the regression guard, and it deliberately checks what GitHub actually
serves — the tracked file set — rather than the working tree, because an ignored
scratch file is not what gets downloaded. Run it before a demo; a failure here
means someone's download is about to be eaten.
"""

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Assembled the same way the fixtures are, for the same reason — this file must
# not become the thing it is guarding against.
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EIC~AR-STANDARD-ANTIVIRUS-TE~ST-FILE!$H+H*".replace("~", "")

# A PHP open tag followed closely by an exec sink: the shape that reads as a
# runnable webshell rather than as a detection pattern. The sinks on their own
# are fine and are exactly what the bundled YARA rule looks for.
_SINK = r"(?:ev al\(\$_(?:POST|GET|REQUEST)|sys tem\(\$_(?:POST|GET|REQUEST)|shell_ exec\(|pass thru\()".replace(" ", "")
WEBSHELL_RE = re.compile(r"<\?(?:php|=)\b.{0,200}?" + _SINK, re.IGNORECASE | re.DOTALL)

# Binary and generated files a scanner treats as data, plus this guard itself.
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".ico", ".woff", ".woff2",
                 ".zip", ".gz", ".pcap", ".pcapng", ".docx", ".xlsx"}
SKIP_NAMES = {"test_repo_hygiene.py"}


def _tracked_files() -> list:
    """Exactly what a `git archive` / GitHub zip contains."""
    try:
        out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                             capture_output=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - git is always present in CI
        pytest.skip("git not available to enumerate the shipped file set")
    return [ROOT / name for name in out.decode("utf-8", "replace").split("\0") if name]


def _scannable() -> list:
    files = []
    for path in _tracked_files():
        if path.suffix.lower() in SKIP_SUFFIXES or path.name in SKIP_NAMES:
            continue
        if not path.is_file():
            continue
        files.append(path)
    return files


def test_the_shipped_file_set_is_not_empty():
    """A guard that silently scans nothing is worse than no guard."""
    files = _scannable()
    assert len(files) > 100, f"only {len(files)} files enumerated — is this a git checkout?"
    assert any(f.name == "test_yara.py" for f in files), "the file that caused this is not being scanned"


def test_no_shipped_file_contains_the_eicar_string():
    """Every anti-virus product on earth detects EICAR — that is its whole
    purpose — so a literal copy anywhere in the archive quarantines the archive."""
    hits = [str(p.relative_to(ROOT)) for p in _scannable()
            if EICAR in p.read_text(encoding="utf-8", errors="replace")]
    assert not hits, (
        f"EICAR appears verbatim in {hits}. Assemble it at runtime (see "
        "tests/test_yara.py) or write it as bytes (see the bundled .yar rules); "
        "a scanner will otherwise delete the download.")


def test_no_shipped_file_contains_a_complete_webshell():
    """A `<?php` tag near an exec sink is what Defender matched. Detection
    patterns are fragments and stay fragments; fixtures are assembled at runtime."""
    hits = []
    for p in _scannable():
        m = WEBSHELL_RE.search(p.read_text(encoding="utf-8", errors="replace"))
        if m:
            hits.append(f"{p.relative_to(ROOT)}: {m.group(0)[:60]!r}")
    assert not hits, (
        "a runnable-looking webshell is present verbatim in: " + "; ".join(hits) +
        ". Split it with the `~` marker the YARA fixtures use.")


def test_the_guard_actually_matches_what_defender_matched():
    """Proof the pattern above has teeth: the exact literal that got the download
    quarantined must be something this test would have caught."""
    original = "<?php ev~al($_POST['x']); ?>".replace("~", "")
    assert WEBSHELL_RE.search(original)
    assert WEBSHELL_RE.search("<?php sys~tem($_REQUEST['cmd']); ?>".replace("~", ""))
    # …and that it does not fire on the detection patterns themselves, which are
    # fragments with no PHP tag and must stay in the rule file.
    assert not WEBSHELL_RE.search('$php1 = "eval($_POST" nocase')
    assert not WEBSHELL_RE.search("<?php phpinfo(); ?>")
