"""
Holds the packaging files to the promises they make about each other.

Three of those promises lived only as prose comments, and prose does not fail a
build:

  1. requirements.txt calls itself "kept in lockstep with pyproject.toml
     [project.dependencies]". Nothing checked it, so a dependency added to one file
     could quietly miss the other and the two install paths would drift apart.

  2. pyproject advertises `requires-python` and a list of "Programming Language ::
     Python :: X.Y" classifiers, while the CI matrix decides what is really tested.
     A version in one and not the other is either an untested promise to users or a
     guarantee nobody is claiming.

  3. The workflow may only invoke tooling the dev extra installs. This one is a
     regression test with a story: `types-requests` was absent, and because mypy 2.x
     requires Python >=3.10, the then-supported 3.9 leg resolved to mypy 1.x — which,
     unlike 2.x, fails on an installed-but-untyped import. One matrix leg went red
     while the other three stayed green, and the config looked fine from every 3.12
     desk. The stubs stay pinned: the failure mode outlived the 3.9 leg.
"""

import re
from pathlib import Path

import pytest
import yaml
from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
REQUIREMENTS = ROOT / "requirements.txt"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

# Commands the CI `test` job shells out to by bare name. Each must therefore be
# provided by the dev extra, because that extra is the only thing the job installs.
WORKFLOW_TOOLS = {"ruff", "mypy", "pytest"}


def _load_pyproject() -> dict:
    """Parse pyproject with the stdlib parser packetiq/config.py also uses.

    This mirrored config.py's tomllib-or-tomli fallback until the Python floor
    reached 3.11 and made `tomllib` unconditional in both places.
    """
    import tomllib

    with open(PYPROJECT, "rb") as fh:
        return tomllib.load(fh)


PROJECT = _load_pyproject()["project"]


def _key(raw: str):
    """A comparable form of one requirement line, independent of how it was written.

    `packaging` does the normalising: it folds the name's case and separators, orders
    the version specifiers, and re-renders the environment marker with canonical
    quoting — so pyproject's `python_version < '3.11'` and requirements.txt's
    `python_version < "3.11"` compare equal instead of reporting a phantom drift.

    The *marker* is part of the key, not of the compared value. That mattered when
    four dependencies were declared twice — once with the patched floor for 3.10+,
    once with the newest release 3.9 could install — because a name-only key folded
    each pair into one entry and only the arm that came last was ever compared.
    Raising the floor to 3.11 collapsed every split, so no requirement carries a
    marker today; the key keeps the marker anyway, because the next version-split
    dependency should be compared, not silently merged.
    """
    req = Requirement(raw)
    name = re.sub(r"[-_.]+", "-", req.name).lower()
    return (name, str(req.marker or "")), (str(req.specifier), tuple(sorted(req.extras)))


def _collect(raws, where: str) -> dict:
    """Key every requirement by (name, marker), refusing to silently merge two."""
    entries: dict = {}
    for raw in raws:
        key, value = _key(raw)
        if key in entries:  # pragma: no cover - only on a real regression
            pytest.fail(f"{where} declares {key[0]} twice under the same marker "
                        f"{key[1]!r}; one of them is dead weight")
        entries[key] = value
    return entries


def _requirements_lines() -> list:
    lines = []
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        # Trailing "# CVE-..." rationales are documentation, not part of the spec.
        line = re.sub(r"\s+#.*$", "", line).strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def _requirements_txt() -> dict:
    return _collect(_requirements_lines(), "requirements.txt")


def _pyproject_runtime() -> dict:
    return _collect(PROJECT["dependencies"], "pyproject.toml")


def _dev_extra_names() -> set:
    names = set()
    for dep in PROJECT["optional-dependencies"]["dev"]:
        names.add(_key(dep)[0][0])
    return names


def _ci_matrix_versions() -> list:
    workflow = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    return [str(v) for v in workflow["jobs"]["test"]["strategy"]["matrix"]["python-version"]]


def _classifier_versions() -> list:
    prefix = "Programming Language :: Python :: "
    out = []
    for classifier in PROJECT["classifiers"]:
        if classifier.startswith(prefix):
            value = classifier[len(prefix):].strip()
            if "." in value:  # skip the bare "3"
                out.append(value)
    return out


# ── 1. requirements.txt <-> pyproject [project.dependencies] ─────────────────

def test_the_two_dependency_lists_are_not_empty():
    """A parsing slip here would make the comparison below vacuously pass."""
    assert len(_pyproject_runtime()) > 10
    assert len(_requirements_txt()) > 10


def test_requirements_txt_lists_exactly_the_pyproject_dependencies():
    pyproject = _pyproject_runtime()
    requirements = _requirements_txt()

    only_pyproject = sorted(set(pyproject) - set(requirements))
    only_requirements = sorted(set(requirements) - set(pyproject))

    problems = []
    if only_pyproject:
        problems.append(f"in pyproject but missing from requirements.txt: {only_pyproject}")
    if only_requirements:
        problems.append(f"in requirements.txt but missing from pyproject: {only_requirements}")
    if problems:  # pragma: no cover - only on a real regression
        pytest.fail("dependency lists have drifted:\n  " + "\n  ".join(problems))


def test_shared_dependencies_pin_the_same_versions_and_markers():
    pyproject = _pyproject_runtime()
    requirements = _requirements_txt()

    drift = []
    for key in sorted(set(pyproject) & set(requirements)):
        if pyproject[key] != requirements[key]:
            name, marker = key
            where = f"{name} [{marker}]" if marker else name
            drift.append(f"{where}: pyproject={pyproject[key]} requirements.txt={requirements[key]}")
    if drift:  # pragma: no cover - only on a real regression
        pytest.fail(
            "same dependency, different constraint — a security floor raised in one "
            "file and not the other is the failure this catches:\n  " + "\n  ".join(drift)
        )


# ── 2. Declared Python support <-> what CI actually runs ─────────────────────

def test_ci_matrix_is_readable_and_populated():
    versions = _ci_matrix_versions()
    assert len(versions) >= 2, f"CI matrix looks wrong: {versions}"


def test_classifiers_match_the_versions_ci_tests():
    matrix = sorted(_ci_matrix_versions())
    classifiers = sorted(_classifier_versions())
    assert classifiers == matrix, (
        f"classifiers advertise {classifiers} but CI tests {matrix} — either a version "
        "is promised to users without being tested, or tested without being advertised"
    )


def test_requires_python_floor_is_the_oldest_version_ci_tests():
    floor = PROJECT["requires-python"]
    assert floor.startswith(">="), f"unexpected requires-python form: {floor!r}"
    declared = floor[2:].strip()
    oldest = min(_ci_matrix_versions(), key=lambda v: tuple(int(p) for p in v.split(".")))
    assert declared == oldest, (
        f"requires-python promises {declared} but the oldest tested version is {oldest}"
    )


def test_the_packaged_version_matches_the_one_the_code_reports():
    """`pyproject.toml` and `packetiq.__version__` are two copies of one number.

    pip reads the first; `packetiq --version`, the report headers, the web app's
    footer and the PDF chain-of-custody block all read the second. Bump one and
    forget the other and the wheel on PyPI disagrees with the tool inside it —
    the kind of mismatch nobody notices until a bug report quotes a version that
    was never released.
    """
    from packetiq import __version__

    assert PROJECT["version"] == __version__, (
        f"pyproject.toml says {PROJECT['version']} but packetiq.__version__ is "
        f"{__version__}"
    )


# ── 3. The workflow can only run what the dev extra installs ─────────────────

def test_every_tool_the_workflow_invokes_is_in_the_dev_extra():
    dev = _dev_extra_names()
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")

    for tool in sorted(WORKFLOW_TOOLS):
        # Keeps the constant above honest: drop a tool from the workflow and this
        # fails, rather than leaving an entry here that silently guards nothing.
        assert re.search(rf"\b{re.escape(tool)}\b", workflow_text), (
            f"{tool} is listed in WORKFLOW_TOOLS but no longer appears in ci.yml"
        )
        assert tool in dev, f"CI runs `{tool}` but the dev extra does not install it"


def test_request_type_stubs_ship_with_the_dev_extra():
    """Regression guard for the matrix split described in this module's docstring.

    `ignore_missing_imports` covers a module mypy cannot find. It does not cover one
    that is installed but carries no types — mypy calls that `import-untyped` and
    fails the gate on it.
    """
    assert "requests" in {_key(dep)[0][0] for dep in PROJECT["dependencies"]}
    assert "types-requests" in _dev_extra_names(), (
        "packetiq imports `requests` in several modules; without its stubs the mypy "
        "gate fails on an installed-but-untyped import"
    )


# ── 4. README <-> the code it describes ──────────────────────────────────────
#
# The headline numbers in the README are claims about the product, and until now
# nothing checked them. Two had already drifted: the detection-type count said 15
# where 18 event types are emitted, and the capability table listed neither ARP
# scanning, ARP spoofing nor the DoS-flood detector — three detectors a reader
# would conclude the tool does not have.

README = Path(__file__).resolve().parents[1] / "README.md"


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _detector_modules_emitting_events() -> set:
    """Modules under packetiq/detection that construct a DetectionEvent."""
    root = Path(__file__).resolve().parents[1] / "packetiq" / "detection"
    return {p.stem for p in root.glob("*.py")
            if re.search(r"event_type\s*=\s*EventType\.", p.read_text(encoding="utf-8"))}


def test_the_readme_detection_type_count_is_the_number_the_code_emits():
    from packetiq.detection.models import EventType

    claimed = {int(n) for n in re.findall(r"\*\*`?(\d+)`?\*\* detection types", _readme())}
    assert claimed, "the README no longer states a detection-type count"
    assert claimed == {len(EventType)}, (
        f"README claims {claimed} detection types; EventType defines {len(EventType)}"
    )


def test_every_emitted_detection_type_reaches_the_readme_table():
    """A detector nobody documents is a feature nobody knows they have."""
    from packetiq.detection.models import EventType

    readme = _readme().lower()
    # The table names detectors in prose, so match on the words that identify each
    # event type rather than on the enum spelling.
    names = {
        EventType.ARP_SCAN: "arp scan", EventType.ARP_SPOOFING: "arp spoofing",
        EventType.BRUTE_FORCE: "brute force", EventType.C2_BEACON: "c2 beacon",
        EventType.CREDENTIAL_EXPOSURE: "credential exposure", EventType.DNS_ANOMALY: "dns dga",
        EventType.DNS_TUNNELING: "dns tunneling", EventType.DOS_FLOOD: "dos flood",
        EventType.HOST_SCAN: "host scan", EventType.HTTP_ATTACK: "http attack",
        EventType.ICMP_TUNNELING: "icmp tunneling", EventType.IOC_MATCH: "ioc match",
        EventType.JA3_ANOMALY: "ja3", EventType.MALICIOUS_FILE: "file carving",
        EventType.PORT_SCAN: "port scan", EventType.PROTOCOL_MISUSE: "protocol misuse",
        EventType.SUSPICIOUS_FLAGS: "suspicious tcp flags", EventType.TLS_ANOMALY: "tls certificate",
    }
    assert set(names) == set(EventType), "a new EventType needs a row in the README table"
    missing = sorted(v for k, v in names.items() if v not in readme)
    assert not missing, f"detection types absent from the README table: {missing}"


def test_the_readme_detector_module_count_matches_the_package():
    claimed = {int(n) for n in re.findall(r"across (\d+) detector modules", _readme())}
    assert claimed == {len(_detector_modules_emitting_events())}


def test_the_readme_states_the_real_number_of_harness_guards():
    """The README said "Six rules" while conftest had seven autouse guards.

    CI's own comment and tests/test_harness_guards.py both said seven; only the
    README disagreed, and nothing checked it. The count is the whole point of
    that paragraph — it is the claim that coverage is a property of the suite
    rather than of the machine — so it gets a gate like every other figure.
    """
    conftest = (Path(__file__).parent / "conftest.py").read_text(encoding="utf-8")
    real = conftest.count("@pytest.fixture(autouse=True)")
    words = {"Five": 5, "Six": 6, "Seven": 7, "Eight": 8, "Nine": 9, "Ten": 10}
    claimed = {words[w] for w in re.findall(r"(\w+) rules are fixed in", _readme())
               if w in words}

    assert claimed, "the README no longer states how many harness rules are fixed"
    assert claimed == {real}, f"README claims {claimed}, conftest has {real}"


def test_the_readme_never_claims_more_indicators_than_the_feeds_hold():
    """The README's indicator count may only ever be at or under the real one.

    Both forms are accepted — a floor (`7,800+`) and the exact bundled total
    (`7,855`) — because the README states the exact figure now that it is quoted
    beside a screenshot of the feeds panel. The `+` is therefore optional in the
    pattern; what is not optional is the direction of the comparison, so a
    bundled snapshot that ever shrinks fails here rather than leaving the README
    overclaiming.

    Counted the way the app's own feeds panel counts: per-feed entries as
    ingested, plus the JA3 fingerprint blocklist.
    """
    from packetiq.detection.ja3 import load_blocklist
    from packetiq.enrichment.feeds import load_store

    real = sum(load_store().counts.values()) + len(load_blocklist())
    claimed = {int(n.replace(",", "")) for n in re.findall(r"`?([\d,]+)\+?`?\*{0,2}\s*(?:live )?(?:threat-intel )?indicators", _readme())}
    assert claimed, "the README no longer states an indicator count"
    for n in claimed:
        assert n <= real, f"README claims {n:,} indicators; the feeds hold {real:,}"


# ── 5. The container build <-> the files it copies ───────────────────────────
#
# The Dockerfile copied `setup.py`, which stopped existing when packaging moved
# to pyproject-only. `docker build` therefore failed on its first COPY — on the
# exact path the README tells a new user to take — and nothing in the suite
# noticed, because nothing in the suite read the Dockerfile.

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def test_every_path_the_dockerfile_copies_exists():
    root = Path(__file__).resolve().parents[1]
    missing = []
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if not line.startswith("COPY "):
            continue
        parts = line.split()[1:]          # drop COPY; last token is the destination
        for src in parts[:-1]:
            if src.startswith("--"):      # --from=, --chown= and friends
                continue
            if not (root / src).exists():
                missing.append(src)
    assert not missing, f"Dockerfile copies files that are not in the repo: {missing}"


def test_the_container_copies_every_file_pyproject_declares_as_required():
    """The reverse of the test above, which is the direction that bit.

    `pyproject.toml` declares `license-files = ["LICENSE"]` (PEP 639). The
    Dockerfile copied only `pyproject.toml`, `README.md` and the package, so
    inside the image that pattern matched nothing: setuptools printed `Pattern
    'LICENSE' did not match any files`, built the wheel with no licence metadata,
    and warned that such builds stop being supported in February 2027. Every
    local build was fine, because the repository root has the file. Only the
    container was wrong, and only a test that reads both files can say so.
    """
    root = Path(__file__).resolve().parents[1]
    declared = re.findall(r'license-files\s*=\s*\[([^\]]*)\]', (root / "pyproject.toml").read_text(encoding="utf-8"))
    required = [p.strip().strip('"\'') for group in declared for p in group.split(",") if p.strip()]
    assert required, "pyproject no longer declares license-files; drop this test with it"

    copied = set()
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("COPY "):
            copied.update(line.split()[1:-1])

    missing = [name for name in required if name not in copied]
    assert not missing, (
        f"pyproject requires {missing} but the Dockerfile never copies it into the "
        "build context, so the image's wheel is built without it"
    )


def test_the_container_does_not_install_the_package_editable():
    """An editable install is silently skipped by some Python 3.12+ builds, which
    leaves the image without the `packetiq` entry point its ENTRYPOINT invokes —
    the same trap `PacketIQ.bat` and `PacketIQ.command` already avoid."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "pip install" in text
    assert " -e ." not in text and "--editable" not in text
