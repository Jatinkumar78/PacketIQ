"""
Holds the published documentation to the repository it describes.

Every claim in this project's code is gated by a test, and the documents were the
one surface where that was not true. Three defects found at once, all of which a
reader hits before they ever run the tool:

  1. **The documented clone command did not work.** The README told a new user to
     run `git clone https://github.com/PacketIQ/PacketIQ.git`, which answers
     `remote: Repository not found.` The real remote is `Jatinkumar78/PacketIQ`.

  2. **Two links pointed at a stranger.** `github.com/PacketIQ` is an unrelated
     real person's account, and the README's GitHub button, the hero banner link,
     the `[project.urls] Homepage` that PyPI renders in its sidebar, and the
     version line the CLI prints on every run all pointed at it.

  3. **`pyproject.toml`'s Changelog URL was missing the repository segment** and
     returned 404, so a PyPI release would have shipped a dead sidebar link.

None of that was detectable from a desk, because a wrong URL looks exactly like a
right one. So the shape of every repository URL is asserted here, and every
relative link is resolved against the filesystem.

What this file deliberately does **not** do is make an HTTP request. The suite is
sealed off from the network by the autouse guards in conftest (a test cannot open
a socket at all), and link liveness is a property of the internet rather than of
this commit. Reachability is checked by hand when the documents change; what is
checked here is every claim that *can* be verified offline, which is the repo
coordinates and every path.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# The repository this project actually lives in, and the account that owns it.
# `git remote get-url origin` is the authority; it is written out rather than
# shelled out for so the test works in an exported tarball with no git metadata.
OWNER = "Jatinkumar78"
REPO_URL = f"https://github.com/{OWNER}/PacketIQ"

# The account the documents used to point at. It is a real, unrelated user, which
# is what makes this worth a standing gate rather than a one-time fix: the string
# is a plausible-looking typo for this project's own name.
WRONG_ACCOUNT = re.compile(r"github\.com/PacketIQ(?![A-Za-z0-9-])")

# Files whose links are checked. Everything tracked and human-readable, plus the
# packaging and workflow files that carry URLs of their own.
DOC_SUFFIXES = {".md", ".cff"}
SKIP_DIRS = {".git", ".venv", "venv", "build", "dist", "node_modules",
             "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
             "htmlcov", "packetiq.egg-info", ".claude"}


def _walk(suffixes: set, extra: tuple = ()) -> list:
    out = [p for p in ROOT.rglob("*")
           if p.suffix in suffixes
           and not any(part in SKIP_DIRS for part in p.relative_to(ROOT).parts)]
    out += [ROOT / name for name in extra]
    return sorted(p for p in out if p.is_file())


DOCS = _walk(DOC_SUFFIXES)
URL_BEARING = DOCS + [ROOT / "pyproject.toml",
                      ROOT / "packetiq" / "display" / "terminal.py",
                      ROOT / ".github" / "dependabot.yml",
                      ROOT / ".github" / "CODEOWNERS",
                      ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"]

README = ROOT / "README.md"


def _text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _slug(heading: str) -> str:
    """Reproduce github-slugger, which is what GitHub anchors a heading with.

    The order matters and is easy to get wrong: it lowercases, **trims, then**
    strips punctuation and emoji, and only then turns spaces into hyphens. So
    `## 🚀 Quick Start` keeps the space the emoji left behind and becomes
    `-quick-start`, with a leading hyphen. Trimming after the strip instead
    yields `quick-start` and declares all nine of the README's working
    navigation links broken.
    """
    s = heading.lower().strip()
    s = re.sub(r"[^\w\s\-]", "", s, flags=re.UNICODE)
    return s.replace(" ", "-")


def _headings(text: str) -> set:
    return {_slug(m.group(1))
            for m in re.finditer(r"^#{1,6}\s+(.*)$", text, re.MULTILINE)}


def _links(text: str) -> list:
    """Markdown link/image targets plus HTML src/href attributes."""
    found = [m.group(1) for m in re.finditer(r"\]\(([^)\s]+)\)", text)]
    found += [m.group(1) for m in re.finditer(r'(?:src|href)="([^"]+)"', text)]
    return found


# ── 1. The repository coordinates ────────────────────────────────────────────


@pytest.mark.parametrize("path", URL_BEARING, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_file_points_at_the_wrong_github_account(path):
    """`github.com/PacketIQ` belongs to someone else. Nothing here may link it."""
    hits = [line for line in _text(path).splitlines() if WRONG_ACCOUNT.search(line)]
    assert not hits, (
        f"{path.relative_to(ROOT)} points at github.com/PacketIQ, which is an "
        f"unrelated account; the repository is {REPO_URL}\n  " + "\n  ".join(hits)
    )


def test_every_github_url_in_the_docs_names_this_repository():
    """A github.com URL may only reference this project, GitHub itself, or a
    named third-party project. Anything else is a typo waiting to be published."""
    allowed_prefixes = (
        f"https://github.com/{OWNER}",
        "https://github.com/user-attachments/",       # README hero image upload
        "https://github.com/SigmaHQ/",                # the SIGMA specification
        "https://github.com/markedjs/",               # vendored front-end library
        "https://github.com/kurkle/",                 # vendored front-end library
    )
    bad = []
    for path in URL_BEARING:
        for url in re.findall(r"https://github\.com/[^\s\"'()<>\]]+", _text(path)):
            if not url.startswith(allowed_prefixes):
                bad.append(f"{path.relative_to(ROOT)}: {url}")
    assert not bad, "unexpected github.com URLs:\n  " + "\n  ".join(bad)


def test_the_clone_command_the_readme_documents_is_this_repository():
    """The published command answered "Repository not found" for every reader."""
    clones = re.findall(r"git clone (\S+)", _text(README))
    assert clones, "the README no longer documents a clone command"
    for url in clones:
        assert url == f"{REPO_URL}.git", f"README clones {url}"


def test_pyproject_publishes_a_complete_set_of_correct_urls():
    """`[project.urls]` becomes the sidebar on the PyPI project page, so a wrong
    entry there is published rather than merely wrong in a file."""
    import tomllib

    with open(ROOT / "pyproject.toml", "rb") as fh:
        urls = tomllib.load(fh)["project"]["urls"]

    for key in ("Homepage", "Repository", "Issues", "Changelog", "Security"):
        assert key in urls, f"[project.urls] is missing {key}"
        assert urls[key].startswith(REPO_URL), f"{key} = {urls[key]}"

    # The old Changelog URL was https://github.com/PacketIQ/blob/main/CHANGELOG.md,
    # which omits the repository segment entirely and 404s.
    assert urls["Changelog"] == f"{REPO_URL}/blob/main/CHANGELOG.md"


# ── 2. Every relative link resolves ──────────────────────────────────────────


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_relative_link_in_the_docs_resolves_to_a_real_path(path):
    text = _text(path)
    missing = []
    for target in _links(text):
        if target.startswith(("http://", "https://", "mailto:", "#", "data:")):
            continue
        rel = target.split("#")[0].split("?")[0]
        if not rel:
            continue
        if not (path.parent / rel).exists():
            missing.append(target)
    assert not missing, f"{path.relative_to(ROOT)} links to missing paths: {missing}"


@pytest.mark.parametrize("path", DOCS, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_same_page_anchor_matches_a_heading(path):
    """A broken in-page anchor scrolls nowhere and reports no error, which is why
    the README's navigation row could be wrong without anyone noticing."""
    text = _text(path)
    heads = _headings(text)
    broken = [t for t in _links(text)
              if t.startswith("#") and t[1:] and t[1:] not in heads]
    assert not broken, f"{path.relative_to(ROOT)} has dead anchors: {broken}"


def test_cross_file_anchors_match_a_heading_in_the_file_they_name():
    """`SUPPORT.md` links into README sections, so the anchor has to exist there."""
    broken = []
    for path in DOCS:
        for target in _links(_text(path)):
            if target.startswith(("http", "mailto:", "#")) or "#" not in target:
                continue
            rel, _, frag = target.partition("#")
            dest = path.parent / rel
            if not frag or dest.suffix != ".md" or not dest.exists():
                continue
            if frag not in _headings(_text(dest)):
                broken.append(f"{path.relative_to(ROOT)} -> {target}")
    assert not broken, "anchors that name a missing heading:\n  " + "\n  ".join(broken)


# ── 3. The README badges are buttons, not decoration ─────────────────────────


def test_every_readme_badge_is_wrapped_in_a_link():
    """All twelve badges used to be bare images: they looked like buttons, and
    clicking one did nothing. A badge that states a fact should take the reader
    to the thing that substantiates it."""
    text = _text(README)
    bare = []
    for m in re.finditer(r"(.?)!\[([^\]]*)\]\((https://img\.shields\.io[^)]+)\)(.?)",
                         text):
        before, alt, _, after = m.groups()
        if not (before == "[" and after == "]"):
            bare.append(alt or "<no alt text>")
    assert not bare, f"README badges that are not links: {bare}"


def test_the_live_ci_badge_reads_this_repositorys_workflow():
    """The badge is served from shields rather than GitHub's own endpoint so it
    can carry `for-the-badge` and match the rest of the row. It names the
    workflow file and the branch, both of which have to exist."""
    text = _text(README)
    m = re.search(r"img\.shields\.io/github/actions/workflow/status/"
                  r"([^/]+)/([^/]+)/([^?]+)\?([^)\"]*)", text)
    assert m, "the README no longer carries a live CI badge"
    owner, repo, workflow, query = m.groups()
    assert owner == OWNER and repo == "PacketIQ"
    assert (ROOT / ".github" / "workflows" / workflow).exists(), workflow
    branch = re.search(r"branch=([^&]+)", query)
    assert branch and branch.group(1) == "main"


def test_no_badge_claims_a_github_release_that_does_not_exist():
    """A `github/v/release` badge renders the words "no releases or repo not
    found" on a repository that has never tagged one, which is worse than a
    static version badge. The version badge stays static and links the changelog
    until a release is actually published."""
    assert "img.shields.io/github/v/release" not in _text(README), (
        "this repository has no published GitHub release, so the live release "
        "badge would render an error string"
    )


# ── 4. The community-health file set ─────────────────────────────────────────

COMMUNITY_FILES = [
    "README.md", "LICENSE", "SECURITY.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SUPPORT.md", "CITATION.cff",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/detection_issue.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
]


@pytest.mark.parametrize("name", COMMUNITY_FILES)
def test_the_community_health_file_exists(name):
    assert (ROOT / name).is_file(), f"{name} is missing"


@pytest.mark.parametrize("name", [
    "README.md", "LICENSE", "SECURITY.md", "CHANGELOG.md",
    "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SUPPORT.md", "CITATION.cff",
])
def test_the_sdist_carries_the_file(name):
    """`python -m build` copies exactly what MANIFEST.in lists. The manifest named
    only README and LICENSE, so a published tarball would have shipped without
    the changelog, the security policy or the citation metadata."""
    manifest = _text(ROOT / "MANIFEST.in")
    assert f"include {name}" in manifest, f"MANIFEST.in does not include {name}"


def test_the_issue_templates_are_valid_github_forms():
    """GitHub silently falls back to a blank issue when a form fails to parse, so
    a typo here removes the template rather than reporting an error."""
    import yaml

    valid = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
    forms = sorted((ROOT / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))
    forms = [f for f in forms if f.name != "config.yml"]
    assert forms, "no issue forms found"

    for f in forms:
        doc = yaml.safe_load(_text(f))
        assert isinstance(doc.get("name"), str), f"{f.name}: no name"
        assert isinstance(doc.get("description"), str), f"{f.name}: no description"
        for i, element in enumerate(doc["body"]):
            kind = element.get("type")
            assert kind in valid, f"{f.name} body[{i}]: bad type {kind!r}"
            # A markdown block carries no id, and every other kind needs one for
            # its answer to be identifiable in the filed issue.
            assert ("id" in element) is (kind != "markdown"), \
                f"{f.name} body[{i}]: id present for markdown, or absent for {kind}"
            if kind in {"dropdown", "checkboxes"}:
                assert element["attributes"].get("options"), \
                    f"{f.name} body[{i}]: {kind} with no options"


def test_blank_issues_are_disabled_so_the_templates_are_actually_used():
    import yaml

    cfg = yaml.safe_load(_text(ROOT / ".github" / "ISSUE_TEMPLATE" / "config.yml"))
    assert cfg.get("blank_issues_enabled") is False


# ── 5. Citation metadata tracks the release ──────────────────────────────────


def _citation() -> dict:
    import yaml

    return yaml.safe_load(_text(ROOT / "CITATION.cff"))


def test_the_citation_file_is_valid_cff_with_the_required_fields():
    cff = _citation()
    assert cff["cff-version"] == "1.2.0"
    for key in ("message", "title", "authors", "type", "license",
                "repository-code", "version", "date-released"):
        assert cff.get(key), f"CITATION.cff is missing {key}"
    for author in cff["authors"]:
        assert "family-names" in author or "name" in author, author


def test_the_citation_version_is_the_version_the_package_reports():
    """GitHub renders APA and BibTeX from this file, so a stale version here is a
    wrong citation in someone else's bibliography."""
    from packetiq import __version__

    assert _citation()["version"] == __version__


def test_the_citation_release_date_matches_the_newest_changelog_entry():
    cff = _citation()
    changelog = _text(ROOT / "CHANGELOG.md")
    m = re.search(r"^## \[([^\]]+)\][^\d]*(\d{4}-\d{2}-\d{2})",
                  changelog, re.MULTILINE)
    assert m, "could not find a dated release heading in CHANGELOG.md"
    version, date = m.groups()
    assert cff["version"] == version, (
        f"CITATION.cff says {cff['version']}, newest changelog entry is {version}"
    )
    assert str(cff["date-released"]) == date, (
        f"CITATION.cff released {cff['date-released']}, changelog says {date}"
    )


def test_the_citation_repository_url_is_this_repository():
    cff = _citation()
    assert cff["repository-code"] == REPO_URL
    assert cff["url"] == REPO_URL


def test_the_citation_claims_no_doi_it_does_not_have():
    """The accompanying short paper has no venue and no DOI. Inventing either in
    citation metadata would put a fabricated reference into a bibliography, which
    is the documentation equivalent of a hallucinated indicator."""
    cff = _citation()
    assert "doi" not in cff
    assert "doi" not in cff["preferred-citation"]
    assert "journal" not in cff["preferred-citation"]


# ── 6. No contact details are published by accident ──────────────────────────


def test_the_docs_publish_no_email_address():
    """The maintainer is declared by name only, in `pyproject.toml` and in
    `CITATION.cff`. Nothing in the documentation should leak an address, and a
    citation file is a particularly easy place to add one without thinking."""
    pattern = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    # Placeholders and protocol examples that are not anybody's address.
    benign = re.compile(r"example\.(com|org|net)|@param|@type|user@host|"
                        r"your-?email|noreply@|@BotFather|@Jatinkumar78")
    found = []
    for path in DOCS + [ROOT / "pyproject.toml", ROOT / "CITATION.cff"]:
        for line in _text(path).splitlines():
            if pattern.search(line) and not benign.search(line):
                found.append(f"{path.relative_to(ROOT)}: {line.strip()[:90]}")
    assert not found, "an email address appears in the docs:\n  " + "\n  ".join(found)
