#!/usr/bin/env bash
#
# PacketIQ quickstart — one command to set everything up and launch.
#
#   ./quickstart.sh            # set up + launch the web app  (http://localhost:8080)
#   ./quickstart.sh analyze    # set up + analyze the demo capture in the terminal
#   ./quickstart.sh setup      # set up only (create venv, install, make demo pcap)
#
# Safe to re-run: it reuses the existing virtual environment.

set -e
cd "$(dirname "$0")"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
say()  { printf "${GREEN}▸ %s${NC}\n" "$1"; }
warn() { printf "${YELLOW}%s${NC}\n" "$1"; }

# 1) Find a Python 3 to bootstrap the venv with — prefer a newer, CI-tested
#    interpreter (3.12 → 3.10) when installed, so a fresh .venv gets fully-patched
#    dependencies; otherwise fall back to python3 (3.9 still works).
BOOT_PY=""
for cand in python3.12 python3.11 python3.10 python3 python; do
  if command -v "$cand" >/dev/null 2>&1; then BOOT_PY="$cand"; break; fi
done
if [ -z "$BOOT_PY" ]; then
  warn "Python 3.9+ is required but was not found. Install it from https://python.org"
  exit 1
fi
# Make sure it's new enough (3.9+), or the install below fails with a confusing error
if ! "$BOOT_PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 9) else 1)' 2>/dev/null; then
  HAVE=$("$BOOT_PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "unknown")
  warn "PacketIQ needs Python 3.9 or newer, but found Python $HAVE. Install a newer one from https://python.org and re-run."
  exit 1
fi

# 2) Create the virtual environment if needed
if [ ! -d ".venv" ]; then
  say "Creating virtual environment (.venv)…"
  "$BOOT_PY" -m venv .venv
fi

# macOS: make sure .venv isn't flagged UF_HIDDEN. If it is, pip writes editable
# `.pth` files hidden too, and CPython's site.py silently skips hidden `.pth`
# files — which would break `pip install -e .` (live-edit) for developers.
# Harmless to run every time; no-op on Linux/Windows (no chflags).
if command -v chflags >/dev/null 2>&1; then
  chflags -R nohidden .venv >/dev/null 2>&1 || true
fi

# Use explicit venv paths (no reliance on 'activate' / PATH)
VENV_PY=".venv/bin/python"
[ -x "$VENV_PY" ] || VENV_PY=".venv/bin/python3"
"$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 || true

# Permanent UF_HIDDEN safety net (macOS). chflags above is best-effort — a
# background service can re-hide .venv, and site.py then skips the editable
# `.pth`, breaking the `packetiq` command outside the repo. A sitecustomize.py is
# immune (Python imports it even when hidden), so we drop one in that re-adds the
# repo root to sys.path. No-op for the non-editable install below (the copied
# package resolves first) and off macOS.
if command -v chflags >/dev/null 2>&1; then
  SP=$("$VENV_PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])' 2>/dev/null)
  if [ -n "$SP" ] && [ -d "$SP" ]; then
    cat > "$SP/sitecustomize.py" <<'PYEOF'
"""PacketIQ editable-install robustness (macOS UF_HIDDEN workaround).

CPython's site.py skips .pth files carrying the macOS UF_HIDDEN flag, which a
background service periodically re-applies to a dot-directory such as .venv —
silently breaking an editable install. Python's import machinery does NOT skip
hidden modules, so this sitecustomize still runs and re-adds the repo root.
"""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_repo = os.path.abspath(os.path.join(_here, "..", "..", "..", ".."))
if os.path.isdir(os.path.join(_repo, "packetiq")) and _repo not in sys.path:
    sys.path.append(_repo)
PYEOF
  fi
fi

# 3) Install PacketIQ (+ deps) if not installed yet. Check a real dependency
#    (fastapi), not just `import packetiq` — run from the repo root the source
#    tree shadows an uninstalled package, which would wrongly skip the install.
if ! "$VENV_PY" -c "import packetiq, fastapi, scapy" >/dev/null 2>&1; then
  say "Installing PacketIQ and dependencies (first run only, ~1-2 min)…"
  "$VENV_PY" -m pip install -q --upgrade pip
  # Regular (non-editable) install: copies the package into site-packages so the
  # `packetiq` console script resolves from ANY working directory. Editable (.pth)
  # installs are unreliable on some Python 3.12+ standalone builds.
  "$VENV_PY" -m pip install -q .
fi

# 4) Create .env from the template if missing (AI keys are optional)
if [ ! -f ".env" ]; then
  say "Creating .env from template (add free AI keys later for the copilot)…"
  cp .env.example .env
fi

# 5) Generate the demo capture if missing
if [ ! -f "samples/demo_attack.pcap" ]; then
  say "Generating a demo capture (samples/demo_attack.pcap)…"
  "$VENV_PY" samples/generate_sample.py >/dev/null
fi

printf "${GREEN}✓ Setup complete.${NC}\n"

case "${1:-webapp}" in
  setup)
    printf "\nNext, run any of these:\n"
    printf "  ${CYAN}source .venv/bin/activate${NC}   # then the 'packetiq' command is available\n"
    printf "  ${CYAN}packetiq analyze samples/demo_attack.pcap${NC}\n"
    printf "  ${CYAN}packetiq webapp${NC}             # → http://localhost:8080\n"
    ;;
  analyze)
    say "Analyzing the demo capture…"
    "$VENV_PY" -m packetiq.cli analyze samples/demo_attack.pcap
    ;;
  webapp|*)
    say "Launching the web app → http://localhost:8080  (Ctrl+C to stop)"
    say "Upload samples/demo_attack.pcap in your browser to try it."
    "$VENV_PY" -m packetiq.cli webapp
    ;;
esac
