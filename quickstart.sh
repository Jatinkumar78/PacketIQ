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

# 1) Find a Python 3 to bootstrap the venv with
BOOT_PY=python3
command -v "$BOOT_PY" >/dev/null 2>&1 || BOOT_PY=python
if ! command -v "$BOOT_PY" >/dev/null 2>&1; then
  warn "Python 3.9+ is required but was not found. Install it from https://python.org"
  exit 1
fi

# 2) Create the virtual environment if needed
if [ ! -d ".venv" ]; then
  say "Creating virtual environment (.venv)…"
  "$BOOT_PY" -m venv .venv
fi

# Use explicit venv paths (no reliance on 'activate' / PATH)
VENV_PY=".venv/bin/python"
[ -x "$VENV_PY" ] || VENV_PY=".venv/bin/python3"
"$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 || true

# 3) Install PacketIQ (+ deps) if not importable yet
if ! "$VENV_PY" -c "import packetiq" >/dev/null 2>&1; then
  say "Installing PacketIQ and dependencies (first run only, ~1-2 min)…"
  "$VENV_PY" -m pip install -q --upgrade pip
  "$VENV_PY" -m pip install -q -e .
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
