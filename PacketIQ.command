#!/usr/bin/env bash
#
# PacketIQ — double-click launcher (macOS / Linux)
#
# Just double-click this file in Finder. On first run it sets everything up
# (this takes a minute); after that it starts instantly. It opens the web app
# in your browser automatically. Close the Terminal window or press Ctrl+C to stop.
#
set -e
cd "$(dirname "$0")"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
banner() {
  printf '%b' "${CYAN}${BOLD}"
  # Single-quoted heredoc → printed verbatim (no backslash / escape mangling)
  cat <<'ART'

   ____            _        _    ___ ___
  |  _ \ __ _  ___| | _____| |_ |_ _/ _ \
  | |_) / _` |/ __| |/ / _ \ __| | | | | |
  |  __/ (_| | (__|   <  __/ |_  | | |_| |
  |_|   \__,_|\___|_|\_\___|\__|___/\__\_\
ART
  printf '%b\n\n' "${NC}${CYAN}  AI PCAP Forensics & SOC Intelligence — Web App${NC}"
}
say()  { printf "${GREEN}▸ %s${NC}\n" "$1"; }
warn() { printf "${YELLOW}%s${NC}\n" "$1"; }

banner

# 1) Find Python 3.9+
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
if ! command -v "$PY" >/dev/null 2>&1; then
  warn "Python 3.9+ is required. Install it from https://www.python.org/downloads/ and double-click this file again."
  read -r -p "Press Enter to close..."
  exit 1
fi

# 2) Create the virtual environment on first run
if [ ! -d ".venv" ]; then
  say "First-time setup: creating an isolated environment…"
  "$PY" -m venv .venv
fi
VENV_PY=".venv/bin/python"
[ -x "$VENV_PY" ] || VENV_PY=".venv/bin/python3"
"$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 || true

# 3) Install PacketIQ + dependencies on first run
if ! "$VENV_PY" -c "import packetiq, fastapi, scapy" >/dev/null 2>&1; then
  say "Installing PacketIQ and its dependencies (one-time, ~1–2 minutes)…"
  "$VENV_PY" -m pip install -q --upgrade pip
  "$VENV_PY" -m pip install -q -e . || {
    warn "Install failed. Check your internet connection and try again."
    read -r -p "Press Enter to close..."
    exit 1
  }
fi

# 4) Create .env from template if missing (AI keys are optional)
[ -f ".env" ] || cp .env.example .env 2>/dev/null || true

# 5) Build a demo capture so there's something to try immediately
if [ ! -f "samples/demo_attack.pcap" ]; then
  say "Creating a demo capture you can try right away…"
  "$VENV_PY" samples/generate_sample.py >/dev/null 2>&1 || true
fi

printf "\n${GREEN}${BOLD}✓ Ready!${NC}\n"
say "Opening PacketIQ in your browser at http://localhost:8080"
say "A demo capture is at:  samples/demo_attack.pcap  (drag it into the upload box)"
printf "${YELLOW}Keep this window open while you use the app. Close it (or press Ctrl+C) to stop.${NC}\n\n"

# 6) Launch the web app (it opens the browser automatically)
exec "$VENV_PY" -m packetiq.cli webapp --port 8080
