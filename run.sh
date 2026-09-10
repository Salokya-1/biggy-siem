#!/usr/bin/env bash
# Biggy SIEM launcher for Linux / macOS (e.g. Kali).
# Creates the venv on first run, installs deps, and starts the server bound to
# all interfaces so the console is reachable from your host / LAN.
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[biggy] creating virtualenv…"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

# bind to all interfaces by default so a VM/host can reach it; override with ARGUS_HOST=127.0.0.1
export ARGUS_HOST="${ARGUS_HOST:-0.0.0.0}"
echo "[biggy] starting — open http://<this-host-ip>:${ARGUS_PORT:-8642}  (login: admin / argus)"
exec python run.py
