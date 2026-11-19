#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if [ ! -d ".venv" ]; then
  echo "[PhishRadar] Creating virtual environment..."
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
echo "[PhishRadar] Installing dependencies..."
python -m pip install -q -r requirements.txt
[ -f .env ] || { [ -f .env.example ] && cp .env.example .env; }
echo "[PhishRadar] Starting on http://127.0.0.1:8003  (Ctrl+C to stop)"
( sleep 3; (xdg-open http://127.0.0.1:8003 || open http://127.0.0.1:8003) >/dev/null 2>&1 || true ) &
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8003
