#!/usr/bin/env bash
# ============================================================================
#  ReconMap Pro - easy Linux / macOS launcher
#
#  Usage:  ./start.sh
#
#  Creates a venv on first run, installs dependencies, builds the frontend,
#  starts the local demo lab and the ReconMap Pro API + web UI.
#
#  Press Ctrl+C to stop everything.
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

cyan=$'\033[1;36m'; green=$'\033[0;32m'; red=$'\033[0;31m'; nc=$'\033[0m'

echo
echo "  ${cyan}============================================================${nc}"
echo "  ${cyan} ReconMap Pro - local launcher${nc}"
echo "  ${cyan}============================================================${nc}"
echo

# --- Check Python -----------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  echo "  ${red}[ERROR]${nc} python3 not found. Install Python 3.11+ and retry."
  exit 1
fi
echo "  ${green}[ok]${nc} Found $(python3 --version)"

# --- Check Node (optional) --------------------------------------------------
HAS_NODE=1
if ! command -v npm >/dev/null 2>&1; then
  echo "  [warn] Node.js/npm not found - the UI will not be built."
  echo "         Install Node from https://nodejs.org/ for the full dashboard."
  HAS_NODE=0
else
  echo "  ${green}[ok]${nc} Found $(node --version)"
fi

# --- Backend venv -----------------------------------------------------------
if [ ! -d backend/.venv ]; then
  echo
  echo "  [1/4] Creating Python virtual environment..."
  python3 -m venv backend/.venv
  # shellcheck disable=SC1091
  source backend/.venv/bin/activate
  echo "  [2/4] Installing backend dependencies..."
  pip install --upgrade pip >/dev/null
  pip install -r backend/requirements.txt
else
  echo
  echo "  [1/4] Using existing backend virtual environment."
  # shellcheck disable=SC1091
  source backend/.venv/bin/activate
fi

# --- Frontend build ---------------------------------------------------------
if [ "$HAS_NODE" = "1" ]; then
  if [ ! -d frontend/node_modules ]; then
    echo "  [3/4] Installing frontend dependencies..."
    (cd frontend && npm install)
  fi
  if [ ! -f frontend/dist/index.html ]; then
    echo "  [4/4] Building React frontend..."
    (cd frontend && npm run build)
  else
    echo "  [3/4] Using existing frontend build."
  fi
else
  echo "  [3/4] Skipping frontend (Node.js not installed)."
fi

# --- Environment ------------------------------------------------------------
export RECONMAP_ALLOW_PRIVATE_NETWORKS=true
export RECONMAP_LAB_EXTRA_PORTS=8099
export RECONMAP_DATABASE_URL="sqlite+aiosqlite:///./reconmap.db"
export RECONMAP_REPORT_DIR="./reports"
export RECONMAP_CORS_ORIGINS="http://localhost:8000,http://localhost:5173"
export PYTHONUNBUFFERED=1

# --- Start the demo lab in the background -----------------------------------
echo
echo "  Starting local demo lab on http://localhost:8099 ..."
python3 lab/server.py &
LAB_PID=$!
trap 'echo; echo "  Shutting down..."; kill $LAB_PID 2>/dev/null || true' EXIT

sleep 2

# --- Open the browser (best effort) -----------------------------------------
( sleep 3; (command -v xdg-open >/dev/null && xdg-open http://localhost:8000) \
  || (command -v open >/dev/null && open http://localhost:8000) ) >/dev/null 2>&1 &

# --- Start the API + web UI -------------------------------------------------
echo
echo "  ${cyan}============================================================${nc}"
echo "   ReconMap Pro is starting ..."
echo
echo "     Web UI:        http://localhost:8000"
echo "     API docs:      http://localhost:8000/docs"
echo "     Demo lab:      http://localhost:8099"
echo
echo "   In the UI, click \"New scan\" and target:  lab.local"
echo
echo "   Press Ctrl+C to stop."
echo "  ${cyan}============================================================${nc}"
echo

cd backend
exec python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
