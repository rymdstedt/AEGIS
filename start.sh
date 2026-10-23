#!/bin/bash
# Quick start — runs backend (FastAPI) + frontend dev (vite on 3000 w/ proxy)
# For single port: use backend/server.py after building the frontend.

DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON_BIN="$DIR/backend/.venv/bin/python"

if [ ! -x "$PYTHON_BIN" ]; then
    echo "AEGIS development environment is missing: backend/.venv/bin/python" >&2
    echo "Create it with Python 3.12 and install backend/requirements-dev.txt as described in README.md." >&2
    exit 1
fi
if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'; then
    echo "AEGIS development requires Python 3.12 or newer in backend/.venv." >&2
    echo "Recreate that venv with python3.12 and install backend/requirements-dev.txt." >&2
    exit 1
fi
if ! (cd "$DIR/backend" && "$PYTHON_BIN" -c 'import main'); then
    echo "AEGIS backend dependencies are incomplete in backend/.venv." >&2
    echo "Run: backend/.venv/bin/python -m pip install -r backend/requirements-dev.txt" >&2
    exit 1
fi

echo "⚡ Starting AEGIS (LM Studio / local LLM)..."
echo ""

AEGIS_DEV_TOKEN="$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('base64url'))")"
export AEGIS_AUTH_TOKEN="$AEGIS_DEV_TOKEN"
export AEGIS_ALLOWED_ORIGINS="http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
export VITE_AEGIS_AUTH_TOKEN="$AEGIS_DEV_TOKEN"

# Start backend
cd "$DIR/backend"
echo "→ Backend API/WS on http://localhost:8000 (serves built UI too if frontend/dist exists)"
"$PYTHON_BIN" server.py --port 8000 --auth-token "$AEGIS_DEV_TOKEN" --allowed-origin http://localhost:3000 --allowed-origin http://127.0.0.1:3000 &
BACKEND_PID=$!

# Start frontend dev server (for live dev)
cd "$DIR/frontend"
echo "→ Frontend dev UI on http://localhost:3000 (proxies /api /ws)"
npm run dev &
FRONTEND_PID=$!

echo ""
echo "⚡ AEGIS running!"
echo "   - Dev UI: http://localhost:3000"
echo "   - Or after 'cd frontend && npm run build': use http://localhost:8000 (single origin)"
echo "   - Make sure LM Studio server+model is running (backend auto-tries via lms CLI)"
echo "   Press Ctrl+C to stop"
echo ""

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
