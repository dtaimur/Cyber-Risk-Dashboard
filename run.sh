#!/usr/bin/env bash
# Starts the API (port 8000) and the web app (port 5173). Ctrl+C stops both.
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$ROOT/backend/.venv" ]; then
  python3 -m venv "$ROOT/backend/.venv"
  "$ROOT/backend/.venv/bin/pip" install -q -r "$ROOT/backend/requirements-dev.txt"
fi
# Pick up dependencies added since the environment was created
"$ROOT/backend/.venv/bin/python" -c "import anthropic" 2>/dev/null || "$ROOT/backend/.venv/bin/pip" install -q -r "$ROOT/backend/requirements-dev.txt"
[ -d "$ROOT/frontend/node_modules" ] || (cd "$ROOT/frontend" && npm install)

# Settings and secrets (ANTHROPIC_API_KEY, passwords) live in .env at the project root
if [ ! -f "$ROOT/.env" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  chmod 600 "$ROOT/.env"
fi
# Read KEY=VALUE lines as plain data (never executed as shell code), so passwords may
# contain spaces or characters like $ ! & ; and stray spaces around "=" are ignored.
load_env() {
  local line key val n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line="${line%$'\r'}"                                    # tolerate Windows line endings
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue          # comments and blank lines
    if [[ "$line" != *=* ]]; then
      echo "Warning: .env line $n ignored (expected KEY=VALUE)" >&2; continue
    fi
    key="${line%%=*}"; val="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"   # trim key
    key="${key#export }"
    val="${val#"${val%%[![:space:]]*}"}"; val="${val%"${val##*[![:space:]]}"}"   # trim value
    if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi  # strip one pair of quotes
    if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      echo "Warning: .env line $n ignored (invalid name)" >&2; continue
    fi
    if [ -n "$val" ]; then export "$key=$val"; else unset "$key"; fi   # empty means "not set"
  done < "$1"
}
load_env "$ROOT/.env"
if [ -n "$ANTHROPIC_API_KEY" ]; then echo "AI Analyst: enabled"; else echo "AI Analyst: no ANTHROPIC_API_KEY in .env (assistant disabled)"; fi

# An earlier copy of this dashboard may still hold the ports, possibly paused with Ctrl+Z
# (paused processes ignore a normal kill). Stop our own leftovers; refuse if something
# else owns the port, since the browser would otherwise talk to the wrong server.
for port in 8000 5173; do
  for pid in $(lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null); do
    cmd="$(ps -o command= -p "$pid" 2>/dev/null || true)"
    cwd="$(lsof -a -p "$pid" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' || true)"
    if [[ "$cmd" == *"$ROOT"* || "$cwd" == "$ROOT"* ]]; then
      echo "Stopping an earlier copy of the dashboard on port $port (pid $pid)..."
      kill "$pid" 2>/dev/null || true; kill -CONT "$pid" 2>/dev/null || true
      for _ in 1 2 3 4 5; do lsof -ti "tcp:$port" -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 1; done
      if lsof -ti "tcp:$port" -sTCP:LISTEN >/dev/null 2>&1; then kill -9 "$pid" 2>/dev/null || true; sleep 1; fi
    else
      echo "Port $port is in use by another program: $cmd"
      echo "Close that program, or stop it with:   kill -9 $pid"
      exit 1
    fi
  done
done

if [ "$1" = "--reset" ]; then
  echo "Rebuilding demo database with fresh threat intel..."
  rm -f "$ROOT/backend/dashboard.db"
fi

(cd "$ROOT/backend" && .venv/bin/uvicorn app.main:app --port 8000) &
API_PID=$!
trap 'kill $API_PID 2>/dev/null' EXIT
sleep 3
if [ -f "$ROOT/backend/.demo-credentials" ]; then
  echo ""
  echo "Sign-in accounts are in: backend/.demo-credentials   (cat it to see them)"
  echo ""
fi
echo "Dashboard: http://localhost:5173   (press Ctrl+C to stop; Ctrl+Z only pauses it)"
cd "$ROOT/frontend" && npm run dev
