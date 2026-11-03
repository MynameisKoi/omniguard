#!/usr/bin/env bash
# One command to bring up the manual dev stack on fixed ports.
#   ./dev.sh         start core, verifyeye agent, dashboard and the fake sites
#   ./dev.sh stop    stop them all
# Neo4j, Mongo and Ollama are apps — this only checks they're up, it can't start them.

cd "$(dirname "$0")" || exit 1
LOGS=".devlogs"
mkdir -p "$LOGS"

CORE_PORT=8000
VERIFYEYE_PORT=8100
DASH_PORT=5173

free_port () { lsof -ti ":$1" | xargs kill -9 2>/dev/null; }

if [ "$1" = "stop" ]; then
  for p in $CORE_PORT $VERIFYEYE_PORT $DASH_PORT; do free_port "$p"; done
  ./fake_sites/serve.sh stop
  echo "stopped core, verifyeye, dashboard and fake sites"
  exit 0
fi

check () {
  if lsof -ti ":$2" >/dev/null 2>&1; then echo "  ok   $1 (:$2)"; else echo "  DOWN $1 (:$2) — start with: $3"; fi
}
echo "infra (start these apps yourself if DOWN):"
check "Neo4j"   7687  "open Neo4j Desktop and press Start"
check "MongoDB" 27017 "brew services start mongodb-community"
check "Ollama"  11434 "ollama serve   (or open the Ollama app)"

echo "starting services:"
free_port $CORE_PORT
( cd backend && source venv/bin/activate && uvicorn main:app --port $CORE_PORT > "../$LOGS/core.log" 2>&1 & )
echo "  core API        → http://localhost:$CORE_PORT"

free_port $VERIFYEYE_PORT
( cd verifyeye-ingress && source venv/bin/activate && uvicorn service:app --port $VERIFYEYE_PORT > "../$LOGS/verifyeye.log" 2>&1 & )
echo "  verifyeye agent → http://localhost:$VERIFYEYE_PORT"

free_port $DASH_PORT
( cd frontend && npm run dev > "../$LOGS/dashboard.log" 2>&1 & )
echo "  dashboard       → http://localhost:$DASH_PORT"

./fake_sites/serve.sh | sed 's/^/  /'

echo "logs in ./$LOGS — stop everything with ./dev.sh stop"
