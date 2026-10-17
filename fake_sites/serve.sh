#!/usr/bin/env bash
# Local phishing-fixture harness. Serves every fake site on a fixed port so
# VerifyEye can be tested against them. LOCAL ONLY — these are targets for our
# own detector, never deployed anywhere.
#
#   ./serve.sh         start every site
#   ./serve.sh stop    stop them all

cd "$(dirname "$0")" || exit 1

# site folder -> port. add a new fake site here and it just works.
SITES="claude:5500 claude-popup:5550 spa-test:5600 google:5700 netflix:5800 tiktok:5900 amazon:6000 apple:6100"

if [ "$1" = "stop" ]; then
  for pair in $SITES; do
    port="${pair#*:}"
    lsof -ti ":$port" | xargs kill -9 2>/dev/null
  done
  echo "stopped all fake sites"
  exit 0
fi

for pair in $SITES; do
  site="${pair%:*}"
  port="${pair#*:}"
  [ -d "$site" ] || { echo "  (skip $site — no folder)"; continue; }
  lsof -ti ":$port" | xargs kill -9 2>/dev/null   # free the port first
  ( cd "$site" && python3 -m http.server "$port" >/dev/null 2>&1 & )
  echo "  $site → http://localhost:$port"
done

echo "all fake sites up. stop them with: ./serve.sh stop"
