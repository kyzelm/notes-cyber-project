#!/usr/bin/env bash
# Vuln #8 — no login rate limit. Fire 15 guesses at Alice's account.
# VULN: all 15 processed (401s), attacker can keep going forever.
# SECURE: after 5 attempts/min the server replies 429 and stops checking.
set -euo pipefail
BASE="${1:-http://localhost:${PORT:-3000}}"
for i in $(seq 1 15); do
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$BASE/api/login" \
    -H 'Content-Type: application/json' \
    --data-raw "{\"username\":\"alice\",\"password\":\"guess$i\"}")
  echo "attempt $i -> HTTP $CODE"
done
echo "(VULN: all 401. SECURE: flips to 429 after the 5th.)"
