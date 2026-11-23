#!/usr/bin/env bash
# Captures and measurements for the report. Needs tshark, curl, mkcert certs.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -z "${IN_NS:-}" ]; then
  CA="$(mkcert -CAROOT)/rootCA.pem" IN_NS=1 exec unshare -rn bash "report/$(basename "$0")"
fi
ip link set lo up
OUT=report/evidence
mkdir -p "$OUT"; rm -f "$OUT"/*
TMP=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$TMP"' EXIT
export CURL_CA_BUNDLE="$CA"
VULN=http://localhost:3000 SECURE_URL=https://localhost:3443

start() { # mode(0/1) port
  SECURE=$1 PORT=$2 node server.js >/dev/null 2>&1 & SRV=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$([ "$1" = 1 ] && echo $SECURE_URL || echo $VULN)" && return; sleep 0.1; done
  echo "server on $2 did not start" >&2; exit 1
}
stop() { kill $SRV; wait $SRV 2>/dev/null || true; }
tsh() { tshark "$@" 2>/dev/null; }
scenario() { # base
  local B=$1 JAR="$TMP/jar" CSRF ID
  rm -f "$JAR"
  c() { curl -s -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' "$@"; }
  CSRF=$(c -X POST "$B/api/login" --data-raw '{"username":"alice","password":"alicepass"}' | sed 's/.*"csrf":"\([^"]*\)".*/\1/')
  c "$B/api/notes" >/dev/null
  ID=$(c -H "X-CSRF-Token: $CSRF" -X POST "$B/api/notes" --data-raw '{"title":"tajne","body":"PIN do karty 9876"}' | tr -dc 0-9)
  c "$B/api/notes/$ID" >/dev/null
  c -H "X-CSRF-Token: $CSRF" -X PUT "$B/api/notes/$ID" --data-raw '{"title":"tajne","body":"PIN do karty 5432"}' >/dev/null
  c "$B/api/notes?q=tajne" >/dev/null
  c -H "X-CSRF-Token: $CSRF" -X DELETE "$B/api/notes/$ID" >/dev/null
  c "$B/api/me" >/dev/null
}

for MODE in vuln secure; do
  [ $MODE = vuln ] && { S=0 P=3000 B=$VULN; } || { S=1 P=3443 B=$SECURE_URL; }
  CAP="$OUT/$MODE.pcapng"
  start $S $P
  tshark -q -i lo -f "tcp port $P" -w "$TMP/cap.pcapng" 2>/dev/null & TS=$!
  sleep 2
  SSLKEYLOGFILE="$TMP/keys" scenario "$B"
  sleep 1; kill -INT $TS; wait $TS || true
  cp "$TMP/cap.pcapng" "$CAP"
  if [ $MODE = vuln ]; then
    SID=$(tsh -r "$CAP" -Y http.cookie -T fields -e http.cookie | head -1)
    { echo "cookie read from capture: $SID"
      echo "GET /api/me with it:";    curl -s -H "Cookie: $SID" "$B/api/me"; echo
      echo "GET /api/notes with it:"; curl -s -H "Cookie: $SID" "$B/api/notes"; echo; } >"$OUT/replay.txt"
  fi
  stop
  [ -f "$TMP/keys" ] && cp "$TMP/keys" "$OUT/secure.keylog"
  for W in alicepass "PIN do karty" csrf Cookie /api/notes localhost; do
    printf '%-14s %s frames\n' "$W" "$(tsh -r "$CAP" -Y "tcp contains \"$W\"" | wc -l)"
  done >"$OUT/$MODE-strings.txt"
  printf '%s\n' login list create read update search delete me >"$TMP/ops"
  for i in $(seq 0 7); do
    tsh -r "$CAP" -Y "tcp.stream==$i" -T fields -e frame.len -e tcp.len -e tcp.dstport |
      awk -v p=$P '{n++; b+=$1; if($3==p) up+=$2; else dn+=$2} END{print n, b, up, dn}'
  done | paste -d' ' "$TMP/ops" - >"$OUT/$MODE-ops.txt"
  tsh -r "$CAP" -q -z io,phs >"$OUT/$MODE-protocols.txt"
done

tsh -r "$OUT/vuln.pcapng" -q -z follow,http,ascii,0 >"$OUT/vuln-login-stream.txt"
tsh -r "$OUT/secure.pcapng" -Y tcp.stream==0 >"$OUT/secure-login-packets.txt"
tsh -r "$OUT/vuln.pcapng" -Y tcp.stream==0 >"$OUT/vuln-login-packets.txt"
tsh -r "$OUT/secure.pcapng" -Y tcp.stream==0 -T fields -e frame.number -e tcp.srcport -e tls.record.content_type -e tls.record.length >"$OUT/secure-login-records.txt"
tsh -r "$OUT/secure.pcapng" -Y 'tls.handshake.type==1 && tcp.stream==0' -T fields -e tls.handshake.extensions_server_name >"$OUT/secure-sni.txt"
tsh -r "$OUT/secure.pcapng" -Y 'tls.handshake.type==2' -T fields -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite -e tls.handshake.extensions_key_share_group | sort | uniq -c >"$OUT/secure-negotiated.txt"
tsh -o "tls.keylog_file:$OUT/secure.keylog" -r "$OUT/secure.pcapng" -q -z follow,http,ascii,0 >"$OUT/secure-login-decrypted.txt"
for MODE in vuln secure; do
  [ $MODE = vuln ] && { S=0 P=3000 B=$VULN N=sid; } || { S=1 P=3443 B=$SECURE_URL N=__Host-sid; }
  for A in sqli idor bruteforce; do start $S $P; bash attacks/$A.sh $B >"$OUT/$MODE-$A.txt"; stop; done
  start $S $P
  curl -s -o /dev/null -X POST "$B/api/login" -H 'Content-Type: application/json' --data-raw '{"username":"bob","password":"bobsecret"}'
  for i in 1 2 3; do printf 'sid=%s -> ' $i; curl -s -H "Cookie: $N=$i" "$B/api/me"; echo; done >"$OUT/$MODE-session.txt"
  curl -s -D - -o /dev/null "$B/" >"$OUT/$MODE-headers.txt"
  curl -s -D - -o /dev/null -X POST "$B/api/login" -H 'Content-Type: application/json' --data-raw '{"username":"alice","password":"alicepass"}' | grep -i set-cookie >"$OUT/$MODE-cookie.txt"
  curl -s -X POST "$B/api/login" -H 'Content-Type: application/json' --data-raw '{bad' >"$OUT/$MODE-error.txt"
  for _ in $(seq 200); do curl -s -o /dev/null -w '%{time_connect} %{time_appconnect} %{time_total}\n' "$B/mode.js"; done |
    awk '{c+=$1; a+=$2; t+=$3} END{printf "new connection, n=%d: tcp %.2f ms, tls done %.2f ms, total %.2f ms\n", NR, c/NR*1e3, a/NR*1e3, t/NR*1e3}' >"$OUT/$MODE-latency.txt"
  URLS=(); for _ in $(seq 200); do URLS+=(-o /dev/null "$B/mode.js"); done
  curl -s -w '%{time_total}\n' "${URLS[@]}" | tail -n +2 |
    awk '{t+=$1} END{printf "reused connection, n=%d: total %.2f ms\n", NR, t/NR*1e3}' >>"$OUT/$MODE-latency.txt"
  for _ in $(seq 20); do curl -s -o /dev/null -w '%{time_total}\n' -X POST "$B/api/login" -H 'Content-Type: application/json' --data-raw '{"username":"alice","password":"alicepass"}'; done |
    awk '{t+=$1} END{printf "login, n=%d: total %.2f ms\n", NR, t/NR*1e3}' >>"$OUT/$MODE-latency.txt"
  stop
done
node --version >"$OUT/versions.txt"; tsh --version | head -1 >>"$OUT/versions.txt"; curl --version | head -1 | cut -d' ' -f1-4 >>"$OUT/versions.txt"; node -p '"openssl (node) "+process.versions.openssl' >>"$OUT/versions.txt"; uname -r >>"$OUT/versions.txt"
echo "done: $OUT"
