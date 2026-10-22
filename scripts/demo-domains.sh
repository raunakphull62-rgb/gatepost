#!/usr/bin/env bash
# Gatepost demo: scripted curl walkthrough of the B2 domains/origins API.
# claim → instructions → failing verify → dedupe → origin set + test against
# a local test origin (loopback hook ON) → second-user same-hostname claim →
# isolation checks. Prints PASS/FAIL per step; exits nonzero on any failure.
# Secrets stay in .env, which is never printed. Rate-limit hygiene mirrors
cd "$(dirname "$0")/.."

BASE="${GP_PUBLIC_BASE_URL:-http://localhost:8091}"
JAR="$(mktemp)"; JAR2="$(mktemp)"
BASE="${GP_PUBLIC_BASE_URL:-http://localhost:8091}"
ORIGIN_PORT=18081
trap 'kill ${SRV_PID:-0} 2>/dev/null; kill ${ORIGIN_PID:-0} 2>/dev/null; rm -f "${JAR:-}" "${JAR2:-}"' EXIT

if [ ! -f .env ]; then
  echo "no .env at repo root (DB connection strings live there; create it yourself, never paste it here)" >&2
  exit 2
fi

PASS=0 FAIL=0
s=1
check() { # check <desc> <actual> <want>
  if [ "$2" = "$3" ]; then
    echo "PASS $s: $1"; PASS=$((PASS+1))
  else
    echo "FAIL $s: $1 (want $3, got $2)"; FAIL=$((FAIL+1))
  fi
  s=$((s+1))
}
CIP="10.$((RANDOM%200+20)).$((RANDOM%200+20)).$((RANDOM%200+20))"
CIP2="10.$((RANDOM%200+20)).$((RANDOM%200+20)).$((RANDOM%200+20))"
# cb prints BODY, then CODE on the last line; split with bodyof/codeof.
# Each client keeps its own cookie jar (session state per user).
cb()   { curl -s -w '\n%{http_code}' -b "$JAR"  -c "$JAR"  -H "X-Forwarded-For: $CIP"  "$@"; }
cb2()  { curl -s -w '\n%{http_code}' -b "$JAR2" -c "$JAR2" -H "X-Forwarded-For: $CIP2" "$@"; }
bodyof(){ printf '%s' "$1" | head -n -1; }
codeof(){ printf '%s' "$1" | tail -n 1; }
mail_token() { grep -m1 -o 'token: [A-Za-z0-9_-]*' "$(ls -t outbox/*.txt | head -1)" | cut -d' ' -f2; }

mkdir -p outbox
go build -o gatepost ./cmd/gatepost || exit 2

# a tiny local test origin for the "test connection" step
python3 -m http.server "${ORIGIN_PORT}" --bind 127.0.0.1 >/dev/null 2>&1 &
ORIGIN_PID=$!

# demo server: loopback origins allowed (TEST hook), resolvers pointed at a
# dead address so the verify-failure step is deterministic (never the net)
BASE="${GP_PUBLIC_BASE_URL:-http://localhost:8091}"
ENV=development GP_TRUSTED_PROXIES=127.0.0.1/32 GP_HTTP_ADDR=127.0.0.1:8091 \
  GP_TEST_ALLOW_LOOPBACK=true GP_SERVICE_HOSTNAMES=api.gatepost.net \
  GP_NS1=ns1.gatepost.test GP_NS2=ns2.gatepost.test \
  GP_TEST_ZONE=gatepost.test GP_ALLOW_SUBDOMAIN_ZONES=true \
  GP_DNS_RESOLVERS=127.0.0.1:5333 \
  ./gatepost >/tmp/gatepost-domains-demo-server.log 2>&1 &
SRV_PID=$!
for _ in $(seq 1 30); do
  C=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $CIP" "$BASE/api/me")
  [ "$C" != "000" ] && [ -n "$C" ] && break
  sleep 0.5
done
[ -n "$C" ] && [ "$C" != "000" ] || { echo "server did not come up (see /tmp/gatepost-domains-demo-server.log)"; exit 2; }
for _ in $(seq 1 20); do curl -s -o /dev/null "http://127.0.0.1:${ORIGIN_PORT}/" 2>/dev/null && break; sleep 0.5; done
curl -s -o /dev/null "http://127.0.0.1:${ORIGIN_PORT}/" 2>/dev/null || { echo "local test origin did not come up"; exit 2; }

TS=$(date +%s)-$RANDOM
U="demo-dom-$TS@x.test";  PW="demo-password-1"
U2="demo-dom2-$TS@x.test"
HOST="shop-$TS.example.com"

# --- accounts ---
check "signup A" "$(codeof "$(cb -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")")" "200"
VT=$(mail_token)
check "signup B" "$(codeof "$(cb2 -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U2\",\"password\":\"$PW\"}")")" "200"
VT2=$(mail_token)
check "verify A" "$(codeof "$(cb -X POST "$BASE/auth/verify" -H 'Content-Type: application/json' -d "{\"token\":\"$VT\"}")")" "200"
check "verify B" "$(codeof "$(cb2 -X POST "$BASE/auth/verify" -H 'Content-Type: application/json' -d "{\"token\":\"$VT2\"}")")" "200"

# --- claim + instructions ---
OUT=$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST\"}")
check "claim $HOST" "$(codeof "$OUT")" "201"
DOM=$(bodyof "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["domain"]["id"])' 2>/dev/null)
check "claim returned an id" "$([ -n "$DOM" ] && echo yes)" "yes"

check "list shows the hostname" "$(bodyof "$(cb "$BASE/v1/domains")" | grep -c "$HOST")" "1"
VERIF=$(cb "$BASE/v1/domains/$DOM/verification")
check "instructions name the TXT record" "$(bodyof "$VERIF" | grep -c "_gatepost-verify.$HOST")" "1"
check "instructions carry the gatepost-verify value" "$(bodyof "$VERIF" | grep -c 'gatepost-verify=')" "1"

# re-add: the held claim comes back (no second row)
check "re-add returns the held claim (200)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST\"}")")" "200"

# --- a verify attempt that fails (dead resolvers: deterministic) ---
check "verify attempt fails (502: resolvers unreachable)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM/verify")")" "502"

# --- refused claims: reserved service name / IP literal / bare public suffix ---
check "claim of api.gatepost.net refused (403)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d '{"hostname":"api.gatepost.net"}')")" "403"
check "claim of 1.2.3.4 refused (422)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d '{"hostname":"1.2.3.4"}')")" "422"
check "claim of bare com refused (422)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d '{"hostname":"com"}')")" "422"

# --- origin settings + test connection against the local test origin ---
check "origin set http://127.0.0.1:$ORIGIN_PORT (test hook)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
      -d "{\"scheme\":\"http\",\"address\":\"127.0.0.1\",\"port\":$ORIGIN_PORT,\"tls_verify\":false}")")" "201"
check "origin duplicate refused (409)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
      -d "{\"scheme\":\"http\",\"address\":\"127.0.0.1\",\"port\":$ORIGIN_PORT}")")" "409"
OTEST=$(cb -X POST "$BASE/v1/domains/$DOM/origin/test")
check "origin test reachable (local test origin)" "$(codeof "$OTEST")" "200"
check "origin test saw http 200" "$(bodyof "$OTEST" | grep -c '"status_code":200')" "1"

# --- second user claims the same hostname (many pending claims allowed) ---
check "B claims the same hostname (own row)" \
  "$(codeof "$(cb2 -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST\"}")")" "201"

# --- isolation: B gets nothing of A's ---
check "B gets A's domain: 404"              "$(codeof "$(cb2 "$BASE/v1/domains/$DOM")")" "404"
check "B gets A's origin: 404"              "$(codeof "$(cb2 "$BASE/v1/domains/$DOM/origin")")" "404"
check "B sets A's origin: 404"              "$(codeof "$(cb2 -X POST "$BASE/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"127.0.0.1\",\"port\":$ORIGIN_PORT}")")" "404"
check "B tests A's origin: 404"             "$(codeof "$(cb2 -X POST "$BASE/v1/domains/$DOM/origin/test")")" "404"
check "B deletes A's domain: 404"           "$(codeof "$(cb2 -X DELETE "$BASE/v1/domains/$DOM")")" "404"
check "B's instructions call returns no token" "$(bodyof "$(cb2 "$BASE/v1/domains/$DOM/verification")" | grep -c 'gatepost-verify=')" "0"
check "B's list shows none of A's row ids"  "$(bodyof "$(cb2 "$BASE/v1/domains")" | grep -c "$DOM")" "0"

# --- nameserver mode + zone records (items 10–12 walkthrough) ---
OUT=$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' \
  -d "{\"hostname\":\"dm-$TS.gatepost.test\",\"setup_type\":\"nameserver\"}")
check "nameserver claim accepted (test-zone subdomain)" "$(codeof "$OUT")" "201"
DOM2=$(bodyof "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["domain"]["id"])' 2>/dev/null)
check "claim carries the assigned nameserver pair" \
  "$(bodyof "$OUT" | grep -c '"ns1":"ns1.gatepost.test"')" "1"
check "instructions list the pair" \
  "$(bodyof "$(cb "$BASE/v1/domains/$DOM2/verification")" | grep -c '"nameservers":\["ns1.gatepost.test","ns2.gatepost.test"\]')" "1"
check "nameserver TXT leak absent" \
  "$(bodyof "$(cb "$BASE/v1/domains/$DOM2/verification")" | grep -c 'gatepost-verify=')" "0"
check "delegation verification fails while resolvers are dead (502)" \
  "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM2/verify")")" "502"

rrecord() { cb -X POST "$BASE/v1/domains/$DOM2/records" -H 'Content-Type: application/json' -d "$1"; }
ROUT=$(rrecord '{"name":"@","type":"A","value":"93.184.216.34"}')
check "A record created" "$(codeof "$ROUT")" "201"
R1=$(bodyof "$ROUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["record"]["id"])' 2>/dev/null)
check "AAAA record created" "$(codeof "$(rrecord '{"name":"v6","type":"AAAA","value":"2606:4700::1111"}')")" "201"
check "MX with priority created" "$(codeof "$(rrecord '{"name":"@","type":"MX","value":"mail.example.net","priority":10}')")" "201"
check "CNAME beside the apex A refused (409)" "$(codeof "$(rrecord '{"name":"@","type":"CNAME","value":"other.example.net"}')")" "409"
check "garbage type refused" "$(codeof "$(rrecord '{"name":"g","type":"WIFI","value":"x"}')")" "422"
check "record patched (value + ttl)" \
  "$(codeof "$(cb -X PATCH "$BASE/v1/domains/$DOM2/records/$R1" -H 'Content-Type: application/json' -d '{"value":"93.184.216.35","ttl":600}')")" "200"
HIST=$(cb "$BASE/v1/domains/$DOM2/records/$R1")
check "history has create+update" "$(printf '%s' "$(bodyof "$HIST")" | grep -c '"action":"create"')" "1"
check "history shows the old value" "$(printf '%s' "$(bodyof "$HIST")" | grep -c '"old_value":"93.184.216.34"')" "1"
check "record deleted" "$(codeof "$(cb -X DELETE "$BASE/v1/domains/$DOM2/records/$R1")")" "200"
check "zone keeps AAAA + MX, not the deleted A" \
  "$(bodyof "$(cb "$BASE/v1/domains/$DOM2/records")" | grep -o '"id":' | grep -c '')" "2"

echo
echo "=== domains/origins demo: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
