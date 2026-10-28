#!/usr/bin/env bash
# Gatepost edge acceptance (item 7). Runs against the REAL compose stack
# (edge + poller + the realistic origin-test container), the REAL API on
# 172.17.0.1:8090 (this script owns it for the whole run) and a node minted
# for the run. Proves, with a PASS/FAIL line each:
#
#   fixture  origin-test through the edge: /ok /slow /big /redirect (passed
#            through, not followed) /cookie /echo-headers /status/N /chunked
#   a) cold start, API down, saved snapshot: traffic still serves
#   b) cold start, no snapshot: 421 for every host
#   c) tampered snapshot rejected; the last-good config keeps serving
#   d) an API origin change reaches the edge — with the seconds it took
#   e) a spoofed X-Forwarded-For is replaced with the real client IP
#   f) private/metadata origins are refused at set time, never reached
#   g) unknown host: 421, no certificate attempt
#   h) allowed host gets a certificate (internal issuer); a denied host
#      does not (the ask answers 421)
#   i) API down mid-run: keeps serving; API back: recovers (a change
#      propagates again); a revoked token (401): last-good keeps serving
#   j) the run's whole access log: no secrets, no query strings — and no
#      access entry ever reaches the edge container's stderr either
#
# Secrets stay in deploy/dev/secrets/ (gitignored) and .env; nothing
# secret is printed. Exits nonzero on any failure.
set -u
cd "$(dirname "$0")/.."

COMPOSE=deploy/dev/compose.yaml
SECRETS=deploy/dev/secrets
API=http://172.17.0.1:8090
EDGE_HTTP=http://127.0.0.1:8081
EDGE_HTTPS=https://127.0.0.1:8445
ORIGIN_IP=192.88.99.10
STUB_PY="$(mktemp)"; STUB_TOK="$(mktemp)"
JAR="$(mktemp)"
API_PID=""; STUB_PID=""
# The compose supervisor (scripts/edge-supervise.sh) must stay out of the
# run: it reconciles the stack every ~15s and would fight the teardown and
# fresh-volume setup below. Off for the run, restored by the EXIT trap.
SUPERVISE_OFF=deploy/dev/.supervise-off
trap 'kill ${API_PID:-0} ${STUB_PID:-0} 2>/dev/null; rm -f "$STUB_PY" "$STUB_TOK" "$JAR" "$SUPERVISE_OFF"' EXIT

[ -f .env ] || { echo "no .env at repo root (create it yourself; never paste it here)" >&2; exit 2; }
mkdir -p outbox "$SECRETS" && chmod 755 "$SECRETS"
TS=$(date +%s)-$RANDOM
U="accept-$TS@x.test"; PW="accept-password-1"
HOST="accept-a-$TS.example.test"
DENIED="accept-d-$TS.example.test"   # claimed, NEVER verified: ask must refuse
STRANGER="accept-x-$TS.example.test"  # never claimed at all
NTOK=""; NID=""; DOM=""

PASS=0 FAIL=0
pass() { echo "PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $*" >&2; FAIL=$((FAIL+1)); }
check() { # check <desc> <actual> <want>
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (want '$3', got '$2')"; fi
}
check_ne() { # check_ne <desc> <actual> <not-want>
  if [ "$2" != "$3" ]; then pass "$1"; else fail "$1 (got the unwanted '$3')"; fi
}
section() { echo; echo "== $*"; }

# dc — every compose call: root for the docker socket, internal issuer so
# the run mints certificates deterministically and never touches ACME.
dc() { sudo env GP_EDGE_ISSUER=internal GP_EDGE_API_BASE="$API" docker compose -f "$COMPOSE" --profile poller "$@"; }

# until_ok <timeout-s> <what> <shell-condition>: evaluated in THIS shell
# (dc is a function) until it succeeds; a FAIL line on timeout.
until_ok() {
  local timeout="$1" what="$2" cond="$3"
  local deadline=$((SECONDS + timeout))
  while [ $SECONDS -lt $deadline ]; do
    eval "$cond" >/dev/null 2>&1 && return 0
    sleep 1
  done
  fail "$what did not happen within ${timeout}s"
  return 1
}
code_of() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# cb talks as the operator (session cookie); the XFF header mirrors
# demo-nodes.sh (GP_TRUSTED_PROXIES=127.0.0.1/32 keys per-IP counters).
CIP="10.$((RANDOM%200+20)).$((RANDOM%200+20)).$((RANDOM%200+20))"
cb()  { curl -s -w '\n%{http_code}' -b "$JAR" -c "$JAR" -H "X-Forwarded-For: $CIP" "$@"; }
codeof(){ printf '%s' "$1" | tail -n 1; }
bodyof(){ printf '%s' "$1" | head -n -1; }
mail_token() { grep -m1 -o 'token: [A-Za-z0-9_-]*' "$(ls -t outbox/*.txt | head -1)" | cut -d' ' -f2; }
jget() { printf '%s' "$1" | python3 -c "import json,sys; print(json.load(sys.stdin)$2)"; }

kill_api() { if [ -n "${API_PID:-}" ]; then sudo kill "$API_PID" 2>/dev/null; API_PID=""; sleep 0.5; fi; }
# start_api: clean environment, this run's operator + snapshot key, the
# stub as its only resolver. .env (cwd) supplies the database URL.
start_api() {
  env -i ENV=development GP_HTTP_ADDR=172.17.0.1:8090 \
    GP_DNS_RESOLVERS=127.0.0.1:5344 GP_SNAPSHOT_KEY="$KEY" \
    GP_OPERATOR_EMAILS="$U" GP_TRUSTED_PROXIES=127.0.0.1/32 \
    ./gatepost >/tmp/gatepost-edge-accept-api.log 2>&1 &
  API_PID=$!
  local C=""
  for _ in $(seq 1 30); do
    C=$(code_of "$API/api/me"); [ "$C" != "000" ] && [ -n "$C" ] && return 0
    sleep 0.5
  done
  fail "API did not come up (/tmp/gatepost-edge-accept-api.log)"
  return 1
}

# --- 0. preflight: binary, ports, the API address is ours ------------------
section "setup"
touch "$SUPERVISE_OFF"   # supervisor out of the run (restored by the trap)
go build -o gatepost ./cmd/gatepost || exit 2

# Tear down any leftover stack FIRST — dc down removes the docker networks
# (and their 192.88.99.0/24 route), so the preflight check below passes.
dc down >/dev/null 2>&1
for v in caddy_data caddy_config poller_state; do sudo docker volume rm "gatepost-edge-dev_$v" >/dev/null 2>&1; done

# Kill any leftover process on the API port (port 8090, not 8080 — docker's
# NAT for the host-publish 8080 would intercept 172.17.0.1:8080).
OLD_PID=$(sudo ss -ltnp 'sport = :8090' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$OLD_PID" ]; then sudo kill "$OLD_PID" 2>/dev/null; sleep 1; fi
# a previous run's stub can survive a killed script (it has no parent to
# clean it up); the port is ours for this run
STUB_PID=$(sudo ss -ltnup 'sport = :5344' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$STUB_PID" ]; then sudo kill "$STUB_PID" 2>/dev/null; sleep 0.5; fi
if [ -s "$SECRETS/snapshot_key" ]; then
  KEY="$(cat "$SECRETS/snapshot_key")"
else
  KEY="accept-snapshot-key-$(openssl rand -hex 16)"
  printf '%s' "$KEY" > "$SECRETS/snapshot_key"
fi
chmod 644 "$SECRETS/snapshot_key"
check_ne "snapshot key material is non-empty" "$KEY" ""
check "no host route squats the origin fixture's range (192.88.99.0/24)" \
  "$(ip route show | grep -c 192.88.99)" "0"

# the DNS TXT stub (raw UDP, from demo-nodes.sh): answers _gatepost-verify.*
# with whatever token file it holds, re-read on every query
cat > "$STUB_PY" <<'EOF'
import socket, sys
tok_path = sys.argv[1]
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 5344))
while True:
    data, addr = srv.recvfrom(4096)
    try:
        i = 12
        while data[i] != 0:
            i += 1 + data[i]
        i += 1
        question = data[12:i+4]
        txt = b'gatepost-verify=' + open(tok_path, 'rb').read().strip()
        answer = (b'\xc0\x0c' + b'\x00\x10\x00\x01' + b'\x00\x00\x00\x05'
                  + (len(txt) + 1).to_bytes(2, 'big') + bytes([len(txt)]) + txt)
        srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
                   + question + answer, addr)
    except Exception:
        pass
EOF
python3 "$STUB_PY" "$STUB_TOK" >/dev/null 2>&1 &
STUB_PID=$!
sleep 0.5; kill -0 "$STUB_PID" 2>/dev/null && pass "DNS TXT stub up on 127.0.0.1:5344" || { fail "DNS stub did not start"; exit 2; }

start_api && pass "API up on $API"

# the compose stack: fresh volumes (certs, caddy state, poller state) so
# every byte of this run's access log and cert store belongs to this run
dc up -d --build edge origin-test >/dev/null 2>&1 \
  && pass "compose stack rebuilt: edge + origin-test (fresh volumes)" \
  || { fail "compose up failed"; exit 2; }

# --- the operator: signup, mint the node, claim + verify the domain ------
OUT=$(cb -X POST "$API/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")
check "operator signup" "$(codeof "$OUT")" "200"
OUT=$(cb -X POST "$API/auth/verify" -H 'Content-Type: application/json' -d "{\"token\":\"$(mail_token)\"}")
check "operator verified (mail loop)" "$(codeof "$OUT")" "200"
OUT=$(cb -X POST "$API/v1/nodes" -H 'Content-Type: application/json' -d "{\"name\":\"accept-edge-$TS\",\"role\":\"edge\"}")
check "node minted (201)" "$(codeof "$OUT")" "201"
NTOK=$(jget "$(bodyof "$OUT")" '["token"]')
NID=$(jget "$(bodyof "$OUT")" '["node"]["id"]')
printf '%s' "$NTOK" > "$SECRETS/token" && chmod 644 "$SECRETS/token"
check_ne "node token material is non-empty" "$NTOK" ""

OUT=$(cb -X POST "$API/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST\"}")
check "claim $HOST" "$(codeof "$OUT")" "201"
DOM=$(jget "$(bodyof "$OUT")" '["domain"]["id"]')
VT=$(jget "$(bodyof "$(cb "$API/v1/domains/$DOM/verification")")" '["verification"]["record_value"]' | cut -d= -f2)
printf '%s' "$VT" > "$STUB_TOK"
OUT=$(cb -X POST "$API/v1/domains/$DOM/verify")
check "verify $HOST against the TXT stub" "$(codeof "$OUT")" "200"
OUT=$(cb -X POST "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9001,\"tls_verify\":false}")
check "origin set: http://$ORIGIN_IP:9001 (public-range fixture)" "$(codeof "$OUT")" "201"
OUT=$(cb -X POST "$API/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$DENIED\"}")
check "claim $DENIED (left UNVERIFIED on purpose)" "$(codeof "$OUT")" "201"

# the poller starts only now: it reads the just-minted token secret, and
# --build rebuilds its image so the binary carries this tree's edge code
dc up -d --build poller >/dev/null 2>&1 && pass "poller up (node token from $SECRETS/token)" \
  || { fail "poller did not start"; exit 2; }
until_ok 30 "poller applied the snapshot" \
  'dc logs poller 2>/dev/null | grep -q "applied snapshot generation"'
until_ok 30 "edge serves $HOST from origin-test" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
pass "snapshot fetched and the edge serves the origin through the tunnel"

# --- fixture: every origin behavior, through the edge --------------------
section "origin-test fixture through the edge"
SLOW=$(curl -s -H "Host: $HOST" "$EDGE_HTTP/slow" -w ' %{time_total}')
check "/slow: delayed body, >= 2s (took ${SLOW##* }s)" \
  "$(awk -v t="${SLOW##* }" 'BEGIN{print (t>=2)?"y":"n"}')" "y"
curl -s -H "Host: $HOST" "$EDGE_HTTP/big" -o /tmp/gpaccept-big
check "/big: 5 MiB streamed body" "$(wc -c < /tmp/gpaccept-big)" "5242880"
H=$(curl -s -D - -o /dev/null -H "Host: $HOST" "$EDGE_HTTP/redirect")
check "/redirect: edge passes the 302 through (does not follow)" \
  "$(printf '%s' "$H" | grep -c -i '^HTTP/1.1 302')" "1"
check "/redirect: Location header survives" "$(printf '%s' "$H" | grep -i -c '^location: /ok')" "1"
check "/redirect: a following client lands on /ok" \
  "$(curl -s -L -H "Host: $HOST" "$EDGE_HTTP/redirect" | grep -c 'port 9001')" "1"
H=$(curl -s -D - -o /dev/null -H "Host: $HOST" "$EDGE_HTTP/cookie")
check "/cookie: Set-Cookie passes through" "$(printf '%s' "$H" | grep -i -c 'set-cookie: gporigin=port-9001')" "1"
check "/status/503: status code passes through" "$(code_of -H "Host: $HOST" "$EDGE_HTTP/status/503")" "503"
H=$(curl -s -D - -H "Host: $HOST" "$EDGE_HTTP/chunked")
check "/chunked: chunked transfer to the client" "$(printf '%s' "$H" | grep -i -c 'transfer-encoding: chunked')" "1"
check "/chunked: all three chunks arrived" \
  "$(printf '%s' "$H" | grep -c 'chunk-one chunk-two chunk-three')" "1"

# --- a) cold start, API down, saved snapshot ------------------------------
section "a) cold start with the API down and a saved snapshot"
kill_api
check "API is down" "$(code_of "$API/api/me")" "000"
# Restart edge and poller in dependency order: the poller shares the edge's
# network namespace (network_mode: service:edge), so edge must be running
# before the poller starts. A combined "dc restart edge poller" races — Docker
# Compose starts the poller before the edge's namespace is ready, and the
# poller exits (cannot join network namespace). Stop poller, restart edge,
# wait for edge, then recreate the poller.
dc stop poller >/dev/null 2>&1
dc restart edge >/dev/null 2>&1
# Edge needs ~1s to boot Caddy and bind :80/:443.
until_ok 10 "edge is back after restart" 'code_of "$EDGE_HTTP/ok"' >/dev/null 2>&1 || true
dc up -d --force-recreate poller >/dev/null 2>&1
until_ok 45 "the restarted edge serves from the SAVED snapshot" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
until_ok 15 "a) https serves the snapshot (on-demand internal cert)" \
  '[ "$(code_of -sk --resolve "$HOST:8445:127.0.0.1" "https://$HOST:8445/ok")" = "200" ]'
C=$(code_of -sk --resolve "$HOST:8445:127.0.0.1" "https://$HOST:8445/ok")
check "a) https serves too (ask answers from the snapshot, internal cert)" "$C" "200"

# --- b) cold start, no snapshot -------------------------------------------
section "b) cold start with NO snapshot: 421 for every host"
dc down >/dev/null 2>&1
sudo docker volume rm gatepost-edge-dev_poller_state >/dev/null 2>&1
dc up -d edge origin-test poller >/dev/null 2>&1
until_ok 30 "the no-snapshot edge takes the deny-all posture" \
  '[ "$(code_of -H "Host: $HOST" $EDGE_HTTP/ok)" = 421 ]'
check "b) known host over http = 421" "$(code_of -H "Host: $HOST" "$EDGE_HTTP/ok")" "421"
check "b) denied host over http = 421" "$(code_of -H "Host: $DENIED" "$EDGE_HTTP/ok")" "421"
check "b) unknown host over http = 421" "$(code_of -H "Host: $STRANGER" "$EDGE_HTTP/ok")" "421"
C=$(code_of -sk --resolve "$HOST:8445:127.0.0.1" "$EDGE_HTTPS/ok")
check "b) known host over https = 421 (fallback cert, no ask answer)" "$C" "421"

# --- c) tampered snapshot rejected, last-good keeps serving ---------------
section "c) tampered snapshot rejected; the last-good config keeps serving"
start_api
until_ok 120 "the poller refetches a good config after the no-snapshot boot" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
dc exec poller sh -c "sed -i 's/9001/9003/' /state/snapshot.json"
C=$(code_of -H "Host: $HOST" "$EDGE_HTTP/ok")
check "c) edge serves while the on-disk snapshot is tampered (caddy untouched)" "$C" "200"
dc stop poller >/dev/null 2>&1
dc start poller >/dev/null 2>&1
until_ok 30 "the restarted poller REJECTS the tampered snapshot (log line)" \
  'dc logs --since 2m poller 2>/dev/null | grep -q -e "failed verification" -e "unusable"'
C=$(code_of -H "Host: $HOST" "$EDGE_HTTP/ok")
check "c) the last-good config kept serving across the poller restart" "$C" "200"
until_ok 30 "the poller refetches and re-applies the good config" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
check "c) the tampered bytes were never applied (still origin 9001)" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9001')" "1"

# --- d) origin change through the API reaches the edge -------------------
section "d) an API origin change reaches the edge (timed)"
T0=$SECONDS
OUT=$(cb -X PUT "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9002,\"tls_verify\":false}")
check "origin replaced via PUT (port 9001 -> 9002)" "$(codeof "$OUT")" "200"
until_ok 120 "the new origin reaches the edge" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9002"'
echo "     origin change reached the edge in $((SECONDS - T0))s (poll interval 5s + reload cooldown 60s)"
check "d) the edge now serves the new origin" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9002')" "1"

# --- e) spoofed X-Forwarded-For replaced ----------------------------------
section "e) spoofed X-Forwarded-For is replaced with the real client IP"
BASE=$(curl -s -H "Host: $HOST" "$EDGE_HTTP/echo-headers")
SPOOF=$(curl -s -H "Host: $HOST" -H "X-Forwarded-For: 1.2.3.4" "$EDGE_HTTP/echo-headers")
XFF_BASE=$(sed -n 's/.*xff=\([^ ]*\).*/\1/p' <<< "$BASE")
XFF_SPOOF=$(sed -n 's/.*xff=\([^ ]*\).*/\1/p' <<< "$SPOOF")
check "e) the origin sees the public hostname as Host" \
  "$(sed -n 's/.*host=\([^ ]*\).*/\1/p' <<< "$BASE")" "$HOST"
check "e) spoofed XFF replaced with the real client IP ($XFF_SPOOF)" "$XFF_SPOOF" "$XFF_BASE"
check "e) the spoofed value 1.2.3.4 never reached the origin" \
  "$(grep -c '1.2.3.4' <<< "$SPOOF")" "0"

# --- f) private/metadata origins never reached ---------------------------
section "f) private and metadata origins are refused, never reached"
for BAD in "169.254.169.254:metadata" "10.99.99.99:private-rfc1918" "127.0.0.1:loopback"; do
  ADDR="${BAD%%:*}"; WHAT="${BAD##*:}"
  OUT=$(cb -X PUT "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
    -d "{\"scheme\":\"http\",\"address\":\"$ADDR\",\"port\":80,\"tls_verify\":false}")
  check "f) origin $WHAT refused at set time (422)" "$(codeof "$OUT")" "422"
done
check "f) the edge still serves the last-good origin" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9002')" "1"

# --- g) unknown host: 421, no certificate attempt -------------------------
section "g) unknown host: 421 and no certificate attempt"
C=$(code_of -H "Host: $STRANGER" "$EDGE_HTTP/ok")
check "g) unknown host over http = 421" "$C" "421"
C=$(code_of -sk --resolve "$STRANGER:8445:127.0.0.1" "$EDGE_HTTPS/ok")
check "g) unknown host over https = 421 (fallback handshake)" "$C" "421"
check "g) no log line names the stranger (no issuance attempt)" \
  "$(dc logs edge 2>/dev/null | grep -c "$STRANGER")" "0"
check "g) no certificate file for the stranger" \
  "$(dc exec edge sh -c "grep -ri '$STRANGER' /data/caddy/certificates 2>/dev/null | wc -l")" "0"

# --- h) allowed host gets a certificate; denied does not ------------------
section "h) allowed host gets a certificate (internal issuer); denied host does not"
SAN=$(echo | openssl s_client -connect 127.0.0.1:8445 -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -text 2>/dev/null | grep -A1 'Alternative Name' | grep -c "$HOST")
check "h) the allowed host's certificate carries the hostname" "$SAN" "1"
check_ne "h) the allowed host's certificate is persisted" \
  "$(dc exec edge sh -c "grep -rl '$HOST' /data/caddy/certificates 2>/dev/null | wc -l")" "0"
ASK=$(dc exec poller wget -S -O - "http://127.0.0.1:8099/check?domain=$DENIED" 2>&1 | grep -c 'HTTP/1.1 421')
check_ne "h) the ask endpoint refuses the denied host (421)" "$ASK" "0"
# busybox wget prints the status line twice (-S dump + its own error line);
# the fallback cert is SAN-ONLY (subject= empty), so the name lives in the
# SAN extension, not the CN.
FALL=$(echo | openssl s_client -connect 127.0.0.1:8445 -servername "$DENIED" 2>/dev/null \
  | openssl x509 -noout -text 2>/dev/null | grep -A1 'Alternative Name')
check "h) the denied host completes TLS only on the FALLBACK cert (SAN: edge.invalid)" \
  "$(grep -c 'edge.invalid' <<< "$FALL")" "1"
check "h) the denied host's cert does not name it" "$(grep -c "$DENIED" <<< "$FALL")" "0"
C=$(code_of -sk --resolve "$DENIED:8445:127.0.0.1" "$EDGE_HTTPS/ok")
check "h) the denied host serves 421" "$C" "421"
check "h) no certificate file for the denied host" \
  "$(dc exec edge sh -c "grep -ri '$DENIED' /data/caddy/certificates 2>/dev/null | wc -l")" "0"

# --- i) API down/backup mid-run; revoked token -----------------------------
section "i) API stopped mid-run: keeps serving; restarted: recovers; revoked: last-good"
kill_api
check "i) the API is down" "$(code_of "$API/api/me")" "000"
check "i) the edge keeps serving with the API down" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9002')" "1"
sleep 8
FLOOD=$(dc logs --since 1m poller 2>/dev/null | grep -c 'poll failed')
if [ "$FLOOD" -le 4 ]; then
  pass "i) poll failures are throttled in the poller log ($FLOOD line(s) in a minute, not one per 5s tick)"
else
  fail "i) poll-failure lines flooded the log ($FLOOD in a minute)"
fi
start_api
T0=$SECONDS
OUT=$(cb -X PUT "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9001,\"tls_verify\":false}")
check "origin PUT after the API restart (recovery probe)" "$(codeof "$OUT")" "200"
until_ok 120 "the edge recovers: the change propagates again" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
echo "     recovery: the post-restart change reached the edge in $((SECONDS - T0))s"
OUT=$(cb -X POST "$API/v1/nodes/$NID/revoke")
check "node revoked (idempotent route)" "$(codeof "$OUT")" "200"
sleep 8  # a few poll ticks against the 30s log-throttle gap
check "i) the poller logged the 401 (once, loudly)" \
  "$(dc logs --since 1m poller 2>/dev/null | grep -c '401 from API')" "1"
check "i) the revoked node keeps serving the last-good config" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9001')" "1"

# --- j) the whole run's access log: no secrets, no query strings ----------
section "j) the whole run's access log: no secrets, no query strings"
# one maximally hostile request first: query + every credential header
curl -s -o /dev/null -H "Host: $HOST" \
  -H 'Authorization: Bearer LEAK-AUTH-123' -H 'Cookie: session=LEAK-COOKIE-456' \
  -H 'X-Api-Key: LEAK-APIKEY-789' -H 'Referer: http://leak.example.test/r?sid=LEAK-REF-321' \
  "$EDGE_HTTP/leak-me?token=SECRET123&code=abc"
LOG=$(dc exec edge cat /data/logs/access.json)
LINES=$(printf '%s\n' "$LOG" | grep -c '"msg":"handled request"')
if [ "$LINES" -gt 0 ]; then pass "the access log recorded the run ($LINES requests)"; else fail "access log is empty"; fi
for POISON in "SECRET123" "code=abc" "token=" "LEAK-AUTH-123" "LEAK-COOKIE-456" \
               "LEAK-APIKEY-789" "LEAK-REF-321" "Authorization" "Cookie" "X-Api-Key" \
               "Referer" "Set-Cookie" "gporigin=" "$NTOK" "$KEY" "1.2.3.4"; do
  N=$(printf '%s\n' "$LOG" | grep -c -F -- "$POISON")
  check "j) the access log has no '$POISON'" "$N" "0"
done
Q=$(printf '%s\n' "$LOG" | grep -c '?')
check "j) not one question mark anywhere (no query strings at all)" "$Q" "0"
STRUCT=$(printf '%s\n' "$LOG" | python3 -c '
import json, sys
bad = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    m = json.loads(line)
    req = m.get("request", {})
    if not m.get("user_agent"): bad += 1        # the one kept header value
    if "uri" in req or "headers" in req: bad += 1  # no uri, no request headers
    if "resp_headers" in m: bad += 1            # no response headers
print(bad)
')
check "j) every line: user_agent present, no uri/headers/resp_headers" "$STRUCT" "0"
TWIN=$(dc logs edge 2>/dev/null | grep -c 'handled request')
check "j) no access entry ever reached the edge container's stderr (docker log)" "$TWIN" "0"

section "verdict"
echo "=== edge acceptance: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
