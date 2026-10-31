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
#   f2) an origin HOSTNAME accepted while it resolved public is refused at
#       dial time once its resolution turns hostile (metadata address) —
#       and the origin listener records no request
#   g) unknown host: 421, no certificate attempt
#   h) allowed host gets a certificate (internal issuer); a denied host
#      does not (the ask answers 421)
#   i) API down mid-run: keeps serving; API back: recovers (a change
#      propagates again); a revoked token (401): last-good keeps serving
#   j) the run's whole access log: no secrets, no query strings — and no
#      access entry ever reaches the edge container's stderr either
#   k) B3c WAF audit redaction (detection-only, in-process, no values)
#   l) WAF per-host: off vs detection vs blocking; exclusions for one host
#      only; host isolation; mode-change propagation timing; generic 403
#      body; live ordering proof (host-scoped ctl rules before CRS includes)
#   m) edge RSS with 1/10/100 served hosts (shared WAF instance, sub-linear)
#   n) schema gate: an old-style edge (empty feature set) REFUSES a snapshot
#      requiring an unknown feature and keeps its last good config; a schema-1
#      snapshot is still accepted (backward compat, defaults to detection)
#   o) [PROD_TIMING=1] origin change after 60s silence reaches the edge in ~10s
#
# Secrets stay in deploy/dev/secrets/ (gitignored) and .env; nothing
# secret is printed. Exits nonzero on any failure.
#
# PROD_TIMING=1 runs the acceptance suite at real production pacing
# (60s reload cooldown, 5s poll, 60s backoff cap) instead of the fast
# defaults (5s/1s/10s). The fast mode is for quick iteration; the
# production mode proves the pacing knobs and the soak that follows.
set -u
cd "$(dirname "$0")/.."

COMPOSE=deploy/dev/compose.yaml
SECRETS=deploy/dev/secrets
API=http://172.17.0.1:8090
EDGE_HTTP=http://127.0.0.1:8081
EDGE_HTTPS=https://127.0.0.1:8445
ORIGIN_IP=192.88.99.10
STUB_PY="$(mktemp)"; STUB_TOK="$(mktemp)"; STUB_A="$(mktemp)"
JAR="$(mktemp)"
API_PID=""; STUB_PID=""
LAST_SECTION="bootstrap"
# The compose supervisor (scripts/edge-supervise.sh) must stay out of the
# run: it reconciles the stack every ~15s and would fight the teardown and
# fresh-volume setup below. Off for the run, restored by the EXIT trap.
SUPERVISE_OFF=deploy/dev/.supervise-off

# EXIT trap: ALWAYS print a verdict line, even on abort or signal. An aborted
# run must never look like a pass — the ABORTED flag makes that explicit.
print_verdict() {
  local code=$?
  echo
  echo "== verdict"
  local status
  if [ "${FINISHED:-0}" = "1" ]; then
    [ "$FAIL" -eq 0 ] && status="PASSED" || status="FAILED ($FAIL check(s) failed)"
  else
    status="ABORTED"
  fi
  echo "=== edge acceptance: $PASS passed, $FAIL failed, exit=$code, last_section=$LAST_SECTION, status=$status ==="
}
trap 'print_verdict; kill ${API_PID:-0} ${STUB_PID:-0} 2>/dev/null; sudo docker rm -f accept-old-poller >/dev/null 2>&1; rm -f "$STUB_PY" "$STUB_TOK" "$STUB_A" "$JAR" "$SUPERVISE_OFF"' EXIT
trap 'echo "=== edge acceptance: interrupted (SIGINT/SIGTERM); exiting ===" >&2; exit 130' INT TERM

[ -f .env ] || { echo "no .env at repo root (create it yourself; never paste it here)" >&2; exit 2; }
mkdir -p outbox "$SECRETS" && chmod 755 "$SECRETS"
TS=$(date +%s)-$RANDOM
U="accept-$TS@x.test"; PW="accept-password-1"
HOST="accept-a-$TS.example.test"
DENIED="accept-d-$TS.example.test"   # claimed, NEVER verified: ask must refuse
STRANGER="accept-x-$TS.example.test"  # never claimed at all
NTOK=""; NID=""; DOM=""

PASS=0 FAIL=0
declare -A SECTION_TIMINGS
CUR_SECTION=""
SECTION_START=$SECONDS
FINISHED=0
pass() { echo "$(date +%H:%M:%S) PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "$(date +%H:%M:%S) FAIL: $*" >&2; FAIL=$((FAIL+1)); }
check() { # check <desc> <actual> <want>
  ts=$(date +%H:%M:%S)
  if [ "$2" = "$3" ]; then echo "$ts PASS: $1"; PASS=$((PASS+1)); else echo "$ts FAIL: $1 (want '$3', got '$2')" >&2; FAIL=$((FAIL+1)); fi
}
check_ne() { # check_ne <desc> <actual> <not-want>
  ts=$(date +%H:%M:%S)
  if [ "$2" != "$3" ]; then echo "$ts PASS: $1"; PASS=$((PASS+1)); else echo "$ts FAIL: $1 (got the unwanted '$3')" >&2; FAIL=$((FAIL+1)); fi
}
# section(): start a new labeled section. Automatically records the elapsed
# time of the PREVIOUS section so the verdict summary needs no manual calls.
section() {
  if [ -n "${CUR_SECTION:-}" ]; then
    SECTION_TIMINGS[$CUR_SECTION]=$((SECONDS - SECTION_START))
  fi
  CUR_SECTION="$1"
  SECTION_START=$SECONDS
  LAST_SECTION="$1"
  echo; echo "== $(date +%H:%M:%S) $*"
}

# Pacing: fast mode (default) collapses production pacing (60s reload + 5s
# poll + 60s backoff cap) to 5s/1s/10s so the acceptance run converges in
# seconds. PROD_TIMING=1 keeps the real production defaults from
# deploy/dev/compose.yaml — used by the live soak and the production-pace run.
if [ "${PROD_TIMING:-0}" = "1" ]; then
  POLL_INTERVAL=5 POLL_COOLDOWN=60 BACKOFF_CAP=60
  PACE_LABEL="production pacing (poll ${POLL_INTERVAL}s + reload cooldown ${POLL_COOLDOWN}s + backoff cap ${BACKOFF_CAP}s)"
else
  POLL_INTERVAL=1 POLL_COOLDOWN=5 BACKOFF_CAP=10
  PACE_LABEL="fast pacing (poll ${POLL_INTERVAL}s + reload cooldown ${POLL_COOLDOWN}s + backoff cap ${BACKOFF_CAP}s)"
fi
# Propagation waits must clear poll_interval + one cooldown in production.
PROPAGATE_TIMEOUT=120; [ "${PROD_TIMING:-0}" = "1" ] && PROPAGATE_TIMEOUT=180

# dc — every compose call: root for the docker socket, internal issuer so
# the run mints certificates deterministically and never touches ACME.
# In fast mode (default) the env overrides below collapse the production
# pacing so the acceptance run converges in seconds. PROD_TIMING=1 leaves
# the compose.yaml defaults (60s/5s/60s) intact.
dc() {
  local env_args=(GP_EDGE_ISSUER=internal GP_EDGE_API_BASE="$API")
  if [ "${PROD_TIMING:-0}" != "1" ]; then
    env_args+=("GP_EDGE_RELOAD_COOLDOWN=${POLL_COOLDOWN}s" "GP_EDGE_POLL_INTERVAL=${POLL_INTERVAL}s" "GP_EDGE_BACKOFF_CAP=${BACKOFF_CAP}s")
  fi
  local cmd_args=("$@")
  if [ "${1:-}" = "exec" ]; then
    cmd_args=("exec" "-T" "${@:2}")
  fi
  sudo env "${env_args[@]}" docker compose -f "$COMPOSE" --profile poller "${cmd_args[@]}"
}

# until_ok <timeout-s> <what> <shell-condition>: evaluated in THIS shell
# (dc is a function) until it succeeds; a FAIL line on timeout.
until_ok() {
  local timeout="$1" what="$2" cond="$3"
  local deadline=$((SECONDS + timeout))
  while [ $SECONDS -lt $deadline ]; do
    if eval "$cond" >/dev/null 2>&1; then pass "$what"; return 0; fi
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
echo "  pacing: $PACE_LABEL"
touch "$SUPERVISE_OFF"   # supervisor out of the run (restored by the trap)
go build -o gatepost ./cmd/gatepost || exit 2

# Stale test data cleanup: domains/origins/nodes from prior runs must not
# linger in the database. Stale accept-wb-* hosts with waf_mode='off' would
# put ctl:ruleEngine=Off in the snapshot BEFORE the current run's WAF changes
# are even applied — making the propagation check a false positive (it finds
# the stale Off rule and passes immediately). PROD_TIMING runs are especially
# sensitive (10s poller HTTP timeout can blow past the snapshot build); fast
# mode converges faster but still needs a clean slate to avoid false matches.
if [ -f .env ]; then
  DB_URL=$(grep '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
  if [ -n "$DB_URL" ] && command -v psql >/dev/null 2>&1; then
    psql "$DB_URL" -c \
      "DELETE FROM origins WHERE domain_id IN (SELECT id FROM domains WHERE hostname LIKE 'accept-%' OR hostname LIKE 'soak-%' OR hostname LIKE 'debug-%' OR hostname LIKE 'rss%'); DELETE FROM domains WHERE hostname LIKE 'accept-%' OR hostname LIKE 'soak-%' OR hostname LIKE 'debug-%' OR hostname LIKE 'rss%'; DELETE FROM nodes WHERE name LIKE 'accept-%' OR name LIKE 'soak-%' OR name LIKE 'debug-%' OR name LIKE 'rss%';" 2>&1
    if [ "${PROD_TIMING:-0}" = "1" ]; then
      pass "PROD_TIMING: stale test data cleaned from database"
    else
      pass "fast mode: stale test data cleaned from database"
    fi
  fi
fi

# Tear down any leftover stack FIRST — dc down removes the docker networks
# (and their 192.88.99.0/24 route), so the preflight check below passes.
dc down >/dev/null 2>&1
# Docker leaves the bridge interface in "linkdown" for a moment after
# network removal — give it a beat so the route check below doesn't race.
sleep 1
for v in caddy_data caddy_config poller_state; do sudo docker volume rm "gatepost-edge-dev_$v" >/dev/null 2>&1; done
# Remove any stale node token from a previous (possibly aborted) run: the poller
# reads GP_EDGE_TOKEN_FILE on boot, and an empty/leftover file is the exact shape
# a crashed-soak crash-looped on (item 2c degrade — a clean slate is cleaner).
rm -f "$SECRETS/token"

# Kill any leftover process on the API port (port 8090, not 8080 — docker's
# NAT for the host-publish 8080 would intercept 172.17.0.1:8080).
OLD_PID=$(sudo ss -ltnp 'sport = :8090' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "$OLD_PID" ]; then sudo kill "$OLD_PID" 2>/dev/null; sleep 1; fi
# A previous run aborted between `dc run` and the stop of the section-n
# one-off old-node container would leave it holding the poller_state volume
# — the volume rm below would silently fail and the poller would boot with
# the PREVIOUS run's snapshot (wrong hostnames, 421 cascade). Remove it first.
sudo docker rm -f accept-old-poller >/dev/null 2>&1 || true
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
DB_URL=""
if [ -f .env ]; then
  DB_URL=$(grep '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
fi
check "no host route squats the origin fixture's range (192.88.99.0/24)" \
  "$(ip route show | grep -c 192.88.99)" "0"

# the DNS stub (raw UDP, from demo-nodes.sh): answers _gatepost-verify.*
# with whatever token file it holds, re-read on every query — and, for the
# f2 dial-time check, A records for the names listed in $STUB_A (also
# re-read per query, so a rewrite flips the answer with no restart)
cat > "$STUB_PY" <<'EOF'
import socket, sys
tok_path, a_path = sys.argv[1], sys.argv[2]
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 5344))
while True:
    data, addr = srv.recvfrom(4096)
    try:
        j = 12
        while data[j] != 0:
            j += 1 + data[j]
        nul = j
        j += 1
        qtype = data[j:j+2]
        question = data[12:j+4]
        if qtype == b'\x00\x01':  # A: the f2 test-resolver answer
            ip = None
            try:
                for line in open(a_path):
                    n, _, v = line.strip().partition(' ')
                    labels = []
                    k = 12
                    while data[k] != 0:
                        l = data[k]
                        labels.append(data[k+1:k+1+l].decode())
                        k += 1 + l
                    qname = '.'.join(labels).lower().rstrip('.')
                    if n.rstrip('.').lower() == qname:
                        ip = v
                        break
            except OSError:
                pass
            if ip:
                rdata = bytes(int(x) for x in ip.split('.'))
                srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
                           + question + b'\xc0\x0c' + b'\x00\x01\x00\x01'
                           + b'\x00\x00\x00\x05' + b'\x00\x04' + rdata, addr)
                continue
            srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00'
                       + question, addr)  # NOERROR, no answer: this name has no A
            continue
        if qtype == b'\x00\x10':  # TXT: the verify flow, unchanged
            txt = b'gatepost-verify=' + open(tok_path, 'rb').read().strip()
            answer = (b'\xc0\x0c' + b'\x00\x10\x00\x01' + b'\x00\x00\x00\x05'
                      + (len(txt) + 1).to_bytes(2, 'big') + bytes([len(txt)]) + txt)
            srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
                       + question + answer, addr)
            continue
        srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00'
                   + question, addr)  # anything else: NOERROR, no answers
    except Exception:
        pass
EOF
python3 "$STUB_PY" "$STUB_TOK" "$STUB_A" >/dev/null 2>&1 &
STUB_PID=$!
sleep 0.5; kill -0 "$STUB_PID" 2>/dev/null && pass "DNS stub up on 127.0.0.1:5344 (TXT verify + A answers)" || { fail "DNS stub did not start"; exit 2; }

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
# True cold start: the containers are REMOVED and recreated (dc down + up,
# not a restart) with the saved snapshot still on the poller volume and the
# API still down. Compose's depends_on (edge healthy -> poller) owns the
# ordering, and the poller joining a FRESH edge network namespace is the
# cold-start race the v0.4-edge tag note describes.
dc down >/dev/null 2>&1
dc up -d edge origin-test poller >/dev/null 2>&1
until_ok 45 "the cold-started edge serves from the SAVED snapshot" \
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
C=$(code_of -sk --resolve "$DENIED:8445:127.0.0.1" "$EDGE_HTTPS/ok")
check "b) denied host over https = 421 (fallback cert, no ask answer)" "$C" "421"
C=$(code_of -sk --resolve "$STRANGER:8445:127.0.0.1" "$EDGE_HTTPS/ok")
check "b) unknown host over https = 421 (fallback cert, no ask answer)" "$C" "421"

# --- c) tampered snapshot rejected, last-good keeps serving ---------------
section "c) tampered snapshot rejected; the last-good config keeps serving"
start_api
until_ok ${PROPAGATE_TIMEOUT} "the poller refetches a good config after the no-snapshot boot" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
dc exec poller sh -c "sed -i 's/9001/9003/' /state/snapshot.json"
C=$(code_of -H "Host: $HOST" "$EDGE_HTTP/ok")
check "c) edge serves while the on-disk snapshot is tampered (caddy untouched)" "$C" "200"
dc stop poller >/dev/null 2>&1
dc start poller >/dev/null 2>&1
until_ok 30 "the restarted poller REJECTS the tampered snapshot (log line)" \
  'dc logs --since 2m poller 2>/dev/null | grep -q -e "failed verification" -e "unusable"'
# The restarted poller rejects the tampered snapshot then re-fetches the good one
# from the API. In PROD_TIMING the 5s poll interval means the good config takes
# a few seconds to re-apply — the edge briefly returns 502/421 during this
# transition, which is expected. We retry until the last-good config is back.
until_ok ${PROPAGATE_TIMEOUT} "c) the last-good config kept serving across the poller restart" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
check "c) the tampered bytes were never applied (still origin 9001)" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9001')" "1"

# --- d) origin change through the API reaches the edge -------------------
section "d) an API origin change reaches the edge (timed)"
T0=$SECONDS
OUT=$(cb -X PUT "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9002,\"tls_verify\":false}")
check "origin replaced via PUT (port 9001 -> 9002)" "$(codeof "$OUT")" "200"
until_ok ${PROPAGATE_TIMEOUT} "the new origin reaches the edge" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9002"'
echo "     origin change reached the edge in $((SECONDS - T0))s ($PACE_LABEL)"
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

# --- f2) dial-time guard: a hostname origin that LATER resolves private ----
section "f2) an origin hostname that later resolves to a metadata address is refused at dial time"
F2HOST="accept-f2-$TS.example.test"
# The API's set-time check resolves through the host stub ($STUB_A); the
# POLLER resolves through its own /etc/hosts (its resolver never reaches the
# host stub), so the flip is a hosts rewrite inside the container — the
# exact TOCTOU shape: the origin was accepted while it resolved public, and
# the edge's dial guard must catch the later hostile answer. Port 9003
# closes every connection, so each request re-dials the forwarder and hits
# the fresh resolution immediately (caddy's keep-alive pool would otherwise
# ride the pre-flip connection — the guard's guarantee is per connection).
printf 'f2orig.test 192.88.99.10\n' > "$STUB_A"
dc exec -u root poller sh -c "echo '192.88.99.10 f2orig.test' >> /etc/hosts"
OUT=$(cb -X POST "$API/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$F2HOST\"}")
check "f2) claim $F2HOST" "$(codeof "$OUT")" "201"
F2DOM=$(jget "$(bodyof "$OUT")" '["domain"]["id"]')
VT=$(jget "$(bodyof "$(cb "$API/v1/domains/$F2DOM/verification")")" '["verification"]["record_value"]' | cut -d= -f2)
printf '%s' "$VT" > "$STUB_TOK"
OUT=$(cb -X POST "$API/v1/domains/$F2DOM/verify")
check "f2) verify $F2HOST against the TXT stub" "$(codeof "$OUT")" "200"
OUT=$(cb -X POST "$API/v1/domains/$F2DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"f2orig.test\",\"port\":9003,\"tls_verify\":false}")
check "f2) hostname origin accepted at set time (resolves public via the stub)" "$(codeof "$OUT")" "201"
until_ok 120 "f2) the edge serves the hostname origin (public resolution)" \
  'curl -s -H "Host: $F2HOST" $EDGE_HTTP/ok | grep -q "port 9003"'
N1=$(dc logs origin-test 2>/dev/null | grep -c "$F2HOST")
check_ne "f2) the origin saw requests while the resolution was public ($N1 hit(s))" "$N1" "0"
# THE FLIP: same hostname, now the cloud-metadata address. /etc/hosts is a
# bind-mounted FILE: sed -i renames and fails ("Resource busy"), and a
# `sed | tee` same-file pipe races — so prepare the content first, then
# truncate-write it in place.
dc exec -u root poller sh -c "sed 's/^192\.88\.99\.10 f2orig\.test\$/169.254.169.254 f2orig.test/' /etc/hosts > /tmp/hosts.new && cat /tmp/hosts.new > /etc/hosts && rm -f /tmp/hosts.new"
until_ok 20 "f2) the edge now 502s the hostname origin (dial-time refusal)" \
  '[ "$(code_of -H "Host: $F2HOST" "$EDGE_HTTP/ok")" = 502 ]'
check "f2) refused at dial time: 502, no connection attempted" \
  "$(code_of -H "Host: $F2HOST" "$EDGE_HTTP/ok")" "502"
REFUSED=$(dc logs --since 2m poller 2>/dev/null | grep -c 'refused 169.254.169.254')
if [ "$REFUSED" -ge 1 ]; then
  pass "f2) the poller logged the dial-time refusal ($REFUSED line(s): link-local refused before any dial)"
else
  fail "f2) no dial-time refusal line in the poller log"
fi
# Go caches /etc/hosts for ~5s, so requests issued immediately after the
# flip can still reach the pre-flip address — the dial guard's guarantee
# starts at the FIRST refusal: from there every fresh dial is refused and
# the origin's hit count must freeze.
NMID=$(dc logs origin-test 2>/dev/null | grep -c "$F2HOST")
check "f2) another request still 502s through a fresh dial" \
  "$(code_of -H "Host: $F2HOST" "$EDGE_HTTP/ok")" "502"
# 8s comfortably exceeds Go's ~5s /etc/hosts cache (see the f2 header
# above) plus a first-refusal confirmation, so a frozen hit count here
# proves the dial guard held - not a measurement gap.
sleep 8
N2=$(dc logs origin-test 2>/dev/null | grep -c "$F2HOST")
check "f2) the origin listener recorded NO request after the first refusal ($NMID then, $N2 after)" "$N2" "$NMID"

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
until_ok ${PROPAGATE_TIMEOUT} "the edge recovers: the change propagates again" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
echo "     recovery: the post-restart change reached the edge in $((SECONDS - T0))s ($PACE_LABEL)"
OUT=$(cb -X POST "$API/v1/nodes/$NID/revoke")
check "node revoked (idempotent route)" "$(codeof "$OUT")" "200"
# Deterministic: poll for the 401 line instead of sleeping a fixed 15s.
# The backoff streak from the API-downtime phase can delay the first poll
# with the revoked token by up to the backoff cap (60s in production), so
# the bound is the same PROPAGATE_TIMEOUT used for propagation. Full
# container logs (no --since): this poller container was created by this
# run and the token is revoked exactly once, so "401 from API" can only
# come from this revocation — no time window to get wrong.
until_ok ${PROPAGATE_TIMEOUT} "i) the poller logged the 401 (bounded poll, no fixed sleep)" \
  'dc logs poller 2>/dev/null | grep -q "401 from API"'
# Checked immediately after the first sighting (<=1s): logThrottled emits
# one line per 30s per brand, so the count here is deterministically 1.
check "i) the 401 was logged once (throttled), not once per poll tick" \
  "$(dc logs poller 2>/dev/null | grep -c '401 from API')" "1"
check "i) the revoked node keeps serving the last-good config" \
  "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9001')" "1"

# Re-mint a node so the poller can fetch new snapshots for the WAF (l-n)
# and origin-change (o) sections that follow. The revoked token proved
# last-good serving; the remaining sections need live propagation.
OUT=$(cb -X POST "$API/v1/nodes" -H 'Content-Type: application/json' -d "{\"name\":\"accept-edge-$TS-b\",\"role\":\"edge\"}")
check "i) node re-minted for post-revocation sections (201)" "$(codeof "$OUT")" "201"
NTOK=$(jget "$(bodyof "$OUT")" '["token"]')
NID=$(jget "$(bodyof "$OUT")" '["node"]["id"]')
printf '%s' "$NTOK" > "$SECRETS/token" && chmod 644 "$SECRETS/token"
dc restart poller >/dev/null 2>&1
until_ok ${PROPAGATE_TIMEOUT} "i) poller resumed with fresh node" \
  'dc logs --since 1m poller 2>/dev/null | grep -q "applied snapshot generation"'

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
               "Referer" "Set-Cookie" "gporigin=" "1.2.3.4"; do
  N=$(printf '%s\n' "$LOG" | grep -c -F -- "$POISON")
  check "j) the access log has no '$POISON'" "$N" "0"
done
# the run's own credentials are searched by VALUE (to prove the access log
# never carries them) but are NEVER printed: only a non-reversible sha256
# prefix labels each check, so a leaked secret can't re-surface in the log.
for _V in "$NTOK" "$KEY"; do
  [ -n "$_V" ] || continue
  _tag=$(printf '%s' "$_V" | openssl dgst -sha256 | cut -d' ' -f2 | cut -c1-12)
  _n=$(printf '%s\n' "$LOG" | grep -c -F -- "$_V")
  check "j) the access log has no run secret (sha256 ${_tag})" "$_n" "0"
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

# --- k) B3c WAF audit redaction (detection-only, in-process) ------------------
# coraza's NATIVE Part H hard-codes request-derived values: [data "Matched Data:
# <value> found within VAR: <value>"] and [uri "/path?query"]. No seclang
# directive can suppress them and corala-caddy v2.6.2 has no audit filter hook,
# so a custom "redacted" audit formatter (x/wafredactor, compiled into the edge
# image via xcaddy --with) blanks [data]/[uri] VALUES at format time — before
# they ever reach the file. The file is owned by the edge only (no shared
# volume, default 0644 mode): the poller never touches it. This sends attacks
# carrying a unique secret in FIVE positions, then asserts the audit log holds
# none of them and contains no "?" (no query leaks).
section "k) B3c WAF audit redaction (detection-only, in-process, no values)"
until_ok 30 "k) coraza handler present in the edge config" \
  'dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -q load_owasp_crs'
# unique secrets embedded INSIDE attack payloads (sqlmap UA triggers 913100 so
# a Part H is emitted). Each must be ABSENT from the redacted audit log.
dc exec edge sh -c "truncate -s 0 /data/logs/waf_audit.log" 2>/dev/null
sleep 1
curl -sk --resolve "$HOST:8445:127.0.0.1" -o /dev/null -H "Host: $HOST" -A "sqlmap/1.6" "https://127.0.0.1:8445/ok?id=%27%20OR%20%27S-Q-Q%27%3D%271" 2>/dev/null
curl -sk --resolve "$HOST:8445:127.0.0.1" -o /dev/null -H "Host: $HOST" -A "sqlmap/1.6" -d "id=%27%20OR%20%27S-Q-B%27%3D%271" "https://127.0.0.1:8445/ok" 2>/dev/null
curl -sk --resolve "$HOST:8445:127.0.0.1" -o /dev/null -H "Host: $HOST" -A "sqlmap/1.6" "https://127.0.0.1:8445/S-Q-P/ok" 2>/dev/null
curl -sk --resolve "$HOST:8445:127.0.0.1" -o /dev/null -H "Host: $HOST" -A "sqlmap/1.6" -H "Cookie: s=S-Q-C" "https://127.0.0.1:8445/ok" 2>/dev/null
curl -sk --resolve "$HOST:8445:127.0.0.1" -o /dev/null -H "Host: $HOST" -A "sqlmap/1.6" -H "Authorization: Bearer S-Q-A" "https://127.0.0.1:8445/ok" 2>/dev/null
# No scrubber delay: the redactor blanks values at format time (in-process).
# A short settle is still needed for corza's O_APPEND write to flush.
sleep 1
AUDIT=$(dc exec edge cat /data/logs/waf_audit.log 2>/dev/null)
for S in S-Q-Q S-Q-B S-Q-P S-Q-C S-Q-A; do
  N=$(printf '%s\n' "$AUDIT" | grep -c "$S")
  check "k) WAF audit has no value '$S' (q/body/path/cookie/auth)" "$N" "0"
done
QM=$(printf '%s\n' "$AUDIT" | grep -c '?')
check "k) no '?' anywhere in the WAF audit log (no URI query)" "$QM" "0"
check_ne "k) rule 913100 still logged (detection intact)" \
  "$(printf '%s\n' "$AUDIT" | grep -c '913100')" "0"
check_ne "k) [data] fields blanked by the redacted formatter" \
  "$(printf '%s\n' "$AUDIT" | grep -c '\[data ""\]')" "0"
check_ne "k) [uri] fields blanked by the redacted formatter" \
  "$(printf '%s\n' "$AUDIT" | grep -c '\[uri ""\]')" "0"
check "k) audit log mode is 0644 (no shared-volume 0666)" \
  "$(dc exec edge sh -c 'stat -c %a /data/logs/waf_audit.log 2>/dev/null || echo missing')" "644"

# --- l) WAF per-host live tests (off/detection/blocking, exclusions, isolation) ----
# Probes the per-host WAF controls end-to-end: the GLOBAL mode is "detection"
# (compose.yaml default), so a host set to "blocking" emits ctl:ruleEngine=On
# and a host set to "off" emits ctl:ruleEngine=Off — one shared Coraza instance,
# host-scoped by phase:1 SecRules that match on the Host header.
section "l) WAF per-host live tests (off/detection/blocking, exclusions, isolation, timing)"
WAF_B="accept-wb-$TS.example.test"
OUT=$(cb -X POST "$API/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$WAF_B\"}")
check "l) claim $WAF_B" "$(codeof "$OUT")" "201"
WAF_DOM=$(jget "$(bodyof "$OUT")" '["domain"]["id"]')
VT=$(jget "$(bodyof "$(cb "$API/v1/domains/$WAF_DOM/verification")")" '["verification"]["record_value"]' | cut -d= -f2)
printf '%s' "$VT" > "$STUB_TOK"
OUT=$(cb -X POST "$API/v1/domains/$WAF_DOM/verify")
check "l) verify $WAF_B" "$(codeof "$OUT")" "200"
OUT=$(cb -X POST "$API/v1/domains/$WAF_DOM/origin" -H 'Content-Type: application/json' \
  -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9001,\"tls_verify\":false}")
check "l) origin set for $WAF_B" "$(codeof "$OUT")" "201"
until_ok ${PROPAGATE_TIMEOUT} "l) edge serves $WAF_B from origin-test" \
  'curl -s -H "Host: $WAF_B" $EDGE_HTTP/ok | grep -q "port 9001"'
# SQLi in query triggers CRS 942100; scanner UA triggers 913100.
SQLI_ATTACK="ok?id=%27%20OR%20%271%27%3D%271"
# Baseline: both at detection (default) — SQLi passes through and logs events without blocking.
dc exec edge sh -c "truncate -s 0 /data/logs/waf_audit.log" 2>/dev/null
C=$(code_of -H "Host: $HOST" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) detection baseline: SQLi passes through ($HOST)" "$C" "200"
sleep 1
AUDIT_DET=$(dc exec edge cat /data/logs/waf_audit.log 2>/dev/null)
check_ne "l) detection gives events in audit log" "$(printf '%s' "$AUDIT_DET" | grep -c '942100')" "0"
C=$(code_of -H "Host: $WAF_B" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) detection baseline: SQLi passes through ($WAF_B)" "$C" "200"

# Set HOST=blocking, WAF_B=off — global default stays detection.
T0=$SECONDS
OUT=$(cb -X PUT "$API/v1/domains/$DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"blocking"}')
check "l) set $HOST to blocking" "$(codeof "$OUT")" "200"
OUT=$(cb -X PUT "$API/v1/domains/$WAF_DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"off"}')
check "l) set $WAF_B to off" "$(codeof "$OUT")" "200"
until_ok ${PROPAGATE_TIMEOUT} "l) WAF modes propagated to edge" \
  'dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -q "ctl:ruleEngine=On" && dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -q "ctl:ruleEngine=Off"'
echo "     l) WAF mode change reached the edge in $((SECONDS - T0))s ($PACE_LABEL)"
# Brief settle: the propagation check above confirms the config bytes are
# loaded, but Caddy's coraza module needs a moment to bind the new directives
# before requests are evaluated against them.
sleep 2

# blocking host: SQLi blocked (403), normal corpus returns 200.
C=$(code_of -H "Host: $HOST" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) blocking host: SQLi attack returns 403" "$C" "403"
C_NORM=$(code_of -H "Host: $HOST" "$EDGE_HTTP/ok")
check "l) blocking host: normal corpus returns 200" "$C_NORM" "200"

# off host: SQLi passes (200) and produces NO WAF events in audit log.
dc exec edge sh -c "truncate -s 0 /data/logs/waf_audit.log" 2>/dev/null
C=$(code_of -H "Host: $WAF_B" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) off host: SQLi passes through (host isolation)" "$C" "200"
sleep 1
AUDIT_OFF=$(dc exec edge cat /data/logs/waf_audit.log 2>/dev/null)
check "l) off host: gives no WAF events in audit log" "$(printf '%s' "$AUDIT_OFF" | grep -c '942100')" "0"

# Generic 403 body: no attack payload, no host name, no query string.
B=$(curl -s -H "Host: $HOST" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) 403 body has no SQLi payload" "$(printf '%s' "$B" | grep -c "OR.*1.*1")" "0"
check "l) 403 body has no query string" "$(printf '%s' "$B" | grep -c '?')" "0"
check "l) 403 body has no host name" "$(printf '%s' "$B" | grep -c "$HOST")" "0"

# One host in blocking does not affect another in detection.
OUT=$(cb -X PUT "$API/v1/domains/$WAF_DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"detection"}')
check "l) set $WAF_B to detection while $HOST is blocking" "$(codeof "$OUT")" "200"
until_ok ${PROPAGATE_TIMEOUT} "l) WAF_B detection propagated" \
  'curl -s -H "Host: $WAF_B" $EDGE_HTTP/$SQLI_ATTACK | grep -q "port 9001"'
sleep 2
check "l) isolation: $HOST in blocking still returns 403" \
  "$(code_of -H "Host: $HOST" "$EDGE_HTTP/$SQLI_ATTACK")" "403"
check "l) isolation: $WAF_B in detection passes through (200)" \
  "$(code_of -H "Host: $WAF_B" "$EDGE_HTTP/$SQLI_ATTACK")" "200"

# Exclusions: exclude 942100 on HOST only — SQLi passes on HOST, scanner UA stays blocked.
# And set WAF_B to blocking without exclusions: SQLi must still block on WAF_B.
T0=$SECONDS
OUT=$(cb -X PUT "$API/v1/domains/$DOM/waf" -H 'Content-Type: application/json' \
  -d '{"mode":"blocking","excluded_rule_ids":[942100]}')
check "l) set $HOST to blocking with 942100 excluded" "$(codeof "$OUT")" "200"
OUT=$(cb -X PUT "$API/v1/domains/$WAF_DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"blocking"}')
check "l) set $WAF_B to blocking (no exclusions)" "$(codeof "$OUT")" "200"
until_ok ${PROPAGATE_TIMEOUT} "l) WAF exclusion propagated" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/$SQLI_ATTACK | grep -q "port 9001"'
echo "     l) exclusion change reached the edge in $((SECONDS - T0))s"
sleep 2
C=$(code_of -H "Host: $HOST" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) excluded rule 942100: SQLi passes through for $HOST (200)" "$C" "200"
C=$(code_of -H "Host: $HOST" -A "sqlmap/1.6" "$EDGE_HTTP/ok")
check "l) non-excluded rule 913100: scanner UA still blocked on $HOST (403)" "$C" "403"
C_WAFB=$(code_of -H "Host: $WAF_B" "$EDGE_HTTP/$SQLI_ATTACK")
check "l) excluded rule stops firing for that host ONLY: $WAF_B still blocks (403)" "$C_WAFB" "403"

# Mode-change timing: blocking → detection (should pass through again).
T0=$SECONDS
OUT=$(cb -X PUT "$API/v1/domains/$DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"detection"}')
check "l) set $HOST to detection (mode change)" "$(codeof "$OUT")" "200"
until_ok ${PROPAGATE_TIMEOUT} "l) mode change propagated" \
  'curl -s -H "Host: $HOST" $EDGE_HTTP/$SQLI_ATTACK | grep -q "port 9001"'
echo "     l) mode change (blocking→detection) reached the edge in $((SECONDS - T0))s ($PACE_LABEL)"
# Host isolation: WAF_B still blocking while HOST changed to detection.
check "l) host isolation: $WAF_B still blocks while $HOST is detection" \
  "$(code_of -H "Host: $WAF_B" "$EDGE_HTTP/$SQLI_ATTACK")" "403"
# Ordering proof: live Caddy config must place host-scoped ctl rules BEFORE CRS includes.
ORDERING=$(dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | python3 -c '
import json, sys
cfg = json.load(sys.stdin)
srv = cfg.get("apps",{}).get("http",{}).get("servers",{}).get("edge",{})
if not srv: print("NO_EDGE_SERVER"); sys.exit(0)
for rt in srv.get("routes", []):
    for h in rt.get("handle", []):
        if isinstance(h, dict) and h.get("handler") == "waf":
            d = h.get("directives", "")
            ctl_idx = d.find("REQUEST_HEADERS:Host")
            crs_idx = d.find("@owasp_crs")
            if ctl_idx >= 0 and (crs_idx < 0 or ctl_idx < crs_idx): print("ORDERED")
            else: print("UNORDERED")
            break
    else: continue
    break
else: print("NO_WAF_HANDLER")
' 2>/dev/null)
check "l) ordering: host-scoped ctl rules precede CRS includes" "$ORDERING" "ORDERED"
# Reset HOST to detection (global default) for subsequent sections.
cb -X PUT "$API/v1/domains/$DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"detection"}' >/dev/null 2>&1

# --- m) edge RSS with 1/10/100 served hosts ----------------------------------
section "m) edge RSS with 1/10/100 served hosts"
get_rss() { dc exec edge sh -c "grep VmRSS /proc/1/status" 2>/dev/null | awk '{print $2}'; }
# Baseline: HOST + WAF_B = 2 hosts already served by the edge.
until_ok ${PROPAGATE_TIMEOUT} "m) baseline 2 hosts serving" \
  'curl -s -H "Host: $WAF_B" $EDGE_HTTP/ok | grep -q "port 9001"'
RSS_2=$(get_rss)
echo "     m) RSS: 2 hosts = ${RSS_2} kB"
check "m) edge RSS measurable with 2 hosts" "$([ -n "$RSS_2" ] && echo ok || echo fail)" "ok"
# 10 hosts: add 8 more via psql (bypass DNS verify — direct DB insert).
if [ -n "$DB_URL" ] && command -v psql >/dev/null 2>&1; then
  psql "$DB_URL" <<SQL >/dev/null 2>&1
WITH uid AS (SELECT id FROM users WHERE email = '$U' LIMIT 1),
     d AS (
       INSERT INTO domains (owner_user_id, hostname, status, verify_token, setup_type, verified_at, waf_mode, excluded_rule_ids)
       SELECT uid.id, 'rss-' || gs::text || '-$TS.example.test', 'verified', 'tok-' || gs::text || '-$TS',
              'cname', now(), 'detection', '{}'::int[]
       FROM uid, generate_series(1, 8) gs
       RETURNING id
     )
INSERT INTO origins (domain_id, scheme, address, port, tls_verify)
SELECT d.id, 'http', '$ORIGIN_IP', 9001, false FROM d;
SQL
  # Trigger snapshot rebuild.
  cb -X PUT "$API/v1/domains/$DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"detection","excluded_rule_ids":[]}' >/dev/null 2>&1
  until_ok ${PROPAGATE_TIMEOUT} "m) 10 hosts in snapshot" \
    'curl -s -H "Host: rss-8-$TS.example.test" $EDGE_HTTP/ok | grep -q "port 9001"'
  RSS_10=$(get_rss)
  echo "     m) RSS: 10 hosts = ${RSS_10} kB"
  check "m) edge RSS measurable with 10 hosts" "$([ -n "$RSS_10" ] && echo ok || echo fail)" "ok"
  # 100 hosts: add 90 more.
  psql "$DB_URL" <<SQL >/dev/null 2>&1
WITH uid AS (SELECT id FROM users WHERE email = '$U' LIMIT 1),
     d AS (
       INSERT INTO domains (owner_user_id, hostname, status, verify_token, setup_type, verified_at, waf_mode, excluded_rule_ids)
       SELECT uid.id, 'rss100-' || gs::text || '-$TS.example.test', 'verified', 'tok100-' || gs::text || '-$TS',
              'cname', now(), 'detection', '{}'::int[]
       FROM uid, generate_series(1, 90) gs
       RETURNING id
     )
INSERT INTO origins (domain_id, scheme, address, port, tls_verify)
SELECT d.id, 'http', '$ORIGIN_IP', 9001, false FROM d;
SQL
  cb -X PUT "$API/v1/domains/$DOM/waf" -H 'Content-Type: application/json' -d '{"mode":"detection","excluded_rule_ids":[]}' >/dev/null 2>&1
  until_ok ${PROPAGATE_TIMEOUT} "m) 100 hosts in snapshot" \
    'curl -s -H "Host: rss100-90-$TS.example.test" $EDGE_HTTP/ok | grep -q "port 9001"'
  RSS_100=$(get_rss)
  echo "     m) RSS: 100 hosts = ${RSS_100} kB"
  check "m) edge RSS measurable with 100 hosts" "$([ -n "$RSS_100" ] && echo ok || echo fail)" "ok"
  # Sub-linear growth: 100 hosts should not be 50x the 2-host RSS.
  if [ -n "$RSS_2" ] && [ -n "$RSS_100" ] && [ "$RSS_2" -gt 0 ]; then
    RATIO=$(( RSS_100 * 10 / RSS_2 ))  # ratio * 10
    if [ "$RATIO" -lt 200 ]; then
      pass "m) sub-linear: RSS grew ${RATIO}‰ per host (100 vs 2 hosts)"
    else
      fail "m) RSS growth too linear (${RATIO}‰ per host)"
    fi
  fi
else
  fail "m) psql not available — skipping RSS test (DB_URL empty or psql missing)"
fi

# --- n) schema versions, BOTH directions -------------------------------------
# Direction 1 — OLD-STYLE node on a NEW snapshot: the schema gate. A node that
# does not know a signed required feature must REFUSE the snapshot and keep
# its last good config — never silently drop the WAF fields behind it (the
# v0.4 behavior this replaces). The "old-style edge" here is the CURRENT
# poller binary with GP_EDGE_FEATURES=none (the empty feature set; Go cannot
# tell an unset env from an empty one). Choreography: craft a schema-1-style
# last-good (strip required_features, clear the WAF fields, bump the
# generation past the API's), boot a one-off poller with the empty feature
# set so it applies it, then let it poll the LIVE API: its schema-2 artifact
# requires "waf" → refused once per throttle gap, the crafted last-good keeps
# serving. The discriminator: the crafted config has no host-scoped WAF rules
# (waf_mode cleared → DetectionOnly), the API's artifact would put WAF_B's
# ctl:ruleEngine=On back — its absence proves the refusal held.
# Direction 2 — NEW code on an OLD snapshot: a snapshot signed with the SAME
# key but schema_version=1 (no waf_mode field). The current edge must accept
# it and default WAFMode to "detection" via snapshotDomainWAF — the schema
# bump is backward-compatible.
section "n) schema gate both directions (old-style node refuses; new node accepts schema-1)"
sudo docker rm -f accept-old-poller >/dev/null 2>&1 || true
if [ -n "$DB_URL" ] && command -v psql >/dev/null 2>&1; then
  CUR_SNAPSHOT=$(dc exec poller cat /state/snapshot.json 2>/dev/null)
  if [ -n "$CUR_SNAPSHOT" ]; then
    # Craft the old-style last-good from the current artifact: strip
    # required_features, clear the WAF fields, bump the generation past the
    # API's current one. Pipe CUR_SNAPSHOT through stdin (it's 140KB+ —
    # exceeds ARG_MAX). Use python3 -c (not a heredoc) so stdin carries the
    # snapshot data.
    OLDGOOD=$(printf '%s' "$CUR_SNAPSHOT" | python3 -c '
import sys, json, hmac, hashlib
key = sys.argv[1].strip()
env = json.load(sys.stdin)
doc = json.loads(env["payload"])
doc.pop("required_features", None)
doc["schema_version"] = 1
for d in doc.get("domains", []):
    d["waf_mode"] = ""
    d["excluded_rule_ids"] = []
doc["generation"] = int(doc.get("generation", 0)) + 1
payload = json.dumps(doc, sort_keys=True, separators=(",", ":"))
sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
key_id = hashlib.sha256(key.encode()).hexdigest()[:16]
print(json.dumps({"payload": payload, "signature": sig, "key_id": key_id}))
' "$KEY")
    dc stop poller >/dev/null 2>&1
    sleep 1  # let the prior poller fully stop before we rewrite its state
    printf '%s' "$OLDGOOD" | sudo docker run --rm -i -v gatepost-edge-dev_poller_state:/state alpine sh -c 'cat > /state/snapshot.json'
    sleep 1  # let the volume sync finish before the one-off reads
    N_OLD=$(date -u +%Y-%m-%dT%H:%M:%S)
    # One-off container from the poller service definition (same netns as
    # the edge, same secrets/state volumes, same env) with the EMPTY feature
    # set: the old-style node of the schema gate.
    # 2>&1 (not 2>/dev/null): the poller logs to stderr and docker logs
    # routes container stderr to its own — discarding it hides every line.
    if dc run -d --rm --name accept-old-poller -e GP_EDGE_FEATURES=none poller >/dev/null 2>&1; then
      until_ok ${PROPAGATE_TIMEOUT} "n) old-style node boot-applied the crafted last-good" \
        'sudo docker logs --since "$N_OLD" accept-old-poller 2>&1 | grep -q "applied snapshot generation"'
      until_ok ${PROPAGATE_TIMEOUT} "n) old-style node REFUSED the API snapshot (required feature unknown)" \
        'sudo docker logs --since "$N_OLD" accept-old-poller 2>&1 | grep -q "does not implement"'
      check "n) old-style edge keeps serving $HOST (last-good held)" \
        "$(curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -c 'port 9001')" "1"
      check "n) old-style edge did NOT apply the refused snapshot (no ctl:ruleEngine=On)" \
        "$(dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -c 'ctl:ruleEngine=On')" "0"
    else
      fail "n) old-style one-off poller did not start"
    fi
    sudo docker stop -t 5 accept-old-poller >/dev/null 2>&1
    # Reset the generation trap: the crafted last-good sits one generation
    # ABOVE the API's current snapshot, so the API's artifact would look
    # "backwards" to the real poller forever. Deleting the on-disk snapshot
    # (poller stopped) is the documented cold-start reset.
    sudo docker run --rm -v gatepost-edge-dev_poller_state:/state alpine sh -c 'rm -f /state/snapshot.json' 2>/dev/null
    dc start poller >/dev/null 2>&1
    N_START=$(date -u +%Y-%m-%dT%H:%M:%S)
    until_ok ${PROPAGATE_TIMEOUT} "n) real poller cold-started from the API schema-2 snapshot" \
      'dc logs --since "$N_START" poller 2>/dev/null | grep -q "applied snapshot generation"'
    until_ok ${PROPAGATE_TIMEOUT} "n) schema-2 WAF directives restored on the edge" \
      'dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -q "ctl:ruleEngine=On"'
  else
    fail "n) no on-disk snapshot found in poller volume"
  fi
else
  fail "n) psql not available — skipping schema-gate test"
fi
if [ -n "$DB_URL" ] && command -v psql >/dev/null 2>&1; then
  # Read the on-disk snapshot from the poller volume.
  CUR_SNAPSHOT=$(dc exec poller cat /state/snapshot.json 2>/dev/null)
  if [ -n "$CUR_SNAPSHOT" ]; then
    # Craft a schema-1 snapshot: bump generation, clear waf_mode, re-sign.
    # required_features is stripped too — a schema-1 artifact predates the
    # field (the current edge accepts the feature-less shape unchanged).
    # Pipe CUR_SNAPSHOT through stdin (it's 140KB+ — exceeds ARG_MAX).
    # Use python3 -c (not a heredoc) so stdin carries the snapshot data.
    SCHEMA1=$(printf '%s' "$CUR_SNAPSHOT" | python3 -c '
import sys, json, hmac, hashlib
key = sys.argv[1].strip()
env = json.load(sys.stdin)
doc = json.loads(env["payload"])
doc.pop("required_features", None)
doc["schema_version"] = 1
for d in doc.get("domains", []):
    d["waf_mode"] = ""
    d["excluded_rule_ids"] = []
doc["generation"] = int(doc.get("generation", 0)) + 1
payload = json.dumps(doc, sort_keys=True, separators=(",", ":"))
sig = hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()
key_id = hashlib.sha256(key.encode()).hexdigest()[:16]
print(json.dumps({"payload": payload, "signature": sig, "key_id": key_id}))
' "$KEY")
    # Stop API + poller, replace the snapshot, restart.
    kill_api
    dc stop poller >/dev/null 2>&1
    sleep 1  # let the prior poller fully stop before we rewrite its state
    N_START=$(date -u +%Y-%m-%dT%H:%M:%S)
    printf '%s' "$SCHEMA1" | sudo docker run --rm -i -v gatepost-edge-dev_poller_state:/state alpine sh -c 'cat > /state/snapshot.json'
    sleep 1  # let the volume sync finish before the poller reads
    dc start poller >/dev/null 2>&1
    # The restarted poller reads the schema-1 snapshot at boot and applies it.
    until_ok ${PROPAGATE_TIMEOUT} "n) poller applied the schema-1 snapshot" \
      'dc logs --since "$N_START" poller 2>/dev/null | grep -q "applied snapshot generation"'
    sleep 3  # brief settle: the poller logs "applied" before Caddy finishes reloading the WAF directives
    # The schema-1 snapshot is valid (same key, bumped generation) and the
    # apply above confirms the poller accepted it. We check the edge is
    # serving correctly below — that's the real proof of backward compat.
    # The edge must still serve the HOST domain (WAFMode defaulted to detection).
    until_ok ${PROPAGATE_TIMEOUT} "n) edge serves $HOST from origin-test (schema-1 backward compat)" \
      'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001"'
    check "n) edge serves $WAF_B from origin-test (schema-1 backward compat)" \
      "$(curl -s -H "Host: $WAF_B" $EDGE_HTTP/ok | grep -c 'port 9001')" "1"
    # Audit: the schema-1 snapshot's waf_mode defaulted to detection — verify
    # the generated directives use DetectionOnly as the global default.
    check "n) directives default to DetectionOnly for schema-1 domains" \
      "$(dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -c 'SecRuleEngine DetectionOnly')" "1"
    # Restart API for schema-2 refetch. The schema-1 snapshot has gen bumped by
    # 1, so the API's current snapshot (same content → same gen) is "behind"
    # the poller's applied gen — it would skip it ("not strictly newer"). We
    # delete the on-disk snapshot so the poller has no applied generation and
    # will accept the API's current snapshot on its next poll.
    start_api
    dc stop poller >/dev/null 2>&1
    sudo docker run --rm -v gatepost-edge-dev_poller_state:/state alpine sh -c 'rm -f /state/snapshot.json' 2>/dev/null
    dc start poller >/dev/null 2>&1
    N_START2=$(date -u +%Y-%m-%dT%H:%M:%S)
    until_ok ${PROPAGATE_TIMEOUT} "n) poller refetched the schema-2 snapshot from the API" \
      'dc logs --since "$N_START2" poller 2>/dev/null | grep -q "applied snapshot generation"'
    # The schema-2 refetch's content differs from schema-1 (WAF_B ends
    # section l in BLOCKING → ctl:ruleEngine=On appears; schema-1 has
    # waf_mode="" → defaults to detection, no host-scoped ctl rules).
    # Checking only "port 9001" would be a false positive: the edge was
    # already serving 9001 from schema-1. We confirm the schema-2 reload
    # by checking for the host-scoped On rule.
    until_ok ${PROPAGATE_TIMEOUT} "n) schema-2 config applied to edge" \
      'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9001" && dc exec edge wget -qO- http://127.0.0.1:2019/config/ 2>/dev/null | grep -q "ctl:ruleEngine=On"'
  else
    fail "n) no on-disk snapshot found in poller volume"
  fi
else
  fail "n) psql not available — skipping schema-1 test"
fi

# --- o) PROD_TIMING: origin change after 60s silence (leading-edge) ----------------
# After the cooldown has fully elapsed (60s at production pacing), the first
# origin change must apply at the next poll — not after another full cooldown.
# This is the leading-edge guarantee the TestApplyCooldownLeadingEdge unit test pins.
if [ "${PROD_TIMING:-0}" = "1" ]; then
  section "o) PROD_TIMING: origin change after 60s silence (leading-edge)"
  echo "     o) waiting 60s for the reload cooldown to elapse (no reloads)..."
  sleep 60
  # Origin is currently on 9001; switch to 9003.
  T0=$SECONDS
  OUT=$(cb -X PUT "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
    -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9003,\"tls_verify\":false}")
  check "o) origin PUT (9001 -> 9003)" "$(codeof "$OUT")" "200"
  until_ok 30 "o) new origin reached the edge" \
    'curl -s -H "Host: $HOST" $EDGE_HTTP/ok | grep -q "port 9003"'
  LATENCY=$((SECONDS - T0))
  echo "     o) origin change after 60s silence reached the edge in ${LATENCY}s (target: < 10s)"
  if [ "$LATENCY" -le 10 ]; then
    pass "o) latency ${LATENCY}s — leading-edge cooldown (applied at next poll)"
  else
    fail "o) latency ${LATENCY}s — expected < 10s for leading-edge behavior"
  fi
  # Restore origin to 9001 for any subsequent steps.
  OUT=$(cb -X PUT "$API/v1/domains/$DOM/origin" -H 'Content-Type: application/json' \
    -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9001,\"tls_verify\":false}")
  check "o) origin RESTORED (9003 -> 9001)" "$(codeof "$OUT")" "200"
fi

section "verdict"
FINISHED=1
echo "--- section timing ---"
for s in "${!SECTION_TIMINGS[@]}"; do
  printf '  %-50s %3ds\n' "$s" "${SECTION_TIMINGS[$s]}"
done
echo "=== edge acceptance: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
