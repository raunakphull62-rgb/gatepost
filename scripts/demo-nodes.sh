#!/usr/bin/env bash
# Gatepost demo: scripted curl walkthrough of the B3a node API.
# operator minted → node token → claim+TXT+verify against a local DNS stub
# (raw UDP, no libraries) → signed config polled and verified in python
# (HMAC + key id + generation) → no account secrets in the envelope → second
# domain bumps the version → free 304 on unchanged → heartbeat stamps the
# roster → unknown version refused → revoke → instant 401. Prints PASS/FAIL
# per step; exits nonzero on any failure. Secrets stay in .env, never printed.
cd "$(dirname "$0")/.."

BASE="${GP_PUBLIC_BASE_URL:-http://localhost:8092}"
JAR="$(mktemp)"; TNOK="$(mktemp)"; CFGF="$(mktemp)"; STUB_PY="$(mktemp)"
SRV_PID=""; STUB_PID=""
trap 'kill ${SRV_PID:-0} ${STUB_PID:-0} 2>/dev/null; rm -f "${JAR:-}" "${TNOK:-}" "${CFGF:-}" "${STUB_PY:-}"' EXIT

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
# cb talks as the operator (own cookie jar); cbn talks as the node (bearer
# token); cbx is an anonymous /node route client. XFF keeps per-IP counters
# isolated from other demo runs (GP_TRUSTED_PROXIES makes the server read it).
cb()  { curl -s -w '\n%{http_code}' -b "$JAR" -c "$JAR" -H "X-Forwarded-For: $CIP" "$@"; }
cbn() { curl -s -w '\n%{http_code}' -H "Authorization: Bearer $NTOK" "$@"; }
cbx() { curl -s -w '\n%{http_code}' -H "X-Forwarded-For: $CIP" "$@"; }
bodyof(){ printf '%s' "$1" | head -n -1; }
codeof(){ printf '%s' "$1" | tail -n 1; }
mail_token() { grep -m1 -o 'token: [A-Za-z0-9_-]*' "$(ls -t outbox/*.txt | head -1)" | cut -d' ' -f2; }

mkdir -p outbox
go build -o gatepost ./cmd/gatepost || exit 2

TS=$(date +%s)-$RANDOM
U="op-nodes-$TS@x.test"; PW="demo-password-1"
HOST="nodes-a-$TS.example.com"; HOST2="nodes-b-$TS.example.com"
KEY="nodes-demo-snapshot-key-0123456789abcdef" # 40 bytes, over the 32-byte floor
NTOK="" # filled after the mint below

# --- the DNS stub: raw-UDP TXT answers for _gatepost-verify.*, the token
# file is re-read on every query so a changed claim verifies without restarts
cat > "$STUB_PY" <<'EOF'
import socket, sys
tok_path = sys.argv[1]
srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(("127.0.0.1", 5344))
while True:
    data, addr = srv.recvfrom(4096)
    try:
        i = 12
        while data[i] != 0:            # walk the QNAME labels
            i += 1 + data[i]
        i += 1
        question = data[12:i+4]        # QNAME + QTYPE + QCLASS, echoed verbatim
        txt = b'gatepost-verify=' + open(tok_path, 'rb').read().strip()
        answer = (b'\xc0\x0c'          # name → pointer at offset 12
                  b'\x00\x10\x00\x01'  # TXT, IN
                  b'\x00\x00\x00\x05'  # TTL 5s: fresh answers land fast
                  + (len(txt) + 1).to_bytes(2, 'big')  # RDLENGTH = the length byte + the string
                  + bytes([len(txt)]) + txt)     # the one TXT string
        srv.sendto(data[:2]            # echo the query id
                   + b'\x84\x00'       # response | recursion desired+available
                   + b'\x00\x01\x00\x01\x00\x00\x00\x00'  # QD=1 AN=1
                   + question + answer, addr)
    except Exception:
        pass  # a malformed probe stays a dropped probe, never a stub crash
EOF
python3 "$STUB_PY" "$TNOK" >/dev/null 2>&1 &
STUB_PID=$!

# demo server: the operator list has just this run's user; the snapshot key is
# the same material python verifies below; resolvers pinned to the stub
ENV=development GP_TRUSTED_PROXIES=127.0.0.1/32 GP_HTTP_ADDR=127.0.0.1:8092 \
  GP_DNS_RESOLVERS=127.0.0.1:5344 GP_SNAPSHOT_KEY="$KEY" \
  GP_OPERATOR_EMAILS="$U" \
  ./gatepost >/tmp/gatepost-nodes-demo-server.log 2>&1 &
SRV_PID=$!
for _ in $(seq 1 30); do
  C=$(curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $CIP" "$BASE/api/me")
  [ "$C" != "000" ] && [ -n "$C" ] && break
  sleep 0.5
done
[ -n "$C" ] && [ "$C" != "000" ] || { echo "server did not come up (see /tmp/gatepost-nodes-demo-server.log)"; exit 2; }
sleep 1; kill -0 "$STUB_PID" 2>/dev/null || { echo "DNS stub did not start"; exit 2; }

# --- the operator: signup → mail → verify; signup opens the session ---
check "operator signup" "$(codeof "$(cb -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")")" "200"
VT=$(mail_token)
check "operator verified (mail loop)" "$(codeof "$(cb -X POST "$BASE/auth/verify" -H 'Content-Type: application/json' -d "{\"token\":\"$VT\"}")")" "200"

# --- mint a node: the token shows up exactly once and never again ---
OUT=$(cb -X POST "$BASE/v1/nodes" -H 'Content-Type: application/json' -d "{\"name\":\"demo-edge-$TS\",\"role\":\"edge\"}")
check "node minted (201)" "$(codeof "$OUT")" "201"
NODE_BODY=$(bodyof "$OUT")
NTOK=$(printf '%s' "$NODE_BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
NID=$(printf '%s' "$NODE_BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["node"]["id"])')
check "the mint reply carries the token exactly once" "$(printf '%s' "$NODE_BODY" | grep -ce "$NTOK")" "1"
check "re-mint of the same name refused (409)" "$(codeof "$(cb -X POST "$BASE/v1/nodes" -H 'Content-Type: application/json' -d "{\"name\":\"demo-edge-$TS\",\"role\":\"edge\"}")")" "409"

# --- isolation: the two principal families do not cross (mutual 401s) ---
check "anonymous /node/v1/config refused (401)" "$(codeof "$(cbx "$BASE/node/v1/config")")" "401"
check "node token on a user route refused (401)" "$(codeof "$(cbn "$BASE/v1/domains")")" "401"
check "node token on /api/me refused (401)" "$(codeof "$(cbn "$BASE/api/me")")" "401"

# --- claim → TXT instructions → the stub answers the live token → verified ---
OUT=$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST\"}")
check "claim $HOST" "$(codeof "$OUT")" "201"
DOM=$(bodyof "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["domain"]["id"])')
check "instructions name the TXT record" "$(bodyof "$(cb "$BASE/v1/domains/$DOM/verification")" | grep -c "_gatepost-verify.$HOST")" "1"
VT1=$(bodyof "$(cb "$BASE/v1/domains/$DOM/verification")" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verification"]["record_value"])' | cut -d= -f2)
printf '%s' "$VT1" > "$TNOK" # the stub serves the token from now on
check "verify against the live TXT stub" "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM/verify")")" "200"
check "origin set (literal IP: no resolver cost)" "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM/origin" -H 'Content-Type: application/json' -d '{"scheme":"http","address":"93.184.216.34","port":80,"tls_verify":false}')")" "201"

# --- the node polls its config: python checks signature, key id, generation ---
CFG=$(cbn "$BASE/node/v1/config")
check "config fetched (200)" "$(codeof "$CFG")" "200"
printf '%s' "$(bodyof "$CFG")" > "$CFGF"
VOUT=$(python3 - "$KEY" "$CFGF" "$HOST" <<'EOF'
import json, sys, hmac, hashlib
key = sys.argv[1].encode()
env = json.load(open(sys.argv[2]))
doc = json.loads(env["payload"])
sig = hmac.new(key, env["payload"].encode(), hashlib.sha256).hexdigest()
kid = hashlib.sha256(key).hexdigest()[:16]
assert env["signature"] == sig, f"signature mismatch: {env['signature']}"
assert env["key_id"] == kid, f"key id mismatch: want {kid}, got {env['key_id']}"
names = [d["hostname"] for d in doc["domains"]]
want = sys.argv[3]
mine = [d for d in doc["domains"] if d["hostname"] == want]
assert mine, f"{want} must be served, got: {names}"  # the registry is shared with earlier demo runs: subset, not equality
o = mine[0]["origin"]
assert o["address"] == "93.184.216.34" and o["port"] == 80, f"origin mismatch: {o}"
print("verified")
print(doc["generation"])
EOF
)
check "python verifies the envelope (HMAC + key id + the domain + origin)" "$(printf '%s' "$VOUT" | sed -n 1p)" "verified"
GEN1=$(printf '%s' "$VOUT" | sed -n 2p)
check "no '@' anywhere in the envelope a node could download" "$(printf '%s' "$(bodyof "$CFG")" | grep -c '@')" "0"

# --- a second verified domain changes the content: version bump, new valid sig ---
OUT=$(cb -X POST "$BASE/v1/domains" -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST2\"}")
check "claim $HOST2" "$(codeof "$OUT")" "201"
DOM2=$(bodyof "$OUT" | python3 -c 'import json,sys; print(json.load(sys.stdin)["domain"]["id"])')
VT2=$(bodyof "$(cb "$BASE/v1/domains/$DOM2/verification")" | python3 -c 'import json,sys; print(json.load(sys.stdin)["verification"]["record_value"])' | cut -d= -f2)
printf '%s' "$VT2" > "$TNOK"
check "verify $HOST2" "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM2/verify")")" "200"
check "$HOST2 origin set" "$(codeof "$(cb -X POST "$BASE/v1/domains/$DOM2/origin" -H 'Content-Type: application/json' -d '{"scheme":"http","address":"93.184.216.34","port":8081,"tls_verify":false}')")" "201"
CFG2=$(cbn "$BASE/node/v1/config")
check "config re-fetched after the write (200)" "$(codeof "$CFG2")" "200"
printf '%s' "$(bodyof "$CFG2")" > "$CFGF"
GEN2=$((GEN1 + 1))
VOUT=$(python3 - "$KEY" "$CFGF" "$HOST" "$HOST2" "$GEN2" <<'EOF'
import json, sys, hmac, hashlib
key = sys.argv[1].encode()
env = json.load(open(sys.argv[2]))
doc = json.loads(env["payload"])
sig = hmac.new(key, env["payload"].encode(), hashlib.sha256).hexdigest()
assert env["signature"] == sig, f"signature mismatch: {env['signature']}"
assert doc["generation"] == int(sys.argv[5]), f"generation want {sys.argv[5]}, got {doc['generation']}"
names = [d["hostname"] for d in doc["domains"]]
for want in (sys.argv[3], sys.argv[4]):
    assert want in names, f"{want} must be served after the claim, got: {names}"
print("verified")
EOF
)
check "the version bumped to GEN1+1 and the new payload still verifies" "$VOUT" "verified"

# --- unchanged content = a free pull: If-None-Match on the generation → 304 ---
check "If-None-Match on the current generation → 304" "$(codeof "$(cbn -H "If-None-Match: \"$GEN2\"" "$BASE/node/v1/config")")" "304"

# --- heartbeat: only a generation that exists is stamped, on the roster too ---
check "heartbeat generation $GEN2 → 200" "$(codeof "$(cbn -X POST "$BASE/node/v1/heartbeat" -H 'Content-Type: application/json' -d "{\"generation\":$GEN2}")")" "200"
check "the roster stamps applied_version $GEN2" "$(bodyof "$(cb "$BASE/v1/nodes")" | grep -c "\"applied_version\":$GEN2")" "1"
check "the roster carries no token material" "$(bodyof "$(cb "$BASE/v1/nodes")" | grep -ce "$NTOK")" "0"
check "heartbeat of an unknown generation refused (400)" "$(codeof "$(cbn -X POST "$BASE/node/v1/heartbeat" -H 'Content-Type: application/json' -d "{\"generation\":$((GEN2 + 999999))}")")" "400"
check "heartbeat of a zero generation refused (400)" "$(codeof "$(cbn -X POST "$BASE/node/v1/heartbeat" -H 'Content-Type: application/json' -d '{"generation":0}')")" "400"

# --- revoke: the token dies on its very next request ---
check "revoke (idempotent route, 200)" "$(codeof "$(cb -X POST "$BASE/v1/nodes/$NID/revoke")")" "200"
check "the revoked token polls: 401" "$(codeof "$(cbn "$BASE/node/v1/config")")" "401"

echo
echo "=== nodes demo: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
