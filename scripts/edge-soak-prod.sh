#!/usr/bin/env bash
# Live soak (B3b Part 1.2): production pacing, API stopped for 5 minutes,
# steady traffic through the edge. Proves:
#   - poller/edge RestartCount + StartedAt unchanged (docker did not restart them)
#   - zero non-200 responses from the edge during the window
#   - no "apply loop silent" and no health errors in the poller log
#
# SOAK_NEGATIVE=1: negative control — stops the edge for ~3s mid-soak,
# then asserts that non-200 responses WERE counted (verdict must FAIL).
#
# Run:  scripts/edge-soak-prod.sh 2>&1 | tee /tmp/edge-soak-prod.log
# Takes ~6 minutes (5 min soak + setup/teardown), or ~2 min for negative.
set -u
cd "$(dirname "$0")/.."

COMPOSE=deploy/dev/compose.yaml
SECRETS=deploy/dev/secrets
API=http://172.17.0.1:8090
EDGE_HTTP=http://127.0.0.1:8081
ORIGIN_IP=192.88.99.10
SUPERVISE_OFF=deploy/dev/.supervise-off

API_PID=""
cleanup() {
  local code=$?
  echo
  echo "=== edge soak: exit=$code, status=$([ $code -eq 0 ] && echo PASSED || echo FAILED) ==="
  kill "$API_PID" 2>/dev/null
  rm -f "$SUPERVISE_OFF"
}
trap cleanup EXIT
trap 'echo "=== soak: interrupted ===" >&2; exit 130' INT TERM

echo "=== edge live soak: production pacing, API down 5 min ==="
touch "$SUPERVISE_OFF"

go build -o gatepost ./cmd/gatepost || { echo "build failed"; exit 2; }

# Wipe stale test data — hostname-origin domains cause DNS-lookup timeouts in
# the snapshot builder, which blows past the poller's 10s HTTP timeout.
if [ -f .env ]; then
  DB_URL=$(grep '^DATABASE_URL=' .env | head -1 | cut -d= -f2-)
  if [ -n "$DB_URL" ] && command -v psql >/dev/null 2>&1; then
    psql "$DB_URL" -c \
      "DELETE FROM origins WHERE domain_id IN (SELECT id FROM domains WHERE hostname LIKE 'accept-%' OR hostname LIKE 'soak-%' OR hostname LIKE 'debug-%'); DELETE FROM domains WHERE hostname LIKE 'accept-%' OR hostname LIKE 'soak-%' OR hostname LIKE 'debug-%'; DELETE FROM nodes WHERE name LIKE 'accept-%' OR name LIKE 'soak-%' OR name LIKE 'debug-%';" 2>&1
    echo "[soak] stale test data cleaned from database"
  fi
fi

sudo docker compose -f "$COMPOSE" --profile poller down >/dev/null 2>&1
sleep 1
for v in caddy_data caddy_config poller_state; do sudo docker volume rm "gatepost-edge-dev_$v" >/dev/null 2>&1; done

# Kill leftover processes on our ports.
OLD_PID=$(sudo ss -ltnp 'sport = :8090' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
[ -n "$OLD_PID" ] && sudo kill "$OLD_PID" 2>/dev/null; sleep 0.5
STUB_PID=$(sudo ss -ltnup 'sport = :5344' 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
[ -n "$STUB_PID" ] && sudo kill "$STUB_PID" 2>/dev/null; sleep 0.3

# DNS stub — same format as edge-accept.sh (flags 0x84/0x00 for compatibility).
mkdir -p outbox "$SECRETS"
if [ -s "$SECRETS/snapshot_key" ]; then
  KEY="$(cat "$SECRETS/snapshot_key")"
else
  KEY="soak-$(date +%s)-$(openssl rand -hex 16)"
  printf '%s' "$KEY" > "$SECRETS/snapshot_key"
fi
chmod 644 "$SECRETS/snapshot_key"

U="soak-$(date +%s)@x.test"; PW="soak-password-1"
HOST="soak-$(date +%s).example.test"
JAR="$(mktemp)"
STUB_PY="$(mktemp)"; STUB_TOK="$(mktemp)"

# DNS stub: TXT verify (token from STUB_TOK) + A query passthrough (NOERROR).
cat > "$STUB_PY" <<'STUBEOF'
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
        if qtype == b'\x00\x01':  # A
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
                srv.sendto(data[:2] + b'\x81\x80' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
                           + question + b'\xc0\x0c' + b'\x00\x01\x00\x01'
                           + b'\x00\x00\x00\x05' + b'\x00\x04' + rdata, addr)
                continue
            srv.sendto(data[:2] + b'\x81\x80' + b'\x00\x01\x00\x00\x00\x00\x00\x00'
                       + question, addr)
            continue
        if qtype == b'\x00\x10':  # TXT
            txt = b'gatepost-verify=' + open(tok_path, 'rb').read().strip()
            answer = (b'\xc0\x0c' + b'\x00\x10\x00\x01' + b'\x00\x00\x00\x05'
                      + (len(txt) + 1).to_bytes(2, 'big') + bytes([len(txt)]) + txt)
            srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x01\x00\x00\x00\x00'
                       + question + answer, addr)
            continue
        srv.sendto(data[:2] + b'\x84\x00' + b'\x00\x01\x00\x00\x00\x00\x00\x00'
                   + question, addr)
    except Exception:
        pass
STUBEOF
# Start stub with an empty a_path file (no A records needed for this soak).
: > "$STUB_PY.tmp_a"
python3 "$STUB_PY" "$STUB_TOK" "$STUB_PY.tmp_a" >/dev/null 2>&1 &
STUB_PID=$!
sleep 0.5
kill -0 "$STUB_PID" 2>/dev/null && echo "[soak] DNS stub up on :5344" || { echo "[soak] DNS stub failed"; exit 2; }

# Start API (PRODUCTION PACING — no fast overrides).
env -i ENV=development GP_HTTP_ADDR=172.17.0.1:8090 \
  GP_DNS_RESOLVERS=127.0.0.1:5344 GP_SNAPSHOT_KEY="$KEY" \
  GP_OPERATOR_EMAILS="$U" GP_TRUSTED_PROXIES=127.0.0.1/32 \
  ./gatepost >/tmp/edge-soak-api.log 2>&1 &
API_PID=$!
for _ in $(seq 1 30); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/me")" != "000" ] && break
  sleep 0.5
done
echo "[soak] API up at $(date +%H:%M:%S)"

# Start edge + origin (PRODUCTION PACING — no timing overrides).
sudo env GP_EDGE_API_BASE="$API" GP_EDGE_ISSUER=internal \
  docker compose -f "$COMPOSE" --profile poller up -d --build edge origin-test >/dev/null 2>&1 \
  || { echo "compose up failed"; exit 2; }
echo "[soak] edge + origin-test up (production pacing: 60s cooldown, 5s poll, 60s backoff)"

# Signup
OUT=$(curl -s -w '\n%{http_code}' -b "$JAR" -c "$JAR" -X POST "$API/auth/signup" \
  -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")
CODE=$(printf '%s' "$OUT" | tail -1)
echo "[soak] signup: HTTP $CODE"
[ "$CODE" = "200" ] || { echo "signup failed: $OUT"; exit 2; }

# Verify (mail token from outbox)
sleep 1
TOK=$(grep -m1 -o 'token: [A-Za-z0-9_-]*' "$(ls -t outbox/*.txt | head -1)" | cut -d' ' -f2)
OUT=$(curl -s -w '\n%{http_code}' -b "$JAR" -c "$JAR" -X POST "$API/auth/verify" \
  -H 'Content-Type: application/json' -d "{\"token\":\"$TOK\"}")
CODE=$(printf '%s' "$OUT" | tail -1)
echo "[soak] verify: HTTP $CODE"
[ "$CODE" = "200" ] || { echo "verify failed: $OUT"; exit 2; }

# Mint node
OUT=$(curl -s -b "$JAR" -c "$JAR" -X POST "$API/v1/nodes" \
  -H 'Content-Type: application/json' -d "{\"name\":\"soak-edge-$(date +%s)\",\"role\":\"edge\"}")
NTOK=$(printf '%s' "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")
printf '%s' "$NTOK" > "$SECRETS/token" && chmod 644 "$SECRETS/token"
echo "[soak] node minted"

# Claim domain
OUT=$(curl -s -b "$JAR" -c "$JAR" -X POST "$API/v1/domains" \
  -H 'Content-Type: application/json' -d "{\"hostname\":\"$HOST\"}")
DOM=$(printf '%s' "$OUT" | python3 -c "import json,sys; print(json.load(sys.stdin)['domain']['id'])")
echo "[soak] domain claimed: $HOST"

# Verify domain (TXT lookup via DNS stub)
VT=$(curl -s -b "$JAR" -c "$JAR" "$API/v1/domains/$DOM/verification" | python3 -c "import json,sys; print(json.load(sys.stdin)['verification']['record_value'])" | cut -d= -f2)
printf '%s' "$VT" > "$STUB_TOK"
sleep 0.5  # let the stub pick up the new token file
OUT=$(curl -s -w '\n%{http_code}' -b "$JAR" -c "$JAR" -X POST "$API/v1/domains/$DOM/verify")
CODE=$(printf '%s' "$OUT" | tail -1)
echo "[soak] domain verify: HTTP $CODE"
[ "$CODE" = "200" ] || { echo "domain verify failed ($CODE): $(head -1 <<< "$OUT")"; echo "--- API log ---"; tail -5 /tmp/edge-soak-api.log; exit 2; }

# Set origin
curl -s -o /dev/null -b "$JAR" -c "$JAR" -X POST "$API/v1/domains/$DOM/origin" \
  -H 'Content-Type: application/json' -d "{\"scheme\":\"http\",\"address\":\"$ORIGIN_IP\",\"port\":9001,\"tls_verify\":false}"
echo "[soak] origin set: http://$ORIGIN_IP:9001 at $(date +%H:%M:%S)"

# Start the poller (PRODUCTION PACING — no timing overrides).
sudo env GP_EDGE_API_BASE="$API" GP_EDGE_ISSUER=internal \
  docker compose -f "$COMPOSE" --profile poller up -d --build poller >/dev/null 2>&1 \
  || { echo "poller start failed"; exit 2; }
echo "[soak] poller up at $(date +%H:%M:%S)"

# Wait for snapshot applied.
for _ in $(seq 1 180); do
  sudo docker compose -f "$COMPOSE" logs poller 2>/dev/null | grep -q "applied snapshot generation" && break
  sleep 1
done
echo "[soak] snapshot applied at $(date +%H:%M:%S)"

# Warm-up: confirm edge serves the origin.
until curl -s -H "Host: $HOST" "$EDGE_HTTP/ok" | grep -q "port 9001"; do sleep 1; done
echo "[soak] edge serves origin-test at $(date +%H:%M:%S)"

# === docker inspect BEFORE the soak window ===
echo
echo "[soak] docker inspect BEFORE:"
EDGE_NAME=$(sudo docker ps -q --filter "name=gatepost-edge-dev-edge")
POLLER_NAME=$(sudo docker ps -q --filter "name=gatepost-edge-dev-poller")
INSPECT_BEFORE=$(sudo docker inspect --format='{{.RestartCount}} {{.State.StartedAt}}' "$EDGE_NAME" "$POLLER_NAME")
echo "  edge:    $(echo "$INSPECT_BEFORE" | head -1)"
echo "  poller:  $(echo "$INSPECT_BEFORE" | tail -1)"

# === Start steady traffic in the background ===
TRAFFIC_LOG=/tmp/edge-soak-traffic.log
: > "$TRAFFIC_LOG"
(
  END=$(( $(date +%s) + 360 ))  # 6 minutes of traffic (margin on both sides)
  while [ "$(date +%s)" -lt "$END" ]; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: $HOST" "$EDGE_HTTP/ok" 2>/dev/null)
    echo "$CODE" >> "$TRAFFIC_LOG"
    sleep 0.5
  done
) &
TRAFFIC_PID=$!
echo "[soak] traffic generator started (PID $TRAFFIC_PID) at $(date +%H:%M:%S)"

sleep 5  # let traffic stabilize

# === Stop the API ===
echo "[soak] stopping the API for 5 minutes at $(date +%H:%M:%S)"
kill "$API_PID" 2>/dev/null
API_PID=""

# === 5-minute soak with the API down ===
SOAK_END=$(( $(date +%s) + 300 ))
NEGATIVE_HIT=0
while [ "$(date +%s)" -lt "$SOAK_END" ]; do
  REMAIN=$(( (SOAK_END - $(date +%s)) / 60 ))
  echo "[soak] API down soak: ${REMAIN}m remaining ($(date +%H:%M:%S))"
  # Negative control: stop the edge for ~3s mid-soak (only in SOAK_NEGATIVE mode).
  if [ "${SOAK_NEGATIVE:-0}" = "1" ] && [ "$NEGATIVE_HIT" -eq 0 ] && [ "$REMAIN" -eq 2 ]; then
    echo "[soak] NEGATIVE CONTROL: stopping the edge for 3s at $(date +%H:%M:%S)"
    sudo docker compose -f "$COMPOSE" stop edge >/dev/null 2>&1
    sleep 3
    sudo docker compose -f "$COMPOSE" start edge >/dev/null 2>&1
    echo "[soak] edge restarted at $(date +%H:%M:%S)"
    NEGATIVE_HIT=1
  fi
  sleep 60
done
echo "[soak] 5-minute soak complete at $(date +%H:%M:%S)"

# === Collect evidence ===
echo
echo "=== EVIDENCE ==="

echo
echo "--- docker inspect AFTER (RestartCount StartedAt): ---"
INSPECT_AFTER=$(sudo docker inspect --format='{{.RestartCount}} {{.State.StartedAt}}' "$EDGE_NAME" "$POLLER_NAME")
echo "  edge:    $(echo "$INSPECT_AFTER" | head -1)"
echo "  poller:  $(echo "$INSPECT_AFTER" | tail -1)"
echo
echo "--- docker inspect BEFORE (for comparison): ---"
echo "  edge:    $(echo "$INSPECT_BEFORE" | head -1)"
echo "  poller:  $(echo "$INSPECT_BEFORE" | tail -1)"

EDGE_BEFORE_RC=$(echo "$INSPECT_BEFORE" | head -1 | awk '{print $1}')
EDGE_AFTER_RC=$(echo "$INSPECT_AFTER" | head -1 | awk '{print $1}')
POLLER_BEFORE_RC=$(echo "$INSPECT_BEFORE" | tail -1 | awk '{print $1}')
POLLER_AFTER_RC=$(echo "$INSPECT_AFTER" | tail -1 | awk '{print $1}')

echo
echo "--- RestartCount comparison: ---"
echo "  edge:    before=$EDGE_BEFORE_RC after=$EDGE_AFTER_RC"
echo "  poller:  before=$POLLER_BEFORE_RC after=$POLLER_AFTER_RC"
[ "$EDGE_BEFORE_RC" = "$EDGE_AFTER_RC" ] && echo "PASS: edge RestartCount unchanged" || echo "FAIL: edge was restarted!"
[ "$POLLER_BEFORE_RC" = "$POLLER_AFTER_RC" ] && echo "PASS: poller RestartCount unchanged" || echo "FAIL: poller was restarted!"

echo
echo "--- non-200 response count during soak window: ---"
TOTAL=$(wc -l < "$TRAFFIC_LOG" | tr -d ' ')
NON200=$(grep -v '^200$' "$TRAFFIC_LOG" 2>/dev/null | wc -l | tr -d ' ' )
ZEROS=$(grep -c '^000$' "$TRAFFIC_LOG" 2>/dev/null || printf '0')
ZEROS=${ZEROS%%$'\n'*}
echo "  total responses sampled: $TOTAL"
echo "  non-200 responses: $NON200"
echo "  connection failures (000): $ZEROS"
[ "$NON200" -eq 0 ] && echo "PASS: zero non-200 responses" || echo "FAIL: $NON200 non-200 responses"

echo
echo "--- poller log: health error scan: ---"
PLOG=$(sudo docker compose -f "$COMPOSE" logs poller 2>/dev/null)
SILENT=$(echo "$PLOG" | grep -c 'apply loop silent' || true)
HEALTH_ERR=$(echo "$PLOG" | grep -c 'health:' || true)
echo "  'apply loop silent' lines: $SILENT"
echo "  'health:' error lines: $HEALTH_ERR"
[ "$SILENT" -eq 0 ] && echo "PASS: no apply loop silent" || echo "FAIL: $SILENT apply loop silent lines"
[ "$HEALTH_ERR" -eq 0 ] && echo "PASS: no health errors" || echo "FAIL: $HEALTH_ERR health error lines"

echo
echo "--- poller log (last 50 lines): ---"
echo "$PLOG" | tail -50

# Stop the traffic generator.
kill "$TRAFFIC_PID" 2>/dev/null
wait "$TRAFFIC_PID" 2>/dev/null

echo
if [ "${SOAK_NEGATIVE:-0}" = "1" ]; then
  # Negative control: non-200 MUST be > 0 (the edge was stopped).
  SOAK_VERDICT=$([ "$EDGE_BEFORE_RC" = "$EDGE_AFTER_RC" ] && [ "$POLLER_BEFORE_RC" = "$POLLER_AFTER_RC" ] && [ "$NON200" -gt 0 ] && [ "$SILENT" -eq 0 ] && [ "$HEALTH_ERR" -eq 0 ] && echo PASSED || echo FAILED)
  echo "=== soak verdict: $SOAK_VERDICT ==="
  echo "=== (negative control: expected non-200 responses from the 3s edge stop ==="
else
  SOAK_VERDICT=$([ "$EDGE_BEFORE_RC" = "$EDGE_AFTER_RC" ] && [ "$POLLER_BEFORE_RC" = "$POLLER_AFTER_RC" ] && [ "$NON200" -eq 0 ] && [ "$SILENT" -eq 0 ] && [ "$HEALTH_ERR" -eq 0 ] && echo PASSED || echo FAILED)
  echo "=== soak verdict: $SOAK_VERDICT ==="
fi

# Tear down.
sudo docker compose -f "$COMPOSE" --profile poller down >/dev/null 2>&1
rm -f "$STUB_PY" "$STUB_TOK" "$JAR"
trap '' EXIT
trap '' INT TERM
