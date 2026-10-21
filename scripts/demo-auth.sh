#!/usr/bin/env bash
# Gatepost demo: scripted curl walkthrough of the auth API.
# Builds the server, runs it against the .env database, then exercises
# signup → verify → login → logout → reset → API keys → user-data.
# Every step prints PASS/FAIL; the script exits nonzero if any step fails.
# Secrets stay in .env, which is never printed.
set -u
cd "$(dirname "$0")/.."

BASE="${GP_PUBLIC_BASE_URL:-http://localhost:8090}"
JAR="$(mktemp)"; JAR2="$(mktemp)"
OUTDIR=outbox
trap 'kill ${SRV_PID:-0} 2>/dev/null; rm -f "$JAR" "$JAR2"' EXIT

if [ ! -f .env ]; then
  echo "no .env at repo root (DB connection strings live there; create it yourself, never paste it here)" >&2
  exit 2
fi

PASS=0 FAIL=0
check() { # check <step> <desc> <actual> <want>
  if [ "$3" = "$4" ]; then
    echo "PASS $1: $2"; PASS=$((PASS+1))
  else
    echo "FAIL $1: $2 (want $4, got $3)"; FAIL=$((FAIL+1))
  fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
newest_mail() { # newest outbox file matching a pattern
  grep -l "$1" $(ls -t "$OUTDIR"/*.txt 2>/dev/null) 2>/dev/null | head -1
}
mail_token() {
  grep -m1 -o 'token: [A-Za-z0-9_-]*' "$(newest_mail "$1")" | cut -d' ' -f2
}

mkdir -p "$OUTDIR"
go build -o gatepost ./cmd/gatepost || exit 2
./gatepost >/tmp/gatepost-demo-server.log 2>&1 &
SRV_PID=$!
for _ in $(seq 1 30); do curl -s -o /dev/null "$BASE/api/me" && break; sleep 0.5; done
curl -s -o /dev/null "$BASE/api/me" || { echo "server did not come up (see /tmp/gatepost-demo-server.log)"; exit 2; }

TS=$(date +%s)-$RANDOM
U="demo-$TS@x.test";   PW="demo-password-1"
U2="demo-$TS-b@x.test"

s=1
check $((s++)) "signup $U" \
  "$(code -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 200
check $((s++)) "duplicate signup answers the same (no enumeration)" \
  "$(code -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 200

VT=$(mail_token 'Your verification token')
check $((s++)) "verify token arrived in outbox file" "$([ -n "$VT" ] && echo yes)" yes
check $((s++)) "verify (also starts a session)" \
  "$(code -X POST "$BASE/auth/verify" -c "$JAR" -H 'Content-Type: application/json' -d "{\"token\":\"$VT\"}")" 200
check $((s++)) "session works (/api/me)" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/api/me")" 200

check $((s++)) "login with wrong password → 401" \
  "$(code -X POST "$BASE/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"wrong-wrong\"}")" 401
check $((s++)) "login" \
  "$(code -X POST "$BASE/auth/login" -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 200
check $((s++)) "logout" "$(code -X POST "$BASE/auth/logout" -c "$JAR" -b "$JAR")" 200
check $((s++)) "session dead after logout" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/api/me")" 401
check $((s++)) "login again" \
  "$(code -X POST "$BASE/auth/login" -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 200

check $((s++)) "welcome mail sent exactly once to $U, in the outbox" \
  "$(grep -l 'Welcome to Gatepost' "$OUTDIR"/*.txt 2>/dev/null | xargs grep -l "To: $U" 2>/dev/null | wc -l)" 1

check $((s++)) "password reset request (uniform 202)" \
  "$(code -X POST "$BASE/auth/password-reset-request" -H 'Content-Type: application/json' -d "{\"email\":\"$U\"}")" 202
RT=$(mail_token 'Your password reset token')
check $((s++)) "password reset" \
  "$(code -X POST "$BASE/auth/password-reset" -H 'Content-Type: application/json' -d "{\"token\":\"$RT\",\"new_password\":\"demo-password-2\"}")" 200
check $((s++)) "old session dead after reset" "$(curl -s -o /dev/null -w '%{http_code}' -b "$JAR" "$BASE/api/me")" 401
check $((s++)) "login with new password" \
  "$(code -X POST "$BASE/auth/login" -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"demo-password-2\"}")" 200
check $((s++)) "old password rejected" \
  "$(code -X POST "$BASE/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 401

KEY_JSON=$(curl -s -X POST "$BASE/auth/api-keys" -b "$JAR" -H 'Content-Type: application/json' -d '{"name":"demo"}')
KEY=$(printf '%s' "$KEY_JSON" | jq -r .key); KID=$(printf '%s' "$KEY_JSON" | jq -r .id)
check $((s++)) "api key created (gp_pat_…, shown once)" "$(printf '%s' "$KEY" | grep -c '^gp_pat_')" 1
check $((s++)) "Bearer key authenticates /api/me" "$(code "$BASE/api/me" -H "Authorization: Bearer $KEY")" 200
check $((s++)) "user-data put via Bearer" \
  "$(code -X PUT "$BASE/api/user-data" -H 'Content-Type: application/json' -H "Authorization: Bearer $KEY" -d '{"demo":true,"items":[1,2,3]}')" 200
check $((s++)) "user-data get returns own doc" \
  "$(curl -s "$BASE/api/user-data" -H "Authorization: Bearer $KEY" | jq -r '.demo')" true
check $((s++)) "api key list shows prefix, never the key" \
  "$(curl -s "$BASE/auth/api-keys" -b "$JAR" | grep -c "$KEY")" 0
check $((s++)) "revoke" "$(code -X POST "$BASE/auth/api-keys/$KID/revoke" -b "$JAR")" 200
check $((s++)) "revoked key is dead instantly" "$(code "$BASE/api/me" -H "Authorization: Bearer $KEY")" 401

# cross-user isolation, quickly: a second user must see an empty document
check $((s++)) "second user signup" \
  "$(code -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U2\",\"password\":\"$PW\"}")" 200
VT2=$(mail_token "$U2")
check $((s++)) "second user verify" \
  "$(code -X POST "$BASE/auth/verify" -c "$JAR2" -H 'Content-Type: application/json' -d "{\"token\":\"$VT2\"}")" 200
check $((s++)) "user B sees an empty doc (isolated from A)" \
  "$(curl -s "$BASE/api/user-data" -b "$JAR2")" "{}"

echo
echo "=== demo: $PASS pass, $FAIL fail ==="
[ "$FAIL" -eq 0 ]
