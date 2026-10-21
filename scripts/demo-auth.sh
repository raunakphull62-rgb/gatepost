#!/usr/bin/env bash
# Gatepost demo: scripted curl walkthrough of the auth API.
# Builds the server, runs it against the .env database, then exercises
# signup → verify → login → logout → reset → API keys → user-data.
# Every step prints PASS/FAIL; the script exits nonzero if any step fails.
# Secrets stay in .env, which is never printed.
# Rate-limit hygiene: the server runs with 127.0.0.1 trusted and every demo
# request spoofs its own unique X-Forwarded-For, so repeated runs don't trip
# the 20-auth/15-min IP cap (mirrors how the go tests isolate their IPs).
set -u
cd "$(dirname "$0")/.."

BASE="${GP_PUBLIC_BASE_URL:-http://localhost:8090}"
JAR="$(mktemp)"; JAR2="$(mktemp)"
OUTDIR=outbox
trap 'kill ${SRV_PID:-0} 2>/dev/null; rm -f "${JAR:-}" "${JAR2:-}" "${J3:-}" "${J4:-}"' EXIT

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
CIP="10.$((RANDOM%200+20)).$((RANDOM%200+20)).$((RANDOM%200+20))"
code()  { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $CIP" "$@"; }
pcode() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $CIP" "$@"; }
raw()   { curl -s -H "X-Forwarded-For: $CIP" "$@"; }
newest_mail() { # newest outbox file matching a pattern
  grep -l "$1" $(ls -t "$OUTDIR"/*.txt 2>/dev/null) 2>/dev/null | head -1
}
mail_token() {
  grep -m1 -o 'token: [A-Za-z0-9_-]*' "$(newest_mail "$1")" | cut -d' ' -f2
}

mkdir -p "$OUTDIR"
go build -o gatepost ./cmd/gatepost || exit 2
ENV=development GP_TRUSTED_PROXIES=127.0.0.1/32 ./gatepost >/tmp/gatepost-demo-server.log 2>&1 &
SRV_PID=$!
for _ in $(seq 1 30); do pcode "$BASE/api/me" >/dev/null 2>&1 && break; sleep 0.5; done
pcode "$BASE/api/me" >/dev/null 2>&1 || { echo "server did not come up (see /tmp/gatepost-demo-server.log)"; exit 2; }

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
check $((s++)) "session works (/api/me)" "$(pcode -b "$JAR" "$BASE/api/me")" 200

check $((s++)) "login with wrong password → 401" \
  "$(code -X POST "$BASE/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"wrong-wrong\"}")" 401
check $((s++)) "login" \
  "$(code -X POST "$BASE/auth/login" -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 200
check $((s++)) "logout" "$(code -X POST "$BASE/auth/logout" -c "$JAR" -b "$JAR")" 200
check $((s++)) "session dead after logout" "$(pcode -b "$JAR" "$BASE/api/me")" 401
check $((s++)) "login again" \
  "$(code -X POST "$BASE/auth/login" -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 200

check $((s++)) "welcome mail sent exactly once to $U, in the outbox" \
  "$(grep -l 'Welcome to Gatepost' "$OUTDIR"/*.txt 2>/dev/null | xargs grep -l "To: $U" 2>/dev/null | wc -l)" 1

check $((s++)) "password reset request (uniform 202)" \
  "$(code -X POST "$BASE/auth/password-reset-request" -H 'Content-Type: application/json' -d "{\"email\":\"$U\"}")" 202
RT=$(mail_token 'Your password reset token')
check $((s++)) "password reset" \
  "$(code -X POST "$BASE/auth/password-reset" -H 'Content-Type: application/json' -d "{\"token\":\"$RT\",\"new_password\":\"demo-password-2\"}")" 200
check $((s++)) "old session dead after reset" "$(pcode -b "$JAR" "$BASE/api/me")" 401
check $((s++)) "login with new password" \
  "$(code -X POST "$BASE/auth/login" -c "$JAR" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"demo-password-2\"}")" 200
check $((s++)) "old password rejected" \
  "$(code -X POST "$BASE/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW\"}")" 401

KEY_JSON=$(raw -X POST "$BASE/auth/api-keys" -b "$JAR" -H 'Content-Type: application/json' -d '{"name":"demo"}')
KEY=$(printf '%s' "$KEY_JSON" | jq -r .key); KID=$(printf '%s' "$KEY_JSON" | jq -r .id)
check $((s++)) "api key created (gp_pat_…, shown once)" "$(printf '%s' "$KEY" | grep -c '^gp_pat_')" 1
check $((s++)) "Bearer key authenticates /api/me" "$(code "$BASE/api/me" -H "Authorization: Bearer $KEY")" 200
check $((s++)) "user-data put via Bearer" \
  "$(code -X PUT "$BASE/api/user-data" -H 'Content-Type: application/json' -H "Authorization: Bearer $KEY" -d '{"demo":true,"items":[1,2,3]}')" 200
check $((s++)) "user-data get returns own doc" \
  "$(raw "$BASE/api/user-data" -H "Authorization: Bearer $KEY" | jq -r '.demo')" true
check $((s++)) "api key list shows prefix, never the key" \
  "$(raw "$BASE/auth/api-keys" -b "$JAR" | grep -c "$KEY")" 0
check $((s++)) "revoke" "$(code -X POST "$BASE/auth/api-keys/$KID/revoke" -b "$JAR")" 200
check $((s++)) "revoked key is dead instantly" "$(code "$BASE/api/me" -H "Authorization: Bearer $KEY")" 401

# cross-user isolation, quickly: a second user must see an empty document
check $((s++)) "second user signup" \
  "$(code -X POST "$BASE/auth/signup" -H 'Content-Type: application/json' -d "{\"email\":\"$U2\",\"password\":\"$PW\"}")" 200
VT2=$(mail_token "$U2")
check $((s++)) "second user verify" \
  "$(code -X POST "$BASE/auth/verify" -c "$JAR2" -H 'Content-Type: application/json' -d "{\"token\":\"$VT2\"}")" 200
check $((s++)) "user B sees an empty doc (isolated from A)" \
  "$(raw "$BASE/api/user-data" -b "$JAR2")" "{}"

# --- sessions: sliding+rotation, list, revoke, logout-everywhere -------------
J3="$(mktemp)"; J4="$(mktemp)"
PW3="demo-password-3"

# two extra devices logged in (password is demo-password-2 right now)
check $((s++)) "login device 2" \
  "$(code -X POST "$BASE/auth/login" -c "$J3" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"demo-password-2\"}")" 200
check $((s++)) "login device 4" \
  "$(code -X POST "$BASE/auth/login" -c "$J4" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"demo-password-2\"}")" 200
check $((s++)) "sessions list: 3 rows, 1 current (fresh session per login)" \
  "$(raw "$BASE/auth/sessions" -b "$JAR" | jq -r '[(.sessions|length), ([.sessions[]|select(.current)]|length)] | join(" of ")')" "3 of 1"
check $((s++)) "sessions list leaks no token material" \
  "$(raw "$BASE/auth/sessions" -b "$JAR" | grep -ci token)" 0

# password change: current password required; wrong answer counts like login
check $((s++)) "password change with wrong current password → 401" \
  "$(code -X POST "$BASE/auth/password-change" -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -d "{\"current_password\":\"nope-nope\",\"new_password\":\"$PW3\"}")" 401
check $((s++)) "password change (correct current password)" \
  "$(code -X POST "$BASE/auth/password-change" -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -d "{\"current_password\":\"demo-password-2\",\"new_password\":\"$PW3\"}")" 200
check $((s++)) "rotated session cookie still works (/api/me)" "$(pcode -b "$JAR" "$BASE/api/me")" 200
check $((s++)) "other devices logged out by the password change" "$(pcode -b "$J3" "$BASE/api/me")" 401
check $((s++)) "previous password rejected" \
  "$(code -X POST "$BASE/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"demo-password-2\"}")" 401

# list & revoke: back to exactly 2 live sessions (jar + new j3 login)
check $((s++)) "login again (new password)" \
  "$(code -X POST "$BASE/auth/login" -c "$J3" -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW3\"}")" 200
SID=$(raw "$BASE/auth/sessions" -b "$JAR" | jq -r '[.sessions[] | select(.current == false)][0].id // empty')
check $((s++)) "revoke one session by id" \
  "$(code -X POST "$BASE/auth/sessions/$SID/revoke" -b "$JAR")" 200
check $((s++)) "revoked device session is dead instantly" "$(pcode -b "$J3" "$BASE/api/me")" 401
check $((s++)) "revoke of an absent id → 404" \
  "$(code -X POST "$BASE/auth/sessions/00000000-0000-0000-0000-000000000000/revoke" -b "$JAR")" 404
check $((s++)) "list shrunk to 1 (current only)" \
  "$(raw "$BASE/auth/sessions" -b "$JAR" | jq '.sessions | length')" 1

# logout everywhere: every session of the user dies in one call
check $((s++)) "logout everywhere" "$(code -X POST "$BASE/auth/logout-everywhere" -b "$JAR")" 200
check $((s++)) "device 1 session dead" "$(pcode -b "$JAR" "$BASE/api/me")" 401
check $((s++)) "login still possible afterwards" \
  "$(code -X POST "$BASE/auth/login" -c /dev/null -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW3\"}")" 200

# storage + cookie hygiene, shown: cookie flags from a live Set-Cookie header
# and the argon2id PHC string in the database (never a plaintext password)
CD=$(curl -sS -D - -o /dev/null -X POST "$BASE/auth/login" -c /dev/null \
  -H 'Content-Type: application/json' -d "{\"email\":\"$U\",\"password\":\"$PW3\"}" | tr -d '\r' | grep -i '^set-cookie:')
check $((s++)) "session cookie flags shown (HttpOnly, Path=/, SameSite=Lax)" \
  "$(printf '%s' "$CD" | grep -oc 'HttpOnly')/$(printf '%s' "$CD" | grep -oc 'SameSite=Lax')/$(printf '%s' "$CD" | grep -oc 'Path=/')" "1/1/1"
DBURL="$(sed -n 's/^DATABASE_URL=//p' .env)"
check $((s++)) "argon2id PHC hash stored (db shows hash, never plaintext)" \
  "$(psql "$DBURL" -tAc "SELECT count(*) FROM users WHERE email = '$U' AND password_hash LIKE '\$argon2id\$%'")" 1

echo
echo "=== demo: $PASS pass, $FAIL fail ==="
[ "$FAIL" -eq 0 ]
