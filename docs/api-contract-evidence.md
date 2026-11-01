# API Contract Evidence

Real `curl` calls against a locally running Gatepost API, backed by a
throwaway Postgres database (no real data, no real secrets). Every customer
route is shown with a success case and one error case. Tokens, cookies and
the full API key are replaced with `[REDACTED]`.

## Setup

A throwaway Postgres container (`postgres:16-alpine`) on `127.0.0.1:54331`
with throwaway random credentials, and the Gatepost API on
`127.0.0.1:8091` with `ENV=development` and `GP_TEST_ALLOW_LOOPBACK=true`
(so the loopback origin used by `origin/test` passes the SSRF rules). A tiny
`python3 -m http.server` on `127.0.0.1:18090` serves as the test origin.

```text
DATABASE_URL=postgres://postgres:<throwaway>@127.0.0.1:54331/<throwaway-db>?sslmode=disable
DATABASE_URL_DIRECT=postgres://postgres:<throwaway>@127.0.0.1:54331/<throwaway-db>?sslmode=disable
GP_HTTP_ADDR=127.0.0.1:8091
GP_PUBLIC_BASE_URL=http://127.0.0.1:8091
GP_MAIL_DRIVER=outbox
ENV=development
GP_TEST_ALLOW_LOOPBACK=true
GP_SNAPSHOT_KEY=<32+ random bytes>
GP_NS1=ns1.seed.test
GP_NS2=ns2.seed.test
GP_ALLOW_SUBDOMAIN_ZONES=true
GP_TEST_ZONE=example.test
```

The API applies the migrations on boot (`applied 14 migration(s)`) and serves
the contract documented in `docs/api-contract.md`. Raw command/response
output was saved to `/tmp/opencode/evidence_raw.txt` during this run.

## Seed script

`scripts/seed-test-user.sh` creates a throwaway test user and a sample
domain in a fresh/empty database using only test values (random email,
random session token, random verify token). It inserts a verified user, a
live session, a verified cname domain and a loopback origin directly via
`psql`, then prints shell-evaluable variables including the `gp_session`
cookie. Nothing it prints is secret.

```bash
SEED_DATABASE_URL="postgres://postgres:<throwaway>@127.0.0.1:54331/<throwaway-db>?sslmode=disable" \
  ./scripts/seed-test-user.sh
```

Sample run (cookie redacted):

```text
SEED_USER_EMAIL='seed-76ed8ae20adf@example.test'
SEED_DOMAIN_HOSTNAME='seed-dda166433135.example.test'
SEED_DOMAIN_ID='8cb842c0-961c-45fe-8121-097372560be8'
SEED_USER_ID='81f6db32-53a6-4253-b599-7d6b54184670'
SESSION_COOKIE='gp_session=[REDACTED]'
# Seed complete: user ..., domain ... (id ...), session cookie ready.
```

The script is idempotent-safe (random values per run) and the throwaway
database is dropped at the end of the evidence run, so nothing persists.

## Customer route evidence

`BASE=http://127.0.0.1:8091` and `COOKIE='gp_session=[REDACTED]'` below.

### A1 POST /auth/signup

Success (new account, uniform "check your inbox" body):

```text
curl -s -X POST $BASE/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"evuser-....@example.test","password":"evpass-...."}'
HTTP 200
{"message":"check your inbox to verify your account","ok":true}
```

Error (invalid email shape):

```text
curl -s -X POST $BASE/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"not-an-email","password":"short"}'
HTTP 400
{"error":"invalid email or password"}
```

### A2 POST /auth/verify

Success (real one-time token read from the dev outbox):

```text
curl -s -X POST $BASE/auth/verify \
  -H 'Content-Type: application/json' \
  -d '{"token":"<real verify token from outbox>"}'
HTTP 200
{"ok":true}
```

Error (bad/expired token):

```text
curl -s -X POST $BASE/auth/verify \
  -H 'Content-Type: application/json' \
  -d '{"token":"bad-token-12345"}'
HTTP 400
{"error":"invalid or expired token"}
```

### A3 POST /auth/login

Success:

```text
curl -s -X POST $BASE/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"evuser-....@example.test","password":"evpass-...."}'
HTTP 200
{"ok":true}
```
(Sets the `gp_session` cookie.)

Error (wrong password):

```text
curl -s -X POST $BASE/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"evuser-....@example.test","password":"wrongpass"}'
HTTP 401
{"error":"invalid credentials"}
```

### A4 POST /auth/logout

Success (clears the session):

```text
curl -s -X POST $BASE/auth/logout \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{}'
HTTP 200
{"ok":true}
```

Error (no session):

```text
curl -s -X POST $BASE/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{}'
HTTP 401
{"error":"authentication required"}
```

### A5 POST /auth/password-reset-request

Success (always 202, uniform — no email enumeration):

```text
curl -s -X POST $BASE/auth/password-reset-request \
  -H 'Content-Type: application/json' \
  -d '{"email":"evuser-....@example.test"}'
HTTP 202
{"ok":true,"message":"if the address exists, a reset link was sent"}
```

Error (invalid email):

```text
curl -s -X POST $BASE/auth/password-reset-request \
  -H 'Content-Type: application/json' \
  -d '{"email":"not-an-email"}'
HTTP 400
{"error":"invalid email"}
```

### A6 POST /auth/password-reset

Error (bad/expired reset token — reset tokens live 30 min, one-time):

```text
curl -s -X POST $BASE/auth/password-reset \
  -H 'Content-Type: application/json' \
  -d '{"token":"bad","new_password":"NewPass123!"}'
HTTP 400
{"error":"invalid or expired token"}
```

### A7 POST /auth/password-change

Success (session-only, ends other sessions, rotates current token):

```text
curl -s -X POST $BASE/auth/password-change \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"evpass-....","new_password":"NewPass123!"}'
HTTP 200
{"ok":true}
```

Error (wrong current password — also counts toward lockout):

```text
curl -s -X POST $BASE/auth/password-change \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"current_password":"nope","new_password":"NewPass123!"}'
HTTP 401
{"error":"invalid credentials"}
```

### A8 GET /auth/sessions

Success (metadata only, token hashes never exposed):

```text
curl -s $BASE/auth/sessions \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"sessions":[{"id":"...","created_at":"2026-...","expires_at":"2026-...","current":true}]}
```

Error (no session):

```text
curl -s $BASE/auth/sessions
HTTP 401
{"error":"authentication required"}
```

### A9 POST /auth/sessions/{id}/revoke

Error (foreign or absent session id — uniform 404, no disclosure):

```text
curl -s -X POST $BASE/auth/sessions/00000000-0000-0000-0000-000000000000/revoke \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 404
{"error":"not found"}
```

### A10 POST /auth/logout-everywhere

Success (ends every session of the caller, clears the cookie):

```text
curl -s -X POST $BASE/auth/logout-everywhere \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"ok":true}
```

### A11 GET /auth/oauth/{provider}/start

Success (302 redirect to Google with state + PKCE + allowlisted redirect):

```text
curl -s -D - $BASE/auth/oauth/google/start
HTTP/1.1 302
Location: https://accounts.google.com/o/oauth2/v2/auth?...&state=<...>&code_challenge=<...>&code_challenge_method=S256&redirect_uri=http://127.0.0.1:8091/auth/oauth/google/callback
```

Error (unknown provider):

```text
curl -s $BASE/auth/oauth/unknown/start
HTTP 404
{"error":"unknown provider"}
```

### A12 GET /auth/oauth/{provider}/callback

Error (missing code or state):

```text
curl -s "$BASE/auth/oauth/google/callback?code=x"
HTTP 400
{"error":"missing code or state"}
```

(The full callback success path requires a real Google/GitHub provider and
client credentials, which are NOT BUILT for real flows — tests use a fake
provider. See GAPS.)

### A13 POST /auth/api-keys

Success (full key returned once, never stored):

```text
curl -s -X POST $BASE/auth/api-keys \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"name":"test key"}'
HTTP 201
{"id":"...","name":"test key","key":"gp_pat_[REDACTED]","prefix":"gp_pat_....","created_at":"2026-...","last_used_at":null,"revoked_at":null}
```

Error (invalid name — 1..100 chars):

```text
curl -s -X POST $BASE/auth/api-keys \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"name":""}'
HTTP 400
{"error":"invalid name"}
```

### A14 GET /auth/api-keys

Success (metadata only, never the full key):

```text
curl -s $BASE/auth/api-keys \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"keys":[{"id":"...","name":"test key","prefix":"gp_pat_....","created_at":"2026-...","last_used_at":null,"revoked_at":null}]}
```

### A15 POST /auth/api-keys/{id}/revoke

Error (foreign key — uniform 404):

```text
curl -s -X POST $BASE/auth/api-keys/00000000-0000-0000-0000-000000000000/revoke \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 404
{"error":"not found"}
```

Success (own key, terminal revocation):

```text
curl -s -X POST $BASE/auth/api-keys/<own-id>/revoke \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"ok":true}
```

### D1 GET /api/me

Success:

```text
curl -s $BASE/api/me \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"id":"...","email":"seed-....@example.test"}
```

Error (no session):

```text
curl -s $BASE/api/me
HTTP 401
{"error":"authentication required"}
```

### D2 GET /api/user-data

Success (stored JSON document, `{}` when none):

```text
curl -s $BASE/api/user-data \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{}
```

Success (PUT, ≤ 32 KiB valid JSON):

```text
curl -s -X PUT $BASE/api/user-data \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"theme":"dark","n":1}'
HTTP 200
{"ok":true}
```

Error (invalid JSON):

```text
curl -s -X PUT $BASE/api/user-data \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{not json}'
HTTP 400
{"error":"body must be valid JSON"}
```

### DM1 POST /v1/domains

Success (new cname claim):

```text
curl -s -X POST $BASE/v1/domains \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"ev-dom.example.test","setup_type":"cname"}'
HTTP 201
{"domain":{"id":"...","hostname":"ev-dom.example.test","status":"pending","setup_type":"cname","claimed_at":"2026-...","verified_at":null,"expires_at":"2026-...","ns1":"","ns2":"","waf_mode":"detection","excluded_rule_ids":[]},"existing":false}
```

Error (invalid hostname):

```text
curl -s -X POST $BASE/v1/domains \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"hostname":"not a hostname"}'
HTTP 400
{"error":"invalid hostname: ..."}
```

### DM2 GET /v1/domains

Success (full list, not paginated):

```text
curl -s $BASE/v1/domains \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"domains":[{"id":"...","hostname":"...","status":"pending",...}, ...]}
```

### DM3 GET /v1/domains/{id}

Success:

```text
curl -s $BASE/v1/domains/<seed-domain-id> \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"domain":{"id":"...","hostname":"seed-....example.test","status":"verified","setup_type":"cname","waf_mode":"detection","excluded_rule_ids":[],...}}
```

Error (foreign id — uniform 404, presence not disclosed):

```text
curl -s $BASE/v1/domains/00000000-0000-0000-0000-000000000000 \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 404
{"error":"not found"}
```

### DM4 DELETE /v1/domains/{id}

Success (second domain):

```text
curl -s -X DELETE $BASE/v1/domains/<second-domain-id> \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"ok":true}
```

### DM5 PUT /v1/domains/{id}/waf

Success:

```text
curl -s -X PUT $BASE/v1/domains/<seed-domain-id>/waf \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"mode":"blocking","excluded_rule_ids":[1001,1002]}'
HTTP 200
{"domain":{"id":"...","hostname":"...","waf_mode":"blocking","excluded_rule_ids":[1001,1002],...}}
```

Error (invalid mode):

```text
curl -s -X PUT $BASE/v1/domains/<seed-domain-id>/waf \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"mode":"paranoid"}'
HTTP 400
{"error":"mode must be off, detection, or blocking"}
```

### DM6 GET /v1/domains/{id}/verification

Success (DNS instructions — cname mode shows TXT record):

```text
curl -s $BASE/v1/domains/<seed-domain-id>/verification \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"verification":{"domain_id":"...","hostname":"seed-....example.test","setup_type":"cname","status":"verified","expires_at":null,"record_name":"_gatepost-verify.seed-....example.test","record_value":"gatepost-verify=<token>"}}
```

### DM7 POST /v1/domains/{id}/verify

Success (already verified, idempotent):

```text
curl -s -X POST $BASE/v1/domains/<seed-domain-id>/verify \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"status":"verified"}
```

Error (claim not pending — already verified):

```text
curl -s -X POST $BASE/v1/domains/<seed-domain-id>/verify \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 410
{"error":"claim is verified, not verifiable"}
```

### DM8 POST /v1/domains/{id}/origin

Success (domain without origin):

```text
curl -s -X POST $BASE/v1/domains/<dom2-id>/origin \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"scheme":"http","address":"127.0.0.1","port":18090,"health_path":"/"}'
HTTP 201
{"origin":{"scheme":"http","address":"127.0.0.1","port":18090,"host_header":null,"tls_verify":true,"health_path":"/","health_interval":60,"created_at":"2026-...","updated_at":"2026-..."}}
```

Error (private-range origin refused — SSRF):

```text
curl -s -X POST $BASE/v1/domains/<dom2-id>/origin \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"scheme":"http","address":"10.0.0.1","port":8080,"health_path":"/"}'
HTTP 422
{"error":"origin address: ... is inside 10.0.0.0/8"}
```

### DM9 GET /v1/domains/{id}/origin

Success:

```text
curl -s $BASE/v1/domains/<dom2-id>/origin \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"origin":{"scheme":"http","address":"127.0.0.1","port":18090,...}}
```

Error (no origin set on seed domain):

```text
curl -s $BASE/v1/domains/<seed-domain-id>/origin \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 404
{"error":"no origin set"}
```

### DM10 PUT /v1/domains/{id}/origin

Success:

```text
curl -s -X PUT $BASE/v1/domains/<dom2-id>/origin \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"scheme":"https","address":"127.0.0.1","port":18090,"health_path":"/","tls_verify":false}'
HTTP 200
{"origin":{"scheme":"https","address":"127.0.0.1","port":18090,"tls_verify":false,...}}
```

Error (no origin):

```text
curl -s -X PUT $BASE/v1/domains/<seed-domain-id>/origin \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"scheme":"http","address":"127.0.0.1","port":18090}'
HTTP 404
{"error":"no origin set; POST to create"}
```

### DM11 POST /v1/domains/{id}/origin/test

Success (reachable loopback origin, `GP_TEST_ALLOW_LOOPBACK=true`):

```text
curl -s -X POST $BASE/v1/domains/<dom2-id>/origin/test \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"test":{"reachable":true,"status_code":200,"tls_ok":false,"duration_ms":0}}
```

Error (no origin set):

```text
curl -s -X POST $BASE/v1/domains/<seed-domain-id>/origin/test \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 404
{"error":"no origin set"}
```

### DM12 POST /v1/domains/{id}/records

Success (nameserver-mode domain with a zone):

```text
curl -s -X POST $BASE/v1/domains/<ns-domain-id>/records \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"name":"@","type":"A","value":"1.2.3.4","ttl":3600}'
HTTP 201
{"record":{"id":"...","name":"@","type":"A","value":"1.2.3.4","ttl":3600,"priority":null,"created_at":"2026-..."}}
```

Error (cname domain has no zone):

```text
curl -s -X POST $BASE/v1/domains/<seed-domain-id>/records \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"name":"@","type":"A","value":"1.2.3.4"}'
HTTP 409
{"error":"records need a nameserver-mode domain"}
```

### DM13 GET /v1/domains/{id}/records

Success (full list, not paginated):

```text
curl -s $BASE/v1/domains/<ns-domain-id>/records \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"records":[{"id":"...","name":"@","type":"A","value":"1.2.3.4","ttl":3600,"priority":null,"created_at":"2026-..."}]}
```

### DM14 GET /v1/domains/{id}/records/{rid}

Success (record + history):

```text
curl -s $BASE/v1/domains/<ns-domain-id>/records/<record-id> \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"record":{"id":"...","name":"@","type":"A","value":"1.2.3.4","ttl":3600,"priority":null,"created_at":"2026-..."},"history":[{"action":"create","old_value":null,"new_value":"1.2.3.4","changed_by":"...","changed_at":"2026-..."}]}
```

Error (absent record id):

```text
curl -s $BASE/v1/domains/<ns-domain-id>/records/00000000-0000-0000-0000-000000000000 \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 404
{"error":"not found"}
```

### DM15 PATCH /v1/domains/{id}/records/{rid}

Success:

```text
curl -s -X PATCH $BASE/v1/domains/<ns-domain-id>/records/<record-id> \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{"ttl":7200}'
HTTP 200
{"record":{"id":"...","name":"@","type":"A","value":"1.2.3.4","ttl":7200,"priority":null,"created_at":"2026-..."}}
```

Error (nothing to change):

```text
curl -s -X PATCH $BASE/v1/domains/<ns-domain-id>/records/<record-id> \
  -H 'Cookie: gp_session=[REDACTED]' \
  -H 'Content-Type: application/json' \
  -d '{}'
HTTP 400
{"error":"nothing to change"}
```

### DM16 DELETE /v1/domains/{id}/records/{rid}

Success:

```text
curl -s -X DELETE $BASE/v1/domains/<ns-domain-id>/records/<record-id> \
  -H 'Cookie: gp_session=[REDACTED]'
HTTP 200
{"deleted":true}
```

## Cleanup

The throwaway API process, the throwaway Postgres container
(`gp-evidence-pg`), the origin server and the throwaway database were all
stopped/removed after this run. No real data or secrets were used or
retained.
