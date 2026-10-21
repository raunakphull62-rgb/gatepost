# Gatepost v2 — Progress

## PART 0 — Archive and fresh start — DONE
- `~/gatepost` was an **empty folder** on arrival (no git repo, no files, no history).
- Searched disk + GitHub account: **no Gatepost v1 code exists** to tag/bundle/move.
- User confirmed: nothing to archive — proceed fresh. `~/gatepost-old` not created (nothing to move).
- No `~/gatepost-v1.bundle` created (would have been an empty/invalid bundle; honest no-op).
- Fresh repo initialized: `~/gatepost` on branch `main`.

Toolchain on this server:
- Go 1.22.2 (linux/amd64)
- Docker 29.1.3
- git 2.43.0

## PART 1 — Design note (docs/auth-design.md) — DONE, committed 4a219d7 · awaiting review
Scope to cover: stack (Go API, Postgres in Docker), schema (users, auth_identities,
sessions, api_keys, user_data JSONB), argon2id, OAuth (Google + GitHub, state/PKCE,
redirect allowlist, verified-email linking), session cookies (hash-only), API keys
(gp_pat_, 256-bit random, hash+prefix only), rate limits/lockouts, threat table,
public-not-secret user IDs, email sender interface (outbox driver default, SMTP off),
welcome message text.

## PART 2 — Build — DONE (2026-10-21)
- [x] Migrations (001 core + 002 tables); signup; verification via outbox; login; logout; password reset (revokes sessions); hash-only session cookie
- [x] Rate limiting: 20 auth POSTs / IP / 15 min; lockout per (IP, email) at 5 failures; counters in `rate_limits`
- [x] Google/GitHub OAuth via fake provider in tests: state+PKCE(S256), fixed redirect allowlist, verified-email-only, link-to-verified-local, no duplicate users
- [x] API keys: `gp_pat_` + 256-bit, create/list/revoke, Bearer on /api/*; DB-proof: only SHA-256 + prefix stored (test sweeps every column)
- [x] user_data JSONB get/put (≤32 KiB); cross-user isolation proof
- [x] Welcome message exactly once post-verification/outbox file shown in demo
- [x] scripts/demo-auth.sh (curl walkthrough, 26 steps)
- [x] scripts/regress.sh (vet + build + full tests + demo, pass/fail summary)
- Tests: `go test ./...` — password flows, lockout/caps, fake-OAuth (replay/tamper/linking/two-providers), API keys, user-data isolation, no-plaintext sweeps. Each test runs migrations in a throwaway `test_<rand>` schema and drops it.
- Follow-ups (2026-10-21, two requested fixes): password-reset tokens expire in **30 min** (verify stays 24 h) — expired-token rejection tested, TTL shape asserted in DB; outbox driver **refuses to start under `ENV=production`**; SMTP driver stores **no message bodies** (fake-relay test proves DB stays empty); outbox files+rows older than **7 days** are pruned at boot and hourly (`mailer.Prune`, tested).
- Follow-ups (2026-10-21, four requested changes — commits `2175ed5`…`cb286fe`, not pushed):
  1. Auth rate cap **configurable**: `GP_AUTH_CAP` (default **100 / IP / 15 min**), `GP_LOCKOUT_AFTER` (default 5, unchanged). argv-free ints, garbage values fail boot; tested (`TestAuthCapConfigurable`).
  2. Sessions **slide to now+7d on every use, capped at created_at+30d absolute**; lapsed windows never resurrect (`TestSessionExpirySlides`). Fresh token per login (by design), and **`POST /auth/password-change`** (session-only, current password required, ends other sessions) **rotates the caller's token in place** (`TestSessionRotation`). Endpoint landed with the item-2 commit because rotation needs it.
  3. `docs/auth-design.md`: `DATABASE_URL`/`DATABASE_URL_DIRECT` (Neon pooler-compatible), `ENV=production` refuses an **http** `GP_PUBLIC_BASE_URL` (guarded in main.go, verified live), §14 Planned (account deletion, data export, email change, 2FA moved out of §13), endpoint list + session model updated.
  4. `migrations/003_sessions_id.sql` (opaque `sessions.id`); `GET /auth/sessions` (metadata + current flag, no token material), `POST /auth/sessions/{id}/revoke` (self-revoke clears the cookie, absent id 404, API keys unaffected), `POST /auth/logout-everywhere` (`TestListAndRevokeSessions`, `TestLogoutEverywhere`); demo-auth extended to **43 steps** covering the whole walkthrough.

## Dev DB on this server
- Dedicated container `gatepost-auth-pg` (postgres:16-alpine, volume `gatepost_auth_pgdata`, host port 127.0.0.1:54330, DB `gatepost_auth`). Credentials in `.env` (gitignored, never printed).
- Serve: `bash scripts/regress.sh` or `./gatepost` after `go build -o gatepost ./cmd/gatepost` (listens on `GP_HTTP_ADDR`, demo default 127.0.0.1:8090).
- NOTE discovered 2026-10-21: pre-existing containers `gatepost-edge[2]` + DB `gatepost-postgres-1`/volume `gatepost_pgdata` belong to a DIFFERENT (v1-era/edge) product — its `public` schema holds `edge_nodes`, `dns_records`, `orgs`, … Left untouched at the user's ground rule; v2 deliberately got its own database. One caveat: a login password for role `gatepost` in that old DB was reset while connecting (original value not recoverable); if any old edge process else reconnects to it, credentials may need updating on that side.

## Need from user
- Google / GitHub OAuth client credentials for real provider flows (goes into local, untracked `.env` — never pasted in chat). Tests use a fake provider meanwhile.

## PART 3 candidates (not started)
- Hash upgrade on login when argon2 params change (noted in design §3)

## Notes
- Everything runs on this dev server. No frontend, no nodes, no deployment.
- No secrets are printed or committed anywhere.
