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

## PART 1 — Design note (docs/auth-design.md) — PENDING · awaiting "continue"
Scope to cover: stack (Go API, Postgres in Docker), schema (users, auth_identities,
sessions, api_keys, user_data JSONB), argon2id, OAuth (Google + GitHub, state/PKCE,
redirect allowlist, verified-email linking), session cookies (hash-only), API keys
(gp_pat_, 256-bit random, hash+prefix only), rate limits/lockouts, threat table,
public-not-secret user IDs, email sender interface (outbox driver default, SMTP off),
welcome message text.

## PART 2 — Build — PENDING · awaiting "continue"
1. [ ] Migrations; signup; email verification (outbox); login; logout; password reset; session cookie
2. [ ] Rate limiting + lockout keyed by IP + email
3. [ ] Google/GitHub login vs fake OAuth provider in tests (state, redirect URI, unverified email, linking, no duplicates)
4. [ ] API keys: create/list/revoke/Bearer; DB-proof: no plaintext keys or tokens
5. [ ] user_data JSONB get/put; cross-user isolation proof
6. [ ] Welcome message once, post-verification; outbox file shown
7. [ ] scripts/demo-auth.sh (curl walkthrough)
8. [ ] Regression test script with pass/fail summary

## Need from user
- Google / GitHub OAuth client credentials (request at PART 2 step 3; give via local untracked config, never committed/printed)
- Nothing else so far

## Notes
- Everything runs on this dev server. No frontend, no nodes, no deployment.
- No secrets are printed or committed anywhere.
