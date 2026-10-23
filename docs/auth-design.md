# Gatepost v2 — Auth & Accounts Design

Status: proposed (PART 1). No code written yet. Scope: backend only — accounts, login, sessions, API keys, user data, email. No frontend, no nodes, no deployment; everything runs on this dev server.

## 1. Stack

- **Go 1.22** (already on the box), stdlib `net/http` with the 1.22+ `ServeMux` (method+path patterns). No web framework.
- **Postgres** from `DATABASE_URL` (used by the API pool) and `DATABASE_URL_DIRECT` (used by migrations when present). Neon-compatible: with Neon's pooler the pooled URL sits behind transactions and the direct URL hits a real session connection — plain local URLs work with either env set or both pointing at the same database. Driver: `pgx/v5` (`pgxpool`) — the standard Postgres driver for Go, native JSONB support.
- **Migrations:** plain `.sql` files under `migrations/`, applied lexicographically at startup by a ~40-line runner with a `schema_migrations` table and a Postgres advisory lock against double-apply.
- **argon2id** from `golang.org/x/crypto/argon2`. **OAuth** from `golang.org/x/oauth2` (credentials only; endpoints configurable so tests can point it at a fake provider).
- No JWT, no Redis, no ORM. Rate limit state lives in Postgres like everything else.

Module name: `gatepost`. Layout: `cmd/gatepost/`, `internal/…`, `migrations/`, `docs/`, `scripts/`.

## 2. Data model

All IDs are **UUIDv4 (random, opaque)**. The user ID is a random *public* identifier — it appears in URLs, logs and other users' UIs by design and is not a secret. Nothing sequential anywhere; an API key or session token is never a row ID, an address, or a storage path.

| Table | Purpose | Notable columns / constraints |
|---|---|---|
| `users` | One row per account | `id uuid PK`, `email text NOT NULL` (unique on `lower(email)`), `email_verified bool DEFAULT false`, `password_hash text NULL` (NULL for OAuth-only accounts), `welcome_sent_at timestamptz NULL`, `created_at`, `updated_at` |
| `auth_identities` | OAuth identities linked to users | `user_id FK→users`, `provider` (`google`/`github`), `provider_account_id`, `provider_email`, `provider_email_verified bool`, `created_at`; `UNIQUE(provider, provider_account_id)` |
| `sessions` | Server-side sessions | `token_hash text PK` (SHA‑256 of the cookie value), `user_id FK→users`, `id uuid` (safe list/revoke identifier), `created_at`, `expires_at` (7 d sliding, 30 d absolute from `created_at`). Plaintext token never stored |
| `api_keys` | Bearer tokens for API access | `id uuid PK`, `user_id FK→users`, `name text`, `key_hash text UNIQUE` (SHA‑256), `prefix text` (~first 12 chars, for the list view), `created_at`, `last_used_at NULL`, `revoked_at NULL`. Plaintext never stored |
| `user_data` | Per-user JSONB blob | `user_id uuid PK FK→users`, `data jsonb NOT NULL`, `updated_at`. One document per user, typed `jsonb`, keyed by `user_id` only |
| `email_tokens` | Verify/reset link tokens | `token_hash text UNIQUE`, `user_id FK→users`, `purpose` (`verify`/`reset`), `expires_at` (verify 24 h / **reset 30 min**), `used_at NULL`. One-time use |
| `oauth_states` | Anti-CSRF state per OAuth attempt | `state text PK`, `provider`, `code_verifier`, `redirect_uri` (must match allowlist), `created_at`, `expires_at` (10 min), `used_at NULL`. One-time |
| `rate_limits` | Counters & lockouts | `key text PK`, `count int`, `window_start timestamptz`. Atomic upsert; key encodes scope (§7) |
| `outbox_messages` | Dev mail log | `id bigserial`, `sent_at`, `to_addr`, `subject`, `body text`, `kind`. Written by the outbox mail driver |

## 3. Passwords (argon2id)

- Min length 8, max 128, trimmed of whitespace only at edges? No — stored as typed (no silent mutation); no composition rules (NIST).
- Params (OWASP current): `m = 19 MiB, t = 2, p = 1`. Stored in PHC string format (`$argon2id$v=19$m=…`) in `users.password_hash`. Verify is constant-time inside the library.
- One hash per login check; if params change later, hashes upgrade lazily on next successful login (noted, no code until needed).

## 4. Account & session lifecycle (password path)

All auth POSTs return uniform responses and never confirm whether an email exists:

- **POST /auth/signup** `{email, password}` → creates user (`email_verified=false`), sends verification mail (token) to outbox. If email exists → same response ("check your inbox"). Uniform ~constant work/latency.
- **POST /auth/verify** `{token}` → looks up `email_tokens(purpose='verify')`, one-time + 24 h expiry; sets `email_verified=true`, consumes token, creates a session cookie. **Welcome message fires here** (§8) — exactly once.
- **POST /auth/login** `{email, password}` → verify argon2id → new session row → cookie. 401 uniform on wrong creds. Failure counters per §7.
- **POST /auth/logout** (requires session) → deletes session row, clears cookie.
- **POST /auth/password-reset-request** `{email}` → uniform 202 regardless of existence; token to outbox (reset tokens expire after **30 minutes**).
- **POST /auth/password-reset** `{token, new_password}` → updates `password_hash`, consumes token, and **revokes all sessions** of the user. Uniform 200.

**Session cookie:** name `gp_session`; value = 256-bit random (base64url). Cookie flags `HttpOnly; SameSite=Lax; Path=/; Max-Age=30d` + `Secure` whenever `GP_PUBLIC_BASE_URL` is https (dev http: Secure must be off or curl/phone can't use it — this is the one dev-only relaxation, gated to a single env value and listed in the threat table). Server stores only `SHA-256(value)` — a leaked DB does not yield usable session tokens. Expiry **slides to now + 7 days on every authenticated use, capped at 30 days absolute from creation** — a session dies after 7 days idle or 30 days after creation, whichever comes first; lapsed windows are never resurrected. Every login creates a *fresh* session (no reuse — rotating the identifier on each login); a password change ends every *other* session and rotates the current session's token in place; logout deletes the row; expired rows are deleted opportunistically.

## 5. OAuth — Google & GitHub

Two providers behind one flow (endpoints per provider are config: defaults are the real URLs; tests inject a fake provider):

1. **GET /auth/oauth/{provider}/start** → generate `state` (256-bit) + `code_verifier` (S256 PKCE), store in `oauth_states` (provider, verifier, redirect_uri, 10-min expiry), `302` to the provider's authorize URL with `response_type=code`, `scope`, `state`, `code_challenge`, and the `redirect_uri` taken from the **allowlist**.
2. **Redirect URI allowlist:** the only accepted values are `{GP_PUBLIC_BASE_URL}/auth/oauth/google/callback` and `…/github/callback`. A request (start or callback) naming any other redirect is rejected `400`. The allowlist is the second gate; the first is the provider's own app configuration, which the operator also pins.
3. **GET /auth/oauth/{provider}/callback?code&state** → state must exist, be unused, unexpired, and belong to *this* provider; then exchange `code` (+ `code_verifier`) for tokens. Any failure → `403`, state row marked used.
4. **Identity → account:** Google: userinfo `email` + `email_verified` (checked, no assumptions). GitHub: `GET /user` + `GET /user/emails` with scope `user:email`; **only an email that is both `primary` and `verified` is accepted — if none, the login is rejected outright**, nothing is created.
   - Identity `(provider, provider_account_id)` already linked → log that user in.
   - Else, provider email matches an existing user **and both sides' emails are verified** (local `email_verified=true` AND provider verified) → link identity to that user (same account, same session as `login`)
   - Else provider email matches a user that is *not* verified locally → reject `403` ("verify your email-password account first") — no link, no second account.
   - Else → create user (`email_verified=true`, `password_hash` NULL) + identity.
   - Two providers, same verified email → the *same* user with two `auth_identities` rows. The `UNIQUE(provider, provider_account_id)` and unique-email constraints make duplicate users impossible.
5. Session created, cookie set. **Welcome message once** — on the first verified-provider login (§8).

In tests: a fake provider `httptest` server serving `/authorize` (validates client_id/redirect and returns a code or an error), `/token` (validates code, client secret, redirect_uri, code_verifier), `/userinfo`, `/user/emails`. Tests flip knobs: tampered state, bad redirect URI, `email_verified=false`, replayed code.

## 6. API keys

- `POST /auth/api-keys` (session required) `{name}` → generated key = `gp_pat_` + 32 random bytes base64url (**256 bits**). Response contains the full key **once**; only `SHA-256(key)` and `prefix` (`gp_pat_` + first 8 chars) are stored. Losing the response = losing the key (create a new one).
- `GET /auth/api-keys` → list rows: id, name, prefix, created, last_used, revoked. Never the full key.
- `POST /auth/api-keys/{id}/revoke` → sets `revoked_at` (keys are never deleted; revocation is terminal).
- **Use:** `Authorization: Bearer gp_pat_…` on `/api/*` endpoints. Server hashes the bearer, looks up `key_hash`, checks `revoked_at`/user, updates `last_used_at`. A revoked key is dead instantly.

## 7. Rate limits & lockouts

All counters live in `rate_limits`, keyed by **real client IP + scope**. Real IP: `RemoteAddr`, unless the direct peer is in `GP_TRUSTED_PROXIES` (CIDR list, default empty = trust nothing) in which case we take the last non-trusted `X-Forwarded-For` entry. Behind nothing in dev → RemoteAddr.

| Guard | Key | Limit | Effect |
|---|---|---|---|
| Auth endpoint cap | `auth:\|ip` | 20 per IP / 15 min | 429 |
| Failed logins / lockout | `lock:\|ip\|email` (lowercased) | 5 failures per pair / 15 min window | all further attempts on that pair → 429 until window lapses |
| Signup / reset-request | same auth cap + per-IP | 20 / 15 min | 429 |

Failure counts only on *failures*; successful login does not need to reset anything (window is short). Keys are computed with the normalized email+IP pair so distributed guessing at one email is throttled too.

## 8. Email

`mailer` package:

```go
type Message struct { To, Subject, TextBody string; Kind string } // kind: verify|reset|welcome|test
type Sender interface { Send(ctx context.Context, msg Message) error }
```

- **Outbox driver (default, `GP_MAIL_DRIVER=outbox`):** inserts into `outbox_messages` **and** writes `./outbox/<unix-time>-<to>.txt` (address sanitized; file mirrors the row). This is how dev/tests/demo read tokens — no dev backdoor endpoints. Rows and files older than 7 days are deleted by a cleanup (at boot and hourly). **Refuses to start under `ENV=production`** — bodies must never land on a production system; production uses the SMTP driver, which stores no message bodies anywhere.
- **SMTP driver (`smtp`):** plain startTLS via stdlib; **exists but off** (no creds descended).
- **Welcome message** sent exactly once after `email_verified` is first set (password path) or the first verified-provider login: plain text — the user's email, the timestamp, and the line `This is a test message from Gatepost.` **Never a token, never a link.** Exactly-once is enforced by `UPDATE users SET welcome_sent_at = now() WHERE id = $1 AND welcome_sent_at IS NULL RETURNING …` — send only if a row comes back (atomic under concurrency).

## 9. Trust boundaries & invariants

- Random 256-bit tokens (sessions, API keys, states, email tokens) everywhere; stored only as SHA-256 hashes; compared only by index lookup (constant-time inside the hash → lookup, plus `crypto/subtle` where direct comparison exists).
- The user UUID is public; **no data is addressed by secret material** — API keys never form paths, filenames, or addresses; sessions never appear in URLs.
- No plaintext in DB: passwords → argon2id; sessions/API keys/state/verify tokens → SHA-256. Test proves it with a `SELECT` (§ below).
- JSON only; no user HTML is rendered server-side (no XSS surface in v1 backend).
- Everything 401/403-uniform; OAuth/email flows don't confirm account existence beyond what mail delivery inherently reveals.
- Secrets (OAuth client secrets, DB URL) come from env / untracked `.env`; `.gitignore` blocks `.env`, `outbox/`, `*.local`. Secrets are never printed to logs or committed.

## 10. Threat table

| # | Threat | Vector | Control |
|---|---|---|---|
| 1 | Password theft from DB | Compromised Postgres | argon2id (19 MiB, t=2), no plaintext, no reversible scheme |
| 2 | Credential stuffing / brute force | Many logins | rate cap per IP + 5-failure lockout per (IP, email) pair, uniform 401s |
| 3 | Session token theft from DB | Postgres read access | only SHA-256 hashes stored; tokens are 256-bit random |
| 4 | Session hijack over the wire / XSS | Cookie exfiltration | `HttpOnly`, `Secure` (https), `SameSite=Lax`; no HTML rendering |
| 5 | CSRF | Cross-site form hitting POSTs | SameSite=Lax + JSON-only POST endpoints; state-changing GETs don't exist |
| 6 | Session fixation | Attacker forces a known session | fresh random session per login; (rate limiter leaves fixation windows empty) |
| 7 | OAuth CSRF / authorization-code mix-up | Attacker's code into victim's flow | one-time `state` bound to provider + stored PKCE verifier; callback enforces match |
| 8 | OAuth redirect manipulation | Open-redirect / code interception | fixed redirect allowlist derived from base URL; callback must match the row's redirect |
| 9 | Account takeover via unverified provider email | Provider reports unverified email | provider email must be verified; verified-only primary email for GitHub |
| 10 | Unverified password account hijacked by OAuth | Local email unverified, attacker links with verified provider identity | linking requires both sides verified; else 403 |
| 11 | Duplicate identities / user confusion | Same person, two accounts | unique(provider, provider_account_id); verified-email linking merges identities onto one user |
| 12 | Email enumeration | Signup/reset probing | uniform responses + uniform timing; reset always 202 |
| 13 | API key leakage from DB | Postgres compromise | only hash + inert prefix stored; full key shown once |
| 14 | Verification-token replay / theft | Reused link | one-time `used_at`, expiry (verify 24 h / reset 30 min), hashed storage |
| 15 | Cross-user access to user_data | Guessed/known user IDs | users are UUIDv4 (unguessable in practice *and* unknowable via IDs alone: no sequential IDs); endpoints address only the authenticated principal — no user id parameter exists to guess |
| 16 | IDOR on revoked/expired credentials | Old token reuse | checks `revoked_at`, `expires_at`, `used_at` on every use |
| 17 | Secrets in logs/artifacts | Debug output | log redaction, outbox only writes mail bodies (dev), `.gitignore` for `.env`/`outbox/` |
| 18 | DoS on auth endpoints | Flood | per-IP caps in Postgres; cheap (no argon2 on 429 paths; argon2 only after lockout check) |

## 11. Endpoints (v1)

```
POST /auth/signup                      {email, password}
POST /auth/verify                      {token}
POST /auth/login                       {email, password}
POST /auth/logout                      (session)
POST /auth/password-reset-request      {email}
POST /auth/password-reset              {token, new_password}
POST /auth/password-change             {current_password, new_password}  (session; ends other sessions)
GET  /auth/sessions                                      (session; id/created/expires/current, never the token)
POST /auth/sessions/{id}/revoke                          (session)
POST /auth/logout-everywhere                             (session; ends all sessions)
GET  /auth/oauth/{provider}/start
GET  /auth/oauth/{provider}/callback
POST /auth/api-keys                    {name}            (session)
GET  /auth/api-keys                                      (session)
POST /auth/api-keys/{id}/revoke                          (session)
GET  /api/me                                             (session or API key)
GET  /api/user-data                                      (session or API key)
PUT  /api/user-data                        {json doc}    (session or API key, ≤32 KiB, must parse as JSON)

Node management (v1, operator-only; operator = verified user on `GP_OPERATOR_EMAILS`; node tokens are 256 random bits, echoed once, only a SHA-256 stored, revocable):

```
POST /v1/nodes                         {name, role}    (operator; role edge|dns; reply carries the node token exactly once)
GET  /v1/nodes                                         (operator; roster, no token material)
POST /v1/nodes/{id}/revoke                             (operator; idempotent; a revoked token dies on its next request)
```
```

## 12. Configuration (env / untracked `.env`)

`DATABASE_URL` (API pool; Neon pooler-compatible) · `DATABASE_URL_DIRECT` (direct connection, used by migrations; optional — falls back to `DATABASE_URL`) · `GP_HTTP_ADDR` (default `:8080`) · `GP_PUBLIC_BASE_URL` (cookie Secure + OAuth redirects derive from it; with `ENV=production` an http base URL is refused at boot) · `ENV` (only value checked: `production` — also refuses the outbox mail driver) · `GP_MAIL_DRIVER=outbox|smtp` · `GP_SMTP_HOST/PORT/USER/PASS/FROM` (off unless smtp) · `GP_TRUSTED_PROXIES` (default none) · `GP_AUTH_CAP` (auth POSTs per IP per 15 min, default 100) · `GP_LOCKOUT_AFTER` (failed logins locking an IP+email pair, default 5) · `GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET` · `GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET`.

## 13. Out of scope, deliberately (v1 backend)

Admin UI, audit log, transactional email beyond verify/reset/welcome, key expiry/rotation policies, refresh tokens, signup “magic links”, tests for anything but this domain. Each is a checklist item for a later version, not withheld-by-oversight.

## 14. Planned (next version)

- **Account deletion** — self-service, password- or email-confirmed; cascades sessions, API keys, OAuth identities and user data.
- **Data export** — downloadable JSON of account metadata + all user data rows.
- **Email change** — mails a confirmation token to the *new* address before swapping it (sessions survive; the address is the login key, so it must be verified first).
- **2FA** — TOTP with recovery codes, enforced at login and on sensitive endpoints.
- **Periodic ownership re-verification (domains)** — ownership is proven once at verify time; a hostname can change hands afterwards. Plan: resolve the TXT/NS proof for every verified domain weekly; a job re-checks and stamps `rechecked_at`. On the first failed re-check the domain flags **re-verification needed** and the owner is mailed; the check repeats daily. After a **14-day grace period** the domain flips to `expired` — origins and records are disabled together, with **one last alert 48 hours before** the flip. Anything recoverable stays recoverable by re-verifying; an expired-release hostname accepts fresh claims from anyone. Rules: re-check weekly, grace period before disabling, alert before disabling — a transient DNS outage during the window then causes at most a warning, never a lockout.
