# Gatepost API Contract (v1)

Built from the code in `cmd/gatepost` and `internal/server` (router in
`internal/server/server.go`, every handler). This is the contract the
frontend will be built against. Product code, migrations and tests were not
changed to write it.

**Marking convention:** every route is tagged `CUSTOMER` (frontend/customer
plane), `OPERATOR` (operator plane, requires `GP_OPERATOR_EMAILS`), or
`EDGE-NODE` (edge/DNS node principal, bearer node token). The frontend
(customer) uses only the CUSTOMER routes.

## Base

- Base URL: `GP_PUBLIC_BASE_URL` (default `http://localhost:8080`).
- All bodies and responses are `application/json`.
- Timestamps are RFC3339 UTC (see Time section).
- There is **no API version prefix** in the path: `/auth/*`, `/api/*`,
  `/v1/*`, `/node/v1/*`.
- No bearer token is ever a row ID, path segment, or storage path.
- User IDs are public UUIDv4 text and appear in URLs/logs by design.

## Authentication summary

- Session cookie `gp_session`, `HttpOnly; SameSite=Lax; Path=/;
  Max-Age=30d`, `Secure` only when `GP_PUBLIC_BASE_URL` is `https://`.
- Server stores only `SHA-256(cookie value)`.
- Auth POSTs answer uniformly and never confirm whether an email exists.
- CSRF: on `POST/PUT/DELETE`, if an `Origin` header is present its host must
  equal `r.Host`, otherwise `403 "cross-origin request refused"`. Non-browser
  clients (no Origin) pass untouched. See the per-route CSRF column.

Routes:

| # | Method | Path | Who | CSRF | Tag |
|---|--------|------|-----|------|-----|
| A1 | POST | /auth/signup | public | yes | CUSTOMER |
| A2 | POST | /auth/verify | public | yes | CUSTOMER |
| A3 | POST | /auth/login | public | yes | CUSTOMER |
| A4 | POST | /auth/logout | session | yes | CUSTOMER |
| A5 | POST | /auth/password-reset-request | public | yes | CUSTOMER |
| A6 | POST | /auth/password-reset | public | yes | CUSTOMER |
| A7 | POST | /auth/password-change | session | yes | CUSTOMER |
| A8 | GET | /auth/sessions | session | no | CUSTOMER |
| A9 | POST | /auth/sessions/{id}/revoke | session | yes | CUSTOMER |
| A10 | POST | /auth/logout-everywhere | session | yes | CUSTOMER |
| A11 | GET | /auth/oauth/{provider}/start | public | no | CUSTOMER |
| A12 | GET | /auth/oauth/{provider}/callback | public | no | CUSTOMER |
| A13 | POST | /auth/api-keys | session | yes | CUSTOMER |
| A14 | GET | /auth/api-keys | session | no | CUSTOMER |
| A15 | POST | /auth/api-keys/{id}/revoke | session | yes | CUSTOMER |
| D1 | GET | /api/me | session or API key | no | CUSTOMER |
| D2 | GET | /api/user-data | session or API key | no | CUSTOMER |
| D3 | PUT | /api/user-data | session or API key | yes | CUSTOMER |
| DM1 | POST | /v1/domains | session | yes | CUSTOMER |
| DM2 | GET | /v1/domains | session | no | CUSTOMER |
| DM3 | GET | /v1/domains/{id} | session | no | CUSTOMER |
| DM4 | DELETE | /v1/domains/{id} | session | yes | CUSTOMER |
| DM5 | PUT | /v1/domains/{id}/waf | session | yes | CUSTOMER |
| DM6 | GET | /v1/domains/{id}/verification | session | no | CUSTOMER |
| DM7 | POST | /v1/domains/{id}/verify | session | yes | CUSTOMER |
| DM8 | POST | /v1/domains/{id}/origin | session | yes | CUSTOMER |
| DM9 | GET | /v1/domains/{id}/origin | session | no | CUSTOMER |
| DM10 | PUT | /v1/domains/{id}/origin | session | yes | CUSTOMER |
| DM11 | POST | /v1/domains/{id}/origin/test | session | yes | CUSTOMER |
| DM12 | POST | /v1/domains/{id}/records | session | yes | CUSTOMER |
| DM13 | GET | /v1/domains/{id}/records | session | no | CUSTOMER |
| DM14 | GET | /v1/domains/{id}/records/{rid} | session | no | CUSTOMER |
| DM15 | PATCH | /v1/domains/{id}/records/{rid} | session | yes | CUSTOMER |
| DM16 | DELETE | /v1/domains/{id}/records/{rid} | session | yes | CUSTOMER |
| N1 | POST | /v1/nodes | operator (verified, on GP_OPERATOR_EMAILS) | yes | OPERATOR |
| N2 | GET | /v1/nodes | operator | no | OPERATOR |
| N3 | POST | /v1/nodes/{id}/revoke | operator | yes | OPERATOR |
| EN1 | GET | /node/v1/config | edge node bearer token | no | EDGE-NODE |
| EN2 | POST | /node/v1/heartbeat | edge node bearer token | yes | EDGE-NODE |

No route is paginated: every list returns the full un-paginated slice in one
body. This is a GAP for the frontend (see GAPS).

---

## Route reference

### A1 POST /auth/signup — CUSTOMER

**Who:** public.  
**CSRF:** yes (Origin guard applies).

**Request body**
| field | type | required | validation |
|---|---|---|---|
| email | string | yes | loose shape: contains `@`, non-empty local part, domain contains a `.`, length ≤ 254, no whitespace |
| password | string | yes | length 8..128 |

**Success:** `200` `{"ok": true, "message": "check your inbox to verify your account"}` — same body whether the email is new or already exists (uniform, no enumeration).

**Errors:**
- `400` `{"error": "invalid email or password"}` — invalid email or password shape.
- `429` `{"error": "too many requests"}` — auth rate cap (default 100/IP/15 min) or lockout.
- `500` `{"error": "internal error"}`.

### A2 POST /auth/verify — CUSTOMER

**Who:** public.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| token | string | yes | — |

**Success:** `200` `{"ok": true}`. Spends the one-time verify token, sets `email_verified=true`, creates a session cookie, sends welcome message exactly once.

**Errors:**
- `400` `{"error": "invalid or expired token"}` — token missing/used/expired (verify tokens live 24 h).
- `500` `{"error": "internal error"}`.

### A3 POST /auth/login — CUSTOMER

**Who:** public.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| email | string | yes | same shape as signup |
| password | string | yes | — |

**Success:** `200` `{"ok": true}`. Creates a fresh session row and cookie.

**Errors:**
- `401` `{"error": "invalid credentials"}` — uniform for unknown user, wrong password, OAuth-only account; never confirms email existence.
- `429` `{"error": "too many requests"}` — auth cap or per-(IP,email) lockout (default 5 failures/15 min).
- `500` `{"error": "internal error"}`.

### A4 POST /auth/logout — CUSTOMER

**Who:** session (cookie).  
**CSRF:** yes.

**Request body:** none.

**Success:** `200` `{"ok": true}`. Deletes the session row, clears the cookie.

**Errors:**
- `401` `{"error": "authentication required"}`.
- `500` `{"error": "internal error"}`.

### A5 POST /auth/password-reset-request — CUSTOMER

**Who:** public.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| email | string | yes | same shape as signup |

**Success:** `202` `{"ok": true, "message": "if the address exists, a reset link was sent"}` — always 202 regardless of whether the email exists (uniform).

**Errors:**
- `400` `{"error": "invalid email"}`.
- `429` `{"error": "too many requests"}`.
- `500` `{"error": "internal error"}`.

### A6 POST /auth/password-reset — CUSTOMER

**Who:** public.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| token | string | yes | — |
| new_password | string | yes | length 8..128 |

**Success:** `200` `{"ok": true}`. Sets the new hash, consumes the reset token, revokes all sessions of the user.

**Errors:**
- `400` `{"error": "invalid or expired token"}` or `{"error": "invalid password"}` — reset tokens live 30 min, one-time.
- `500` `{"error": "internal error"}`.

### A7 POST /auth/password-change — CUSTOMER

**Who:** session (cookie or Bearer API key? No — `requireSession`, so session-only; API keys are rejected).  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| current_password | string | yes | — |
| new_password | string | yes | length 8..128 |

**Success:** `200` `{"ok": true}`. Verifies current password (failure counts against lockout), sets new hash, deletes every *other* session, rotates the caller's session token in place (new cookie).

**Errors:**
- `401` `{"error": "authentication required"}` or `{"error": "invalid credentials"}`.
- `400` `{"error": "invalid password"}`.
- `429` `{"error": "too many requests"}`.
- `500` `{"error": "internal error"}`.

### A8 GET /auth/sessions — CUSTOMER

**Who:** session (session-only; API keys rejected).  
**CSRF:** no (GET).

**Query params:** none.

**Success:** `200` `{"sessions": [{"id": "<uuid>", "created_at": "<RFC3339>", "expires_at": "<RFC3339>", "current": true|false}, ...]}`. Token hashes never leave the database.

**Errors:**
- `401` `{"error": "authentication required"}`.
- `500` `{"error": "internal error"}`.

### A9 POST /auth/sessions/{id}/revoke — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Path:** `{id}` — opaque session id (uuid text), not the token hash.

**Request body:** none.

**Success:** `200` `{"ok": true}`. Revokes the session; if it is the current session the cookie is cleared too.

**Errors:**
- `401` `{"error": "authentication required"}`.
- `404` `{"error": "not found"}` — foreign or absent id (uniform, no disclosure).
- `500` `{"error": "internal error"}`.

### A10 POST /auth/logout-everywhere — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body:** none.

**Success:** `200` `{"ok": true}`. Deletes every session of the caller, clears the cookie.

**Errors:**
- `401` `{"error": "authentication required"}`.
- `500` `{"error": "internal error"}`.

### A11 GET /auth/oauth/{provider}/start — CUSTOMER

**Who:** public. `provider` = `google` or `github` (unknown/disabled → `404 "unknown provider"`).  
**CSRF:** no (GET).

**Query params:** none.

**Success:** `302` redirect to the provider's authorize URL with `response_type=code`, `client_id`, `redirect_uri` (from allowlist), `scope`, `state`, `code_challenge` (S256), `code_challenge_method=S256`.

**Errors:**
- `404` `{"error": "unknown provider"}`.
- `429` `{"error": "too many requests"}`.
- `500` `{"error": "internal error"}`.

### A12 GET /auth/oauth/{provider}/callback — CUSTOMER

**Who:** public.  
**CSRF:** no (GET).

**Query params**
| field | type | required | validation |
|---|---|---|---|
| code | string | yes | — |
| state | string | yes | must match a stored, unused, unexpired state row for this provider |

**Success:** `200` `{"ok": true}`. Creates/links account per identity rules, sets session cookie, sends welcome once.

**Errors:**
- `400` `{"error": "missing code or state"}`.
- `403` `{"error": "invalid oauth state"}` / `{"error": "oauth login failed"}` / `{"error": "provider email is not verified"}` — uniform, no enumeration.
- `404` `{"error": "unknown provider"}`.
- `500` `{"error": "internal error"}`.

OAuth link/redirect allowlist: `{GP_PUBLIC_BASE_URL}/auth/oauth/{provider}/callback` only. Real provider credentials (`GOOGLE_CLIENT_ID/SECRET`, `GITHUB_CLIENT_ID/SECRET`) are required for real flows; tests use a fake provider.

### A13 POST /auth/api-keys — CUSTOMER

**Who:** session (session-only; Bearer API keys rejected).  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| name | string | yes | 1..100 chars after trim |

**Success:** `201` `{"id": "<uuid>", "name": "...", "key": "gp_pat_<43 chars>", "prefix": "gp_pat_<8 chars>", "created_at": "<RFC3339>", "last_used_at": null, "revoked_at": null}`. The full `key` is returned once and never stored.

**Errors:**
- `400` `{"error": "invalid name"}`.
- `401` `{"error": "authentication required"}`.
- `500` `{"error": "internal error"}`.

### A14 GET /auth/api-keys — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Query params:** none.

**Success:** `200` `{"keys": [{id, name, prefix, created_at, last_used_at, revoked_at}, ...]}` — metadata only, never the full key.

**Errors:** `401`, `500`.

### A15 POST /auth/api-keys/{id}/revoke — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Path:** `{id}` — api key uuid.

**Request body:** none.

**Success:** `200` `{"ok": true}`. Sets `revoked_at` (terminal; keys are never deleted).

**Errors:**
- `401` `{"error": "authentication required"}`.
- `404` `{"error": "not found"}` — uniform for foreign keys.
- `500` `{"error": "internal error"}`.

### D1 GET /api/me — CUSTOMER

**Who:** session or API key (Bearer).  
**CSRF:** no.

**Success:** `200` `{"id": "<uuid>", "email": "..."}`.

**Errors:** `401`, `500`.

### D2 GET /api/user-data — CUSTOMER

**Who:** session or API key.  
**CSRF:** no.

**Success:** `200` the stored JSON document (raw bytes), `{}` when none. Addressed only to the authenticated principal — no user-id parameter exists.

**Errors:** `401`, `500`.

### D3 PUT /api/user-data — CUSTOMER

**Who:** session or API key.  
**CSRF:** yes.

**Request body:** valid JSON, ≤ 32 KiB.

**Success:** `200` `{"ok": true}`.

**Errors:**
- `400` `{"error": "body exceeds 32 KiB"}` or `{"error": "body must be valid JSON"}`.
- `401`, `500`.

---

### DM1 POST /v1/domains — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| hostname | string | yes | normalized: lowercased, punycode, ≤253 octets, labels ≤63, not a bare public suffix, not localhost, not an IP, not a reserved service hostname |
| setup_type | string | no | `cname` (default) or `nameserver` |

**Success:** `201` `{"domain": {...}, "existing": false}` on new claim; `200` `{"domain": {...}, "existing": true}` when the caller already holds it (pending/verified/disabled returned untouched; rejected/expired re-claimed to pending). The `domain` shape:

| field | type | notes |
|---|---|---|
| id | string | uuid text |
| hostname | string | — |
| status | string | pending \| verified \| rejected \| expired \| disabled |
| setup_type | string | cname \| nameserver |
| claimed_at | RFC3339 | — |
| verified_at | RFC3339 or null | — |
| expires_at | RFC3339 or null | claim TTL 7 days |
| ns1 | string | nameserver pair (cname: "") |
| ns2 | string | nameserver pair (cname: "") |
| waf_mode | string | off \| detection \| blocking (default detection) |
| excluded_rule_ids | []int | WAF rule IDs excluded |

**Errors:**
- `400` `{"error": "invalid hostname: ..."}` / `{"error": "setup_type must be cname or nameserver"}` / `{"error": "nameserver mode is not configured (GP_NS1/GP_NS2 missing)"}` / `{"error": "nameserver setup needs a registrable domain ..."}`.
- `403` `{"error": "that hostname is a Gatepost service name"}`.
- `409` `{"error": "hostname already verified by another user"}`.
- `422` `{"error": "domain cap reached (max total N)"}` / `{"error": "pending claim cap reached (max pending N)"}` / `{"error": "the config snapshot is over its size cap — no new domains until it shrinks"}` / `{"error": "the config snapshot is within N bytes of its size cap — no new domains until it shrinks"}`.
- `429` `{"error": "rate limit exceeded for domains:add"}` (per user + per IP, 15 min; default 20).
- `500` `{"error": "internal error"}`.

Caps: `GP_DOMAIN_MAX` (default 20 active incl. pending/disabled), `GP_DOMAIN_PENDING` (default 5 pending). Nameserver mode requires `GP_NS1`/`GP_NS2`; delegated subdomains require `GP_ALLOW_SUBDOMAIN_ZONES=true` under `GP_TEST_ZONE`.

### DM2 GET /v1/domains — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Query params:** none.

**Success:** `200` `{"domains": [{...domain shape...}, ...]}` ordered by `claimed_at DESC, id`. Full list, **not paginated** (GAP).

**Errors:** `401`, `500`.

### DM3 GET /v1/domains/{id} — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Path:** `{id}` — domain uuid owned by the caller.

**Success:** `200` `{"domain": {...}}`.

**Errors:**
- `401` `{"error": "authentication required"}`.
- `404` `{"error": "not found"}` — uniform when the domain is not the caller's (presence not disclosed across users).
- `500` `{"error": "internal error"}`.

### DM4 DELETE /v1/domains/{id} — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Success:** `200` `{"ok": true}`.

**Errors:** `401`, `404` (uniform, not-the-caller's), `500`.

### DM5 PUT /v1/domains/{id}/waf — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| mode | string | no | `off` \| `detection` \| `blocking` (default `detection` when omitted/empty) |
| excluded_rule_ids | []int | no | each in 1..999999 |

**Success:** `200` `{"domain": {...}}` (updated domain shape). Writes a `domain_waf_changes` history row; invalidates the snapshot cache.

**Errors:**
- `400` `{"error": "mode must be off, detection, or blocking"}` / `{"error": "rule id N out of range (1..999999)"}`.
- `401`, `404` (uniform), `500`.

### DM6 GET /v1/domains/{id}/verification — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Success:** `200` `{"verification": {"domain_id": "...", "hostname": "...", "setup_type": "...", "status": "...", "expires_at": "...", ...}}`.

- nameserver mode: adds `nameservers: ["ns1", "ns2"]`.
- cname mode: adds `record_name: "_gatepost-verify.<hostname>"`, `record_value: "gatepost-verify=<token>"`.

**Errors:** `401`, `404` (uniform), `500`.

### DM7 POST /v1/domains/{id}/verify — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body:** none.

**Success:** `200` `{"status": "verified"}`. Idempotent when already verified.

**Errors:**
- `401`, `404` (uniform).
- `409` `{"error": "hostname already verified by another user"}` / `{"error": "verification raced another attempt, try again"}` / `{"error": "claim changed state mid-verification, try again"}`.
- `410` `{"error": "claim is <status>, not verifiable"}` / `{"error": "claim expired, re-claim it"}`.
- `400` `{"error": "verification failed: no TXT record ..."}` / `{"error": "verification failed: no NS records ..."}` / `{"error": "verification failed: NS records missing: ..., unexpected: ..."}` / `{"error": "dns lookup failed: ..."}`.
- `429` `{"error": "rate limit exceeded for domains:verify"}` (per user + per IP, 15 min; default 20).
- `500` `{"error": "internal error"}`.

Verification: cname → TXT `_gatepost-verify.<hostname>` equals `gatepost-verify=<token>`; nameserver → hostname's NS set exactly equals the assigned pair. One-transaction win: this claim → verified, every other pending claim on the hostname → rejected.

### DM8 POST /v1/domains/{id}/origin — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| scheme | string | yes | `http` or `https` |
| address | string | yes | IP literal or hostname; range-checked (SSRF); not a Gatepost-owned address; hostname must resolve via configured resolvers |
| port | int | yes | 1..65535, not on the deny list (21,22,23,25,53,110,135,137,139,143,161,389,445,465,514,587,636,691,993,995,1433,1521,2049,2181,2375,2376,3128,3306,3389,5432,5555,5900,5985,5986,6379,6380,11211,27017,27018,27019) |
| host_header | string | no | if set: non-empty, ≤255 chars, no whitespace/control |
| tls_verify | bool | no | default true |
| health_path | string | no | default `/`; must start with `/`, no `..`, ≤512 chars |
| health_interval | int | no | default 60; 10..86400 |

**Success:** `201` `{"origin": {scheme, address, port, host_header, tls_verify, health_path, health_interval, created_at, updated_at}}`. One origin per domain (UNIQUE); a second create → `409`.

**Errors:**
- `401`, `404` (uniform, not-the-caller's / no domain).
- `409` `{"error": "origin already set; use PUT"}`.
- `422` `{"error": "origin address: ..."}` / `{"error": "scheme must be http or https"}` / `{"error": "port: ..."}` / `{"error": "host_header empty, too long, or contains spaces"}` / `{"error": "health_path must start with / (no dots, max 512)"}` / `{"error": "health_interval must be 10..86400 seconds"}`.
- `429` `{"error": "rate limit exceeded for domains:add"}`.
- `500` `{"error": "internal error"}`.

Origin deny ranges (SSRF): IPv4 `0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4`; IPv6 `::/8, fe00::/9, fe80::/10, fc00::/7, ff00::/8, 2001:db8::/32`. `GP_TEST_ALLOW_LOOPBACK` waives 127/8 + ::1 (test/demo only; production refuses to boot with it set). `GP_OWNED_ADDRESSES` lists Gatepost addresses refused as origins.

### DM9 GET /v1/domains/{id}/origin — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Success:** `200` `{"origin": {...}}`.

**Errors:**
- `401`, `404` (uniform; `{"error": "no origin set"}` when none).
- `500`.

### DM10 PUT /v1/domains/{id}/origin — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body:** same fields as DM8 (all validated; absent fields keep defaults where applicable, but the whole origin is replaced).

**Success:** `200` `{"origin": {...}}`.

**Errors:**
- `401`, `404` (uniform; `{"error": "no origin set; POST to create"}` when none).
- `422` validation errors as DM8.
- `500`.

### DM11 POST /v1/domains/{id}/origin/test — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body:** none.

**Success:** `200` `{"test": {"reachable": bool, "status_code": int, "tls_ok": bool, "duration_ms": int, "error": string}}`. Resolves the stored origin, re-checks every answered IP, dials the validated IP directly (no TOCTOU), GETs the health path with no redirects, reads at most 64 KiB. `error` present only when unreachable.

**Errors:**
- `401`, `404` (uniform; `{"error": "no origin set"}` when none).
- `200` with `reachable: false` + `error` — the test reports the truth, including refusals; it does not return 4xx for an unreachable origin.
- `429` `{"error": "rate limit exceeded for domains:origin-test"}` (per user + per IP, 15 min; default 10).
- `500`.

### DM12 POST /v1/domains/{id}/records — CUSTOMER

**Who:** session (requires a nameserver-mode domain; has a zone).  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| name | string | yes | `@` or label chain of `[a-z0-9_-]`, ≤100 chars, labels ≤63, no leading/trailing hyphen |
| type | string | yes | `A` `AAAA` `CNAME` `MX` `TXT` `NS` `SRV` `CAA` |
| value | string | yes | type-dependent (A: IPv4; AAAA: IPv6; CNAME/NS: hostname; MX/SRV need priority; TXT ≤255 printable; CAA `flag tag value`; SRV `weight port target`) |
| ttl | int | no | 60..86400, default 3600 |
| priority | int | no | 0..65535 (required for MX, SRV) |

**Success:** `201` `{"record": {id, name, type, value, ttl, priority, created_at}}`. Writes a `record_changes` row (`create`). CNAME-exclusivity per name enforced.

**Errors:**
- `401`, `404` (uniform).
- `409` `{"error": "records need a nameserver-mode domain"}` (cname domain has no zone) / `{"error": "another record already exists at this name"}` / `{"error": "a CNAME already exists at this name"}`.
- `422` `{"error": "invalid record name"}` / `{"error": "A value must be an IPv4 address"}` / ... per type / `{"error": "zone record limit reached"}` (cap `GP_MAX_RECORDS`, default 100 per zone).
- `500`.

### DM13 GET /v1/domains/{id}/records — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Success:** `200` `{"records": [{...}, ...]}` ordered by `name, type, id`. Full list, **not paginated**.

**Errors:** `401`, `404` (uniform), `409` (no zone), `500`.

### DM14 GET /v1/domains/{id}/records/{rid} — CUSTOMER

**Who:** session.  
**CSRF:** no.

**Success:** `200` `{"record": {...}, "history": [{action, old_value, new_value, changed_by, changed_at}, ...]}`.

**Errors:** `401`, `404` (uniform), `409` (no zone), `500`.

### DM15 PATCH /v1/domains/{id}/records/{rid} — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Request body** (partial; at least one field required)
| field | type | required | validation |
|---|---|---|---|
| value | string | no | type-dependent validation |
| ttl | int | no | 60..86400 |
| priority | int | no | 0..65535 |

**Success:** `200` `{"record": {...}}`. Writes a `record_changes` row (`update`). Name/type immutable.

**Errors:**
- `400` `{"error": "nothing to change"}`.
- `401`, `404` (uniform), `409` (no zone).
- `422` type/value/ttl/priority validation errors.
- `500`.

### DM16 DELETE /v1/domains/{id}/records/{rid} — CUSTOMER

**Who:** session.  
**CSRF:** yes.

**Success:** `200` `{"deleted": true}`. Writes a `record_changes` row (`delete`); the record row is gone but its history stays.

**Errors:** `401`, `404` (uniform), `409` (no zone), `500`.

---

### N1 POST /v1/nodes — OPERATOR

**Who:** operator — verified user whose email (lowercased, trimmed) is on `GP_OPERATOR_EMAILS`. Any other authenticated caller → `403 "operator access only"`; unauthenticated → `401`.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| name | string | yes | 1..50 chars after trim |
| role | string | yes | `edge` or `dns` |

**Success:** `201` `{"node": {id, name, role, status, last_seen, applied_version, created_at}, "token": "<256-bit random, shown once>"}`. Token hash (SHA-256) stored; plaintext shown exactly once.

**Errors:**
- `400` `{"error": "name must be 1..50 characters"}` / `{"error": "role must be edge or dns"}`.
- `401` `{"error": "authentication required"}`.
- `403` `{"error": "operator access only"}`.
- `409` `{"error": "node name already taken"}`.
- `500` `{"error": "internal error"}`.

### N2 GET /v1/nodes — OPERATOR

**Who:** operator.  
**CSRF:** no.

**Success:** `200` `{"nodes": [{id, name, role, status, last_seen, applied_version, created_at}, ...]}` — roster, no token material.

**Errors:** `401`, `403`, `500`.

### N3 POST /v1/nodes/{id}/revoke — OPERATOR

**Who:** operator.  
**CSRF:** yes.

**Success:** `200` `{"node": {...}}` with `status: "revoked"`. Idempotent; revoked tokens die on their next node request.

**Errors:**
- `401`, `403`, `404` `{"error": "not found"}`.
- `500`.

---

### EN1 GET /node/v1/config — EDGE-NODE

**Who:** edge node bearer token only (`Authorization: Bearer <node token>`). User sessions and API keys never authenticate here (mutual 401).  
**CSRF:** no.

**Headers:** `If-None-Match` optional — equals the generation ETag `"<n>"` → `304` (empty body, free poll).

**Success:** `200` `{"payload": "<canonical JSON string>", "signature": "<hex HMAC-SHA256>", "key_id": "<first 16 hex of SHA-256(key)>"}` with `ETag: "<generation>"`. `304` when unchanged.

**Errors:**
- `401` `{"error": "node authentication required"}` — unknown, revoked, or inactive token (uniform).
- `429` `{"error": "rate limit exceeded for node polls"}` (per node, 15 min; default 500).
- `500` `{"error": "internal error"}`.

### EN2 POST /node/v1/heartbeat — EDGE-NODE

**Who:** edge node bearer token only.  
**CSRF:** yes.

**Request body**
| field | type | required | validation |
|---|---|---|---|
| generation | int64 | yes | must be > 0 and a generation that exists in `snapshot_versions` |
| waf_fallback | bool | no | whether the node is serving WAF-off |

**Success:** `200` `{"applied_generation": <n>}`. Stamps `last_seen`/`applied_version` only when the generation exists; resolves any open `node_stale` alert for the node; records/resolves `waf_config_failed` per `waf_fallback`.

**Errors:**
- `400` `{"error": "generation must be a positive integer"}` / `{"error": "unknown snapshot version"}`.
- `401`, `429`, `500`.

---

## Cross-cutting: error shape

The handler helper `fail(w, code, msg)` writes exactly:

```json
{"error": "<human message>"}
```

There is **no separate `code` field, no `message` field, and no `request_id`** in any response today. Every error uses the same envelope; the HTTP status code is the only machine-readable signal. This is a GAP for the frontend (structured error codes, request IDs).

Real examples observed in code/tests:

1. `401` `{"error": "invalid credentials"}` — login/password-change failure (auth.go).
2. `404` `{"error": "not found"}` — revoke a foreign/absent session or api key (auth.go, apikeys.go).
3. `422` `{"error": "domain cap reached (max total 20)"}` — over the per-user domain cap (domains.go).

Every error status the API can return (by route):

| status | meaning |
|---|---|
| 200 | success (also idempotent/re-claim/already-verified cases) |
| 201 | created (signup-adjacent, api-key create, domain create, origin create, record create) |
| 202 | password-reset-request (always, uniform) |
| 204 | not used |
| 302 | OAuth start redirect |
| 304 | node config unchanged (If-None-Match) |
| 400 | invalid body / invalid email-or-password / invalid token / validation |
| 401 | authentication required / invalid credentials / node auth |
| 403 | operator access only / oauth failures |
| 404 | not found (uniform, no disclosure) / unknown provider |
| 409 | conflict (hostname taken, origin exists, CNAME exclusivity, record conflicts, verification races) |
| 410 | gone (claim not pending / expired) |
| 422 | unprocessable (domain caps, snapshot size cap, origin validation, WAF rule range, record validation, rate-limit-adjacent 422 for caps) |
| 429 | too many requests (auth cap, lockout, domain rate caps, node poll cap, cert hourly cap) |
| 500 | internal error |

Note: the code sometimes returns 422 for business-rule caps (domain cap, snapshot size cap, record limit) and sometimes 429 for rate limits. There is no unified "error code" taxonomy — GAP.

## Cross-cutting: authentication

### Session
- Cookie name: `gp_session`.
- Value: 256-bit random, base64url, unpadded (43 chars).
- Flags: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age=30d`, `Secure` iff `GP_PUBLIC_BASE_URL` is `https://`.
- Storage: only `SHA-256(value)` in `sessions.token_hash`; plaintext never stored.
- Lifetime: slides to `now()+7d` on every authenticated use; absolute cap `created_at+30d`; lapsed windows never resurrect. Fresh session per login. Password change ends every other session and rotates the current token in place. Logout deletes the row. Expired rows deleted opportunistically.
- Session check: every authenticated route resolves the cookie first, then Bearer API key (`principal()`). API keys cannot use session-only routes (`requireSession`).

### Sign-up / sign-in / sign-out / session check / email verification / password reset
Covered in the route reference above (A1–A10). Verify tokens live 24 h, one-time. Reset tokens live 30 min, one-time, and reset revokes all sessions. Reset-request always returns 202.

### OAuth (Google, GitHub)
- `GET /auth/oauth/{provider}/start` → 302 to provider with state + PKCE (S256) + redirect allowlist.
- `GET /auth/oauth/{provider}/callback?code&state` → spends state, exchanges code, verifies provider email is verified (Google `email_verified`; GitHub primary+verified `user:email`), links-or-creates account, sets session cookie.
- Both providers share one flow. Real provider credentials required; tests use a fake `httptest` provider.
- Link rules: existing identity → login; verified provider email matching a locally-verified user → link; unverified local match → 403 (no second account, no takeover); else create verified user + identity.
- OAuth callback returns `200 {"ok": true}` on success (not a redirect) — the session cookie is set and the client follows from there.

**NOT BUILT vs docs/auth-design.md:** everything in §4/§5/§6/§7/§8/§11 of the design is built (signup, verify, login, logout, password-reset-request/reset, password-change, sessions list/revoke, logout-everywhere, OAuth start/callback, api-keys create/list/revoke). Nothing from §14 "Planned" (account deletion, data export, email change, 2FA) is built. No JWT, no refresh tokens.

### CSRF
Origin guard on POST/PUT/DELETE in `Handler()`: present `Origin` host must equal `r.Host`, else `403 "cross-origin request refused"`. No CSRF token; relies on SameSite=Lax + Origin check + JSON-only endpoints. GETs are not guarded.

### Lockout / rate-limit
- Auth endpoint cap: `auth|<ip>` → default 100 POSTs/IP/15 min → 429. Configurable `GP_AUTH_CAP` (default 100).
- Login failure lockout: `lock|<ip>|<lowercased email>` → default 5 failures/15 min → all further attempts on that pair 429 until window lapses. Configurable `GP_LOCKOUT_AFTER` (default 5).
- Argon2 runs only after the lock check (unknown users verify against a dummy hash for uniform timing).
- Domain action rate caps: per user AND per IP, 15 min — `domains:add` (default 20), `domains:verify` (default 20), `domains:origin-test` (default 10).
- Node poll cap: `node:<id>` → default 500/15 min.

Counters live in `rate_limits` (Postgres), 15-minute sliding windows, atomic upsert.

## Cross-cutting: tenant isolation

Every customer resource endpoint scopes by `owner_user_id = <caller>`:
- `ownerDomain()` fetches a domain only if `owner_user_id` matches; anything else → uniform `404 "not found"` (presence not disclosed across users).
- Origins, records, verification, WAF all flow through `ownerDomain`, so another user's domain/origin/record is a 404, never a 403 (no disclosure of existence).
- API keys and user_data are addressed only to the authenticated principal; there is no user-id parameter to guess (threat #15).
- Verification is one-transaction win: this claim → verified, every other pending claim on the hostname → rejected; exactly one verified row per hostname (unique partial index).
- A second user claiming an already-verified hostname → `409 "hostname already verified by another user"` at claim time and at verify time.

## Cross-cutting: limits

| limit | value | source |
|---|---|---|
| per-user total domain cap (pending/verified/disabled) | default 20 | `GP_DOMAIN_MAX` |
| per-user pending domain cap | default 5 | `GP_DOMAIN_PENDING` |
| domain add rate cap (per user + per IP, 15 min) | default 20 | `GP_DOMAIN_ADD_CAP` |
| domain verify rate cap (per user + per IP, 15 min) | default 20 | `GP_DOMAIN_VERIFY_CAP` |
| origin test rate cap (per user + per IP, 15 min) | default 10 | `GP_ORIGIN_TEST_CAP` |
| global snapshot size cap | 256 KiB | `snapshot.MaxBytes`, enforced at Sign and on the poller wire read; a claim near the cap → 422 |
| claim TTL | 7 days | `claimTTL` |
| session slide / absolute | 7d idle / 30d absolute | `sessionSlideDays` / `sessionAbsDays` |
| verify token TTL | 24 h | `newEmailToken` |
| reset token TTL | 30 min | `newEmailToken` |
| OAuth state TTL | 10 min | `oauth_states` |
| WAF rule-ID range | 1..999999 | `checkWAF` |
| WAF modes | off / detection / blocking | `validWAFModes` |
| record TTL | 60..86400 | schema + `checkRecord` |
| record priority | 0..65535 | schema + `checkRecord` |
| record value length | TXT ≤255 printable; others ≤4096 (schema CHECK) | schema |
| record name length | ≤100 chars, labels ≤63 | schema + `validateName` |
| health_path | ≤512 chars, starts `/`, no `..` | `originBody.check` |
| health_interval | 10..86400 s | schema + `originBody.check` |
| host_header | ≤255 chars, no whitespace/control | `originBody.check` |
| api key name | 1..100 chars | `createAPIKey` |
| node name | 1..50 chars | `createNode` |
| password length | 8..128 | `validPassword` |
| email length | ≤254, no whitespace | `validEmail` |
| request body read limit | 40 KiB (`readJSON`) | `server.go` |
| user-data body | ≤32 KiB | `userDataMax` |
| node poll cap | default 500 / 15 min | `GP_NODE_RATE_CAP` |
| snapshot TTL (cache) | default 30 s | `GP_SNAPSHOT_TTL` |
| node stale alert | default 10 min | `GP_NODE_STALE_MINUTES` |
| origin unresolved alert | default 60 min | `GP_ORIGIN_UNRESOLVED_MINUTES` |
| cert hourly cap (edge) | default 50 | `GP_EDGE_CERT_HOURLY_CAP` |

**422 behaviour:** business-rule caps (domain total/pending cap, snapshot size cap near/over, zone record limit) return `422` with a descriptive message. Rate limits return `429`. Validation of field shapes returns `400` or `422` depending on the handler (origin/WAF/record field validation → 422; email/password/name shape → 400).

## Cross-cutting: status values

### Domain status
`pending | verified | rejected | expired | disabled` (CHECK constraint in `004_domains.sql`).

Transitions:
- `pending` → `verified`: `POST /v1/domains/{id}/verify` succeeds (ownership proof). Also competing pending claims on the same hostname → `rejected` by the winner.
- `pending` → `expired`: hourly `ExpireDomainClaims` flips past-TTL (`expires_at < now()`) pending claims.
- `pending` → `disabled`: not set by any current endpoint (used as a held state; counts toward the total cap). No transition path to/from `disabled` exists in code — GAP.
- `rejected` / `expired` → `pending`: re-claim via `POST /v1/domains` flips back with a fresh token.
- `verified` → terminal: no endpoint moves a verified domain to another status. `DELETE /v1/domains/{id}` removes it entirely.

### Origin status
No status column. One origin per domain; `address`/`scheme`/etc. are mutable via PUT. Build-time verdicts (not stored status): `unsafe` (dropped + `origin_unsafe` alert), `unresolved` (kept + warning; `origin_unresolved` alert after 60 min), `ok` (kept).

### Node status
`active | revoked` (CHECK in `007_nodes.sql`). Default `active`. Revoke via `POST /v1/nodes/{id}/revoke` (operator). A revoked/inactive token → `401` on node routes.

### Alert kinds and states
`operator_alerts.kind` CHECK (014): `origin_unsafe | origin_unresolved | snapshot_build_failed | node_stale | waf_config_failed`. Each row: `created_at`, `resolved_at` (null = open). One open row per `(kind, subject)` (partial unique index). Auto-resolve:
- `origin_unsafe` / `origin_unresolved`: resolved when a build re-checks the origin as safe (`noteVerdict` default case).
- `snapshot_build_failed`: resolved by the next successful build.
- `node_stale`: resolved by the next accepted heartbeat (`last_seen` stamped).
- `waf_config_failed`: resolved when heartbeat reports `waf_fallback=false`; recorded when `true`.

### WAF modes
`off | detection | blocking` (per domain, default `detection`).

## Cross-cutting: alerts

Operator-only table `operator_alerts`. There is **no customer-facing read API for alerts** — GAP.

Alert kinds a customer can see for their own domains: **none** (no endpoint). Operator-only kinds: `origin_unsafe`, `origin_unresolved`, `snapshot_build_failed`, `node_stale`, `waf_config_failed`.

Linking:
- `origin_unsafe` / `origin_unresolved`: `subject` = domain hostname.
- `snapshot_build_failed`: `subject` = `"snapshot"`.
- `node_stale` / `waf_config_failed`: `subject` = node id (uuid text).

## Cross-cutting: time

- Format: RFC3339 UTC in all JSON timestamps (`created_at`, `expires_at`, `verified_at`, `last_seen`, `changed_at`, `built_at`).
- Time zone: UTC (Postgres `timestamptz`; Go `time.Now().UTC()` for `built_at`).
- Windows: 15-minute rate-limit windows; session 7d slide / 30d absolute; verify 24 h; reset 30 min; claim TTL 7 days; OAuth state 10 min; node stale default 10 min; origin unresolved default 60 min.

## Cross-cutting: data model (Postgres tables exposed by the API)

| table | key columns | relationships | exposed via |
|---|---|---|---|
| `users` | `id uuid PK`, `email`, `email_verified`, `password_hash`, `welcome_sent_at`, `created_at`, `updated_at` | — | `/api/me`, `/api/user-data`, auth routes |
| `sessions` | `token_hash text PK`, `user_id FK`, `id uuid`, `created_at`, `expires_at` | user → sessions (cascade) | `/auth/sessions`, revoke, logout-everywhere |
| `email_tokens` | `token_hash text PK`, `user_id FK`, `purpose`, `expires_at`, `used_at` | user → tokens | verify, password-reset |
| `outbox_messages` | `id bigserial`, `sent_at`, `to_addr`, `subject`, `body`, `kind` | — | dev mail log (not API-exposed) |
| `auth_identities` | `user_id FK`, `provider`, `provider_account_id`, `provider_email`, `provider_email_verified` | unique(provider, provider_account_id) | OAuth (not API-exposed) |
| `api_keys` | `id uuid PK`, `user_id FK`, `name`, `key_hash`, `prefix`, `created_at`, `last_used_at`, `revoked_at` | user → keys | `/auth/api-keys` |
| `user_data` | `user_id uuid PK FK`, `data jsonb`, `updated_at` | user → user_data | `/api/user-data` |
| `oauth_states` | `state text PK`, `provider`, `code_verifier`, `redirect_uri`, `expires_at`, `used_at` | — | OAuth (not API-exposed) |
| `rate_limits` | `key text PK`, `count`, `window_start` | — | rate limiting (not API-exposed) |
| `domains` | `id uuid PK`, `owner_user_id FK`, `hostname`, `status`, `setup_type`, `verify_token`, `claimed_at`, `verified_at`, `expires_at`, `ns1`, `ns2`, `waf_mode`, `excluded_rule_ids` | user → domains; domains → origins/zones | `/v1/domains*` |
| `origins` | `id uuid PK`, `domain_id uuid UNIQUE FK`, `scheme`, `address`, `port`, `host_header`, `tls_verify`, `health_path`, `health_interval_secs`, `created_at`, `updated_at` | domain → origin (1:1) | `/v1/domains/{id}/origin*` |
| `zones` | `id uuid PK`, `domain_id uuid UNIQUE FK` | nameserver domain → zone | records (not directly API-exposed) |
| `records` | `id uuid PK`, `zone_id FK`, `name`, `type`, `value`, `ttl`, `priority`, `created_at` | zone → records | `/v1/domains/{id}/records*` |
| `record_changes` | `id bigserial PK`, `record_id`, `zone_id`, `changed_by FK`, `action`, `old_value`, `new_value`, `changed_at` | record → history | history on record GET |
| `nodes` | `id uuid PK`, `name`, `role`, `token_hash`, `status`, `last_seen`, `applied_version`, `created_at` | — | `/v1/nodes*`, `/node/v1*` |
| `snapshot_versions` | `generation bigserial PK`, `content_hash`, `created_at` | — | node config ETag |
| `operator_alerts` | `id uuid PK`, `kind`, `subject`, `detail`, `created_at`, `resolved_at` | — | operator-only (no customer API) |
| `origin_unresolved` | `domain_id uuid PK FK`, `first_unresolved_at`, `updated_at` | domain → unresolved tracking | build-time bookkeeping |
| `domain_waf_changes` | `id uuid PK`, `domain_id FK`, `changed_by FK`, `action`, `old_value`, `new_value`, `changed_at` | domain → WAF audit | WAF history (not API-exposed) |

No secrets are stored plaintext: passwords → argon2id PHC; sessions/api_keys/tokens → SHA-256 only.

---

## GAPS for the frontend

Listed one per line with status and proof. These are things the frontend PRD needs that do not exist yet.

| # | GAP | status | proof (file:line) |
|---|-----|--------|-------------------|
| 1 | Email verification endpoint exists but the **verification link/email format** is dev-only (outbox file); no customer-clickable link format is returned by the API | BUILT (endpoint) / NOT BUILT (link format) | `internal/server/auth.go:110` (verify endpoint); `internal/server/server.go:468` (verifyEmailText — raw token POSTed to `/auth/verify`) |
| 2 | Password reset endpoint exists but **reset link/email format** is dev-only (outbox file) | BUILT (endpoint) / NOT BUILT (link format) | `internal/server/auth.go:201` (resetRequest); `internal/server/server.go:474` (resetEmailText) |
| 3 | OAuth callback flow: start returns 302; callback returns 200 + sets cookie — **no frontend redirect target or callback page contract** | PARTIAL | `internal/server/oauth.go:71` (start), `internal/server/oauth.go:109` (callback) |
| 4 | **Customer-facing read API for alerts** — none; `operator_alerts` is operator-only with no customer endpoint | NOT BUILT | `internal/server/snapshot.go:253` (recordAlert), no route exposes alerts to customers |
| 5 | **Operator role and role check** — exists for node management only (`GP_OPERATOR_EMAILS`) | PARTIAL | `internal/server/nodes.go:43` (requireOperator) |
| 6 | `GET /v1/domains/{id}/changes` (domain change history) — no such endpoint | NOT BUILT | no route in `server.go:204` for domain changes; only `record_changes` per record |
| 7 | **Customer-facing read API for nodes** — none; node routes (`/v1/nodes*`) are operator-only | NOT BUILT | `internal/server/nodes.go:59` (createNode), `:92` (listNodes) — operator-only |
| 8 | Domain status values and transitions — `disabled` has no transition path; no re-verification/periodic ownership re-check | PARTIAL | `migrations/004_domains.sql:9` (CHECK), `internal/server/domains.go:202` (no disabled→anything path) |
| 9 | **Way to test an origin connection** — exists | BUILT | `internal/server/origins.go:258` (testOrigin) |
| 10 | **DNS instruction values returned by the API** — exists (verification endpoint) | BUILT | `internal/server/domains.go:313` (domainVerification) |
| 11 | **Pagination on list routes** — none; all lists return full un-paginated slices | NOT BUILT | `internal/server/domains.go:267` (listDomains), `:290` (listRecords) — no limit/offset |
| 12 | **Logout-everywhere / sessions list** — sessions list exists; logout-everywhere exists | BUILT | `internal/server/auth.go:309` (listSessions), `:374` (logoutEverywhere) |
| 13 | **Account change-password route** — exists | BUILT | `internal/server/auth.go:237` (changePassword) |
