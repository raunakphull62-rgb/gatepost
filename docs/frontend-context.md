# Gatepost frontend context

Read-only extract of the public API contract for the spec writer. Every fact is taken from
the code (structs, json tags, handlers, validators, SQL, migrations). UNKNOWN = not
derivable from code. No secrets, tokens, or .env values.

Status: the repo has mid-change working tree modifications (see META).

---

## A. META

commit hash read: cef486b (full: cef486b1397ba5a2fcae4e5713e0af446b79cf9a)
date: 2026-11-01 13:52:54 +0000
Go version: go 1.22.2 (module); toolchain on box go1.26.8 linux/amd64
default listen: GP_HTTP_ADDR, fallback ":8080"; local dev docs default 127.0.0.1:8080

how to run the API locally (env var NAMES only, no values):
  - DATABASE_URL (pooled API connection, e.g. Neon pooler)
  - DATABASE_URL_DIRECT (direct connection, migrations run here)
  - ENV (development vs production fail-safe; anything but exactly "development" = production)
  - GP_HTTP_ADDR (listen address)
  - GP_PUBLIC_BASE_URL (base URL; Secure cookie + OAuth redirects derive from it)
  - GP_MAIL_DRIVER ("outbox" default | "smtp")
  - GP_MAIL_FROM
  - GP_SMTP_HOST / GP_SMTP_PORT / GP_SMTP_TLS / GP_SMTP_INSECURE / GP_SMTP_USER / GP_SMTP_PASSWORD
  - GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET (OAuth; unset => "unknown provider" 404)
  - GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
  - GP_AUTH_CAP / GP_LOCKOUT_AFTER
  - GP_DOMAIN_MAX / GP_DOMAIN_PENDING / GP_DOMAIN_ADD_CAP / GP_DOMAIN_VERIFY_CAP / GP_ORIGIN_TEST_CAP
  - GP_NS1 / GP_NS2 / GP_TEST_ZONE / GP_ALLOW_SUBDOMAIN_ZONES / GP_MAX_RECORDS
  - GP_SERVICE_HOSTNAMES / GP_DNS_RESOLVERS / GP_OWNED_ADDRESSES
  - GP_TEST_ALLOW_LOOPBACK (test/demo only; production boot refuses it)
  - GP_TRUSTED_PROXIES (default empty: trust nothing)
  - GP_SNAPSHOT_KEY (signs node snapshot; dev default "gatepost-development-snapshot-key"; production requires >=32 bytes)
  - GP_ORIGIN_UNRESOLVED_MINUTES
  - GP_NODE_RATE_CAP / GP_NODE_STALE_MINUTES / GP_SNAPSHOT_TTL
  - GP_OPERATOR_EMAILS

mid-change markers in working tree (git status --short):
  M scripts/edge-accept.sh   (modified, not committed)
  ?? docs/evidence/b3d-baseline/  (untracked dir)
No product code, migrations, or tests are modified in the working tree.

---

## B. ROUTES

All audiences: public (no auth), user (session cookie or API key), operator (session + operator email), edge-node (node bearer token, mutual 401 with user routes). CSRF applies to POST/PUT/DELETE only when an `Origin` header is present; that Origin host must equal `r.Host`, else 403 "cross-origin request refused". Missing Origin => passes untouched. Origin "null" parses to a host, will not match r.Host => 403.

Rate limiter: Postgres-backed `rate_limits` table, 15-minute window, key-based, resets when window lapses. "too many requests" (429) for all caps. Lockout: per (IP, email) pair at GP_LOCKOUT_AFTER failures within window; locked => 429 "too many requests" written before any credential check.

### B.1 POST /auth/signup | public | CSRF yes | rate limit key "auth|<ip>", window 15 min, count GP_AUTH_CAP (default 100)

request JSON { email: string (required), password: string (required) }
- email: validEmail => contains exactly one "@", local part non-empty, domain part contains a ".", length <= 254, no whitespace \t\r\n. Validation rule: loose shape only.
- password: len >= 8 and <= 128.
errors:
  - 400 "invalid email or password" (invalid email or password)
  - 429 "too many requests" (auth cap)
  - 500 "internal error"
  - 200 {"ok": true, "message": "check your inbox to verify your account"} — same body whether the email is new or already exists (no email enumeration). Existing email: skips insert and token mail, still returns 200 ok. New email: insert user (argon2id hash, password_hash text, email_verified=false), send verify token (24h TTL) via mailer driver, return 200.

### B.2 POST /auth/verify | public | CSRF yes | no rate limit

request JSON { token: string (required) }
errors:
  - 400 "invalid or expired token" (consumeEmailToken: used, wrong purpose, or expired; verify tokens live 24h)
  - 500 "internal error"
  - 200 {"ok": true} — session cookie set (fresh token), welcome message sent exactly once (welcome_sent_at atomic guard)

### B.3 POST /auth/login | public | CSRF yes | rate limit key "auth|<ip>", GP_AUTH_CAP; then lockout key "lock|<ip>|<lowercase email>", GP_LOCKOUT_AFTER (default 5)

request JSON { email: string, password: string }
errors:
  - 429 "too many requests" (auth cap OR lockout — both write "too many requests")
  - 401 "invalid credentials" (unknown user, wrong password, or OAuth-only account: argon2 verify runs against dummy hash for uniform timing; on any failure the lockout counter is bumped)
  - 500 "internal error"
  - 200 {"ok": true} — fresh session token rotated in place (new token.New(), row reused), cookie set

### B.4 POST /auth/logout | user | CSRF yes | none

request: none (session cookie)
errors:
  - 401 "authentication required"
  - 500 "internal error"
  - 200 {"ok": true} — deletes session row (where token_hash = cookie hash), clears cookie

### B.5 POST /auth/password-reset-request | public | CSRF yes | rate limit key "auth|<ip>", GP_AUTH_CAP

request JSON { email: string (required) }
errors:
  - 400 "invalid email" (validEmail fails)
  - 429 "too many requests" (auth cap)
  - 500 "internal error"
  - 202 {"ok": true, "message": "if the address exists, a reset link was sent"} — uniform whether or not the email exists (confirms non-enumeration). Sends reset token (30min TTL) only if a matching lower(email) user exists.

### B.6 POST /auth/password-reset | public | CSRF yes | none

request JSON { token: string (required), new_password: string (required, 8..128) }
errors:
  - 400 "invalid password" (new_password fails length rule)
  - 400 "invalid or expired token" (consumeEmailToken purpose "reset", 30min TTL, one-time)
  - 500 "internal error"
  - 200 {"ok": true} — sets new argon2id hash, deletes ALL sessions of the user (revokes everywhere)

### B.7 POST /auth/password-change | user (session-only) | CSRF yes | rate limit key "auth|<ip>", GP_AUTH_CAP | re-auth required: yes (current_password verified against stored hash)

request JSON { current_password: string, new_password: string (required, 8..128) }
errors:
  - 401 "authentication required" (no session or API key used)
  - 400 "invalid password" (new_password fails length rule)
  - 429 "too many requests" (auth cap)
  - 401 "invalid credentials" (wrong current password — also bumps lockout key "lock|<ip>|<email>")
  - 500 "internal error"
  - 200 {"ok": true} — sets new hash, deletes every OTHER session of the user, rotates the caller's session token in place (same row, new hash, new cookie)

### B.8 GET /auth/sessions | user | CSRF no | none

request: none
errors:
  - 401 "authentication required"
  - 500 "internal error"
  - 200 {"sessions": [{ id: string(uuid), created_at: RFC3339, expires_at: RFC3339, current: bool }]} — ordered by created_at; current flag = token_hash = cookie hash. No token material exposed.

### B.9 POST /auth/sessions/{id}/revoke | user | CSRF yes | none

path param: id (opaque session id uuid text)
errors:
  - 401 "authentication required"
  - 404 "not found" (absent id OR foreign user's id — uniform)
  - 500 "internal error"
  - 200 {"ok": true} — deletes the row; if revoking the current session, clears the cookie

### B.10 POST /auth/logout-everywhere | user | CSRF yes | none

request: none
errors:
  - 401 "authentication required"
  - 500 "internal error"
  - 200 {"ok": true} — deletes all sessions of the user, clears cookie; API keys unaffected (API keys have no sessions; still 200)

### B.11 POST /auth/api-keys | user (session-only; Bearer keys rejected) | CSRF yes | none

request JSON { name: string (required, trimmed; 1..100 chars) }
errors:
  - 400 "invalid name" (empty or >100)
  - 401 "authentication required" (no session)
  - 500 "internal error"
  - 201 { id, name, key (full "gp_pat_..." returned once, never stored), prefix ("gp_pat_" + first 8), created_at, last_used_at: null, revoked_at: null }

### B.12 GET /auth/api-keys | user (session-only) | CSRF no | none

errors:
  - 401 "authentication required"
  - 500 "internal error"
  - 200 { keys: [{ id, name, prefix, created_at, last_used_at (nullable), revoked_at (nullable) }] } — metadata only, no key material

### B.13 POST /auth/api-keys/{id}/revoke | user (session-only) | CSRF yes | none

path param: id
errors:
  - 401 "authentication required"
  - 404 "not found" (absent or foreign key — uniform)
  - 500 "internal error"
  - 200 {"ok": true} — revoked_at = now() (terminal; idempotent)

### B.14 GET /api/me | user (session or Bearer API key) | CSRF no | none

errors:
  - 401 "authentication required"
  - 500 "internal error"
  - 200 { id: string(uuid), email: string } — principal (session cookie or API key). Does NOT tell whether the user is an operator (see section J).

### B.15 GET /api/user-data | user | CSRF no | none
### B.16 PUT /api/user-data | user | CSRF yes | none

request JSON: any valid JSON document, <= 32 KiB (read with MaxBytesReader userDataMax+1)
errors (PUT):
  - 400 "body exceeds 32 KiB"
  - 400 "body must be valid JSON"
  - 401 "authentication required"
  - 500 "internal error"
  - 200 {"ok": true}
GET: 200 returns stored document, "{}" when none (no envelope; raw JSON written).

### B.17 POST /v1/domains | user | CSRF yes | rate limit key "domains:add|user:<id>" AND "domains:add|ip:<ip>", GP_DOMAIN_ADD_CAP (default 20)

request JSON { hostname: string (required), setup_type: string (optional, default "cname", enum cname|nameserver) }
errors:
  - 403 "that hostname is a Gatepost service name" (matches GP_SERVICE_HOSTNAMES)
  - 422 "invalid hostname: <detail>" (NormalizeHostname: lowercase, no trailing dot, not an IP, no colons, IDN via punycode <=253 octets, labels <=63, not localhost, must contain a dot, not a bare public suffix, not reserved service hostname)
  - 422 "setup_type must be cname or nameserver"
  - 422 "nameserver mode is not configured (GP_NS1/GP_NS2 missing)" (nameserver mode without env pair)
  - 422 "nameserver setup needs a registrable domain (delegated subdomains require GP_ALLOW_SUBDOMAIN_ZONES and the GP_TEST_ZONE suffix)" (nameserver + non-registrable, unless subdomain zone allowed)
  - 422 "domain cap reached (max total <n>)" (total counts pending/verified/disabled; default 20)
  - 422 "pending claim cap reached (max pending <n>)" (default 5)
  - 422 "the config snapshot is over its size cap — no new domains until it shrinks" / "the config snapshot is within 1024 bytes of its size cap — no new domains until it shrinks" (snapshot size gate)
  - 409 "hostname already verified by another user"
  - 429 "rate limit exceeded for domains:add" (per-user or per-IP cap)
  - 500 "internal error"
  - 201 { domain: <domainRow>, existing: false } (new claim)
  - 200 { domain: <domainRow>, existing: true } (caller already holds pending/verified/disabled claim; rejected/expired flips back to pending with fresh token and new claimed_at/expires_at = now()+7 days)

### B.18 GET /v1/domains | user | CSRF no | none

errors:
  - 401 "authentication required"
  - 500 "internal error"
  - 200 { domains: [<domainRow>, ...] } ordered by claimed_at DESC, id. Full list, not paginated.

### B.19 GET /v1/domains/{id} | user | CSRF no | none

path param: id (domain uuid)
errors:
  - 401 "authentication required"
  - 404 "not found" (not caller's domain — presence not disclosed)
  - 500 "internal error"
  - 200 { domain: <domainRow> }

### B.20 DELETE /v1/domains/{id} | user | CSRF yes | none

path param: id
errors:
  - 401 "authentication required"
  - 404 "not found"
  - 500 "internal error"
  - 200 {"ok": true} — deletes claim + its origin (cascade), invalidates snapshot

### B.21 PUT /v1/domains/{id}/waf | user | CSRF yes | none

path param: id
request JSON { mode: string (optional; enum off|detection|binding? no — off|detection|blocking; default "detection"), excluded_rule_ids: array of int (optional; each 1..999999) }
errors:
  - 400 "mode must be off, detection, or blocking"
  - 400 "rule id <n> out of range (1..999999)"
  - 401 "authentication required"
  - 404 "not found"
  - 500 "internal error"
  - 200 { domain: <domainRow> } — records mode + exclude_add/exclude_remove rows in domain_waf_changes; invalidates snapshot

### B.22 GET /v1/domains/{id}/verification | user | CSRF no | none

path param: id
errors:
  - 401 "authentication required"
  - 404 "not found"
  - 500 "internal error"
  - 200 { verification: { domain_id, hostname, setup_type, status, expires_at, [nameservers: [ns1,ns2] if nameserver], [record_name: "_gatepost-verify.<hostname>", record_value: "gatepost-verify=<token>"] } } — cname mode returns the TXT record name/value; nameserver mode returns the assigned pair

### B.23 POST /v1/domains/{id}/verify | user | CSRF yes | rate limit key "domains:verify|user:<id>" AND "...|ip:<ip>", GP_DOMAIN_VERIFY_CAP (default 20)

path param: id
errors:
  - 429 "rate limit exceeded for domains:verify"
  - 410 "claim is <status>, not verifiable" (not pending)
  - 410 "claim expired, re-claim it" (expires_at < now)
  - 409 "hostname already verified by another user" (contested)
  - 400 "verification failed: no TXT record gatepost-verify=<tok> at _gatepost-verify.<hostname>" (cname; DNS lookup or no matching TXT)
  - 400 "verification failed: no NS records for <hostname>" (nameserver; empty NS set)
  - 400 "verification failed: NS records< missing: ...>< unexpected: ...>" (nameserver; NS set != assigned pair exactly, order/case/trailing-dot free)
  - 502 "dns lookup failed: <err>" (nameserver or cname resolver error)
  - 409 "verification raced another attempt, try again" / "claim changed state mid-verification, try again" / "hostname already verified by another user" (markVerified race paths)
  - 500 "internal error"
  - 200 { status: "verified" } — one-transaction win: this claim verified, competing pending claims on hostname rejected; snapshot invalidated

### B.24 POST /v1/domains/{id}/origin | user | CSRF yes | rate limit key "domains:add|user:<id>" AND "...|ip:<ip>" (reuses DomainAddCap)

path param: id
request JSON { scheme: "http"|"https" (required), address: string (required), port: int (required, 1..65535, deny list), host_header: string (optional), tls_verify: bool (optional, default true), health_path: string (optional, default "/"), health_interval: int (optional, default 60, 10..86400) }
errors:
  - 422 "scheme must be http or https"
  - 422 "port: <detail>" (out of range or on deny list: 21,22,23,25,110,135,137,139,143,161,389,445,465,514,587,636,691,993,995,1433,1521,2049,2181,2375,2376,3128,3306,3389,5432,5555,5900,5985,5986,6379,6380,11211,27017,27018,27019)
  - 422 "origin address: <detail>" (ValidateOrigin: empty, IP literals range-checked via CheckIP — forbids 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4, v6 ::/8, fe00::/9, fe80::/10, fc00::/7, ff00::/8, 2001:db8::/32, GP_OWNED_ADDRESSES, malformed numeric spellings), hostname syntax via hostLike [a-z0-9._-], labels <=63, total <=253, not owned)
  - 422 "origin address: cannot resolve <canonical>" / "no A/AAAA record for <canonical>" (hostname origins resolved via configured resolvers, 5s deadline; every resolved IP re-checked via CheckIP)
  - 422 "host_header empty, too long, or contains spaces" (trimmed, non-empty, <=255, no whitespace/NUL)
  - 422 "health_path must start with / (no dots, max 512)"
  - 422 "health_interval must be 10..86400 seconds"
  - 401 "authentication required"
  - 404 "not found"
  - 409 "origin already set; use PUT"
  - 429 "rate limit exceeded for domains:add"
  - 500 "internal error"
  - 201 { origin: <originRow> }

### B.25 GET /v1/domains/{id}/origin | user | CSRF no | none

path param: id
errors:
  - 401 "authentication required"
  - 404 "not found" (domain) / "no origin set" (no origin row)
  - 500 "internal error"
  - 200 { origin: <originRow> }

### B.26 PUT /v1/domains/{id}/origin | user | CSRF yes | same rate limit as add

path param: id
request JSON: same fields as add (all validated again)
errors: same validation as add, plus 404 "no origin set; POST to create" when no existing origin
  - 200 { origin: <originRow> }

### B.27 POST /v1/domains/{id}/origin/test | user | CSRF yes | rate limit key "domains:origin-test|user:<id>" AND "...|ip:<ip>", GP_ORIGIN_TEST_CAP (default 10)

path param: id
request: none
errors:
  - 401 "authentication required"
  - 404 "not found" / "no origin set"
  - 429 "rate limit exceeded for domains:origin-test"
  - 500 "internal error"
  - 200 { test: { reachable: bool, status_code: int (omitempty), tls_ok: bool (omitempty), duration_ms: int64, error: string (omitempty) } } — always 200 even on refusal; reachable=false + error set on any refusal (validation, DNS, dial, TLS, non-2xx is still reachable=true with its status_code). Resolves stored address, re-checks every IP against deny rules, dials the resolved IP directly (no redirect follow, redirects returned as-is), reads at most 64 KiB, 5s deadline, Host header = health path host or HostHeader, SNI = canonical address, InsecureSkipVerify = !tls_verify.

### B.28 POST /v1/domains/{id}/records | user | CSRF yes | rate limit key "domains:add|user:<id>" (reuses DomainAddCap)

path param: id
request JSON { name: string (required), type: string (required, enum A|AAAA|CNAME|MX|TXT|NS|SRV|CAA), value: string (required), ttl: int (optional, default 3600, 60..86400), priority: int (optional, 0..65535) }
errors:
  - 409 "records need a nameserver-mode domain" (no zone row)
  - 422 "invalid record name" / "bad label length" / "bad character in name" / "bad hyphen position" (name: "@" or label chain [a-z0-9_-], <=100 total, labels <=63, no leading/trailing hyphen)
  - 422 "type must be one of A AAAA CNAME MX TXT NS SRV CAA"
  - 422 "A value must be an IPv4 address" / "AAAA value must be an IPv6 address"
  - 422 "CNAME/NS value must be a hostname" / "MX value must be a hostname" (validateRecordTarget: trailing dot ok, labels [a-z0-9-], <=253, not an IP literal)
  - 422 "MX needs a priority" / "SRV needs a priority"
  - 422 `SRV value must be "weight port target"` / "bad SRV weight" / "bad SRV port" / "SRV target must be a hostname or ."
  - 422 `CAA value must be "flag tag value"` / "CAA flag must be 0..255"
  - 422 "TXT value must be 255 printable chars max"
  - 422 "ttl must be 60..86400" / "priority must be 0..65535"
  - 409 "another record already exists at this name" / "a CNAME already exists at this name" (CNAME exclusivity both directions)
  - 422 "zone record limit reached" (count >= GP_MAX_RECORDS default 100)
  - 401 "authentication required"
  - 500 "internal error"
  - 201 { record: <recordRow> } + history row (action 'create')

### B.29 GET /v1/domains/{id}/records | user | CSRF no | none

path param: id
errors:
  - 401 "authentication required"
  - 404 "not found" (domain)
  - 409 "records need a nameserver-mode domain"
  - 500 "internal error"
  - 200 { records: [<recordRow>, ...] } ordered by name, type, id

### B.30 GET /v1/domains/{id}/records/{rid} | user | CSRF no | none

path params: id, rid
errors:
  - 401 "authentication required"
  - 404 "not found" (domain or record)
  - 409 "records need a nameserver-mode domain"
  - 500 "internal error"
  - 200 { record: <recordRow>, history: [<recordChange>, ...] } ordered by changed_at, id

### B.31 PATCH /v1/domains/{id}/records/{rid} | user | CSRF yes | none

path params: id, rid
request JSON { value: string (optional), ttl: int (optional), priority: int (optional) } — at least one required
errors:
  - 422 "nothing to change" (all nil)
  - 422 <typeValueCheck message> (value re-validated against record type)
  - 422 "ttl must be 60..86400"
  - 401 "authentication required"
  - 404 "not found"
  - 409 "records need a nameserver-mode domain"
  - 500 "internal error"
  - 200 { record: <recordRow> } + history row (action 'update', old_value/new_value)

### B.32 DELETE /v1/domains/{id}/records/{rid} | user | CSRF yes | none

path params: id, rid
errors:
  - 401 "authentication required"
  - 404 "not found"
  - 409 "records need a nameserver-mode domain"
  - 500 "internal error"
  - 200 { deleted: true } + history row (action 'delete', old_value)

### B.33 POST /v1/nodes | operator | CSRF yes | none

request JSON { name: string (required, 1..50), role: string (required, enum edge|dns) }
errors:
  - 401 "authentication required"
  - 403 "operator access only" (email not on GP_OPERATOR_EMAILS)
  - 422 "name must be 1..50 characters"
  - 422 "role must be edge or dns"
  - 409 "node name already taken"
  - 500 "internal error"
  - 201 { node: <nodeRow>, token: string (full 256-bit token shown ONCE) }

### B.34 GET /v1/nodes | operator | CSRF no | none

errors:
  - 401 "authentication required"
  - 403 "operator access only"
  - 500 "internal error"
  - 200 { nodes: [<nodeRow>, ...] } — no token material

### B.35 POST /v1/nodes/{id}/revoke | operator | CSRF yes | none

path param: id
errors:
  - 401 "authentication required"
  - 403 "operator access only"
  - 404 "not found"
  - 500 "internal error"
  - 200 { node: <nodeRow> } — status flipped to 'revoked'; idempotent

### B.36 GET /node/v1/config | edge-node | CSRF no | rate limit key "node:<node id>", GP_NODE_RATE_CAP (default 500)

request header: Authorization: Bearer <node token>; optional If-None-Match: "<generation>"
errors:
  - 401 "node authentication required" (missing/invalid token, unknown hash, revoked or non-active node — all uniform)
  - 429 "rate limit exceeded for node polls"
  - 500 "internal error"
  - 304 (empty, ETag set) when If-None-Match matches current generation
  - 200 { payload: string, signature: string (hex HMAC-SHA256), key_id: string (first 16 hex of SHA-256(key)) }, ETag header = "<generation>" — signed snapshot envelope

### B.37 POST /node/v1/heartbeat | edge-node | CSRF yes | rate limit key "node:<node id>", GP_NODE_RATE_CAP

request JSON { generation: int64 (required, >0, must exist in snapshot_versions), waf_fallback: bool (optional) }
errors:
  - 400 "generation must be a positive integer"
  - 400 "unknown snapshot version"
  - 401 "node authentication required"
  - 429 "rate limit exceeded for node polls"
  - 500 "internal error"
  - 200 { applied_generation: <n> } — stamps last_seen + applied_version only when generation exists; resolves open node_stale and (if waf_fallback false) waf_config_failed alerts for this node; if waf_fallback true, records/resolves waf_config_failed alert

---

## C. ERROR ENVELOPE

Exact JSON today for every error: `{"error": "<message>"}` — written by `fail(w, code, msg)` via writeJSON. Content-Type application/json. The HTTP status is the only machine-readable signal; the message string is human text.

Complete list of distinct error message strings and where each occurs:

- "invalid request body" — server.go readJSON (any endpoint with a JSON body), 400
- "internal error" — every handler (500 catch-all)
- "cross-origin request refused" — server.go Handler() CSRF guard, 403 (POST/PUT/DELETE with Origin != r.Host)
- "authentication required" — requireAuth/requireSession/nodeAuth, 401
- "invalid email or password" — signup, 400
- "too many requests" — tooMany() for every rate cap and every lockout, 429
- "invalid or expired token" — verify (verify purpose, 24h), resetComplete (reset purpose, 30m), 400
- "invalid credentials" — login (any failure), changePassword (wrong current password), 401
- "invalid email" — resetRequest, 400
- "if the address exists, a reset link was sent" — that's a 202 success, not an error
- "check your inbox to verify your account" — signup 200 success message
- "rate limit exceeded for domains:add" — addOrigin/addDomain domainRate, 429
- "rate limit exceeded for domains:verify" — verifyDomain domainRate, 429
- "rate limit exceeded for domains:origin-test" — testOrigin domainRate, 429
- "rate limit exceeded for node polls" — nodeAuth, 429
- "that hostname is a Gatepost service name" — addDomain reserved, 403
- "invalid hostname: <detail>" — addDomain NormalizeHostname, 422
- "setup_type must be cname or nameserver" — addDomain, 422
- "nameserver mode is not configured (GP_NS1/GP_NS2 missing)" — addDomain, 422
- "nameserver setup needs a registrable domain (delegated subdomains require GP_ALLOW_SUBDOMAIN_ZONES and the GP_TEST_ZONE suffix)" — addDomain, 422
- "domain cap reached (max total <n>)" — addDomain, 422
- "pending claim cap reached (max pending <n>)" — addDomain, 422
- "the config snapshot is over its size cap — no new domains until it shrinks" — addDomain, 422
- "the config snapshot is within 1024 bytes of its size cap — no new domains until it shrinks" — addDomain, 422
- "hostname already verified by another user" — addDomain / verifyDomain, 409
- "scheme must be http or https" — origin body.check, 422
- "port: <detail>" — CheckPort, 422
- "origin address: <detail>" — ValidateOrigin/CheckIP, 422 (and testOrigin refusals carry these in the test.error field, still HTTP 200)
- "origin address: cannot resolve <canonical>" — checkOrigin/testOrigin, 422
- "origin address: no A/AAAA record for <canonical>" — checkOrigin/testOrigin, 422
- "host_header empty, too long, or contains spaces" — origin body.check, 422
- "health_path must start with / (no dots, max 512)" — origin body.check, 422
- "health_interval must be 10..86400 seconds" — origin body.check, 422
- "origin already set; use PUT" — addOrigin, 409
- "no origin set" — getOrigin/testOrigin, 404
- "no origin set; POST to create" — putOrigin, 404
- "generation must be a positive integer" — nodeHeartbeat, 400
- "unknown snapshot version" — nodeHeartbeat, 400
- "name must be 1..50 characters" — createNode, 422
- "role must be edge or dns" — createNode, 422
- "node name already taken" — createNode, 409
- "claim is <status>, not verifiable" — verifyDomain, 410
- "claim expired, re-claim it" — verifyDomain, 410
- "verification failed: no TXT record ..." — verifyDomain cname, 400
- "verification failed: no NS records for ..." — verifyDomain nameserver, 400
- "verification failed: NS records<missing: ...><unexpected: ...>" — verifyDomain nameserver, 400
- "dns lookup failed: <err>" — verifyDomain, 502
- "verification raced another attempt, try again" — markVerified, 409
- "claim changed state mid-verification, try again" — markVerified, 409
- "records need a nameserver-mode domain" — zoneForDomain, 409
- "invalid record name" / "bad label length" / "bad character in name" / "bad hyphen position" — validateName, 422
- "type must be one of A AAAA CNAME MX TXT NS SRV CAA" — checkRecord, 422
- "A value must be an IPv4 address" / "AAAA value must be an IPv6 address" — checkRecord, 422
- "CNAME/NS value must be a hostname" / "MX value must be a hostname" — validateRecordTarget/checkRecord, 422
- "MX needs a priority" / "SRV needs a priority" — checkRecord, 422
- `SRV value must be "weight port target"` / "bad SRV weight" / "bad SRV port" / "SRV target must be a hostname or ." — checkRecord, 422
- `CAA value must be "flag tag value"` / "CAA flag must be 0..255" — checkRecord, 422
- "TXT value must be 255 printable chars max" — checkRecord, 422
- "ttl must be 60..86400" — checkRecord / patchRecord, 422
- "priority must be 0..65535" — checkRecord, 422
- "another record already exists at this name" / "a CNAME already exists at this name" — addRecord, 409
- "zone record limit reached" — addRecord, 422
- "nothing to change" — patchRecord, 422
- "mode must be off, detection, or blocking" — checkWAF, 400
- "rule id <n> out of range (1..999999)" — checkWAF, 400
- "node authentication required" — nodeAuth, 401
- "operator access only" — requireOperator, 403

Validation errors tied to a specific field (field derivable from message context):
- email: "invalid email or password" (signup), "invalid email" (resetRequest) — field: email
- password: "invalid email or password", "invalid credentials" (login), "invalid password" (password-change/reset) — field: current_password/new_password
- hostname: "invalid hostname: <detail>" — field: hostname
- scheme: "scheme must be http or https" — field: scheme
- port: "port: <detail>" — field: port
- address: "origin address: <detail>" — field: address
- host_header: "host_header empty, too long, or contains spaces" — field: host_header
- health_path: "health_path must start with / (no dots, max 512)" — field: health_path
- health_interval: "health_interval must be 10..86400 seconds" — field: health_interval
- mode: "mode must be off, detection, or blocking" — field: mode
- excluded_rule_ids: "rule id <n> out of range (1..999999)" — field: excluded_rule_ids
- name (node): "name must be 1..50 characters" — field: name
- role (node): "role must be edge or dns" — field: role
- record name/type/value/ttl/priority: checkRecord messages — fields: name, type, value, ttl, priority
- generation: "generation must be a positive integer" / "unknown snapshot version" — field: generation
- token: "invalid or expired token" — field: token

---

## D. AUTH FLOWS

### D.1 Sign-up (browser view)
POST /auth/signup {email, password} -> 200 {"ok": true, "message": "check your inbox to verify your account"} (same for new/existing email). A verify token (24h TTL) is inserted into email_tokens (purpose 'verify') and mailed: text "Your verification token: <token>\n\nPOST it to <GP_PUBLIC_BASE_URL>/auth/verify to verify your account.\nThe token expires in 24 hours." via outbox file (./outbox/<nanotime>-<to>.txt) + outbox_messages row in dev; SMTP in production. No link is embedded — the raw token is sent and the client POSTs it.

### D.2 Email verification
POST /auth/verify {token} -> spends the token atomically (used_at set, purpose='verify', expires_at > now), sets email_verified=true, starts a session (newSession: fresh token.New(), cookie gp_session), sends welcome message exactly once (welcome_sent_at atomic UPDATE ... RETURNING email), returns 200 {"ok": true}. Token lifetime 24h. Invalid/expired/used -> 400 "invalid or expired token".

### D.3 Sign-in
POST /auth/login {email, password} -> capped per IP (auth cap). Lockout checked per (IP, lowercase email) BEFORE argon2; locked -> 429 "too many requests" with no timing reveal. Unknown user / OAuth-only / wrong password: verify against dummy hash (uniform timing), on failure bump lockout counter -> 401 "invalid credentials". Success: newSession fresh token, cookie set, 200 {"ok": true}. Failed sign-in response: 401 {"error": "invalid credentials"}; time left is NOT reported (no retry-after, no remaining-attempts field — UNKNOWN whether UI can compute time left; lockout window is 15 min but not exposed).

### D.4 Sign-out
POST /auth/logout -> deletes the caller's session row, clears gp_session cookie (MaxAge=-1), 200 {"ok": true}.

### D.5 Session check
GET /api/me -> 200 { id, email } (session cookie or Bearer API key). No operator flag exposed. Session cookie slides on every authenticated use (sessionPrincipal UPDATE: expires_at = least(now()+7d, created_at+30d)), capped at created_at+30d absolute; lapsed windows never resurrect.

### D.6 Sessions list and revoke
GET /auth/sessions -> 200 { sessions: [{id, created_at, expires_at, current}] }.
POST /auth/sessions/{id}/revoke -> deletes one session by opaque id; if it's current, clears cookie; absent/foreign id -> 404 "not found" (uniform).
POST /auth/logout-everywhere -> deletes all sessions of the user, clears cookie, 200 {"ok": true}. API keys unaffected.

### D.7 Logout-everywhere
See D.6: POST /auth/logout-everywhere ends all sessions + clears cookie.

### D.8 Change password
POST /auth/password-change {current_password, new_password} — session-only (API key rejected with 401). Re-auth required: yes, current_password verified. Wrong password bumps lockout (IP, email) -> 401 "invalid credentials". Success: new hash set, every OTHER session deleted, caller's session token rotated in place (new cookie), 200 {"ok": true}.

### D.9 Forgot / reset password
POST /auth/password-reset-request {email} -> always 202 {"ok": true, "message": "if the address exists, a reset link was sent"} — confirms it does NOT reveal whether the email exists. Reset token (30m TTL, purpose 'reset') mailed only if lower(email) user exists: "Your password reset token: <token>\n\nPOST it to <GP_PUBLIC_BASE_URL>/auth/password-reset to set a new password.\nThe token expires in 24 hours." (note: text says 24 hours but TTL is 30 minutes — code discrepancy). POST /auth/password-reset {token, new_password} -> spends token, sets hash, deletes all sessions, 200 {"ok": true}; invalid/expired -> 400 "invalid or expired token".

### D.10 OAuth Google and GitHub
Start: GET /auth/oauth/{provider}/start (provider=google|github) -> 302 to provider authorize URL with client_id, redirect_uri (= GP_PUBLIC_BASE_URL + "/auth/oauth/" + provider + "/callback", which IS the allowlisted redirect — allowlisted() returns exactly this), scope, state, code_challenge (S256 of verifier), code_challenge_method=S256. State row stored in oauth_states (10 min TTL, single-use). Rate limited by auth cap. Unknown provider -> 404 "unknown provider".
Callback: GET /auth/oauth/{provider}/callback?code&state -> spends state atomically (used_at, unexpired, provider match; redirect must equal allowlisted value else 403 "invalid oauth state"), exchanges code for access token (server-side form POST to provider token URL with client_id/secret), fetches userinfo, requires email + email_verified (Google: email_verified field; GitHub: primary+verified email from /user/emails), links-or-logins: existing (provider,account) identity -> login; verified local email match -> link identity; unverified local match -> error (no takeover); else create verified user + identity. Then newSession + welcomeOnce, 200 {"ok": true}. Any failure -> 403 "oauth login failed" (uniform, no enumeration).
Redirect URIs expected: <GP_PUBLIC_BASE_URL>/auth/oauth/google/callback and .../github/callback (must match provider console config; env var names: GOOGLE_CLIENT_ID/SECRET, GITHUB_CLIENT_ID/SECRET).
State handling: state+verifier = token.New() each, stored 10 min, single-use atomic spend; tampered/expired/replayed -> 403.

### D.11 Session cookie
Name: gp_session. Flags: HttpOnly, SameSite=Lax, Path=/, MaxAge=30d (2592000s), Secure when GP_PUBLIC_BASE_URL is https. Value = raw token (browser-side); server stores only SHA-256(token_hash). Lifetime: slides to now()+7d on every use, absolute cap created_at+30d (never resurrects). readJSON body limit 40 KiB unrelated.

### D.12 CSRF
Applies to POST/PUT/DELETE only. Checked in server.go Handler(): if Origin header present, parse it; error or empty host or u.Host != r.Host -> 403 "cross-origin request refused". Missing Origin -> passes untouched (non-browser clients). Origin "null" -> parses to a URL with host "null" (or empty), won't equal r.Host -> 403.

---

## E. CLIENT IP

Server.clientIP(r) in internal/server/server.go (lines ~295-308): returns net.SplitHostPort(r.RemoteAddr) host UNLESS the direct peer is in TrustedProxies AND an X-Forwarded-For header is present (peerIsTrusted requires both CIDR match and XFF non-empty). When trusted, walks X-Forwarded-For from the LAST entry backward, returning the first entry NOT in TrustedProxies; if all are trusted, falls back to peer. Default GP_TRUSTED_PROXIES empty -> trust nothing -> every request's IP is RemoteAddr and client XFF is ignored entirely. Spoofed XFF without a trusted proxy is ignored (TestSpoofedXFFIgnoredWithoutTrustedProxies). File+line: internal/server/server.go clientIP ~line 295.

---

## F. OBJECTS

### user (row) — id uuid, email text, email_verified bool, password_hash text (nullable; OAuth-only users have none), welcome_sent_at timestamptz (nullable), created_at, updated_at. Never returns password_hash to client.
JSON via GET /api/me: { id: string(uuid), email: string }.

### session — id uuid (opaque, URL-safe), token_hash text (never exposed), user_id, created_at timestamptz, expires_at timestamptz.
JSON via GET /auth/sessions: { id, created_at, expires_at, current: bool }.

### domain (domainRow) — { id: string(uuid), hostname: string, status: string enum pending|verified|rejected|expired|disabled, setup_type: string enum cname|nameserver, claimed_at: RFC3339, verified_at: nullable RFC3339, expires_at: nullable RFC3339, ns1: string (nullable->"" coalesced), ns2: string (nullable->"" coalesced), waf_mode: string (default "detection" coalesced), excluded_rule_ids: []int (default empty coalesced) }. verify_token never exposed. verified_at/expires_at null when not applicable.

### origin (originRow) — { scheme: "http"|"https", address: string (canonical form), port: int, host_header: *string (nullable), tls_verify: bool (default true), health_path: string (default "/"), health_interval: int (default 60), created_at: RFC3339, updated_at: RFC3339 }.

### domain verification instructions (GET /v1/domains/{id}/verification) — { verification: { domain_id, hostname, setup_type, status, expires_at (nullable), nameservers: [ns1, ns2] (nameserver mode only), record_name: "_gatepost-verify.<hostname>" (cname mode only), record_value: "gatepost-verify=<token>" (cname mode only) } }. DNS the customer must create: cname mode -> TXT record at name "_gatepost-verify.<hostname>" with value "gatepost-verify=<token>"; nameserver mode -> delegate the zone to nameservers ns1 and ns2 (the GP_NS1/GP_NS2 pair).

### origin test result — { test: { reachable: bool, status_code: int (omitempty), tls_ok: bool (omitempty), duration_ms: int64, error: string (omitempty) } } — always HTTP 200.

### WAF settings (domain.waf_mode + excluded_rule_ids) — mode: off|detection|blocking (default detection); excluded_rule_ids: []int, each 1..999999. Change trail in domain_waf_changes (action: mode|exclude_add|exclude_remove, old_value, new_value, changed_by, changed_at).

### alert (operator_alerts row) — { id, kind: string enum origin_unsafe|origin_unresolved|snapshot_build_failed|node_stale|waf_config_failed, subject: string, detail: text, created_at, resolved_at (nullable) }. One OPEN row per (kind, subject) (unique partial index). No operator-facing API route to list alerts exists in the API (UNKNOWN if console reaches them directly via DB).

### node (nodeRow) — { id: string(uuid), name: string, role: string enum edge|dns, status: string enum active|revoked, last_seen: nullable RFC3339, applied_version: *int64 (nullable), created_at: RFC3339 }. Token never exposed (create returns it once).

### domain WAF change-trail entry (domain_waf_changes row) — { id uuid, domain_id uuid, changed_by uuid, action: enum mode|exclude_add|exclude_remove, old_value text (nullable), new_value text (nullable), changed_at timestamptz }.

### snapshot envelope (GET /node/v1/config) — { payload: string (canonical JSON), signature: string (hex HMAC-SHA256), key_id: string (first 16 hex of SHA-256 key)) }.

---

## G. ENUMS AND STATE MACHINES

Domain status values: pending | verified | rejected | expired | disabled (CHECK constraint in 004).
- pending -> verified: POST /v1/domains/{id}/verify (TXT/NS proof), markVerified one-transaction win.
- pending -> rejected: when another user verifies the same hostname first (competing pending claims rejected); also verifyDomain 409 contest.
- pending -> expired: ExpireDomainClaims hourly background job (main.go loop, runs every 1h) flips pending claims with expires_at < now() to expired. claimTTL = 7 days.
- pending -> pending (fresh token): re-claiming a rejected/expired claim via POST /v1/domains flips back to pending, claimed_at=now(), expires_at=now()+7d, verified_at=NULL.
- verified -> disabled: no API path sets 'disabled' in product code. It exists in the CHECK constraint and counts toward the total cap (pending/verified/disabled), but nothing in the server sets it. SET by raw SQL in tests only (domains_test.go UPDATE domains SET status='disabled'). WHO sets it in production: UNKNOWN / no code path. "disabled" means the claim is held but inactive (counts toward caps, excluded from snapshot since snapshot requires status='verified').
- rejected/expired -> pending: re-claim via POST /v1/domains.

Origin verdict values (buildSnapshot originVerdict): unsafe (drop entry + origin_unsafe operator alert), keep (entry served; if reason != "" it's unresolvable — kept and retried; safe otherwise). Causes: unsafe = address resolves into a deny range (private/loopback/link-local/etc. or GP_OWNED_ADDRESSES) or ValidateOrigin syntax failure; keep reason = cannot resolve / no A/AAAA record (resolver timeout/SERVFAIL/NXDOMAIN — treated as outage, entry kept).

WAF modes: off | detection | blocking (default detection). Per-domain via PUT /v1/domains/{id}/waf.

Node status: active | revoked (default active; revokeNode flips to revoked, dies on next request via nodeAuth status check).

Alert kinds: origin_unsafe, origin_unresolved, snapshot_build_failed, node_stale, waf_config_failed. Alert states: open (resolved_at NULL) vs resolved. Deduped one open row per (kind, subject).

Background job re-checking domain ownership: NO. Ownership is verified once via POST /v1/domains/{id}/verify; there is no periodic re-verification of domain ownership. What IS re-checked: origin addresses are re-validated on every snapshot build (buildSnapshot, invalidated on any write, TTL-rebuilt at most every GP_SNAPSHOT_TTL default 30s). Origin unresolved tracking: origin_unresolved.first_unresolved_at (wall clock, migration 010); alert origin_unresolved raised after GP_ORIGIN_UNRESOLVED_MINUTES (default 60) from first unresolvable build; cleared on safe re-check. The snapshot builder runs on each poll/cache miss — NOT a separate timer job; cadence driven by node polls + TTL.

Stale-node sweep: background goroutine in main.go runs SweepStaleNodes every 2 minutes (fixed interval); threshold GP_NODE_STALE_MINUTES (default 10); opens node_stale alert for ACTIVE nodes with last_seen not null but older than threshold; nodes never connected (last_seen NULL) never alerted. Auto-resolved by next heartbeat.

Domain claim expiry: background goroutine in main.go runs ExpireDomainClaims every hour (live window, no fixed sleeps).

Outbox prune: mailer.Prune at boot and hourly, removes outbox rows/files older than 7 days (dev only).

---

## H. VALIDATION RULES

Hostname (NormalizeHostname, domains.NormalizeHostname): lowercased, trailing dot stripped; not empty; no colons (IPv6 literals/ports rejected); not an IP literal; IDN via golang.org/x/net/idna to ASCII punycode; total <=253 octets; each label <=63 octets, non-empty; not "localhost" or *.localhost; must contain a dot (no single-label); not a bare public suffix; not in GP_SERVICE_HOSTNAMES (-> 403 reserved). Wildcards: rejected (contain "*" which fails idna/label rules — effectively no wildcards). IDN: supported via punycode conversion. Apex or subdomain: both allowed (any registrable non-suffix with a dot). Reserved names: GP_SERVICE_HOSTNAMES + localhost + public suffixes.

Origin address (ValidateOrigin + CheckIP): IP literal or hostname. IP literals and hostnames both range-checked via CheckIP which forbids: 0.0.0.0/8, 10/8, 100.64/10, 127/8 (loopback; test hook GP_TEST_ALLOW_LOOPBACK waives 127.0.0.0/8 only), 169.254/16 (metadata), 172.16/12, 192.0.0/24, 192.0.2/24 (TEST-NET-1), 192.168/16, 198.18/15, 198.51.100/24 (TEST-NET-2), 203.0.113/24 (TEST-NET-3), 224/4, 240/4; v6 ::/8, fe00::/9, fe80::/10, fc00::/7, ff00::/8, 2001:db8/32; plus GP_OWNED_ADDRESSES (IPs exact or hostnames normalized). Numeric IP spellings (decimal/hex/octal/partial quads) detected and refused — never fall through to DNS. Hostname form: [a-z0-9._-], labels <=63, total <=253, not owned. Hostnames are resolved (5s deadline) and every answered IP re-checked; unresolvable name = refusal at create/test time ("cannot resolve"/"no A/AAAA record"); at build time unresolvable = keep + retry (outage, not removal).
Allowed ports: 1..65535 minus PortDeny set {21,22,23,25,110,135,137,139,143,161,389,445,465,514,587,636,691,993,995,1433,1521,2049,2181,2375,2376,3128,3306,3389,5432,5555,5900,5985,5986,6379,6380,11211,27017,27018,27019}.
Allowed schemes: http, https only.
WAF rule ID range: 1..999999. Max exclusions: no cap on array length (only per-ID range). (No explicit max count of excluded_rule_ids found in code — UNKNOWN.)

Password: len 8..128 (validPassword). argon2id m=19456 KiB t=2 p=1 32-byte key 16-byte salt PHC format.
Email: validEmail — one "@", local non-empty, domain contains a dot, <=254 octets, no whitespace. Loose shape only.
Numeric caps: domains per user total default 20 (GP_DOMAIN_MAX), pending default 5 (GP_DOMAIN_PENDING); records per zone default 100 (GP_MAX_RECORDS); user_data <= 32 KiB; record name <=100 chars; record value 1..4096 chars (DB CHECK); TTL 60..86400; priority 0..65535; SRV weight/port ints; CAA flag 0..255; TXT 255 printable chars max; hostname <=253 octets / labels <=63; origin health_path <=512; host_header <=255; node name 1..50; API key name 1..100; 422 condition = any validation failure (unprocessable entity). Auth cap default 100/IP/15min (GP_AUTH_CAP); lockout after 5 (GP_LOCKOUT_AFTER); domain add/verify/origin-test caps per user+IP per 15min (20/20/10 defaults); node poll cap 500/node/15min (GP_NODE_RATE_CAP); snapshot size cap 256 KiB (snapshot.MaxBytes); claim TTL 7 days; verify token 24h; reset token 30m; OAuth state 10 min.

---

## I. WHAT THE API CAN TELL THE UI ABOUT EACH DOMAIN

- ownership verified: YES — status field == "verified" on GET /v1/domains, GET /v1/domains/{id}, GET /v1/domains/{id}/verification.
- certificate issued and its expiry: NO — the API does not issue or track certificates (edge/Caddy handles on-demand TLS; no cert fields in domainRow). UNKNOWN from API.
- first request seen: NO — no first-request field.
- config live on edge nodes (applied generation): PARTIAL — node.applied_version (per node, GET /v1/nodes operator-only) and snapshot_versions generation; the domain itself carries no generation. NO domain-level route reports applied generation.
- WAF mode: YES — waf_mode field on every domain response.
- origin health over time: NO — only on-demand POST /origin/test point-in-time result; no history.
- request counts or traffic stats: NO — none stored/exposed.
- blocked-request counts: NO.
- security events: PARTIAL — operator alerts (origin_unsafe/origin_unresolved per domain hostname) exist but no operator-facing API route to list them (UNKNOWN how console reads them; direct DB).
- change history: PARTIAL — record-level history via GET /records/{rid} (record_changes create/update/delete); WAF change trail via domain_waf_changes (no API route to read it — UNKNOWN); domain-level change history (no route).
- alerts for this domain: PARTIAL — origin_unsafe/origin_unresolved keyed by hostname exist in operator_alerts but no API route lists them.
- which edge nodes serve it: NO — nodes roster is operator-only and not domain-associated; no domain->nodes mapping exposed.

---

## J. OPERATOR

Operator status: decided by GP_OPERATOR_EMAILS env var (comma-separated, normalized lowercase+trim, stored in Server.operators map). Unset => nobody is an operator. requireOperator checks session/API-key principal email against the set; non-operator authenticated => 403 "operator access only"; unauthenticated => 401. No route tells the logged-in user whether they are an operator (GET /api/me returns only id, email — no role/operator flag). Operator routes: POST/GET /v1/nodes, POST /v1/nodes/{id}/revoke. Node data for console: nodeRow {id, name, role (edge|dns), status (active|revoked), last_seen (nullable RFC3339), applied_version (*int64 nullable), created_at}. waf_fallback flag: sent by node in heartbeat (POST /node/v1/heartbeat body), stored as alert waf_config_failed when true (not a node column). stale flag: no column; derived — node is "stale" when active, last_seen not null, older than GP_NODE_STALE_MINUTES (default 10); node_stale alert raised by 2-minute sweep; "stale" not exposed via user API.

---

## K. EMAIL

Emails sent: verify (signup/verify), reset (password-reset-request/reset), welcome (post-verification and post-OAuth link, exactly once via welcome_sent_at guard). Kind field: verify | reset | welcome | test.
Through what: mailer.Sender interface. Default dev driver = outbox: writes every message body to outbox_messages DB table AND ./outbox/<nanotime>-<to>.txt file (no secrets filtering). SMTP driver (GP_MAIL_DRIVER=smtp) stores nothing (no bodies), hands to relay. Outbox driver REFUSES to start under ENV=production.
Sender/link-building config (env var NAMES): GP_MAIL_FROM (From), GP_PUBLIC_BASE_URL (base for "POST it to <base>/auth/..." links — links are raw tokens, no clickable URL in text), GP_SMTP_HOST/PORT/TLS/USER/PASSWORD/INSECURE. SMTP TLS: GP_SMTP_TLS = "implicit" (465), "starttls" (587, default), "none"; auto = 465->implicit else starttls. Credentials refused over unencrypted. GP_SMTP_INSECURE=true accepts self-signed (dev/test only).
Dev-only: outbox driver (files+bodies), outbox prune (7 days), welcome message, GP_TEST_ALLOW_LOOPBACK.

---

## L. IN-PROGRESS / INCONSISTENCIES (code vs docs/api-contract.md or openapi.yaml)

1. reset email text says "The token expires in 24 hours." (internal/server/server.go resetEmailText) but the actual TTL is 30 minutes (newEmailToken purpose "reset" -> "30 minutes"). openapi.yaml says "reset tokens live 30 min". So the email body text is wrong (says 24h).
2. api-contract.md / openapi.yaml may describe statuses/responses; code has some 410s ("claim is <status>, not verifiable", "claim expired, re-claim it") — need to confirm contract matches. Not fully verified line-by-line (UNKNOWN depth of drift).
3. openapi.yaml recordRow requires ttl but PATCH can leave it; code sends stored ttl always — consistent.
4. Domain 422 for snapshot size cap ("within 1024 bytes") — snapshotClaimMargin = 1<<10 = 1024, matches code.
5. WORKING TREE has uncommitted change: M scripts/edge-accept.sh and untracked docs/evidence/b3d-baseline/ — these are test/evidence, not product code; mark as mid-change.

I did not do a full line-by-line diff of api-contract.md vs code (beyond scope / not certain) — flagged UNKNOWN where relevant.

---

## M. OPEN QUESTIONS (frontend will need these; not derivable from code)

1. Does any route expose operator status to the logged-in user? (GET /api/me returns only id, email — no flag.)
2. Is there an operator-facing route to list operator_alerts (origin_unsafe, origin_unresolved, node_stale, waf_config_failed, snapshot_build_failed)? None exists in server routes.
3. Is there a route to read domain_waf_changes (WAF change trail)? None exists.
4. Which backend service reads operator_alerts / domain_waf_changes for the console? UNKNOWN (likely direct DB or a not-yet-built console API).
5. "disabled" domain status: no code path sets it; who/what sets it in production is UNKNOWN.
6. Certificate issuance/expiry per domain: not tracked by API (edge handles TLS) — UNKNOWN how UI would surface it.
7. Time-left reporting on lockout: not exposed (no retry-after/remaining-attempts).
8. Wildcard hostname support: effectively rejected (fails idna/label rules) but not explicitly stated — confirm intent.
9. Max number of excluded_rule_ids: no array-length cap found — confirm whether one should exist.
10. Full drift between openapi.yaml/api-contract.md and handlers was not line-by-line audited.
11. Real Google/GitHub OAuth client credentials are not configured locally (tests use a fake provider) — GOOGLE_CLIENT_ID etc. unset => provider route returns 404 "unknown provider".
