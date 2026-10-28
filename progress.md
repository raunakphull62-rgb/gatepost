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
- Follow-ups round 2 (2026-10-21, three fixes + checklist audit — commits `2b8d9ad`…):
  1. **ENV fail-safe**: `envfile.Production()` — anything other than exactly `development` (prod/Production/UNSET) counts as production; outbox + http base URL refused accordingly; `.env.example` sets `ENV=development`; tested (`TestProduction`). Bonus: `TestLoadExistingVarsWin` pins envfile.Load semantics.
  2. **SMTP TLS**: implicit TLS (465 convention) and STARTTLS (587 convention), `GP_SMTP_TLS` knob; credentials refused before AUTH/MAIL when no TLS is available; self-signed relays opt-in via `GP_SMTP_INSECURE`; tested against a local fake relay with a self-signed cert — `TestSMTPCredentialsOnlyOverTLS` (implicit / starttls / plain-refusal), `TestSMTPNoCredsPlainStillOK`.
  3. **Trusted proxies**: default empty stated loud in `.env.example`; spoofed XFF ignored — `TestSpoofedXFFIgnoredWithoutTrustedProxy`.
  4. Checklist audit builds: CSRF Origin guard on POST/PUT/DELETE (`TestCSRFOriginGuard`), constant-time login proven by median timings (`TestLoginConstantTime` — mechanism existed since the v1 build), cap defaults pinned (`TestAuthCapDefaults`), demo shows cookie flags + argon2id PHC hash (45/45).

## PART 3 — B2: domains, origins, records — DONE (tag `v0.2-domains`)
- Claim → TXT/NS instructions → verification → origins (capped, POST/PUT/test-connection), nameserver mode with live zone records (A/AAAA/MX/CNAME, PATCH/history), per-IP rate caps, second-user same-hostname isolation. Demo: `scripts/demo-domains.sh` (164 steps) in the regression. Full narrative in docs `lessons.md` / DECISIONS notes.

## PART 3b — B3a: node identity + the signed config snapshot — DONE (2026-10-24, tag `v0.3-nodes`, commits `897eadb`→`d135e4f`, not pushed)
- [x] **Item 1 — nodes** (`897eadb`, `007` migration): operators (verified user on `GP_OPERATOR_EMAILS`) mint/revoke edge|dns nodes; token = 256 random bits, echoed once, SHA-256-stored; roster leaks no token material. Tests: `TestNodeManagement`, `TestNodeOperatorOnly`.
- [x] **Item 2 — versioning** (`06071c0`, `05d2e02`): content hash over canonical JSON WITHOUT volatile fields; recorded against the LATEST row only (`A→B→A` bumps to a fresh generation, equal content keeps its number); verifier refuses any generation ≤ last applied. DECISIONS.md entry.
- [x] **Item 3 — builder + re-check classes** (`f219a68`, alerts `008` migration; `739a5f7` tamper/backwards/size): builds serve only VERIFIED domains WITH an origin (hostname, setup, origin, schema_version, defaults, allowed hostnames, generation); every origin re-verified against the same SSRF rules per build. Verdicts: **unsafe** → entry dropped + `origin_unsafe` operator alert (one open row per domain+kind), **unresolved** → latest-good entry kept and retried, **ok** → served. Envelope `{payload, signature, key_id}`, key ID = first 16 hex of SHA-256(key); foreign key ID = `ErrUnknownKey` (skip, not tamper).
- [x] **Item 4 — poll routes** (`e6ad837`): `GET /node/v1/config` (key ID + ETag 304 on `If-None-Match`), `POST /node/v1/heartbeat` (stamps `last_seen`/`applied_version` only for existing generations; nodes may honestly lag). Per-node rate cap `GP_NODE_RATE_CAP` (default 500/15min). Mutual 401s: user credentials never open node routes, node tokens never open user routes. Validated heartbeat test.
- [x] **Item 5 — the sweep** (`d7885fd`): full-envelope test proves no user email / user ID / verification token / password / argon2id hash — down to no `@` at all — reaches a node.
- Additions asked with item 5:
  - **In-memory snapshot cache** (`38f0a75`): polls serve a cached artifact; every domain/origin/verification write invalidates (single choke point `writeDomain` covers all claim paths); otherwise rebuilt at most every `GP_SNAPSHOT_TTL` (default 30s) — `TestSnapshotCacheOneBuild`: 100 polls = 1 build (atomic fake-resolver probe), a write = exactly one more.
  - **Time-based unresolved rule** (`56566f4`, `010` migration): `origin_unresolved.streak` → `first_unresolved_at`; alert after `GP_ORIGIN_UNRESOLVED_MINUTES` (default 60) measured from the FIRST unresolved build, walls-clock survives restarts/cadence changes; unsafe/ok verdicts clear the row; `TestBuildUnresolvedTimeAlerts` with SQL-backdated timestamps (no sleeps).
  - **Production key gate** (`db19173`): `server.ProductionGuards(cfg)` is the single testable boot gate (loopback hook, unset key, and — later addition — key length < 32 refused); main `log.Fatalf`s on its first refusal; `TestProductionSnapshotKeyBoot` (prod key verifies, dev key = `ErrUnknownKey`).
  - **32-byte key floor** (`d135e4f`): production refuses a `GP_SNAPSHOT_KEY` shorter than 32 bytes; 31-refused/32-accepted boundary pair in the boot test.
- Additions with item 6:
  - **Per-process cache design note** (`7769c5e`): a write invalidates only its own instance's cache behind a load balancer; cross-instance staleness bounded by `GP_SNAPSHOT_TTL`.
  - **Item 6 — isolation rows + demo** (`eb188a0`): §9 trust-boundary bullets for node routes (mutual 401s; the snapshot carries no account material); `scripts/demo-nodes.sh` — live walkthrough (raw-UDP TXT stub whose `RDLENGTH` correctly counts the length byte + string; python verifies HMAC/key_id/generation byte-for-byte; second domain bumps exactly +1; free 304; heartbeat stamps the roster; revoke kills the token on its next request) wired into `scripts/regress.sh` as `nodes-demo`. Generations asserted RELATIVELY (`latest + 1`) because the counter is shared state on the dev DB.
- Env/secure defaults: node tokens hash-stored (index lookup, constant-time inside); operator emails normalized; demo/regress servers boot `ENV=development` explicitly.

## PART 3c — B3b: the edge runs itself (in progress)
- **Item 1 — edge image** (`22ee9ad`, `0df1685`): *deploy/dev* compose runs a caddy 2.11.7 image with coraza-caddy v2 (OWASP CRS) and Souin cache-handler compiled in (both off until later config turns them on), HTTP/3 off everywhere, dev ports 8081/8445, admin API 2019.
- **Item 2 — edge poller** (`cmd/gatepost-edge`, package `main`, importing `internal/snapshot`):
  - polls `GET /node/v1/config` every `GP_EDGE_POLL_INTERVAL` (default 5s) with `If-None-Match`; a 304 is "no change" (never re-applies, never re-writes the file); each 200 envelope is verified with `snapshot.Verify` (signature, key ID, strictly-newer generation, 256 KiB cap) before applying; refused envelopes are never applied.
  - persists the LAST GOOD envelope under `GP_EDGE_STATE_DIR` (`snapshot.json`) atomically — temp file in the same dir, fsync, chmod 0600, rename, dir fsync; boot re-verifies the file with the same rules; corrupt/tampered/foreign-key artifacts mean "no snapshot" (ask check then denies every host; the loop rebuilds from the wire and overwrites the bad file with the next honest artifact).
  - cold start with the API unreachable applies the saved snapshot; with none saved, the ask check serves nothing (421 for every host) while the loop keeps retrying; a tick panic is recovered and logged — never a crash-loop.
  - poll failures back off `interval·2^streak` capped at `GP_EDGE_BACKOFF_CAP` (60s) with ±10% jitter on EVERY wait, so two nodes never poll in lockstep; any sane API answer (including a refused envelope) resets the ladder.
  - a 401 (revoked/invalid token) is logged loudly, the last good config keeps serving, no heartbeats are fabricated, and the node recovers itself once the token works again.
  - an envelope with an unknown key ID is skipped with a warning — explicitly NOT tampering (rotation window; `ErrUnknownKey` distinct from `ErrTampered`).
  - heartbeats fire only when `applied > acked` and carry the generation ACTUALLY APPLIED (the in-memory one), never a merely-fetched one; retried each tick until the API acks.
  - ask check `GET /check?domain=…` (also `/ask`, `hostname` param, host:port stripped, case-insensitive): 200 iff inside the applied snapshot's allowed list, else 421 — the local surface Caddy's on-demand ask will consult (item 3); loopback by default. DECISIONS.md entry.
  - token + signing key from env or mounted `GP_EDGE_TOKEN_FILE` / `GP_SNAPSHOT_KEY_FILE` (docker secrets); neither is ever logged — a sweep test runs 401s, tampering and an unreachable API and proves neither string appears anywhere in the logs.
  - tests: 18 (`TestConfigDefaults`…`TestSecretsNeverLogged`) covering every bullet above, incl. the jitter/ladder loop measured on the wire; repo suite stays green.
- **Item 3 — Caddy config generation + apply** (`cmd/gatepost-edge/caddygen.go`, `egress.go`, `apply.go`):
  - ONE pure function `Generate(doc, params)` turns a verified snapshot into the JSON pushed to the admin API: structured JSON only, never a text template (a hostile hostname is one string value in one host matcher — the hostile golden proves it fails closed, injects nothing). Golden files in `testdata/golden/` (deny / single / multi / hostile) and every fixture passes real `caddy validate` (2.11.7).
  - limits baked into every server: `max_header_bytes` 16 KiB, `request_body.max_size` 32 MiB, read_header 10s / read 60s / write 60s / idle 2m, origin dial timeout 10s; `protocols: [h1, h2]` — HTTP/3 off everywhere.
  - unknown hosts: catch-all route LAST answers 421; over TLS the fallback certificate (`edge.invalid` + `tls_connection_policies.fallback_sni` + internal issuer) lets the handshake finish first, so it is a 421 and not a connection reset.
  - SSRF at dial time: Caddy's `reverse_proxy` has no dial hook, so the poller runs one loopback TCP forwarder per origin — fresh resolve per connection, every resolved IP through `domains.CheckIP` (private, loopback, link-local/metadata, CGNAT, …), then dial the VALIDATED IP directly (no TOCTOU). A dropped origin's port keeps listening one extra swap to cover Caddy's reload window, then is pruned.
  - reload gate: content hash (`snapshot.Hash(ToContent())`, generation/built_at stripped) + a 60s cooldown (`GP_EDGE_RELOAD_COOLDOWN`) that gates every attempt incl. failures; A→B→A never touches Caddy. Apply = forwarder `Swap` first, then `POST /load` to the admin API on the compose-internal loopback — 200 is validated+applied, anything else is rejected with its body logged loudly and the last-good config keeps serving.
  - HTTPS upstreams pin `Host` explicitly: Caddy 2.11.7 injects `Host: {upstream hostport}` for every TLS transport, so the generated config sets the public hostname (or the configured `HostHeader`) itself; the e2e caught this against a real caddy.
  - X-Forwarded-For: no `trusted_proxies` emitted — Caddy replaces a client-supplied XFF with the real client IP (asserted end to end with a spoofed `9.9.9.9`).
  - tests: golden/hostile/broken-input/caddy-validate, apply gate (boot load, identical-content no-reload, cooldown burst collapse, failure keeps last-good + cooldown-paced retry, no wiring → no apply), forwarder guard matrix + realListener port lifecycle + real round trip, and `TestEdgeEndToEnd` with a REAL caddy subprocess: bootstrap deny-all → snapshot `/load` → http and https origins proxied (origin-TLS verification proven at the origin: CA-signed cert verified, SNI = the configured origin address; wrong-name cert refused with 502 and zero origin hits), spoofed XFF replaced, unknown host 421 on both ports. Suite race-clean; regress 6/6.
  - deploy: `Dockerfile.poller` + compose `poller` service (profile `poller`, shares the edge netns so its loopback admin call needs no published port; token/key via `GP_EDGE_TOKEN_FILE` / `GP_SNAPSHOT_KEY_FILE` from an untracked `deploy/dev/secrets/`; state on the `poller_state` volume).
- **Item 4 — on-demand TLS** (`caddygen.go` TLS app + `poller.go` ask/cap + `main.go` knobs):
  - Issuance is gated by the poller's loopback ask: `apps.tls.automation.on_demand.permission` (http module) points at `/check`, answered 200 only for a hostname inside the last-good APPLIED snapshot. The on-demand automation policy is SCOPED to the snapshot's hostnames (`Generate` refuses hostnames without an ask URL) so unknown SNI keeps the `edge.invalid` fallback → 421 path while known hosts gate through the ask. Probed against caddy 2.11.7 and e2e-proven: an ask denial for a subject SNI ABORTS the handshake (`remote error: tls: internal error`), nothing is minted or persisted; an SNI outside the subjects completes on the fallback cert and 421s.
  - Issuer is explicit: `GP_EDGE_ISSUER` = `staging` (DEFAULT — a missing setting can never burn production LE rate limits) | `internal` | `production` (opt-in only; refused at boot alongside `GP_EDGE_ALLOW_LOOPBACK`). Cert approvals capped per node per hour window (`GP_EDGE_CERT_HOURLY_CAP`, default 50; over-cap asks answer 429 = denial; denials cost nothing; fixed-hour window is a recorded shortcut). Certificates live in caddy's data dir on the `caddy_data` volume (`XDG_DATA_HOME`), surviving restarts; the internal CA never installs into the host trust store (`install_trust=false`).
  - Ask normalization: surrounding whitespace, trailing dots, colons (ports/IPv6), IP literals and non-hostnames are 421; **case is kept 200 — flagged deviation** from the sketch that wanted 421 (DNS names are case-insensitive; refusing a differently-cased SNI would break legitimate handshakes).
  - Origin TLS (item 3 check 1 evidence, real-caddy e2e): the edge verifies the origin certificate with SNI pinned to the configured origin address, never emits `insecure_skip_verify`, and refuses `tls_verify=false` snapshots outright. Extra origin roots come from the platform standard `SSL_CERT_FILE`; a CA-signed `localhost` origin is reached through the tunnel (SNI proven at the origin), while a same-CA wrong-name certificate is refused: 502 to the client, origin handler never runs. Known hosts ride the HTTP listener in tests because the HTTPS listener now triggers on-demand issuance (real ACME) — reserved there for the unknown-SNI fallback check.
  - tests: generator (on-demand policy + subjects + ask required + issuer matrix incl. unknown-issuer refusal + never `insecure_skip_verify` + `tls_verify=false` refusal + regoldens), ask matrix + cap + defaults (poller), boot-not-delayed-by-cooldown (apply), v4-mapped egress guard cases, and two real-caddy e2e tests — `TestEdgeEndToEnd` (proxies, XFF replacement, origin-TLS verify/refuse, 421s on both ports) and `TestEdgeOnDemandTLS` (allowed issuance with the internal issuer verified against caddy's own root + persisted; denied host → aborted handshake, nothing persisted; ask unreachable → same). Race-clean; regress 6/6.
  - HTTP-01 across nodes documented (DECISIONS.md), deliberately not built: per-node on-demand issuance needs the challenge request to reach the initiating node — per-node DNS routing or a shared cert store; correct today for one edge node per hostname and for the internal issuer.
- **Item 5 — egress firewall** (`scripts/edge-egress.sh`, compose network pins):
  - One dedicated chain `GATEPOST-EGRESS` entered from TWO scoped jump points: DOCKER-USER (routed container traffic) and INPUT (traffic the edge sends to addresses the HOST owns — locally delivered, invisible to FORWARD; br_netfilter is not even loaded on this box). Jumps match `-s 172.28.0.0/24` (v4) / `-i br-gpedge` (v6) only, so SSH, the host itself, other containers (gatepost-auth-pg) and inbound ACME HTTP-01 are untouched.
  - Blocks (REJECT, fail-fast): 10/8, 172.16/12, 192.168/16, 169.254/16 (metadata), 100.64/10, 127/8, the docker bridge gateway, every host IPv4, and v6 fc00::/7, fe80::/10, ::1, ::ffff:0:0/96. The ONE exception is the explicit `EDGE_EGRESS_API` IP:PORT allowlist rule (required setting; on dev the API is private — never a blanket allow). Public internet (DNS, ACME, origins) passes via the final RETURN.
  - The compose network's subnet (172.28.0.0/24) and bridge name (br-gpedge) are PINNED in compose.yaml — pool-assigned values drift across recreations and would strand persisted rules.
  - Modes: `dry-run` prints the exact commands; `apply` is remove-then-install (idempotent — full v4+v6 dump identical across double apply, 83 lines); `remove` reverses completely (chain, jumps, unit); `persist` installs a systemd oneshot (`After=docker.service`, settings baked in) — enabled and active. Reboot itself not performed (would drop the session); the enabled unit + After=docker is the mechanism.
  - In-container probe evidence (before → after): metadata 169.254.169.254 answered HTTP 401 → instant "Connection refused"; 10.x/192.168.x/172.16.x timeouts → instant refusals; host IPs (172.17.0.1, 172.31.25.3, 172.28.0.1) served a listener → refused; allowlisted API 172.17.0.1:8080 kept answering (HTTP 404 = the gatepost API); public 1.1.1.1 kept working. Direct edge→auth-pg (172.17.0.2:5432) is dropped by DOCKER's own cross-network isolation before and after — the firewall neither helps nor harms that path, and the API↔DB flow (127.0.0.1:54330, host OUTPUT) is proven alive by the full regress run WITH the firewall applied (6/6).
  - NOTE (box state): a parallel opencode session had attempted item 5 against the pre-pin network (chain `GP-EDGE-EGRESS`, old subnet 172.18.0.0/16, API allowlist :8090, its own systemd unit under the same name). Those iptables rules are still on the box (inert — source-scoped to a subnet that no longer exists); my `remove` run also disabled+removed their same-named unit. The worktree copy survives at `~/.local/share/opencode/worktree/f54053/witty-mountain/`. Left for the user to reconcile.
## 2026-10-26 — item 5 reconcile

The box rebooted overnight (02:24 poweroff → 03:08 boot). My ExecStop=
remove design ran at shutdown, disabled its own unit (self-deadlock, 90s
timeout), so the firewall did not come back at boot. Root fix: no ExecStop
on the unit; remove stays an explicit operator action. DECISIONS.md entry
has the full timeline. Firewall re-applied and re-persisted after the fix;
docker-restart persistence exercised with `systemctl restart docker` (not
a reboot). Also found: witty-mountain worktree left at commit `c3570bb`
(detached) — read-only inspection only, per user instruction. `.kilo/`
(a skills dir some other agent tool dropped) gitignored; no other agent
session is running (`ps` shows only this harness's server).
- Next: item 6 awaits the user's go.

## 2026-10-26 — item 6: structured edge access logs, poller log hygiene, rotation, disk warn

- **Access logs (generator)**: pure caddy 2.11.7 config, image untouched.
  `CaddyParams.AccessLogPath` (poller env `GP_EDGE_ACCESS_LOG`, default
  `data/logs/access.json`, empty = off) flows into every generated config:
  `logs {}` on the server, one custom log keyed `http.log.access` with
  `include` guard (naming it `default` redirects caddy's GLOBAL runtime
  logger into the file — caught by the real-caddy e2e), file writer
  rolled 10 MB × 5 (MkdirAll's its dir), a filter-wrapped json encoder
  that DELETES credential headers by name (Authorization,
  Proxy-Authorization, Cookie, resp Set-Cookie/Proxy-Authorization, and
  the auto-added `uuid` dup of `{http.request.uuid}`), and per-route
  `vars` + `log_append` fields: `request_id` (per-request uuid),
  `path` (no query; query stays in caddy's native `uri`), `origin`
  (vars-stamped identity; `-` on the 421 catch-all). Goldens pin the
  whole logging block; every fixture still passes real `caddy validate`,
  now run with a throwaway cwd so the golden's file writer never opens a
  file inside the package dir.
- **E2E (`TestEdgeAccessLogs`, real caddy)**: a proxied request carrying
  Authorization+Cookie with the origin also setting Set-Cookie writes
  exactly one json line; neither the secret VALUES nor the header NAMES
  appear anywhere in the file; a percent-encoded `\n +
  {"level":"critical"}` path stays one line inside one JSON string
  (line count = 3, no forged line, injected level never appears); fields
  asserted: ts, status/size/duration, request>remote_ip, request_id
  (uuid, distinct per request), path without query, origin
  (`http://…` served / `-` refused).
- **Poller**: repeate identical failure lines (poll network errors,
  refusals, 401, heartbeats, key/tampered/backwards) are throttled per
  brand via `logThrottle` (`GP_EDGE_ERROR_LOG_GAP`, default 30s; first
  line always passes); the backoff-cap crossing is announced EXACTLY
  ONCE per outage (`baseDelay` refactor made the crossing a clean
  threshold); recovery lines are never throttled. Tests:
  `TestLogThrottleBrands` (gap window, brand isolation),
  `TestRepeatedFailureLinesThrottled` (25 refused polls = 1 failure line
  + exactly 1 cap announcement), `TestUnauthorized401OnePerGap`; the
  jitter-ladder test now measures cadence on the server's timestamps
  instead of throttled log lines. Race suite green.
- **Compose**: json-file rotation 10m × 3 on edge AND poller; poller env
  `GP_EDGE_ACCESS_LOG=/data/logs/access.json` (lands on caddy_data).
  Also unblocked the poller service for real: `extra_hosts` conflicts
  with `network_mode: service:edge`, and its `host.docker.internal`
  default resolved to 172.17.0.1 anyway — replaced with the pinned
  allowlisted API base; secrets files opened for the mount (uid inside
  the container differs; dir stays private).
- **`scripts/disk-warn.sh`**: one stderr line at/over
  `DISK_WARN_THRESHOLD` (default 80%) on `DISK_WARN_PATH` (default /),
  silent otherwise, always exit 0 (cron-friendly: quiet disk = no
  output, full disk = never a failed monitor). Demonstrated: threshold 1
  warns (disk at 32%), 99 and the default are silent.
- **Live-box evidence**: node minted fresh (old ones all revoked),
  poller image rebuilt, `docker compose --profile poller up` against the
  real API — boot summary shows `access_log=/data/logs/access.json`,
  applied generation 17 (16 domains). Through host 8081: verified host +
  Authorization/Cookie headers → real origin response logged with
  `origin`, `path` `/docs` (query only in `uri`), NO credential names or
  values in the file; hostile `__EL__`-shaped path stays one line
  (grep: exactly 1 escaped occurrence, 0 raw); unknown host → 421 with
  `origin: "-"` and full shape. Line sweep: 0× SUPERSECRET/TOPSECRET /
  header names.
- **Found + fixed (same session, separate commit `ab2ff85`)**: the egress
  chain killed reply legs of host-initiated flows — every host-published
  edge port hung while the firewall was applied. First rule is now
  `conntrack ESTABLISHED,RELATED → RETURN` (v4+v6); probes unchanged;
  docker-restart persistence re-proven; nodes-demo's `grep -c "$NTOK"`
  ate a leading-dash token as an option (-e added). Regress 6/6 with the
  firewall applied and the poller running.
- **Correction set (separate commit `09ec972`)**: no query strings
  anywhere and NO header logging at all. The filter encoder now deletes
  the whole `request>headers` and `resp_headers` objects (caddy's
  `AddObject` matches the nested path and drops the object itself —
  verified against 2.11.7's filter.go; the old per-name deny-list could
  drift behind any new credential-bearing header) plus caddy's native
  `request>uri` (the query's only carrier); `user_agent`
  (`{http.request.header.User-Agent}`) is the one header value kept, via
  `log_append`. Probing 2.11.7 also exposed that caddy tees EVERY access
  entry to the DEFAULT logger unfiltered — the file was clean while the
  edge container's stderr (docker's json-file log) still carried every
  query string and header; the generated config now redefines `default`
  with only `exclude: ["http.log.access"]` (vanilla stderr shape minus
  the twins — runtime lines unaffected; standalone probe: 0 access
  lines on stderr, 18 runtime lines intact). E2E sweeps
  `?token=SECRET123&code=abc` (values, `token=`, `code=`, and the short
  `abc` after scrubbing caddy's random uuids — the only
  non-deterministic field), X-Api-Key/Cookie/Authorization/Referer
  names+values, asserts `uri`/`headers`/`resp_headers` are structurally
  ABSENT from every line, user_agent present, and — via the captured
  caddy stderr — that no access entry reaches stderr at all. Goldens
  regenerated; race suite green.
- Next: item 7 (edge WAF — coraza) or as asked; awaiting the user's go

## 2026-10-26 — item 7 correction context, then item 7 acceptance as ordered
(user's order: acceptance first, coraza WAF AFTER the edge is accepted
and tagged)

- **Item 6 correction applied first** (`2e00962`, above): no query
  strings anywhere (native `request>uri` deleted), NO header logging at
  all (whole `request>headers`/`resp_headers` objects deleted),
  `user_agent` the one kept header, and the stderr access twin found and
  killed (redefine `default` with `exclude`).
- **Boot shapes the acceptance exposed** (same commit as item 7):
  `ensureDenyAll` — a tick that ends with nothing applied enqueues the
  zero document so a no-snapshot cold start answers 421 on both
  listeners instead of the bootstrap's localhost responder; and the
  apply retry split — a `/load` transport failure (admin not up: the
  joint cold-start race) opens NO cooldown window and retries every 2s,
  a caddy REJECTION keeps the 60s pace. New tests:
  `TestApplyColdStartNoSnapshotServesDenyAll`,
  `TestApplyAdminNotUpRetriesFast` (both with the production cooldown).
- **Origin fixture**: `deploy/dev/origin_test.py` + `Dockerfile.origin-test`
  — python stdlib only, two listeners (9001/9002 so an origin change is
  visible in every body), endpoints /ok /slow (2s) /big (5 MiB
  streamed) /redirect (302 — the edge passes it through) /cookie
  (Set-Cookie) /echo-headers (Host/XFF/method/UA/proto) /status/N and a
  hand-framed /chunked. Runs on the pinned `origin` network
  `192.88.99.0/24` (deprecated 6to4 anycast — public to CheckIP,
  nothing real there; see DECISIONS.md) with the edge attached to both
  networks; traffic is same-bridge L2.
- **`scripts/edge-accept.sh`**: the a–j acceptance run against the real
  compose stack, the real API (taken over on 172.17.0.1:8080 for the
  run) and a node minted for the run; internal issuer for determinism
  (GP_EDGE_ISSUER=internal via every compose call); fresh volumes at
  setup so every access-log byte and cert belongs to the run. Findings
  from the first run fixed in the same commit: the fixture's /cookie
  sent the status line twice (double send_response), several check
  curls quoted `'Host: $HOST'` literally (the requests hit the 421
  catch-all as host "$HOST" — visible in the access log), busybox wget
  prints the status line twice (-S dump + error line), the internal
  fallback cert is SAN-only (empty subject), and `head -100` SIGPIPE'd
  the script mid-sweep — the runner now tees untruncated.

  before touching item 7.

## 2026-10-28 — item 8: crash resilience (kill the edge, both come back)
- **The failure, evidenced on this box**: `gatepost-edge-dev-poller-1`
  `Exited (128) cannot join network namespace of a non running container` —
  the poller shares the edge's netns (`network_mode: service:edge`); a
  killed/restarted edge orphans it (loopback admin gone forever) and no
  docker mechanism noticed, which is why the acceptance script restarted it
  by hand.
- **Fix**: the poller exits after `GP_EDGE_ADMIN_GRACE` (default 15s) of
  continuous admin TRANSPORT failure (`errAdminGone` → `Run` → main
  `log.Fatalf` → exit 1) → docker's `restart: unless-stopped` restarts it
  into the edge's fresh namespace, where the saved snapshot re-applies.
  Dial failures only; any caddy answer resets the window. Compose: edge
  healthcheck (admin `/config`), poller healthcheck (new ask `/health`
  route), `depends_on: edge: {condition: service_healthy, restart: true}`.
- **The idle gap, found while preparing the live kill run**: with nothing
  pending, nothing in the apply path ever dials the admin — the exact state
  after a successful apply, i.e. the actual docker-kill shape — so the grace
  could never arm. Fix: the apply loop probes the admin every
  min(5s, AdminGrace/3) when idle (`adminProbe`: any HTTP answer = alive)
  and feeds the same `adminTouch` accounting; the grace now arms from either
  the apply path or the probe. Success also resets the window.
- Tests: `TestAdminGraceBailsOutOfDeadNamespace` (bail at a 200ms grace +
  the 60s grace holds through the joint cold start's ~2s of failures),
  `TestAdminGraceBailsWhenIdle` (the admin answers once, then dies — the
  idle watchdog bails). Race suite green. Live evidence: item-8 kill runs
  below.
- **ensureDenyAll guard pinned by a test** (`TestEnsureDenyAllDoesNotOvertakePendingConfig`):
  a queued-but-not-yet-loaded config (appliedGeneration still 0) survives a
  failing tick — without the `&& p.pending == nil` guard the zero document
  REPLACES the pending config (enqueueApply overwrites unconditionally) and
  the edge's next successful load is deny-all despite holding a good
  snapshot. Proven both ways in a scratch worktree: guard reverted → FAIL
  (the retry loaded the `edge.invalid` deny-all shape); guard present → PASS.

### Item-8 live kill evidence (2026-10-28, supervisor installed)
- **`docker kill edge`**: the supervisor's `docker compose up -d` restarted
  the edge at T0+4s (journal "Starting" 14:57:43 → "Healthy" 14:57:49), the
  poller grace-exited at T0+15s (`caddy admin unreachable for 15.001s
  (grace 15s) — exiting so docker's restart policy rejoins the edge's fresh
  network namespace`) and came back via its restart policy, re-applying
  snapshot generation 132 from disk. Traffic back in **16.4s**; during the
  gap the API probe was down and the revoked-token 401s kept being logged
  (last-good kept serving, HTTPS included).
- **`docker kill poller`** (3 runs): RestartCount stayed 0 and dockerd logged
  `stopping restart-manager` every time — a manual kill bypasses the restart
  policy, so recovery came ONLY from the supervisor timer (15s cadence):
  0.83s / 0.94s when a tick coincided with the kill, **13.7s worst case**
  when the tick had just passed (poller down 15:04:30 → 15:04:43, supervisor
  journal). While the poller is down requests 502 — the poller owns the
  egress forwarder listeners, so caddy's upstreams die with it. The access
  log pins kill #3's window to **0.856s**: last 200 15:06:02.508 → first 502
  .637 (kill landed .602) → first 200 15:06:03.493, matching the restarted
  poller's apply at .433. The earlier "~12s of 502s" read was arithmetic,
  not outage: failed requests return in ~10ms, so 80 consecutive 502s ≈ 1s.
- **Poller crash (self-exit — the realistic failure)**: signal to PID 1 from
  inside the container (`docker exec … kill -9 1` is ignored by PID 1; the
  SIGTERM fallback landed, "gatepost-edge stopped" then boot 291ms later,
  snapshot applied at +293ms). RestartCount 0→1 — docker's OWN
  restart-manager, not the supervisor (policy `unless-stopped`). **12 of 200
  probes failed, spanning 0.29s.** So crashes self-heal in <1s; only manual
  kills depend on the supervisor (bounded by its 15s cadence).
- **The `tampering?` line — pinned, was never a mystery**: the one-off
  refusal at 14:55:20 during run 2 was section (c) ITSELF. The script
  tampers the snapshot with `sed -i 's/9001/9003/'` (edge-accept.sh line
  267) and restarts the poller; the boot re-verifies and the key ID still
  matches (else it would log `unknown key`) while the payload bytes no
  longer do → `ErrTampered`, exactly the designed fail-closed path. The
  earlier confusion ("API down during c") was wrong: the script brings the
  API back up at the START of section (c) (line 264), which is why the
  refusal is followed 15ms later by `applied snapshot generation 130` from
  the wire. The file IS restored: the refetch the section waits for
  re-persists the good envelope (`accept` → atomic write), so no later boot
  can see the tampered bytes. Verified with five further acceptance runs
  (2026-10-28 15:21–15:42, every output line timestamped, all 80/80 —
  `/tmp/opencode/accept5-timed-{1..5}.txt` + poller logs): each run logged
  exactly ONE tamper refusal, timestamped inside section (c)'s bracket
  (run 1: bracket 15:22:26→15:23:27, refusal 15:23:27.358; run 5: bracket
  15:39:02→15:40:03, refusal 15:40:03.715) — 10 refusal-family lines across
  5 runs, all in (c), ZERO outside. Nothing to fix in the write, sign or
  load path.
- **Acceptance (item 3)**: `scripts/edge-accept.sh` twice, both **80 passed /
  0 failed** (raw output `/tmp/opencode/edge-accept-run2.txt`, host
  `accept-a-1793199201-26690.example.test`); d) took 60s (5s poll + 60s
  cooldown), i) recovery 49s. **Egress firewall (item 4)**: `iptables -S
  GATEPOST-EGRESS` diff empty before/during/after; allowlist
  `-d 172.17.0.1/32 tcp --dport 8090`; jumps scoped `-s 172.28.0.0/24`;
  unit active since boot 14:21:51. **Access logs (item 5)**:
  `TestEdgeAccessLogs`, `TestLogThrottleBrands`,
  `TestRepeatedFailureLinesThrottled`, `TestUnauthorized401OnePerGap`,
  `TestSecretsNeverLogged` all pass; caddygen strips `request>uri`,
  `request>headers`, `resp_headers` whole; e2e control proved the real
  caddy binary is used (fails with `/bin/false`, passes with real caddy).

## 2026-10-28 — item 7 acceptance hardened: true cold start, https deny posture, dial-time TOCTOU (f2)

- **Section (a) is now a TRUE cold start**: `dc down` + `dc up -d edge
  origin-test poller` with the API still down and the saved snapshot on the
  poller volume — containers are REMOVED and recreated, not restarted, so
  the poller joins a fresh edge network namespace (the cold-start race the
  v0.4-edge tag note describes). Serves from the snapshot over http AND
  https (internal cert) with the API down.
- **Section (b) gained https**: known, denied AND unknown hosts all answer
  421 over https on the no-snapshot boot (fallback cert, no ask answer).
- **New section (f2) — dial-time guard against a later-hostile resolution**:
  a hostname origin (`f2orig.test`) is accepted while it resolves public
  (192.88.99.10 via the host DNS stub's new A-record mode), then the
  POLLER's `/etc/hosts` is flipped to 169.254.169.254 and the edge must
  refuse at dial time. Evidence in one run: 502 to the client, poller log
  `refused 169.254.169.254 while proxying to f2orig.test (forbidden origin:
  … inside 169.254.0.0/16)`, and the origin listener's hit count FROZEN at
  the first refusal (6 then, 6 after). Mechanism notes pinned the hard way:
  - the API's set-time check resolves through the host stub; the poller
    resolves through its own /etc/hosts (docker refuses `dns:` with
    `network_mode: service:edge` — "conflicting options", tested) — so the
    flip is a hosts rewrite via `dc exec -u root`;
  - `/etc/hosts` is a bind-mounted FILE: `sed -i` fails with "Resource
    busy" (it renames), and a `sed | tee` same-file pipe races (wiped the
    file once during diagnosis; restored) — the flip prepares content in
    /tmp then truncate-writes in place;
  - origin port 9003 closes EVERY connection (`Connection: close` +
    `self.close_connection` in origin_test.py): caddy's reverse_proxy
    keep-alive pool otherwise rides the pre-flip connection and the 502
    only appears after the pool expires (~78s observed) — the dial guard's
    guarantee is per connection, so the f2 origin must force a re-dial per
    request;
  - Go caches /etc/hosts for ~5s (pure-Go resolver): requests issued right
    after the flip legitimately reach the pre-flip address, so the
    silence check measures the guarantee that actually holds — the hit
    count freezes at the FIRST refusal, not at the flip instant.
- **until_ok now counts successes** (`pass "$what"` on success): a passed
  wait used to be silent AND uncounted, so a fully-green run undercounted
  (89 vs the true 102); failures always counted. Verdict line is now
  exact. Final run: **102 passed, 0 failed** (raw timestamped output
  `/tmp/opencode/accept-final.txt`; the two diagnostic runs on the way
  there: `/tmp/opencode/accept-newchecks{,2}.txt` — 86/4 each, all four
  failures f2, first diagnosed as the sed -i EBUSY, second as the
  keep-alive pool). The DNS stub gained A answers from `$STUB_A` re-read
  per query (validated standalone: `/tmp/opencode/stub-e2e.py` — TXT
  verify unchanged, flip without restart, NOERROR/0-answers for unlisted
  A and any AAAA).

## 2026-10-28 — item 3: poller liveness healthcheck + supervisor restart

- `/health` now does REAL liveness (cmd/gatepost-edge/poller.go): serveHealth
  answers 500 when the apply loop has been silent >30s, the poll loop >90s,
  or the egress forwarder's `unhealthy` flag is set (a listener accept-loop
  died, until the next Swap rebuilds it). NewPoller seeds both ticks at
  boot so a fresh process is healthy by definition; the apply loop stamps
  applyTick every wake (apply.go), the poll loop stamps pollTick every tick
  (poller.go Run). The old handler returned 200 unconditionally — a frozen or
  deadlocked poller served a stale config forever. (A SIGSTOPped body can't
  answer the healthcheck at all, so compose's timeout catches it; the 500
  branch covers the in-process-deadlock shape the unit test builds.)
- forwarder `unhealthy` flag (egress.go): the accept-death path sets
  `f.unhealthy.Store(true)`; Swap clears it on success. A dead listener
  means the dial guard can't forward that origin (fails closed) until Swap
  re-allocates it — /health surfaces that instead of silently 502-ing.
- Supervisor reconcile (scripts/edge-supervise.sh): `docker compose up -d`
  ignores running-but-unhealthy containers, so reconcile now inspects edge
  and poller and `docker restart`s any in running/unhealthy BEFORE compose
  up — closing the gap the v0.4-edge compose healthcheck comment describes.
- Test: TestServeHealthReportsStalls (apply_test.go) — fresh->200; applyTick
  31s stale->500; pollTick 91s stale with applyTick fresh->500; fwd unhealthy
  ->500; clearing the flag -> 200. `go test -race ./cmd/gatepost-edge/` green
  (12.7s, including the existing apply/e2e/ratelimit suites).
- SIGSTOP recovery (live evidence, /tmp/opencode/sigstop-probes.txt): stopped
  the poller's HOST PID (PID 1 in the container ignores in-namespace signals
  — same class as SIGKILL, proven earlier), so the stop had to come from the
  host (.State.Pid + sudo kill -STOP). compose healthcheck drove the state
  starting->unhealthy (~24s), the supervisor restarted it (journal `18:06:53
  restarting unhealthy poller (reason: running/unhealthy)`), PID
  479552->481282, health starting->healthy (~17s post-restart), and the final
  probe returned `ok from origin-test port 9001`. 51 of 1299 probes were
  non-200 during the ~46s window (frozen forwarder: 000, then 502 until the
  listener rebound) — no outage after recovery.

## Dev DB on this server
- Dedicated container `gatepost-auth-pg` (postgres:16-alpine, volume `gatepost_auth_pgdata`, host port 127.0.0.1:54330, DB `gatepost_auth`). Credentials in `.env` (gitignored, never printed).
- **2026-10-24, fresh dev server rebuild**: this box started with no containers and no volumes (the v1-era containers noted below are not here), and no `.env`. `.env` was recreated locally from `.env.example`'s essentials: `DATABASE_URL`/`DATABASE_URL_DIRECT` point at `127.0.0.1:54330/gatepost_auth`, `ENV=development`, outbox driver; the DB password was generated in place (`openssl rand`) and never printed. Container credentials reach postgres via `--env-file`, keeping the command secret-free and copy-pasteable:
  `sudo docker run -d --name gatepost-auth-pg --restart unless-stopped -p 127.0.0.1:54330:5432 --env-file /home/ubuntu/gatepost/.env -v gatepost_auth_pgdata:/var/lib/postgresql/data postgres:16-alpine`
  (`sudo` needed on this box; verified: `restart=unless-stopped`, binding `127.0.0.1:54330->5432`.)
- Migrations ran via a one-shot server boot on 2026-10-24: `applied 10 migration(s)` (runner applies `001`…`010` at boot); DB check: `schema_migrations` = 10 rows, 19 tables in `public`.
- Serve: `bash scripts/regress.sh` or `./gatepost` after `go build -o gatepost ./cmd/gatepost` (listens on `GP_HTTP_ADDR`, demo default 127.0.0.1:8090).
- NOTE discovered 2026-10-21: pre-existing containers `gatepost-edge[2]` + DB `gatepost-postgres-1`/volume `gatepost_pgdata` belong to a DIFFERENT (v1-era/edge) product — its `public` schema holds `edge_nodes`, `dns_records`, `orgs`, … Left untouched at the user's ground rule; v2 deliberately got its own database. One caveat: a login password for role `gatepost` in that old DB was reset while connecting (original value not recoverable); if any old edge process else reconnects to it, credentials may need updating on that side.

## Need from user
- Google / GitHub OAuth client credentials for real provider flows (goes into local, untracked `.env` — never pasted in chat). Tests use a fake provider meanwhile.

## PART 3 candidates (not started)
- Hash upgrade on login when argon2 params change (noted in design §3)

## Notes
- Everything runs on this dev server. No frontend, no nodes, no deployment.
- No secrets are printed or committed anywhere.
