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
