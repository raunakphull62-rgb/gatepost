# Decisions review — B3a (node identity + signed config snapshot)

Every decision I made that was **not** in your prompts: what I decided, the
default, where it lives, whether env can change it, and why. Grouped, with
the obvious ones left out (everything you specified verbatim — the cache
design, the 60-minute rule, the 32-byte boundary, the 31/32 test pair, the
per-process design note, the demo walkthrough list, the tag). Nothing is
changed; this file is the only new artifact — it is not committed.

## Security

| Decision | Default | File / commit | Env? | Why |
|---|---|---|---|---|
| 32-byte floor message names the mechanism: "…at least 32 bytes… (CSPRNG key material)" | fixed text | `internal/server/server.go` · `d135e4f` | no | the operator who hits it at boot must know it is key *material*, not a passphrase |
| Floor applies in production only; development boots with the fallback key | prod-only | `internal/server/server.go` (`ProductionGuards` returns nil unless prod) · `d135e4f` | no (`ENV` toggles production) | dev friction buys nothing — the fallback key (`gatepost-development-snapshot-key`, 33 bytes) never signs production |
| Production boot test key picked at 34 bytes so it predates and still clears the floor | `prod-snapshot-key-…` (anonymized here) | `internal/server/prodkey_test.go` · `db19173` | no | proves "long enough to have passed the later floor", not a 32-exact special case |
| Demo pins `GP_TRUSTED_PROXIES=127.0.0.1/32` and sends per-client `X-Forwarded-For` | per-script | `scripts/demo-nodes.sh` · `eb188a0` | yes (env at boot) | rate counters get a fresh client IP per run instead of hammering one bucket; mirrors `demo-domains.sh` |
| Demo asserts no `@` anywhere in the polled envelope | grep-based | `scripts/demo-nodes.sh` · `eb188a0` | no | a shell-level echo of `TestSnapshotCarriesNoSecrets`, so the demo also proves the secrets invariant live |

## Product behaviour

| Decision | Default | File / commit | Env? | Why |
|---|---|---|---|---|
| Polls **without** `If-None-Match` always return 200, even from cache | 200 | `internal/server/nodes.go` (`nodeConfig`) · `38f0a75` | no | cache only removes the *build cost*; keep serving the body every poll — few clients negotiate ETags |
| Concurrent cache misses may both build; same content records the same generation, last cache write wins | no single-flight queue | `internal/server/snapshot.go` (`currentSnapshot`) · `38f0a75` | no | the duplicate-build window costs one resolver lookup; a strict queue buys complexity for no user-visible change |
| Heartbeat of generation **0 or negative** refused with 400 | `generation must be a positive integer` | `internal/server/nodes.go` (`nodeHeartbeat`) · `e6ad837` | no | a missing body field unmarshals as 0 — that coercion is an invalid heartbeat, never "restart from zero" |
| Demo asserts generations **relatively** (`latest + 1`), not a fixed `1`/`2` | `$((GEN1 + 1))` | `scripts/demo-nodes.sh` · `eb188a0` | no | `snapshot_versions` is shared state on the dev DB — older demo runs leave the counter ahead |
| Demo asserts snapshot domains by **subset**, not exact list equality | `assert want in names` | `scripts/demo-nodes.sh` · `eb188a0` | no | the registry accumulates verified domains from earlier demo runs; equality would make the demo order-dependent |
| Demo names/emails/nodes timestamp-suffixed (`$TS`) per run | `-$(date +%s)-$RANDOM` | `scripts/demo-nodes.sh` · `eb188a0` | no | unique-violation 409 and operator-list matching must not collide with prior runs |
| Demo server listens on 8092, logs to `/tmp/gatepost-nodes-demo-server.log` | fixed port | `scripts/demo-nodes.sh` (boot line) · `eb188a0` | it pins `GP_HTTP_ADDR`, but the env knob exists | leaves 8090/8091 to the other demos' conventions and keeps parallel debugging non-colliding |
| Demo node chooses role `edge`; mutual-401 checks hit `/v1/domains` + `/api/me` | per-script | `scripts/demo-nodes.sh` · `eb188a0` | no | representative user routes for the two-principal 401 symmetry; the role value is irrelevant to node routes |

## Data model

| Decision | Default | File / commit | Env? | Why |
|---|---|---|---|---|
| `first_unresolved_at` upsert keeps the **first** timestamp (`DO UPDATE` touches only `updated_at`) | SQL in `noteVerdict` | `internal/server/snapshot.go` · `56566f4`, migration `010_unresolved_time.sql` | no | the rule is "unresolvable since WHEN" — every later failed build must not move the clock |
| An **unsafe** resolution deletes the tracking row (timer restart), same as the *ok* verdict | DELETE, not reset | `internal/server/snapshot.go` · `56566f4` | no | a resolution IS a re-check result; the outage narrative restarts from zero either way |
| The alert fires on the first build seen **after** `time.Since(first) >= threshold` | checked per build | `internal/server/snapshot.go` · `56566f4` | `GP_ORIGIN_UNRESOLVED_MINUTES` (threshold) | alerts ride the build you already run — no side timer process to keep alive |
| Config field renamed with the rule: `OriginUnresolvedBuilds` → `OriginUnresolvedMinutes` | field names | `internal/server/server.go`, `cmd/gatepost/main.go` · `56566f4` | yes, `GP_ORIGIN_UNRESOLVED_MINUTES` | the env name IS the contract; keeping the old name invites a unit mix-up |

## Tooling

| Decision | Default | File / commit | Env? | Why |
|---|---|---|---|---|
| Fake resolver grew an atomic `ipCalls` counter as the build-cost probe; "1 lookup per build" | `atomic.Int32` | `internal/server/domains_verify_test.go`, `internal/server/nodes_poll_test.go` · `38f0a75` | no (test-only) | DB timestamps cannot measure "how many builds happened"; a wire-visible counter cannot race |
| The cache test's PUT counts as **3** lookups (its own validation + the post-write rebuild), hostname address on purpose | vs. literal-IP = 1 | `internal/server/nodes_poll_test.go` · `38f0a75` | no | decomposes the real cost instead of hiding the PUT's own DNS in a tolerance band |
| Demo DNS stub is **raw-UDP, hand-packed** — no python DNS library | port 5344, TTL 5s, UDP only | `scripts/demo-nodes.sh` · `eb188a0` | no | no `dnslib`/`dnspython` on the box; hand-packing ~40 bytes beats a new dependency |
| Stub answers **every** TXT query with the *current* token-file value (no qname check, per-query read) | token file re-read per query | `scripts/demo-nodes.sh` · `eb188a0` | no | a changed claim verifies without restarting the stub, keeping demo steps linear |
| No TCP listener on the stub | UDP only | `scripts/demo-nodes.sh` · `eb188a0` | no | Go's resolver only falls back to TCP after a UDP failure; answering correctly keeps that path unexercised |
| Demo origins are **literal IPs** (`93.184.216.34`), skipping origin-side DNS | per-script | `scripts/demo-nodes.sh` · `eb188a0` | no | TXT verification is the only DNS the demo needs; literal origins avoid stub double-duty and timing traps |
| Python signature checks live as heredocs inside the demo, not a `scripts/*.py` | inline | `scripts/demo-nodes.sh` · `eb188a0` | no | one self-contained script beats a second file nobody re-runs |
| Regress step named `nodes-demo` (log `/tmp/gatepost-regress-nodes.log`) | `run nodes-demo nodes bash scripts/demo-nodes.sh` | `scripts/regress.sh` · `eb188a0` | no | the step label is the log filename everywhere in regress — consistency over cleverness |
| §15 wording: "refused **at boot** by `ProductionGuards`" | prose | `docs/auth-design.md` · `d135e4f` | no | docs must say *where* enforcement runs, so boot vs runtime is unambiguous |
| §9 gains bullets: node tokens in the hash-token list + two invariant bullets (mutual 401s, no-src sweep) | prose | `docs/auth-design.md` · `eb188a0` | no | "isolation table" ownership — the checklist lines are canonical, so they get the invariants |
| progress.md also gained a short **B2 recap header** before B3a | prose | `progress.md` · `5bb74b6` | no | B2 was documented only by its tag; a one-paragraph bridge keeps the file self-contained |
| Demo tempfiles (`mktemp`) + trap-cleanup of server/stub processes | rm on EXIT | `scripts/demo-nodes.sh` · `eb188a0` | no | failed runs must not strand processes or tempfiles; the other demos share this discipline |
| Demo python asserts the **origin address:port** alongside HMAC/key_id | inline assert | `scripts/demo-nodes.sh` · `eb188a0` | no | a signature over an empty-but-valid artifact would otherwise pass silently |
| All demos boot `ENV=development` explicitly | per-script | `scripts/demo-nodes.sh` · `eb188a0` | yes, but pinned | `envfile.Production()` is fail-safe; a typo'd boot would otherwise hit the key boot gates |
