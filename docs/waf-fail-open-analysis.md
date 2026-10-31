# WAF fail-open analysis (B3c item 4)

How the Coraza edge WAF could fail open, what it does today on each failure
mode, and a defense-in-depth wrapper that fails CLOSED at the per-request
level while degrading to WAF-off (not deny-all) on a config-level failure.

This is a design brief only — nothing here is built.

## Failure modes

### 1. Coraza internal error
A rule's evaluation returns an internal error mid-chain (e.g. an inspect
hook returns an error, a malformed AR body). Today the Coraza handler
returns a 400/500-style error to the client and the request is denied — but
only if the process survives the call.

### 2. Panic in the WAF handler
A nil deref, an out-of-range index, or a bad rule definition panics inside
`eval`/`InspectRequestBody`. Without a recover, the panic propagates through
Caddy's HTTP handler and kills the **whole edge process** (not just the one
request) — every served host drops, TLS handshakes stall, and the node
reboots into a cold-start window every time the rule fires. That is a
stability bug, not just a WAF bug: a single rule in a single tenant's
policy could take down the edge for everyone.

### 3. Slow evaluation (head-of-line blocking)
A pathological request (nested encodings, huge body, a rule with a hot
regex) pins a Coraza worker for longer than Caddy's client timeout. Caddy
aborts the client connection (30s), but the underlying Coraza goroutine is
not cancellable — it keeps churning, and a modest flood saturates the
worker pool / burns CPU and memory. This is a resource-exhaustion vector as
much as a latency one.

### 4. Caddy rejects the WAF config on a fresh boot with a saved snapshot
The edge boots (cold start or after a restart), loads its last-good
snapshot, and the apply loop POSTs a Caddy JSON config containing the Coraza
handler to `/load`. Caddy rejects it (schema error, undefined rule, bad
module version) with a 400. The `/load` fails, the apply loop keeps the
ZERO document it pushes at cold start, and **every host returns 421**: the
edge is on deny-all indefinitely. Recovery only happens when an API-side
write invalidates the snapshot, the next build produces a DIFFERENT
artifact, and that artifact's WAF config is again rejected by Caddy...
or never, if the offending content is still the live config. Today: a
total outage that an operator cannot clear from the operator side (it
requires touching the customer config that triggers the rejection, or
rebuilding/deploying a changed WAF shape).

## Why deny-all is the wrong default here

Deny-all is fail-**closed** and safe *for the WAF*, but the edge's actual
job is to **serve the verified origin**. A rejected WAF config is a
*config-generation* failure, not a "should this request be allowed" failure
— the snapshot's domains, origins, and TLS proof stand regardless of WAF.
Collapsing the whole edge to 421 on a WAF-config rejection conflates two
failure domains (routing vs. WAF) and converts one customer's problem into
an availability incident for everyone.

## Proposed wrapper design

Wrap the Coraza handler in a `wafHandler` that layers three controls, and
repoint the apply loop at its `applyConfigWithFallback` helper:

1. **recover()** — every evaluation runs under a deferred recover. A panic
   becomes a single logged error (`waf panic recovered for <host>`) and a
   per-request deny (403), **not** a process crash. The edge stays up for
   every other host.

2. **Per-request time budget** — evaluation is bounded by a deadline
   (e.g. 3–5s, well below Caddy's 30s client timeout) via
   `context.WithTimeout`. A watchdog goroutine cancels/returns 503 (slow
   down + alert) the moment the budget is exceeded, so a slow rule can no
   longer pin a worker until Caddy's timeout fires.

3. **Bounded concurrency** — a counting semaphore (`runtime.GOMAXPROCS`
   permits, or a small multiple) gates how many requests evaluate the WAF
   simultaneously. Beyond the permit, new requests proceed WAF-OFF (the
   fallback) rather than queueing behind the flood. This caps memory and CPU
   blow-up from a slow-eval storm.

4. **Config-level fallback (the fix for failure mode 4)** — the apply loop
   POSTs `/load` with the Coraza handler as today. On a Caddy 400 to that
   payload, `applyConfigWithFallback` **re-POSTs the same route set WITHOUT
   the Coraza handler** (WAF off, plain TLS/routing/421 ask check intact)
   and calls `recordAlert(ctx, "waf_config_failed", host/snapshot, reason)`.
   The edge serves (fail-open at the WAF boundary, fail-CLOSED for unknown
   hosts via the ask check's 421) and the operator is paged. When the next
   snapshot rebuild yields a config Caddy accepts WITH the WAF, the alert
   auto-resolves and WAF is re-enabled.

   Boundary: fail-open applies **only at the WAF layer** — the origin, TLS,
   and non-routable-host 421 behavior are untouched. A request to a host the
   snapshot doesn't list still gets 421 (the ask check), whether the WAF is
   on or off.

## Injected-fault testing plan

- **Panic (mode 2):** swap the Coraza policy's request-body inspect callback
  for a closure that panics, then send one request. Expect: 403/5xx (not
  200), the process **stays up** (a second request to a different host is
  served normally), and the log contains `waf panic recovered`. Unit-test
  the `wafHandler` directly: feed it a next-handler that panics and assert
  `recover` fired + a 403.

- **Slow evaluation (mode 3):** same swap, but the closure `time.Sleep`s
  past the budget. Expect: 503 within the budget, a second concurrent
  request is NOT blocked (served within the semaphore limit), and an alert
  `waf_slow` fires. Use the fake poller's `ErrorLogGap`/`logHook` to assert
  exactly-once logging.

- **Config rejection (mode 4):** unit-test `applyConfigWithFallback` with a
  `caddyAdmin` fake that returns 400 for any `/load` whose JSON contains
   the `coraza.waf` module. Expect: a second `/load` (no WAF module) returns
  200, the response includes the WAF-off shape, and `recordAlert` was called
  with `waf_config_failed`. (The live edge-accept.sh section `l` already
  proves the real Caddy reloads between WAF shapes — that's the integration
  counterpart.)

- **Regain of WAF:** after the config-rejection fault, push a corrected
  snapshot (one the live Caddy accepts with the WAF) and assert the edge
  re-applies the Coraza shape and resolves the `waf_config_failed` alert.

## Scope / non-goals

- This brief does NOT change the snapshot protocol, the `required_features`
  gate, or the operator_alerts schema — it adds one alert kind
  (`waf_config_failed`) and touches only the edge apply/wrap path.
- The deny-all cold-start shape (apply.go: `ensureDenyAll` on generation 0)
  is retained: with **no** snapshot at all, the edge still has nothing to
  serve, so deny-all stays. The fallback in §4 only engages when a snapshot
  IS loaded but its WAF config is rejected.
- Per-request recover budgets and concurrency limits are tunables (env or
  config) so a noisy-correlator customer can be rate-limited without a
  rebuild.

## Acceptance verdict line (design review)

- `waf panic recovered` must never crash the process — covered by (2).- the semaphore must keep P99 under the budget while under a slow-eval storm — covered by (3).
- a rejected WAF config must produce a serving (WAF-off) edge + exactly one
  `waf_config_failed` alert that auto-resolves on a good reload — covered by (4).
