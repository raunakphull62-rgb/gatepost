# B3c Item 1 Investigation Reports

## 1. Caddy config rejection behavior (Task 3)

### What happens when Caddy rejects a WAF config (e.g., unknown `SecAuditLogFormat`)?

The poller's `stepApply()` (apply.go:205) calls `applyCaddy()` which POSTs the generated JSON to `POST /node/v1/load`. If Caddy rejects the config, it returns a non-200 HTTP status.

**Current behavior:**
- `caddyLoad()` wraps the rejection in an error prefixed `"caddy /load:"` (apply.go:302)
- `stepApply()` logs `"caddy apply FAILED — keeping the last-good config"` at error level (apply.go:242)
- Caddy itself continues serving the **last accepted config** — it does not crash or stop serving
- The rejected config stays in `p.pending` and is retried at the cooldown pace (default 60s)

**Fresh boot scenario:**
- If the poller has a saved snapshot on disk (`loadSavedSnapshot`), it applies that — the rejected config never reaches Caddy
- If there is NO saved snapshot, the poller pushes a deny-all config (no WAF handler, `421` for every host). A reject of this deny-all path would mean Caddy accepts no config at all, which would leave the edge returning 421 for every host — but the deny-all config has no WAF directives, so it validates unconditionally.

**Proposal (not built):**
If a snapshot with a WAF config is persistently rejected, the poller could:
1. Log the rejection at `error` level (already done)
2. Strip the `WAF` field from the snapshot copy
3. Regenerate and POST the config without the WAF handler
4. Alert (the poller already has alerting infrastructure via the ask endpoint)

This would ensure the edge always serves the correct origins even if the WAF config is invalid, trading WAF visibility for availability. This is left as item-2 work.

## 2. Fail-open verification (Task 4)

### What was verified:
- **DetectionOnly mode**: coraza-caddy v2.6.2's `ServeHTTP` (coraza.go:197) calls `processRequest` and checks `it, err`. On an interruption (`it != nil`), it calls `obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK)` (coraza.go:244). In `DetectionOnly` mode, coraza's `Interrupt()` (transaction.go:344) stores the interruption in `detectionOnlyInterruption` but does NOT set `tx.interruption`, so `it` is nil — the handler proceeds to `next.ServeHTTP(w, r)` and proxies the request. ✅ Verified: live test showed 200 responses for attack requests.

- **CRS disruptive actions are not executed**: Verified by code reading coraza v3.8.1 `Interrupt()` (transaction.go:342-354). In DetectionOnly mode, `Interrupt()` only stores to `detectionOnlyInterruption`, never to `tx.interruption`.

### What was NOT verified (unverified):

- **processRequest error path**: If `processRequest` returns an error (processRequest in http.go), coraza-caddy returns `http.StatusInternalServerError` (500). This is NOT fail-open — the request is not proxied. Not tested with a request that triggers this error.

- **Panic in coraza-caddy**: There is NO `defer recover()` in `ServeHTTP`. A panic would propagate to Caddy's HTTP handler, which has its own `recover()` (in Caddy's `http.Server`), returning a 500. Not tested with a crashing rule or malformed input.

- **Slow request / timeout**: Caddy's `header_timeout` (10s in the generated config) applies to the entire request pipeline. If coraza-caddy's `processRequest` blocks (e.g., a pathological regex in CRS), Caddy would return 504 after the timeout. Not tested with a slow CRS rule.

- **Blocking mode**: In `Blocking` mode, `SecRuleEngine On` causes `Interrupt()` to set `tx.interruption`, making `it != nil`, and `obtainStatusCodeFromInterruptionOrDefault` returns the interruption status (default 403). Requests ARE blocked in this mode.

### Corrected claim:
The fail-open guarantee holds for the **disruptive-action path** in DetectionOnly mode (the only mode the edge ships with, per B3c item 1). CRS rules record matches but never execute block/deny actions. However, **internal errors in request processing (processRequest errors, panics, slow CRS evaluation) are NOT covered** by this guarantee — they result in HTTP 500/504 responses, not request passthrough.

## 3. test-alpine-exit investigation (Task)

Container: `test-alpine-exit` (ID: 29940a45322f)
- Image: `alpine:3.21`
- Cmd: `sh -c 'exit 137'`
- Created: `2026-10-28T11:49:13.210910051Z`
- StartedAt: `2026-10-29T07:03:56.765676101Z` (after this session began)
- Restart policy: `always`
- Labels: `{}` (no gatepost labels)
- Networks: `bridge` only
- No secrets, no gatepost env vars, no gatepost networks

**Conclusion**: Stray container, pre-existing from a prior session. Created before this session's work began. Left untouched as instructed.

## 4. TestAskCertCapPerHour race (Task 5)

### Root cause:
The race is in the **test code**, not the product code. The product's `certRoom()` method (poller.go:569) properly uses `p.mu.Lock()`/`Unlock()` to protect `certCount`, `certWindow`, and `certCapWarned`.

The race is between:
- Line 982: `cfg.Now = func() time.Time { return now }` — closure captures local variable `now` by reference
- Line 1007: `now = now.Add(time.Hour)` — test goroutine mutates `now`

Meanwhile, the poller goroutine calls `cfg.Now()` to get the current time for `certRoom()`. This is a classic unsynchronized read/write of a captured variable.

### Fix:
Replaced the bare `now` variable with `atomic.Int64` storing Unix nanoseconds:
```go
nowNs := atomic.Int64{}
nowNs.Store(time.Unix(1_800_000_000, 0).UnixNano())
cfg.Now = func() time.Time { return time.Unix(0, nowNs.Load()) }
// ...
nowNs.Add(int64(time.Hour))
```

Verified: `go test -race -count=20 -run TestAskCertCapPerHour` passes with zero races.
