// Package waffailopen implements a Caddy v2 handler module
// ("gatepost/waffailopen") that wraps the Coraza WAF handler with
// fail-open defence at the per-request level:
//
//   - recover() turns a WAF panic into a single counted event, never a
//     process crash.
//   - A per-request time budget (default 250ms, env-configurable) bounds
//     how long a single WAF evaluation may run.
//   - A counting semaphore bounds concurrent evaluations; a 50ms wait
//     decides whether to queue or fail-open.
//
// On a panic, timeout or saturation the wrapper fails CLOSED for blocking
// hosts (503 + Retry-After) and fails OPEN for detection hosts (the request
// skips the WAF and reaches the origin). The off mode skips the WAF
// entirely — the wrapper is only injected when a WAF handler is present.
//
// The module is compiled into the edge image via xcaddy (see
// deploy/dev/Dockerfile.edge). A companion admin API module exposes
// accumulated panic/timeout/saturated counters on the admin API at
// /waffailopen/stats so the poller can surface them in /health.
package waffailopen

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(FailOpenHandler{})
	caddy.RegisterModule(StatsAPI{})
}

// errWAFOpaque is a generic error returned to the client on a WAF failure.
// It deliberately carries no request-derived text: a blocking host that
// hits the 503 path must never echo the attacker's payload back.
var errWAFOpaque = fmt.Errorf("WAF evaluation unavailable")

// FailOpenHandler wraps the Coraza WAF handler with recover, a per-request
// time budget and bounded concurrency. On failure it either returns 503
// (blocking hosts) or falls through to the next handler (detection/off
// hosts).
//
// In the Caddy JSON config this module sits in the handle array BEFORE
// reverse_proxy. Its "waf" field embeds the coraza handler config; Caddy's
// config adapter resolves it into a MiddlewareHandler at load time.
type FailOpenHandler struct {
	// WAFRaw is the raw JSON config of the embedded Coraza WAF handler.
	// Resolved to WAF (below) in Provision.
	WAFRaw json.RawMessage `json:"waf,omitempty" caddy:"namespace=http.handlers inline_key=handler"`

	// Timeout is the per-request WAF evaluation time budget.
	// Default 250ms. Env-configurable via GP_EDGE_WAF_TIMEOUT.
	Timeout string `json:"timeout,omitempty"`

	// ConcurrentEvaluations is the semaphore size for concurrent
	// WAF evaluations. Default 64. Env-configurable via
	// GP_EDGE_WAF_CONCURRENCY.
	ConcurrentEvaluations int `json:"concurrency,omitempty"`

	// ConcurrencyWait is how long a request will wait for a semaphore
	// slot before failing open. Default 50ms.
	ConcurrencyWait string `json:"concurrency_wait,omitempty"`

	// Mode is the global default WAF mode: "detection" | "blocking".
	Mode string `json:"mode,omitempty"`

	// HostModes maps hostnames to per-host mode overrides.
	HostModes map[string]string `json:"host_modes,omitempty"`

	// WAF is the resolved WAF handler.
	WAF caddyhttp.MiddlewareHandler `json:"-"`
	// next is the handler Caddy chains after this one (reverse_proxy).
	next caddyhttp.Handler `json:"-"`

	// internal config
	timeout time.Duration
	wait    time.Duration
	sem     chan struct{}
	stats   *WAFStats
}

// CaddyModule returns the Caddy module information.
func (FailOpenHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waffailopen",
		New: func() caddy.Module { return new(FailOpenHandler) },
	}
}

// Provision sets up the handler.
func (h *FailOpenHandler) Provision(ctx caddy.Context) error {
	// Resolve the embedded WAF handler.
	wafIface, err := ctx.LoadModule(h, "WAFRaw")
	if err != nil {
		return fmt.Errorf("waffailopen: loading WAF handler: %w", err)
	}
	mh, ok := wafIface.(caddyhttp.MiddlewareHandler)
	if !ok {
		return fmt.Errorf("waffailopen: embedded handler %T does not implement MiddlewareHandler", wafIface)
	}
	h.WAF = mh

	// Parse timeout (default 250ms).
	h.timeout = 250 * time.Millisecond
	if h.Timeout != "" {
		h.timeout, err = time.ParseDuration(h.Timeout)
		if err != nil {
			return fmt.Errorf("waffailopen: invalid timeout %q: %w", h.Timeout, err)
		}
	}
	if h.timeout <= 0 {
		return fmt.Errorf("waffailopen: timeout must be positive")
	}

	// Parse concurrency wait (default 50ms).
	h.wait = 50 * time.Millisecond
	if h.ConcurrencyWait != "" {
		h.wait, err = time.ParseDuration(h.ConcurrencyWait)
		if err != nil {
			return fmt.Errorf("waffailopen: invalid concurrency_wait %q: %w", h.ConcurrencyWait, err)
		}
	}

	// Set up semaphore (default 64).
	if h.ConcurrentEvaluations <= 0 {
		h.ConcurrentEvaluations = 64
	}
	h.sem = make(chan struct{}, h.ConcurrentEvaluations)

	// Register global stats (shared with the admin API module).
	h.stats = getStats()
	h.stats.setConfig(h.Mode, h.HostModes)

	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (h *FailOpenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	host := hostOnly(r.Host)
	mode := h.hostMode(host)

	// off mode: skip WAF entirely, pass request through.
	if mode == "off" {
		return next.ServeHTTP(w, r)
	}

	// --- bounded concurrency ---
	t := time.NewTimer(h.wait)
	defer t.Stop()

	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	case <-t.C:
		h.stats.saturated.Add(1)
		log.Printf("waffailopen: WARN saturated (%d concurrent evals) for host %s",
			h.ConcurrentEvaluations, host)
		return h.failOpen(w, r, host, mode, next)
	case <-r.Context().Done():
		return r.Context().Err()
	}

	// --- per-request time budget ---
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	r2 := r.WithContext(ctx)

	// Response recorder: only the WAF handler writes to rec before it
	// calls next. Pass-through writes go directly to the original
	// writer via passThrough (see below), so buffering overhead is
	// minimal (only WAF-generated error responses).
	rec := caddyhttp.NewResponseRecorder(w, new(bytes.Buffer),
		caddyhttp.ShouldBufferFunc(func(status int, _ http.Header) bool {
			return true
		}))

	// onceHandler ensures next is only invoked once, preventing double
	// reverse_proxy calls when both the WAF goroutine and the timeout
	// handler race to call next.
	onceNext := &onceHandler{next: next}

	// passThrough signals the main goroutine when the WAF handler calls
	// next (i.e. the request passed the WAF), and restores the original
	// context + response writer so reverse_proxy is unaffected by the
	// WAF timeout budget.
	pt := &passThrough{next: onceNext, origW: w, origCtx: r.Context()}

	// Run the WAF handler in a goroutine with recover.
	type wafResult struct{ err error }
	resultCh := make(chan wafResult, 1)

	go func() {
		defer func() {
			if rc := recover(); rc != nil {
				h.stats.panics.Add(1)
			log.Printf("waffailopen: PANIC recovered for host %s: %v", host, rc)
				resultCh <- wafResult{err: errPanic}
			}
		}()
		err := h.WAF.ServeHTTP(rec, r2, pt)
		resultCh <- wafResult{err: err}
	}()

	// Wait for one of: WAF called next, WAF returned, timeout.
	timer := time.NewTimer(h.timeout)
	defer timer.Stop()

	select {
	case <-pt.passed:
		// WAF handler called next — the request passed through.
		// Wait for the goroutine (rule evaluation already done, now
		// waiting on reverse_proxy).
		res := <-resultCh
		// If the WAF wrote anything to the recorder before calling next
		// (e.g. a late 403 that races with the pass-through), commit it.
		if rec.Buffered() {
			return rec.WriteResponse()
		}
		_ = res
		return nil

	case res := <-resultCh:
		// WAF handler returned (error or nil) without calling next.
		if res.err == errPanic {
			return h.failOpen(w, r, host, mode, next)
		}
		// WAF-generated response (e.g. 403) is in the recorder.
		if rec.Buffered() {
			return rec.WriteResponse()
		}
		// No buffered content: return the error (0 if pass-through,
		// HandlerError if blocked).
		return res.err

	case <-timer.C:
		// Timeout: the WAF handler is still in rule evaluation.
		h.stats.timeouts.Add(1)
		log.Printf("waffailopen: TIMEOUT for host %s (budget %s exceeded)", host, h.timeout)
		return h.failOpen(w, r, host, mode, onceNext)
	}
}

// failOpen decides the behaviour when the WAF handler panics, times out or
// saturates. Blocking hosts get a 503 + Retry-After (never echoing the
// payload); detection hosts fall through to next.
func (h *FailOpenHandler) failOpen(w http.ResponseWriter, r *http.Request, host, mode string, hdl caddyhttp.Handler) error {
	if mode == "blocking" {
		w.Header().Set("Retry-After", "1")
		return caddyhttp.Error(http.StatusServiceUnavailable, errWAFOpaque)
	}
	// detection/off: pass through, skip WAF
	return hdl.ServeHTTP(w, r)
}

// hostMode returns the WAF mode for the given host.
func (h *FailOpenHandler) hostMode(host string) string {
	host = hostOnly(host)
	if m, ok := h.HostModes[host]; ok {
		return m
	}
	return h.Mode
}

// hostOnly strips the port from a "host:port" string.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// --- helper types ---

// errPanic is a sentinel error signalling that a WAF panic was recovered.
var errPanic = fmt.Errorf("waf panic recovered")

// onceHandler wraps a Handler so ServeHTTP is only invoked once.
// Subsequent calls are dropped (return nil). This prevents double
// reverse_proxy calls when the WAF goroutine and the timeout/fallback
// path both try to invoke next.
type onceHandler struct {
	next   caddyhttp.Handler
	called atomic.Bool
}

func (o *onceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if !o.called.CompareAndSwap(false, true) {
		return nil
	}
	return o.next.ServeHTTP(w, r)
}

// passThrough wraps an Handler and closes a channel the first time it is
// invoked. It also restores the original response writer and request
// context, so the downstream handler (reverse_proxy) is unaffected by the
// WAF time budget or any response recorder.
type passThrough struct {
	next    caddyhttp.Handler
	origW   http.ResponseWriter
	origCtx context.Context
	passed  chan struct{}
	once    sync.Once
}

func (p *passThrough) ServeHTTP(_ http.ResponseWriter, r *http.Request) error {
	p.once.Do(func() { close(p.passed) })
	// Restore original context so reverse_proxy is not subject to the
	// WAF evaluation timeout.
	r = r.WithContext(p.origCtx)
	return p.next.ServeHTTP(p.origW, r)
}

// Interface guards
var (
	_ caddy.Provisioner            = (*FailOpenHandler)(nil)
	_ caddyhttp.MiddlewareHandler  = (*FailOpenHandler)(nil)
)
