package waffailopen

import (
	"errors"
	"net/http"
	"net/http/httptest"
	
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// blockWAF matches coraza-caddy's real block contract: it writes NOTHING and
// returns a HandlerError carrying the block status. (The live regression: the
// wrapper turned this into an empty 200 because it keyed on
// rec.Buffered(), which is true even when nothing was written.)
type blockWAF struct{ status int }

func (b *blockWAF) Provision(ctx caddy.Context) error { return nil }
func (b *blockWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "test.blockWAF", New: func() caddy.Module { return new(blockWAF) }}
}
func (b *blockWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	return caddyhttp.HandlerError{StatusCode: b.status, Err: errors.New("interruption triggered")}
}

// writeBlockWAF blocks by writing its own response and returning nil.
type writeBlockWAF struct{}

func (wb *writeBlockWAF) Provision(ctx caddy.Context) error { return nil }
func (wb *writeBlockWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "test.writeBlockWAF", New: func() caddy.Module { return new(writeBlockWAF) }}
}
func (wb *writeBlockWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte("blocked by waf"))
	return nil
}

// errorNext is a pass-through chain that fails (e.g. the origin dial being
// refused by the egress guard): the WAF passed the request, the proxy erred.
type errorNext struct{ status int }

func (e *errorNext) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return caddyhttp.HandlerError{StatusCode: e.status, Err: errors.New("dial refused")}
}

func newWAFHandler(t *testing.T, mode string, waf caddyhttp.MiddlewareHandler) *FailOpenHandler {
	t.Helper()
	h := &FailOpenHandler{
		Timeout:               "250ms",
		ConcurrentEvaluations: 1,
		ConcurrencyWait:       "50ms",
		Mode:                  mode,
		WAF:                   waf,
	}
	if err := h.parseConfig(); err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	h.stats = getStats()
	h.stats.setConfig(mode, nil)
	return h
}

// asNext adapts a fakeReverseProxy (2-arg + error, caddy-style) into the
// caddyhttp.Handler the wrapper calls next with.
func asNext(rfp *fakeReverseProxy) caddyhttp.Handler {
	return &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = rfp.ServeHTTP(w, r)
	})}
}

// A coraza-style block (error, nothing written) must reach the client as the
// block status — never as an empty 200, and never by running the origin.
func TestBlockHandlerErrorPropagates(t *testing.T) {
	h := newWAFHandler(t, "blocking", &blockWAF{status: http.StatusForbidden})
	rfp := &fakeReverseProxy{}
	req := httptest.NewRequest("GET", "http://block.example.test/foo?x=evil", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, asNext(rfp))
	var herr caddyhttp.HandlerError
	if !errors.As(err, &herr) || herr.StatusCode != http.StatusForbidden {
		t.Fatalf("ServeHTTP err = %v, want HandlerError 403", err)
	}
	// httptest.ResponseRecorder defaults to 200 in Go 1.22+; the wrapper
	// returns the error without writing, so rec.Code stays at its default.
	// The test asserts on the returned error (which Caddy's server would
	// convert to a 403 response), not on rec.Code.
	if rfp.called.Load() {
		t.Error("origin reached despite a WAF block")
	}
}

// A WAF that writes its own block response gets that response committed.
func TestBlockWrittenResponseCommitted(t *testing.T) {
	h := newWAFHandler(t, "blocking", &writeBlockWAF{})
	rfp := &fakeReverseProxy{}
	req := httptest.NewRequest("GET", "http://block.example.test/foo?x=evil", nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, asNext(rfp)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rec.Code != http.StatusForbidden || rec.Body.String() != "blocked by waf" {
		t.Errorf("response = %d %q, want 403 %q", rec.Code, rec.Body.String(), "blocked by waf")
	}
	if rfp.called.Load() {
		t.Error("origin reached despite a WAF block")
	}
}

// An error AFTER the WAF passed the request (origin dial refused → 502) must
// propagate — the silent-nil shape turned refused origins into empty 200s.
func TestPostPassErrorPropagates(t *testing.T) {
	h := newWAFHandler(t, "detection", &fakeWAFHandler{})
	req := httptest.NewRequest("GET", "http://det.example.test/foo", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, &errorNext{status: http.StatusBadGateway})
	var herr caddyhttp.HandlerError
	if !errors.As(err, &herr) || herr.StatusCode != http.StatusBadGateway {
		t.Fatalf("ServeHTTP err = %v, want HandlerError 502", err)
	}
	// httptest.ResponseRecorder defaults to 200; the wrapper returns the
	// error without writing. Assert on the error, not rec.Code.
}

// Clean pass-through: the origin's own response reaches the client untouched.
func TestCleanPassThroughServesOrigin(t *testing.T) {
	h := newWAFHandler(t, "detection", &fakeWAFHandler{})
	rfp := &fakeReverseProxy{}
	req := httptest.NewRequest("GET", "http://det.example.test/ok", nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, asNext(rfp)); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != "origin ok" {
		t.Errorf("response = %d %q, want 200 %q", rec.Code, rec.Body.String(), "origin ok")
	}
	if !rfp.called.Load() {
		t.Error("origin not reached on a clean pass-through")
	}
}

var _ caddyhttp.MiddlewareHandler = (*blockWAF)(nil)
var _ caddyhttp.MiddlewareHandler = (*writeBlockWAF)(nil)
