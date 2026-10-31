//go:build waffailopen_fault

package waffailopen

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type fakeWAFHandler struct {
	panicVal any
	sleepFor time.Duration
}

func (f *fakeWAFHandler) Provision(ctx caddy.Context) error { return nil }
func (f *fakeWAFHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "test.fakeWAF", New: func() caddy.Module { return new(fakeWAFHandler) }}
}
func (f *fakeWAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if f.sleepFor > 0 {
		time.Sleep(f.sleepFor)
	}
	if f.panicVal != nil {
		panic(f.panicVal)
	}
	return next.ServeHTTP(w, r)
}

type fakeReverseProxy struct {
	called atomic.Bool
}

func (f *fakeReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	f.called.Store(true)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("origin ok"))
	return nil
}

// handlerAdapter wraps an http.Handler as a caddyhttp.Handler (2-arg).
type handlerAdapter struct {
	h http.Handler
}

func (a *handlerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	a.h.ServeHTTP(w, r)
	return nil
}

func newTestHandler(t *testing.T, mode string, panicVal any, sleepFor time.Duration) (*FailOpenHandler, *fakeReverseProxy) {
	t.Helper()
	rfp := &fakeReverseProxy{}
	h := &FailOpenHandler{
		Timeout:               "250ms",
		ConcurrentEvaluations: 1,
		ConcurrencyWait:       "50ms",
		Mode:                  mode,
		WAF:                   &fakeWAFHandler{panicVal: panicVal, sleepFor: sleepFor},
	}
	if err := h.parseConfig(); err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	h.stats = getStats()
	h.stats.setConfig(mode, nil)
	return h, rfp
}

func TestPanicFailClosedInBlockingMode(t *testing.T) {
	h, rfp := newTestHandler(t, "blocking", "nil-deref", 0)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic propagated to caller: %v", r)
		}
	}()
	req := httptest.NewRequest("GET", "http://block.example.test/foo", nil)
	rec := httptest.NewRecorder()
	next := &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rfp.ServeHTTP(w, r)
	})}
	err := h.ServeHTTP(rec, req, next)
	_ = err // blocking mode writes 503 directly, returns nil
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if rec.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want \"1\"", rec.Header().Get("Retry-After"))
	}
	if rfp.called.Load() {
		t.Error("origin was reached despite WAF panic in blocking mode")
	}
	if h.stats.panics.Load() == 0 {
		t.Error("panic counter not incremented")
	}
}

func TestPanicFailOpenInDetectionMode(t *testing.T) {
	h, rfp := newTestHandler(t, "detection", "nil-deref", 0)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic propagated: %v", r)
		}
	}()
	req := httptest.NewRequest("GET", "http://det.example.test/foo", nil)
	rec := httptest.NewRecorder()
	next := &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rfp.ServeHTTP(w, r)
	})}
	err := h.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("expected pass-through, got: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !rfp.called.Load() {
		t.Error("origin not reached in detection mode")
	}
}

func TestTimeoutFailClosedInBlockingMode(t *testing.T) {
	h, rfp := newTestHandler(t, "blocking", nil, 500*time.Millisecond)
	req := httptest.NewRequest("GET", "http://block.example.test/foo", nil)
	rec := httptest.NewRecorder()
	next := &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rfp.ServeHTTP(w, r)
	})}
	err := h.ServeHTTP(rec, req, next)
	_ = err // blocking mode writes 503 directly
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if h.stats.timeouts.Load() == 0 {
		t.Error("timeout counter not incremented")
	}
	if rfp.called.Load() {
		t.Error("origin reached despite timeout")
	}
}

func TestTimeoutFailOpenInDetectionMode(t *testing.T) {
	h, rfp := newTestHandler(t, "detection", nil, 500*time.Millisecond)
	req := httptest.NewRequest("GET", "http://det.example.test/foo", nil)
	rec := httptest.NewRecorder()
	next := &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rfp.ServeHTTP(w, r)
	})}
	err := h.ServeHTTP(rec, req, next)
	if err != nil {
		t.Fatalf("expected pass-through, got: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !rfp.called.Load() {
		t.Error("origin not reached in detection timeout")
	}
}

func TestSaturationFailClosedInBlockingMode(t *testing.T) {
	h, rfp := newTestHandler(t, "blocking", nil, 200*time.Millisecond)
	next := &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rfp.ServeHTTP(w, r)
	})}
	req1 := httptest.NewRequest("GET", "http://block.example.test/1", nil)
	req2 := httptest.NewRequest("GET", "http://block.example.test/2", nil)
	rec1 := httptest.NewRecorder()
	rec2 := httptest.NewRecorder()
	done := make(chan error, 2)
	go func() { done <- h.ServeHTTP(rec1, req1, next) }()
	go func() { done <- h.ServeHTTP(rec2, req2, next) }()
	<-done
	<-done
	if h.stats.saturated.Load() == 0 {
		t.Error("saturated counter not incremented")
	}
	if rec1.Code != http.StatusServiceUnavailable && rec2.Code != http.StatusServiceUnavailable {
		t.Errorf("expected at least one %d, got %d and %d",
			http.StatusServiceUnavailable, rec1.Code, rec2.Code)
	}
}

func TestStatsEndpoint(t *testing.T) {
	s := &StatsAPI{}
	if err := s.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	routes := s.Routes()
	if len(routes) != 1 || routes[0].Pattern != "/waffailopen/stats" {
		t.Fatalf("unexpected routes: %v", routes)
	}
	st := getStats()
	st.panics.Store(3)
	st.timeouts.Store(5)
	st.saturated.Store(7)
	st.setConfig("blocking", map[string]string{"a.test": "off"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/waffailopen/stats", nil)
	if err := s.serveStats(rec, req); err != nil {
		t.Fatalf("serveStats: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var snap statsSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Panics != 3 || snap.Timeouts != 5 || snap.Saturated != 7 {
		t.Errorf("counters = %+v", snap)
	}
	if snap.Mode != "blocking" {
		t.Errorf("mode = %q, want blocking", snap.Mode)
	}
}

func TestFailOpenNoPayloadEcho(t *testing.T) {
	h, rfp := newTestHandler(t, "blocking", "panic", 0)
	next := &handlerAdapter{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rfp.ServeHTTP(w, r)
	})}
	attack := "secret_value=leaked_data"
	req := httptest.NewRequest("GET", "http://block.example.test/foo?"+attack, nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	body := rec.Body.String()
	if len(body) >= len(attack) {
		for i := 0; i <= len(body)-len(attack); i++ {
			if body[i:i+len(attack)] == attack {
				t.Errorf("body contains request payload: %q", body)
			}
		}
	}
}

var _ caddyhttp.MiddlewareHandler = (*fakeWAFHandler)(nil)
var _ caddyhttp.Handler = (*handlerAdapter)(nil)
var _ caddyhttp.Handler = (*fakeReverseProxy)(nil)