package waffailopen

import (
	"net/http"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Shared test fakes — plain (no build tag) so every test file can use them.
// fakeWAFHandler passes requests through untouched; the blocking fakes that
// match coraza's real contracts live in module_test.go.

type fakeWAFHandler struct{}

func (f *fakeWAFHandler) Provision(ctx caddy.Context) error { return nil }
func (f *fakeWAFHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "test.fakeWAF", New: func() caddy.Module { return new(fakeWAFHandler) }}
}
func (f *fakeWAFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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

var _ caddyhttp.MiddlewareHandler = (*fakeWAFHandler)(nil)
var _ caddyhttp.Handler = (*handlerAdapter)(nil)
