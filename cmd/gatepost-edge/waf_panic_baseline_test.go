package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWAFOpaquePanicBaseline verifies the foundational claim documented in
// docs/waf-fail-open-analysis.md (failure mode 2): a panic inside a Caddy
// (or Go net/http) handler is recovered by the server runtime and does NOT
// kill the process. A second request to a different host succeeds after.
func TestWAFOpaquePanicBaseline(t *testing.T) {
	var panicked bool
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !panicked {
			panicked = true
			panic("simulated nil-deref in WAF eval")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := httptest.NewServer(h)
	defer srv.Close()

// First request: the panic may close the connection (Go net/http) or
	// return 500 (Caddy). Either is fine — the assertion is the second
	// request.
	resp1, err := http.Get(srv.URL)
	if err != nil && !panicked {
		t.Fatalf("first request before panic: %v", err)
	}
	if resp1 != nil {
		resp1.Body.Close()
	}

	// Second request must succeed — the process/server survived the panic.
	resp2, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("second request after panic: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("second: status %d, want 200 (process survived)", resp2.StatusCode)
	}
}
