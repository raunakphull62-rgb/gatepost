package server

import (
	"net/http"
	"testing"
)

// TestDomainRateLimits — add/verify/test-connection each have a per-user AND
// a per-IP 15-minute bucket (GP_DOMAIN_ADD_CAP etc.); live-window checks by
// hitting the caps, no fixed sleeps.
func TestDomainRateLimits(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool, func(cfg *Config) {
		cfg.DomainAddCap, cfg.VerifyCap, cfg.OriginTestCap = 2, 1, 1
		cfg.TestAllowLoopback = true // lets the origin-test case store 127.0.0.1
	})
	signupOn(t, pool, a, "rl@x.test")
	b := secondUser(t, pool, a, "rl-b@x.test") // same spoofed IP as a

	da := claimRow(t, a, "rl-1.example.com")
	if code, _ := claimHost(t, a, "rl-2.example.com"); code != http.StatusCreated {
		t.Fatalf("second add: %d", code)
	}
	// per-user: a's third add trips the user bucket
	if code, body := claimHost(t, a, "rl-3.example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("a third add: want 429, got %d %s", code, body)
	}
	// per-IP: b's FIRST add trips the IP bucket a filled up
	if code, body := claimHost(t, b, "rl-b-1.example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("b first add must trip the shared IP bucket: %d %s", code, body)
	}
	// a fresh IP (fresh user too): both buckets clear again → 201
	c := unfollow(a)
	c.ip = "10.77.88.99"
	c.must("POST", "/auth/signup", `{"email":"rl-c@x.test","password":"secretpw123"}`, http.StatusOK)
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
	if code, body := claimHost(t, c, "rl-c-1.example.com"); code != http.StatusCreated {
		t.Fatalf("fresh IP add: want 201, got %d %s", code, body)
	}

	// verify cap (1): first verify consumes the bucket (fails on the real
	// resolver's NXDOMAIN for .example.com), a second verify is 429 before
	// anything else runs
	if code, body := a.do("POST", "/v1/domains/"+da.ID+"/verify", ""); code != http.StatusBadGateway {
		t.Fatalf("first verify (NXDOMAIN): want 502, got %d %s", code, body)
	}
	if code, body := a.do("POST", "/v1/domains/"+da.ID+"/verify", ""); code != http.StatusTooManyRequests {
		t.Fatalf("second verify: want 429, got %d %s", code, body)
	}

	// origin-test cap (1): the stored 127.0.0.1:9 origin refuses connections
	// instantly (closed port) — the first call reports, the second is 429.
	if code, body := originCall(t, a, da.ID, map[string]any{
		"scheme": "http", "address": "127.0.0.1", "port": 9}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	if tr := originTestCall(t, a, da.ID); tr.Reachable {
		t.Fatalf("closed port origin must not be reachable: %+v", tr)
	}
	if code, body := a.do("POST", "/v1/domains/"+da.ID+"/origin/test", ""); code != http.StatusTooManyRequests {
		t.Fatalf("second origin test: want 429, got %d %s", code, body)
	}
}
