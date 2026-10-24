package server

// B3a item 4: the nodes poll the API. GET /node/v1/config returns the
// signed envelope (payload + signature + key ID; the generation as ETag),
// POST /node/v1/heartbeat stamps the node — and nothing here leaks token
// material, the roster, or another node's record.
import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/snapshot"
)

// nodeSetup — loopback-hook server with an operator and one active edge
// node ("e1") whose raw token comes back once.
func nodeSetup(t *testing.T) (*pgxpool.Pool, tc, *fakeDNS, *Server, string) {
	t.Helper()
	pool := testPool(t)
	a, s := newTestServer(t, pool, func(cfg *Config) {
		cfg.OperatorEmails = []string{"ops@x.test"}
		cfg.TestAllowLoopback = true
	})
	signupOn(t, pool, a, "ops@x.test")
	f := &fakeDNS{ips: map[string][]net.IP{}}
	setResolvers(s, f)
	code, body := a.do("POST", "/v1/nodes", `{"name":"e1","role":"edge"}`)
	if code != http.StatusCreated {
		t.Fatalf("node create: %d %s", code, body)
	}
	_, tok := nodeOf(t, body)
	return pool, a, f, s, tok
}

// asNode returns a client that speaks node tokens (bearerRT adds the auth
// header on every request — exactly what the real poller does).
func asNode(t *testing.T, a tc, tok string) tc {
	t.Helper()
	return tc{t: t, base: a.base, ip: testIP(t), hc: &http.Client{Transport: bearerRT(tok)}}
}

// pollConfig runs one request against the node API and returns code, body
// and ETag ("" without a header).
func pollConfig(t *testing.T, c tc, method, path, tok, body, ifNoneMatch string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, c.base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	req.Header.Set("X-Forwarded-For", testIP(t))
	resp, err := c.hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("ETag")
}

// TestNodePollConfig — the config carries a verifiable envelope stamped
// with a key ID; the generation rides in the ETag; If-None-Match is a free
// 304 until content changes; the body leaks no node bookkeeping.
func TestNodePollConfig(t *testing.T) {
	pool, a, f, _, tok := nodeSetup(t)
	n := asNode(t, a, tok)

	code, body, firstETag := pollConfig(t, n, "GET", "/node/v1/config", tok, "", "")
	if code != http.StatusOK {
		t.Fatalf("first config: want 200, got %d %s", code, body)
	}
	var env snapshot.Envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("config body must be the envelope json: %v: %s", err, body)
	}
	doc, err := snapshot.Verify([]byte("gatepost-development-snapshot-key"), env, 0)
	if err != nil {
		t.Fatalf("the served envelope must verify with the server key: %v", err)
	}
	if env.KeyID == "" {
		t.Fatal("the envelope must carry a key ID in the body")
	}
	if got, want := strings.Trim(firstETag, `"`), strconv.FormatInt(doc.Generation, 10); got != want {
		t.Fatalf("ETag %q must equal the signed generation %s", firstETag, want)
	}
	for _, leak := range []string{"token_hash", "last_seen", "applied_version", `"nodes"`, "ops@x.test"} {
		if strings.Contains(body, leak) {
			t.Fatalf("config body must not leak %q: %s", leak, body)
		}
	}

	// unchanged content: If-None-Match on the current ETag is a free 304
	code, seen, _ := pollConfig(t, n, "GET", "/node/v1/config", tok, "", firstETag)
	if code != http.StatusNotModified || seen != "" {
		t.Fatalf("unchanged poll: want 304 empty, got %d %q", code, seen)
	}

	// content changes → the next poll is fresh with a bumped generation
	f.ips["poll.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	row := verifiedClaim(t, pool, a, f, "poll.example.com")
	if code, body := originCall(t, a, row.ID, map[string]any{"address": "poll.example.com", "port": 80}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	code, body2, newETag := pollConfig(t, n, "GET", "/node/v1/config", tok, "", "")
	if code != http.StatusOK {
		t.Fatalf("changed poll: want 200, got %d %s", code, body2)
	}
	if newETag == firstETag {
		t.Fatalf("ETag must move with the generation: %q vs %q", newETag, firstETag)
	}
	var env2 snapshot.Envelope
	if err := json.Unmarshal([]byte(body2), &env2); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.Verify([]byte("gatepost-development-snapshot-key"), env2, doc.Generation); err != nil {
		t.Fatalf("the new generation must verify above the applied one: %v", err)
	}
}

// TestNodeHeartbeat — last_seen and applied_version are stamped only after
// the payload validates: a reported generation must actually exist.
func TestNodeHeartbeat(t *testing.T) {
	pool, a, _, s, tok := nodeSetup(t)
	n := asNode(t, a, tok)
	d1, _, err := s.buildSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	state := func() (lastSeen *time.Time, applied *int64) {
		if err := pool.QueryRow(context.Background(),
			`SELECT last_seen, applied_version FROM nodes WHERE name = 'e1'`).
			Scan(&lastSeen, &applied); err != nil {
			t.Fatal(err)
		}
		return lastSeen, applied
	}

	// a version that does not exist: refused before anything is stamped
	if code, body := n.do("POST", "/node/v1/heartbeat", `{"generation":99999}`); code != http.StatusBadRequest {
		t.Fatalf("unknown generation: want 400, got %d %s", code, body)
	}
	ls, av := state()
	if ls != nil || av != nil {
		t.Fatalf("refused heartbeat must stamp nothing: %v / %v", ls, av)
	}
	// nonsense generations likewise (0, negative)
	if code, body := n.do("POST", "/node/v1/heartbeat", `{"generation":0}`); code != http.StatusBadRequest {
		t.Fatalf("generation 0: want 400, got %d %s", code, body)
	}
	if code, body := n.do("POST", "/node/v1/heartbeat", `{"generation":-1}`); code != http.StatusBadRequest {
		t.Fatalf("negative generation: want 400, got %d %s", code, body)
	}

	// the real generation stamps both fields; an honestly older one too
	if code, body := n.do("POST", "/node/v1/heartbeat",
		`{"generation":`+strconv.FormatInt(d1.Generation, 10)+`}`); code != http.StatusOK {
		t.Fatalf("valid heartbeat: want 200, got %d %s", code, body)
	}
	ls, av = state()
	if ls == nil || av == nil || *av != d1.Generation {
		t.Fatalf("valid heartbeat must stamp: %v / %v (want %d)", ls, av, d1.Generation)
	}
	prev := *ls
	if code, body := n.do("POST", "/node/v1/heartbeat", `{"generation":1}`); code != http.StatusOK {
		t.Fatalf("older honest generation: want 200, got %d %s", code, body)
	}
	ls, av = state()
	if av == nil || *av != 1 {
		t.Fatalf("an older existing generation is accepted: %v", av)
	}
	if !ls.After(prev) && !ls.Equal(prev) {
		t.Fatalf("last_seen must keep stamping: %v then %v", prev, ls)
	}
}

// TestNodeAuthBoundaries — mutual 401s: node tokens fail user (and
// operator) routes, user credentials fail node routes, revocation lands on
// the very next call, and no exchange ever puts a node token into a log.
func TestNodeAuthBoundaries(t *testing.T) {
	_, a, _, _, tok := nodeSetup(t)
	n := asNode(t, a, tok)

	// node token on user routes — including the operator roster: 401
	for _, path := range []string{"/v1/domains", "/v1/nodes"} {
		if code, body := n.do("GET", path, ""); code != http.StatusUnauthorized {
			t.Fatalf("node token on %s: want 401, got %d %s", path, code, body)
		}
	}
	// user credentials on node routes: same silence
	if code, body, _ := pollConfig(t, a, "GET", "/node/v1/config", "", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no credentials on config: want 401, got %d %s", code, body)
	}
	if code, body := a.do("POST", "/node/v1/heartbeat", `{"generation":1}`); code != http.StatusUnauthorized {
		t.Fatalf("user session on heartbeat: want 401, got %d %s", code, body)
	}
	// a bogus bearer: same 401
	if code, _, _ := pollConfig(t, asNode(t, a, "bogus0123456789"), "GET", "/node/v1/config", "bogus0123456789", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("bogus token: want 401, got %d", code)
	}

	// revocation lands instantly
	list := a.must("GET", "/v1/nodes", "", http.StatusOK)
	id := nodeIDOf(t, list, "e1")
	if code, body := a.do("POST", "/v1/nodes/"+id+"/revoke", ""); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if code, body := n.do("GET", "/node/v1/config", ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked token must be 401 immediately, got %d %s", code, body)
	}

	// the node routes never log tokens
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if code, _, _ := pollConfig(t, n, "GET", "/node/v1/config", tok, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked node poll: want 401, got %d", code)
	}
	if strings.Contains(buf.String(), tok) {
		t.Fatal("a node token must never reach the log")
	}
}

// TestNodePollRateCap — each node counts in its own bucket: one node's
// exhaustion cannot take the other down.
func TestNodePollRateCap(t *testing.T) {
	pool := testPool(t)
	a, s := newTestServer(t, pool, func(cfg *Config) {
		cfg.OperatorEmails = []string{"ops@x.test"}
		cfg.TestAllowLoopback = true
		cfg.NodePollCap = 2
	})
	signupOn(t, pool, a, "ops@x.test")
	setResolvers(s, &fakeDNS{ips: map[string][]net.IP{}})
	_, b1 := a.do("POST", "/v1/nodes", `{"name":"r1","role":"edge"}`)
	_, b2 := a.do("POST", "/v1/nodes", `{"name":"r2","role":"edge"}`)
	_, tok1 := nodeOf(t, b1)
	_, tok2 := nodeOf(t, b2)
	n1, n2 := asNode(t, a, tok1), asNode(t, a, tok2)

	code, body, _ := pollConfig(t, n1, "GET", "/node/v1/config", tok1, "", "")
	if code != http.StatusOK {
		t.Fatalf("r1 poll 1: want 200, got %d %s", code, body)
	}
	if code, _, _ := pollConfig(t, n1, "GET", "/node/v1/config", tok1, "", ""); code != http.StatusOK {
		t.Fatalf("r1 poll 2: want 200, got %d", code)
	}
	// bucket for r1 is full: its third poll is a 429 — and only its third
	if code, _, _ := pollConfig(t, n1, "GET", "/node/v1/config", tok1, "", ""); code != http.StatusTooManyRequests {
		t.Fatalf("r1 over cap: want 429, got %d", code)
	}
	// r2's bucket is its own: untouched by r1's exhaustion
	if code, _, _ := pollConfig(t, n2, "GET", "/node/v1/config", tok2, "", ""); code != http.StatusOK {
		t.Fatalf("r2 must have its own bucket: want 200, got %d", code)
	}
}
