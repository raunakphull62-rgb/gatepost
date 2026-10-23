package server

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// operatorSetup — a server with ops@x.test on the operator list and that
// account signed up + verified on it.
func operatorSetup(t *testing.T) (*pgxpool.Pool, tc) {
	t.Helper()
	pool := testPool(t)
	a, _ := newTestServer(t, pool, func(cfg *Config) { cfg.OperatorEmails = []string{"OPS@x.test"} })
	signupOn(t, pool, a, "ops@x.test")
	return pool, a
}

// anonOn copies a client's wiring without a cookie jar: no credentials.
func anonOn(t *testing.T, a tc) tc {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	return tc{t: t, base: a.base, ip: testIP(t), hc: &http.Client{Jar: jar}}
}

func nodeIDOf(t *testing.T, list, name string) string {
	t.Helper()
	var got struct {
		Nodes []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(list), &got); err != nil {
		t.Fatalf("node list json: %v: %s", err, list)
	}
	for _, n := range got.Nodes {
		if n.Name == name {
			return n.ID
		}
	}
	t.Fatalf("no node named %s in %s", name, list)
	return ""
}

func nodeOf(t *testing.T, body string) (id, token string) {
	t.Helper()
	var got struct {
		Token string `json:"token"`
		Node  struct {
			ID string `json:"id"`
		} `json:"node"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("node create json: %v: %s", err, body)
	}
	return got.Node.ID, got.Token
}

// TestNodeManagement — create/list/revoke as the operator: token shown once
// and never again, names unique, role/name validated, revoke idempotent.
func TestNodeManagement(t *testing.T) {
	_, a := operatorSetup(t)

	// the list entry was uppercase OPS@x.test; the lowercased account runs the
	// show — operator emails compare case-insensitively.
	code, body := a.do("POST", "/v1/nodes", `{"name":"edge-one","role":"edge"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	nodeID, nodeTok := nodeOf(t, body)
	if len(nodeTok) < 40 || strings.Contains(strings.ToLower(body), "token_hash") {
		t.Fatalf("create must return the raw 256-bit token once and no hash: %s", body)
	}

	if code, body := a.do("POST", "/v1/nodes", `{"name":"dns-one","role":"dns"}`); code != http.StatusCreated {
		t.Fatalf("dns create: %d %s", code, body)
	}

	for _, c := range []struct{ name, body string }{
		{"bad role", `{"name":"x","role":"waf"}`},
		{"empty name", `{"name":"   ","role":"edge"}`},
		{"long name", `{"name":"` + strings.Repeat("n", 51) + `","role":"edge"}`},
		{"duplicate name", `{"name":"edge-one","role":"edge"}`},
	} {
		want := http.StatusUnprocessableEntity
		if c.name == "duplicate name" {
			want = http.StatusConflict
		}
		if code, body := a.do("POST", "/v1/nodes", c.body); code != want {
			t.Fatalf("%s: want %d, got %d: %s", c.name, want, code, body)
		}
	}

	list := a.must("GET", "/v1/nodes", "", http.StatusOK)
	for _, n := range []string{"edge-one", "dns-one", `"status":"active"`} {
		if !strings.Contains(list, n) {
			t.Fatalf("list must show %q: %s", n, list)
		}
	}
	if strings.Contains(strings.ToLower(list), "token_hash") {
		t.Fatal("the roster must not carry token hashes")
	}
	if nodeIDOf(t, list, "edge-one") != nodeID {
		t.Fatal("list id mismatch")
	}

	// revoke is idempotent and the roster reflects it immediately
	a.must("POST", "/v1/nodes/"+nodeID+"/revoke", "", http.StatusOK)
	a.must("POST", "/v1/nodes/"+nodeID+"/revoke", "", http.StatusOK)
	if got := a.must("GET", "/v1/nodes", "", http.StatusOK); !strings.Contains(got, `"status":"revoked"`) {
		t.Fatalf("revoke must flip status: %s", got)
	}
	if code, _ := a.do("POST", "/v1/nodes/00000000-0000-0000-0000-000000000000/revoke", ""); code != http.StatusNotFound {
		t.Fatalf("unknown node revoke: want 404, got %d", code)
	}
}

// TestNodeOperatorOnly — every node management route is operator-only:
// a plain user is 403, no credentials at all is 401.
func TestNodeOperatorOnly(t *testing.T) {
	pool, a := operatorSetup(t)
	b := secondUser(t, pool, a, "plain@x.test") // not an operator, same server
	anon := anonOn(t, a)

	a.must("POST", "/v1/nodes", `{"name":"edge-two","role":"edge"}`, http.StatusCreated)
	list := a.must("GET", "/v1/nodes", "", http.StatusOK)
	id := nodeIDOf(t, list, "edge-two")

	for _, c := range [][]string{
		{"POST", "/v1/nodes"},
		{"GET", "/v1/nodes"},
		{"POST", "/v1/nodes/" + id + "/revoke"},
	} {
		if code, body := b.do(c[0], c[1], `{"name":"evil","role":"edge"}`); code != http.StatusForbidden {
			t.Fatalf("%s %s as plain user: want 403, got %d: %s", c[0], c[1], code, body)
		}
		if code, _ := anon.do(c[0], c[1], `{"name":"evil","role":"edge"}`); code != http.StatusUnauthorized {
			t.Fatalf("%s %s unauthenticated: want 401, got %d", c[0], c[1], code)
		}
	}
}
