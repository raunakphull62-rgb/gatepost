package server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// nsVerifySetup — user on a nameserver-configured server with an injectable
// fake carrying NS answers.
func nsVerifySetup(t *testing.T) (*pgxpool.Pool, tc, *Server, *fakeDNS) {
	t.Helper()
	pool := testPool(t)
	a, s := newTestServer(t, pool, nsCfg(true))
	signupOn(t, pool, a, "nsverify@x.test")
	f := &fakeDNS{ns: map[string][]string{}, ips: map[string][]net.IP{}}
	setResolvers(s, f)
	return pool, a, s, f
}

// regNS claims a unique registrable domain in nameserver mode; returns
// hostname and row id.
func regNS(t *testing.T, c tc, tag string) (string, string) {
	t.Helper()
	host := strings.ToLower(tag + "-ns-" + strings.ToLower(randHex(t, 3)) + ".com")
	code, body := claimNS(t, c, host, "nameserver")
	if code != http.StatusCreated {
		t.Fatalf("claim %s: %d %s", tag, code, body)
	}
	var got struct {
		Domain domainRow `json:"domain"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	return host, got.Domain.ID
}

// TestNSDelegationVerify — the delegation rules of item 11: the hostname's
// NS set must equal the assigned pair exactly (order/case/trailing-dot
// flexible); the win uses the same one-transaction sweep as TXT.
func TestNSDelegationVerify(t *testing.T) {
	pool, a, _, f := nsVerifySetup(t)

	// exact match wins
	host, id := regNS(t, a, "exact1")
	f.ns[host] = []string{"ns2.gatepost.test.", "NS1.GATEPOST.TEST"}
	if code, body := a.do("POST", "/v1/domains/"+id+"/verify", ""); code != http.StatusOK || !strings.Contains(body, `"status":"verified"`) {
		t.Fatalf("exact delegation: %d %s", code, body)
	}
	if got := a.must("GET", "/v1/domains/"+id, "", http.StatusOK); !strings.Contains(got, `"status":"verified"`) {
		t.Fatalf("row state: %s", got)
	}

	// partial: only one of the two delegated
	host2, id2 := regNS(t, a, "part")
	f.ns[host2] = []string{"ns1.gatepost.test"}
	if code, body := a.do("POST", "/v1/domains/"+id2+"/verify", ""); code != http.StatusBadRequest || !strings.Contains(body, "missing:ns2.gatepost.test") {
		t.Fatalf("partial delegation: %d %s", code, body)
	}
	// extra: the pair plus a rogue third
	f.ns[host2] = []string{"ns1.gatepost.test", "ns2.gatepost.test", "rogue.example.net"}
	if code, body := a.do("POST", "/v1/domains/"+id2+"/verify", ""); code != http.StatusBadRequest || !strings.Contains(body, "unexpected:rogue.example.net") {
		t.Fatalf("extra delegation: %d %s", code, body)
	}
	// none
	f.ns[host2] = nil
	if code, body := a.do("POST", "/v1/domains/"+id2+"/verify", ""); code != http.StatusBadRequest || !strings.Contains(body, "no NS records") {
		t.Fatalf("no delegation: %d %s", code, body)
	}
	// state untouched by the failures
	if got := a.must("GET", "/v1/domains/"+id2, "", http.StatusOK); !strings.Contains(got, `"status":"pending"`) {
		t.Fatalf("failed verifies must not touch state: %s", got)
	}

	// DNS outage → 502; recovery → the pending claim still verifies
	host3, id3 := regNS(t, a, "down")
	f.ns[host3] = []string{"ns1.gatepost.test", "ns2.gatepost.test"}
	f.nsErr = errors.New("timed out")
	if code, _ := a.do("POST", "/v1/domains/"+id3+"/verify", ""); code != http.StatusBadGateway {
		t.Fatalf("ns dns outage: want 502, got %d", code)
	}
	f.nsErr = nil
	if code, _ := a.do("POST", "/v1/domains/"+id3+"/verify", ""); code != http.StatusOK {
		t.Fatalf("recovered delegation: %d", code)
	}

	// competing claims: first to verify wins, the other is swept rejected
	host4, idA := regNS(t, a, "race")
	b := secondUser(t, pool, a, "nsrace-b@x.test")
	idB, ok := claimNSRow(t, b, host4)
	if !ok {
		t.Fatal("b's row on the same hostname missing")
	}
	f.ns[host4] = []string{"ns1.gatepost.test", "ns2.gatepost.test"}
	if code, body := b.do("POST", "/v1/domains/"+idB+"/verify", ""); code != http.StatusOK || !strings.Contains(body, `"status":"verified"`) {
		t.Fatalf("b first-to-verify: %d %s", code, body)
	}
	if got := a.must("GET", "/v1/domains/"+idA, "", http.StatusOK); !strings.Contains(got, `"status":"rejected"`) {
		t.Fatalf("a's pending claim must be swept: %s", got)
	}
	if code, _ := a.do("POST", "/v1/domains/"+idA+"/verify", ""); code != http.StatusGone {
		t.Fatalf("a verify after the sweep: want 410, got %d", code)
	}
}
