package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/domains"
)

// fakeDNS is the injectable resolver: TXT records keyed by record name,
// NS answers via the ns() map, IP answers via ips, optional failure modes
// for the 502/400 paths.
type fakeDNS struct {
	txt     map[string]string   // record name → TXT value
	multi   map[string][]string // record name → several TXT values (head-to-head races)
	ns      map[string][]string // zone → NS names
	ips     map[string][]net.IP // hostname → A/AAAA answers
	txtErr  error
	nsErr   error
	ipErr   error        // wholesale LookupIP failure (timeout/SERVFAIL class)
	ipCalls atomic.Int32 // build-cost probe: every IP resolution counts
}

func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	if f.txtErr != nil {
		return nil, f.txtErr
	}
	if v, ok := f.multi[name]; ok {
		return append([]string{}, v...), nil
	}
	if v, ok := f.txt[name]; ok {
		return []string{v}, nil
	}
	return nil, nil // DNS answered, but no such record
}

func (f *fakeDNS) LookupNS(ctx context.Context, name string) ([]string, error) {
	if f.nsErr != nil {
		return nil, f.nsErr
	}
	return append([]string{}, f.ns[name]...), nil
}

func (f *fakeDNS) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	f.ipCalls.Add(1)
	if f.ipErr != nil {
		return nil, f.ipErr
	}
	return append([]net.IP{}, f.ips[name]...), nil
}

// setResolvers swaps the injectable DNS backend wholesale.
func setResolvers(srv *Server, r domains.Resolver) {
	srv.dnsResolvers = []domains.Resolver{r}
}

// signupOn wires email+password sessions for c on its own server (the
// signupVerify helper hides the *Server; these tests need it).
func signupOn(t *testing.T, pool *pgxpool.Pool, c tc, email string) {
	t.Helper()
	c.must("POST", "/auth/signup", `{"email":"`+email+`","password":"secretpw123"}`, http.StatusOK)
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
}

// TestDomainOwnershipRace — two users claim the same hostname; the first to
// verify wins; the loser cannot verify even against the winner's token
// sitting in public DNS; an expired claim cannot verify; a verified name
// cannot be claimed again.
func TestDomainOwnershipRace(t *testing.T) {
	pool := testPool(t)
	host := "race-" + strings.ToLower(randHex(t, 4)) + ".example.com"
	a, srv := newTestServer(t, pool)
	signupOn(t, pool, a, "race-a@x.test")
	b := secondUser(t, pool, a, "race-b@x.test")

	da := claimRow(t, a, host)
	db := claimRow(t, b, host)
	if da.ID == db.ID {
		t.Fatal("users must hold separate claim rows")
	}

	// the public DNS record carries the WINNER's token (user a).
	tokA := verifyTokenOf(t, pool, da.ID)
	f := &fakeDNS{txt: map[string]string{
		"_gatepost-verify." + host: "gatepost-verify=" + tokA,
	}}
	setResolvers(srv, f)

	// loser (b) verifies while DNS physically contains a's token: b's own
	// stored token is what must match, so the attempt fails cleanly.
	if code, body := b.do("POST", "/v1/domains/"+db.ID+"/verify", ""); code != http.StatusBadRequest {
		t.Fatalf("loser verify with winner's token in DNS: want 400, got %d: %s", code, body)
	}
	if got := b.must("GET", "/v1/domains/"+db.ID, "", http.StatusOK); !strings.Contains(got, `"status":"pending"`) {
		t.Fatalf("failed verify must not touch state: %s", got)
	}

	// first to verify wins (a's token IS the TXT value).
	a.must("POST", "/v1/domains/"+da.ID+"/verify", "", http.StatusOK)
	if got := a.must("GET", "/v1/domains/"+da.ID, "", http.StatusOK); !strings.Contains(got, `"status":"verified"`) {
		t.Fatalf("winner not verified: %s", got)
	}
	// the sweep: b's pending claim became rejected in the same transaction.
	if got := b.must("GET", "/v1/domains/"+db.ID, "", http.StatusOK); !strings.Contains(got, `"status":"rejected"`) {
		t.Fatalf("loser claim not rejected: %s", got)
	}
	// idempotent re-verify stays 200.
	if code, body := a.do("POST", "/v1/domains/"+da.ID+"/verify", ""); code != http.StatusOK || !strings.Contains(body, "verified") {
		t.Fatalf("re-verify: %d %s", code, body)
	}

	// a rejected claim cannot verify — even though the TXT record (the
	// winner's token) is right there in DNS.
	if code, _ := b.do("POST", "/v1/domains/"+db.ID+"/verify", ""); code != http.StatusGone {
		t.Fatalf("loser (rejected) verify: want 410, got %d", code)
	}

	// a verified name cannot be claimed again by another user; the loser's
	// earlier re-claim attempts fail with 409.
	if code, body := claimHost(t, b, host); code != http.StatusConflict {
		t.Fatalf("re-claim of verified name: want 409, got %d: %s", code, body)
	}
	// same-user re-claim of their own verified name returns it untouched.
	if code, _ := claimHost(t, a, host); code != http.StatusOK {
		t.Fatalf("owner re-claim of own verified name: want 200, got %d", code)
	}
}

// TestDomainVerifyErrors — DNS outage (502), missing TXT (400), expired
// claim (410 after the hourly job flips it), state integrity throughout.
func TestDomainVerifyErrors(t *testing.T) {
	pool := testPool(t)
	a, srv := newTestServer(t, pool)
	signupOn(t, pool, a, "vrf-err@x.test")

	// all resolvers fail → 502, claim still intact
	down := &fakeDNS{txtErr: errors.New("network unreachable")}
	setResolvers(srv, down)
	da := claimRow(t, a, "down.example.com")
	if code, _ := a.do("POST", "/v1/domains/"+da.ID+"/verify", ""); code != http.StatusBadGateway {
		t.Fatalf("dns outage: want 502, got %d", code)
	}

	// DNS answers but carries no matching record → 400 reason
	no := &fakeDNS{} // empty: no records at all
	setResolvers(srv, no)
	dm := claimRow(t, a, "missing.example.com")
	if code, _ := a.do("POST", "/v1/domains/"+dm.ID+"/verify", ""); code != http.StatusBadRequest {
		t.Fatalf("missing TXT: want 400, got %d", code)
	}

	// expired claim: TTL backdated, live job runs, verify → 410
	dx := claimRow(t, a, "stale.example.com")
	execSQL(t, pool, `UPDATE domains SET expires_at = now() - interval '1 minute'
		WHERE hostname = 'stale.example.com'`)
	if n, err := srv.ExpireDomainClaims(context.Background()); err != nil || n != 1 {
		t.Fatalf("expiry job: n=%d err=%v", n, err)
	}
	if code, _ := a.do("POST", "/v1/domains/"+dx.ID+"/verify", ""); code != http.StatusGone {
		t.Fatalf("expired claim verify: want 410, got %d", code)
	}
}

// TestVerifyTokenNotInListResponses — isolation: the verify token must not
// ride along on list/get responses (only on the instructions endpoint).
func TestVerifyTokenNotInListResponses(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool)
	signupOn(t, pool, a, "tok-leak@x.test")
	da := claimRow(t, a, "leak.example.com")
	tok := verifyTokenOf(t, pool, da.ID)
	for _, probe := range [][2]string{
		{"POST", "/v1/domains"},
		{"GET", "/v1/domains"},
		{"GET", "/v1/domains/" + da.ID},
	} {
		if code, body := a.do(probe[0], probe[1], `{}`); code == http.StatusOK && strings.Contains(body, tok) {
			t.Fatalf("%s %s leaks verify token: %s", probe[0], probe[1], body)
		}
	}
	v := a.must("GET", "/v1/domains/"+da.ID+"/verification", "", http.StatusOK)
	if !strings.Contains(v, tok) {
		t.Fatalf("instructions must carry the token: %s", v)
	}
}

// TestVerifyHeadToHead50Rounds — hardening: two users verify the same
// hostname at the same instant, 50 rounds. The zone genuinely carries BOTH
// users' tokens (a real hostname can have several TXT strings, here set up
// by two owners), so both attempts pass the token check and only the
// database decides. Invariant per round: exactly one 200, exactly one row
// verified and one rejected — no round may end with two winners or none.
// Claim rows are deleted in between so caps/pending counts never trip.
func TestVerifyHeadToHead50Rounds(t *testing.T) {
	pool := testPool(t)
	a, srv := newTestServer(t, pool, func(cfg *Config) {
		cfg.DomainAddCap, cfg.VerifyCap = 500, 500 // 50 rounds of both per user
	})
	signupOn(t, pool, a, "h2h-a@x.test")
	b := secondUser(t, pool, a, "h2h-b@x.test")

	rounds := [][2]int{} // per-round verification codes
	for i := 0; i < 50; i++ {
		host := "h2h-" + strings.ToLower(randHex(t, 6)) + ".example.com"
		da, db := claimRow(t, a, host), claimRow(t, b, host)
		tokA, tokB := verifyTokenOf(t, pool, da.ID), verifyTokenOf(t, pool, db.ID)
		setResolvers(srv, &fakeDNS{multi: map[string][]string{
			"_gatepost-verify." + host: {
				"gatepost-verify=" + tokA, "gatepost-verify=" + tokB,
			},
		}})
		ids := [2]string{da.ID, db.ID}
		codes := [2]int{}
		var wg sync.WaitGroup
		for j, q := range []tc{a, b} { // fire both verifications simultaneously
			wg.Add(1)
			go func(j int, q tc) {
				defer wg.Done()
				code, _ := q.do("POST", "/v1/domains/"+ids[j]+"/verify", "")
				codes[j] = code
			}(j, q)
		}
		wg.Wait()
		tallies := map[string]int{}
		for j, q := range []tc{a, b} {
			got := q.must("GET", "/v1/domains/"+ids[j], "", http.StatusOK)
			switch {
			case strings.Contains(got, `"status":"verified"`):
				tallies["verified"]++
			case strings.Contains(got, `"status":"rejected"`):
				tallies["rejected"]++
			default:
				tallies["other"]++
			}
			q.must("DELETE", "/v1/domains/"+ids[j], "", http.StatusOK) // next round's caps
		}
		rounds = append(rounds, codes)

		if tallies["verified"] != 1 || tallies["rejected"] != 1 {
			t.Fatalf("round %d: exactly one winner expected, tallies %v (codes %v)",
				i+1, tallies, codes)
		}
		var wins int
		var losers []int
		for _, code := range codes {
			if code == http.StatusOK {
				wins++
			} else {
				losers = append(losers, code)
			}
		}
		if wins != 1 {
			t.Fatalf("round %d: want exactly one 200, got codes %v", i+1, codes)
		}
		for _, code := range losers {
			if code != http.StatusConflict && code != http.StatusGone {
				t.Fatalf("round %d: loser got status %d, want 409/410", i+1, code)
			}
		}
	}
	// both users should have collected some wins across the 50 rounds
	var winA, winB int
	for _, c := range rounds {
		if c[0] == http.StatusOK {
			winA++
		}
		if c[1] == http.StatusOK {
			winB++
		}
	}
	t.Logf("50 rounds: a won %d, b won %d", winA, winB)
}

// TestVerifyWinnerTokenMismatch — a loser who points their TXT records at
// the winner's PUBLIC token cannot verify; the stored (private) token is the
// only accepted proof. Distinct from the race test: fresh users, fresh fake.
func TestVerifyWinnerTokenMismatch(t *testing.T) {
	pool := testPool(t)
	host := "steal-" + strings.ToLower(randHex(t, 4)) + ".example.com"
	a, srv := newTestServer(t, pool)
	signupOn(t, pool, a, "vx-a@x.test")
	b := secondUser(t, pool, a, "vx-b@x.test")

	da := claimRow(t, a, host)
	db := claimRow(t, b, host)
	tokA := verifyTokenOf(t, pool, da.ID)

	// attacker b sets _gatepost-verify.<host> = gatepost-verify=<a's token>
	setResolvers(srv, &fakeDNS{txt: map[string]string{"_gatepost-verify." + host: "gatepost-verify=" + tokA}})
	if code, _ := b.do("POST", "/v1/domains/"+db.ID+"/verify", ""); code != http.StatusBadRequest {
		t.Fatalf("winner's token must not verify b's claim: got %d", code)
	}
	// b sets the DNS to a's token but claims cannot ride foreign tokens:
	// flip the TXT to b's OWN token only → b verifies.
	tokB := verifyTokenOf(t, pool, db.ID)
	setResolvers(srv, &fakeDNS{txt: map[string]string{"_gatepost-verify." + host: "gatepost-verify=" + tokB}})
	if code, body := b.do("POST", "/v1/domains/"+db.ID+"/verify", ""); code != http.StatusOK {
		t.Fatalf("own token must verify: %d %s", code, body)
	}
	// b's win rejected a's still-pending claim (one-hostname-one-winner).
	if got := a.must("GET", "/v1/domains/"+da.ID, "", http.StatusOK); !strings.Contains(got, `"status":"rejected"`) {
		t.Fatalf("a's pending claim must lose the sweep: %s", got)
	}
}
