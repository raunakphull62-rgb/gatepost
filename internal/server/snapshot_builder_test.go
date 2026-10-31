package server

import (
	"bytes"
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/snapshot"
)

// snapshotSetup — loopback-hook server, a flippable resolver, a verified
// user, and the pool for direct SQL tweaks.
func snapshotSetup(t *testing.T) (*pgxpool.Pool, tc, *fakeDNS, *Server) {
	t.Helper()
	pool := testPool(t)
	a, s := newTestServer(t, pool, func(cfg *Config) { cfg.TestAllowLoopback = true })
	signupOn(t, pool, a, "snap@x.test")
	f := &fakeDNS{ips: map[string][]net.IP{}} // tests add entries as they go
	setResolvers(s, f)
	return pool, a, f, s
}

// verifiedClaim claims a hostname and flips it to verified status through
// the fake's TXT map (other zones' entries stay), so the artifact will see it.
func verifiedClaim(t *testing.T, pool *pgxpool.Pool, a tc, f *fakeDNS, host string) domainRow {
	t.Helper()
	row := claimRow(t, a, host)
	if f.txt == nil {
		f.txt = map[string]string{}
	}
	f.txt["_gatepost-verify."+host] = "gatepost-verify=" + verifyTokenOf(t, pool, row.ID)
	a.must("POST", "/v1/domains/"+row.ID+"/verify", "", http.StatusOK)
	return row
}

// literalOrigin adds one IP-literal origin to the given domain.
func literalOrigin(t *testing.T, a tc, domID string) {
	t.Helper()
	if code, body := originCall(t, a, domID, map[string]any{"address": "93.184.216.34"}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
}

func contentHashOf(t *testing.T, d snapshot.Document) string {
	t.Helper()
	h, err := snapshot.Hash(d.ToContent())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestBuildSnapshotInclusions — only VERIFIED domains with an origin reach
// the artifact; verified-without-origin, pending, rejected and expired stay
// out; canonical origin fields and the fixed defaults ride along.
func TestBuildSnapshotInclusions(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)

	// one verified entry carried by hostname resolution...
	f.ips["orig.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	rowHost := verifiedClaim(t, pool, a, f, "orig.example.com")
	if code, body := originCall(t, a, rowHost.ID, map[string]any{"address": "orig.example.com", "port": 8443}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	// ...and a second one by IP literal
	rowLit := verifiedClaim(t, pool, a, f, "literal.example.com")
	literalOrigin(t, a, rowLit.ID)

	// a verified domain WITHOUT an origin stays out
	verifiedClaim(t, pool, a, f, "noorigin.example.com")
	// a pending one WITH an origin stays out
	literalOrigin(t, a, claimRow(t, a, "pending.example.com").ID)
	// a rejected one WITH an origin stays out
	literalOrigin(t, a, claimRow(t, a, "rejected.example.com").ID)
	execSQL(t, pool, `UPDATE domains SET status = 'rejected' WHERE hostname = 'rejected.example.com'`)
	// an expired one WITH an origin stays out
	literalOrigin(t, a, claimRow(t, a, "expired.example.com").ID)
	execSQL(t, pool, `UPDATE domains SET status = 'expired' WHERE hostname = 'expired.example.com'`)

	doc, env, err := s.buildSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Domains) != 2 {
		t.Fatalf("exactly 2 entries expected, got %d: %+v", len(doc.Domains), doc.Domains)
	}
	if doc.Domains[0].Hostname != "literal.example.com" || doc.Domains[1].Hostname != "orig.example.com" {
		t.Fatalf("entries must be hostname-ordered: %+v", doc.Domains)
	}
	o := doc.Domains[1].Origin
	if o.Address != "orig.example.com" || o.Port != 8443 || o.Scheme != "https" || !o.TLSVerify || o.HostHeader != nil {
		t.Fatalf("origin fields wrong: %+v", o)
	}
	if doc.Defaults.FirewallMode != "log_only" || !doc.Defaults.Cache {
		t.Fatalf("defaults wrong: %+v", doc.Defaults)
	}
	// (the absolute generation moved during setup: every domain create now
	// runs the size gate, which builds — same content still records the
	// same generation, proven in TestBuildSnapshotVersionBumps)
	if doc.SchemaVersion != snapshot.SchemaVersion || doc.Generation < 1 {
		t.Fatalf("bookkeeping wrong: %+v", doc)
	}
	if got := strings.Join(doc.AllowedHostnames, ","); got != "literal.example.com,orig.example.com" {
		t.Fatalf("allowed hostnames wrong: %q", got)
	}
	// the envelope really verifies with the server's key
	if _, err := snapshot.Verify([]byte("gatepost-development-snapshot-key"), env, 0); err != nil {
		t.Fatalf("built artifact must verify: %v", err)
	}
}

// TestBuildSnapshotRecheckDrops — an origin whose hostname has since started
// resolving into a deny range (here: cloud metadata) is dropped at build
// time and the drop is logged with the reason; the artifact never carries it.
func TestBuildSnapshotRecheckDrops(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)
	f.ips["flip.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	row := verifiedClaim(t, pool, a, f, "flip.example.com")
	if code, body := originCall(t, a, row.ID, map[string]any{"address": "flip.example.com"}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	f.ips["flip.example.com"] = []net.IP{net.ParseIP("169.254.169.254")} // moved after create

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	doc, _, err := s.buildSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Domains) != 0 {
		t.Fatalf("the moved origin must be dropped, got %+v", doc.Domains)
	}
	if out := buf.String(); !strings.Contains(out, "dropped") || !strings.Contains(out, "169.254") {
		t.Fatalf("the drop must be logged with the reason: %q", out)
	}
}

// TestBuildSnapshotVersionBumps — a changed origin moves the generation; an
// untouched rebuild keeps it (the 304 path of item 4 rests on this).
func TestBuildSnapshotVersionBumps(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)
	row := verifiedClaim(t, pool, a, f, "bump.example.com")
	if code, body := originCall(t, a, row.ID, map[string]any{"address": "93.184.216.34", "port": 80}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	ctx := context.Background()
	d1, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if code, body := a.do("PUT", "/v1/domains/"+row.ID+"/origin",
		`{"scheme":"https","address":"93.184.216.34","port":443}`); code != http.StatusOK {
		t.Fatalf("origin update: %d %s", code, body)
	}
	d2, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Generation != d1.Generation+1 {
		t.Fatalf("content changed, generation must bump: %d → %d", d1.Generation, d2.Generation)
	}
	// an untouched rebuild keeps both the generation and the content hash
	d3, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d3.Generation != d2.Generation {
		t.Fatalf("unchanged rebuild must keep the generation: %d vs %d", d2.Generation, d3.Generation)
	}
	if h2, h3 := contentHashOf(t, d2), contentHashOf(t, d3); h2 != h3 {
		t.Fatal("unchanged rebuild must hash equal")
	}
}

// TestDomainCreateSnapshotCapGate — B3c item 2b: when the artifact cannot
// build (here: over the size cap at Sign), domain creation is refused with a
// clear 4xx, the failure is logged, and an open operator alert fires that the
// next successful build auto-resolves.
func TestDomainCreateSnapshotCapGate(t *testing.T) {
	pool, a, _, s := snapshotSetup(t)
	ctx := context.Background()

	// Bulk-insert verified domains with IP-literal origins for a SECOND user
	// (their own server, same pool): the per-user claim caps must not fire
	// before the snapshot gate. Direct SQL: the HTTP claim path would
	// rate-limit; this is setup, not the test. ~240B per entry measured —
	// 1200 entries ≈ 285KB, over the 256KB cap.
	b, _ := newTestServer(t, pool)
	signupOn(t, pool, b, "bulk@x.test")
	var uid string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM users WHERE email = 'bulk@x.test'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO domains
		(owner_user_id, hostname, status, verify_token, verified_at, waf_mode)
		SELECT $1::uuid, 'cap-' || g || '.loadcap.example', 'verified', 'tok-' || g, now(), 'detection'
		FROM generate_series(1, 1200) g`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO origins (domain_id, scheme, address, port)
		SELECT id, 'http', '93.184.216.34', 80 FROM domains WHERE hostname LIKE 'cap-%'`); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// The build fails the cap at Sign; the create is refused 422, loudly.
	if code, body := a.do("POST", "/v1/domains", `{"hostname":"fresh.example.com"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("create at cap: want 422, got %d: %s", code, body)
	}
	if !strings.Contains(buf.String(), "snapshot build FAILED") {
		t.Fatalf("build failure not logged:\n%s", buf.String())
	}
	if n := countRows(t, pool, "operator_alerts", "kind = 'snapshot_build_failed' AND resolved_at IS NULL"); n != 1 {
		t.Fatalf("open snapshot_build_failed alerts = %d, want 1", n)
	}

	// Shrinking the artifact heals it: the next build succeeds, the alert
	// auto-resolves, and creation works again.
	if _, err := pool.Exec(ctx, `DELETE FROM domains WHERE hostname LIKE 'cap-%'`); err != nil {
		t.Fatal(err)
	}
	s.invalidateSnapshot() // raw SQL writes bypass the write hooks
	a.must("POST", "/v1/domains", `{"hostname":"fresh.example.com"}`, http.StatusCreated)
	if n := countRows(t, pool, "operator_alerts", "kind = 'snapshot_build_failed' AND resolved_at IS NULL"); n != 0 {
		t.Fatalf("snapshot_build_failed alert must auto-resolve, %d still open", n)
	}
}
