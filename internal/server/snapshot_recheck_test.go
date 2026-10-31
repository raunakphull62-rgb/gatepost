package server

// B3a: build-time origin re-check classes. An origin that now resolves into
// a blocked range is DEFINITELY unsafe — drop, log, operator alert. One that
// cannot be re-checked right now (timeout, SERVFAIL, zero answers after it
// used to answer) is NOT a verdict — keep the latest good entry and retry
// the next build.
import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

// nameFailDNS — per-name LookupIP failure on top of the shared fake.
type nameFailDNS struct {
	*fakeDNS
	failIP map[string]error
}

func (n *nameFailDNS) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	if err, ok := n.failIP[name]; ok {
		return nil, err
	}
	return n.fakeDNS.LookupIP(ctx, name)
}

// TestBuildRecheckUnsafeAndTransient — one origin whose hostname moved into
// a deny range is dropped with an operator alert; one whose re-check merely
// fails (timeout, then NXDOMAIN class) stays in the snapshot untouched. The
// recovery build also walks the A→B→A case end to end through the builder.
func TestBuildRecheckUnsafeAndTransient(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)
	f.ips["unsafe.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	f.ips["transient.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	rowU := verifiedClaim(t, pool, a, f, "unsafe.example.com")
	if code, body := originCall(t, a, rowU.ID, map[string]any{"address": "unsafe.example.com", "port": 80}); code != http.StatusCreated {
		t.Fatalf("unsafe origin create: %d %s", code, body)
	}
	rowT := verifiedClaim(t, pool, a, f, "transient.example.com")
	if code, body := originCall(t, a, rowT.ID, map[string]any{"address": "transient.example.com", "port": 80}); code != http.StatusCreated {
		t.Fatalf("transient origin create: %d %s", code, body)
	}

	ctx := context.Background()
	d1, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(d1.Domains) != 2 || d1.Generation < 1 {
		t.Fatalf("first build: want 2 entries, got %d entries gen %d", len(d1.Domains), d1.Generation)
	}

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	// the flip: unsafe.example.com answers into the metadata range now, the
	// transient one's lookup errors (timeout class, per-name wrapper)
	f.ips["unsafe.example.com"] = []net.IP{net.ParseIP("169.254.169.254")}
	setResolvers(s, &nameFailDNS{fakeDNS: f, failIP: map[string]error{
		"transient.example.com": errors.New("read udp: i/o timeout"),
	}})
	d2, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.Domains) != 1 || d2.Domains[0].Hostname != "transient.example.com" {
		t.Fatalf("unsafe must drop, transient must stay: %+v", d2.Domains)
	}
	if d2.Generation != d1.Generation+1 {
		t.Fatalf("content changed (one entry dropped), generation must bump: %d → %d", d1.Generation, d2.Generation)
	}
	if out := buf.String(); !strings.Contains(out, "dropped unsafe.example.com") ||
		!strings.Contains(out, "169.254.169.254") ||
		!strings.Contains(out, "WARNING transient.example.com") {
		t.Fatalf("log must carry the drop AND the transient warning: %q", out)
	}
	if n := countRows(t, pool, "operator_alerts", "kind = 'origin_unsafe'"); n != 1 {
		t.Fatalf("one open alert expected, got %d", n)
	}

	// second failing build: transient still kept, the alert is not duplicated
	d3, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d3.Generation != d2.Generation || len(d3.Domains) != 1 {
		t.Fatalf("unchanged bad state must keep content and generation: %+v", d3.Domains)
	}
	if n := countRows(t, pool, "operator_alerts", "kind = 'origin_unsafe'"); n != 1 {
		t.Fatalf("alerts must dedupe in the DB, got %d", n)
	}

	// recovery: the unsafe name answers with the good IP again — content is
	// back to the FIRST build's shape (A→B→A), so the NEXT number is taken,
	// never an earlier version's number reused
	setResolvers(s, f)
	f.ips["unsafe.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	d4, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(d4.Domains) != 2 || d4.Generation != d2.Generation+1 {
		t.Fatalf("recovered build: want 2 entries gen %d, got %d entries gen %d", d2.Generation+1, len(d4.Domains), d4.Generation)
	}

	// NXDOMAIN class (zero answers after previously answering): NOT a drop
	delete(f.ips, "unsafe.example.com")
	d5, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(d5.Domains) != 2 || d5.Generation != d4.Generation {
		t.Fatalf("NXDOMAIN must keep the entry and the generation: %d entries gen %d", len(d5.Domains), d5.Generation)
	}

	// timeout class through the wrapper: same keep
	setResolvers(s, &nameFailDNS{fakeDNS: f, failIP: map[string]error{
		"unsafe.example.com": errors.New("read udp: i/o timeout"),
	}})
	d6, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(d6.Domains) != 2 || d6.Generation != d4.Generation {
		t.Fatalf("timeout must keep the entry and the generation: %d entries gen %d", len(d6.Domains), d6.Generation)
	}
	if n := countRows(t, pool, "operator_alerts", "kind = 'origin_unsafe'"); n != 1 {
		t.Fatalf("kept entries must never raise alerts, got %d", n)
	}
}

// TestBuildUnsafeAlertAutoResolves — the origin_unsafe alert is not a scar
// forever: the first build that re-checks the origin as safe clears it, and
// a later violation raises a fresh open row.
func TestBuildUnsafeAlertAutoResolves(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)
	f.ips["flap.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	row := verifiedClaim(t, pool, a, f, "flap.example.com")
	if code, body := originCall(t, a, row.ID, map[string]any{"address": "flap.example.com", "port": 80}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	ctx := context.Background()
	flip := func(ip string) {
		f.ips["flap.example.com"] = []net.IP{net.ParseIP(ip)}
	}
	open := func() int {
		return countRows(t, pool, "operator_alerts", "kind = 'origin_unsafe' AND resolved_at IS NULL")
	}

	flip("169.254.169.254")
	if _, _, err := s.buildSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != 1 {
		t.Fatalf("the violation must raise one open alert, got %d", open())
	}

	flip("93.184.216.34") // safe again by resolution → resolved_at stamps
	if _, _, err := s.buildSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != 0 {
		t.Fatalf("recovering builds must auto-resolve the alert, %d still open", open())
	}

	flip("169.254.169.254") // a new violation: a new open alert
	if _, _, err := s.buildSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != 1 {
		t.Fatalf("a fresh violation must raise a fresh alert, got %d", open())
	}
}

// TestBuildUnresolvedTimeAlerts — unresolvable never drops the entry; the
// persistence alert keys on WALL-CLOCK (GP_ORIGIN_UNRESOLVED_MINUTES,
// here the untouched default: 60 minutes): any number of builds before the
// hour stay silent, the first build after the.timestamp passes the threshold
// raises (backdated via SQL, no sleeps), recovery resolves and clears.
func TestBuildUnresolvedTimeAlerts(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)
	f.ips["kx.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	row := verifiedClaim(t, pool, a, f, "kx.example.com")
	if code, body := originCall(t, a, row.ID, map[string]any{"address": "kx.example.com", "port": 80}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}
	ctx := context.Background()
	fail := func() {
		setResolvers(s, &nameFailDNS{fakeDNS: f, failIP: map[string]error{
			"kx.example.com": errors.New("read udp: i/o timeout"),
		}})
	}
	recover := func() { setResolvers(s, f) }
	open := func() int {
		return countRows(t, pool, "operator_alerts", "kind = 'origin_unresolved' AND resolved_at IS NULL")
	}

	fail()
	for i := 0; i < 5; i++ { // ANY number of builds inside the hour stays silent
		doc, _, err := s.buildSnapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(doc.Domains) != 1 {
			t.Fatalf("build %d: unresolved must never drop the entry: %+v", i, doc.Domains)
		}
	}
	if open() != 0 {
		t.Fatalf("inside the hour no alert may exist, got %d", open())
	}
	if kind := countRows(t, pool, "origin_unresolved", "true"); kind != 1 {
		t.Fatalf("the tracker row must exist (first_unresolved_at set), got %d", kind)
	}

	// tipping the clock via SQL — no sleeps: the next build sees an hour old
	execSQL(t, pool, `UPDATE origin_unresolved SET first_unresolved_at = now() - interval '61 minutes'`)
	if _, _, err := s.buildSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != 1 {
		t.Fatalf("past the threshold the next build must raise the alert, got %d", open())
	}

	recover() // resolved by the next good re-check, and the tracker row cleared
	if _, _, err := s.buildSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != 0 {
		t.Fatalf("recovery must auto-resolve the persistence alert, %d open", open())
	}
	if got := countRows(t, pool, "origin_unresolved", "true"); got != 0 {
		t.Fatalf("recovery must clear the tracker row, got %d", got)
	}

	// a fresh outage is a fresh one-hour clock that does NOT inherit the old one
	fail()
	if _, _, err := s.buildSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if open() != 0 {
		t.Fatalf("the fresh outage starts its own clock, got an alert anyway (%d)", open())
	}
}
