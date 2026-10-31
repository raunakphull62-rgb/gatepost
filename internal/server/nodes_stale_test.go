package server

// Tests for B3c item 2c Q7a: the control-plane stale-node alert. An ACTIVE node
// that stops heartbeating opens one node_stale alert (deduped by the DB per
// 008), auto-resolved by the next heartbeat. Nodes that never connected are
// never alerted — "never seen" is not "gone silent".
import (
	"context"
	"net/http"
	"strconv"
	"testing"
)

// TestStaleNodeAlertOpenDedupResolve — a node that once heartbeated but has
// gone silent for > NodeStaleMinutes opens exactly one open node_stale alert;
// a second sweep does not insert a duplicate (in-DB dedupe on the open index);
// and a valid heartbeat auto-resolves it (the row is resolved, not deleted).
// After resolution, re-silencing opens a fresh row.
func TestStaleNodeAlertOpenDedupResolve(t *testing.T) {
	pool, a, _, s, tok := nodeSetup(t)
	n := asNode(t, a, tok)
	ctx := context.Background()

	// e1 exists but never heartbeated: last_seen IS NULL → never alert.
	id := nodeIDOf(t, a.must("GET", "/v1/nodes", "", http.StatusOK), "e1")
	if found, err := s.SweepStaleNodes(ctx); err != nil || found != 0 {
		t.Fatalf("never-connected node must not alert: found=%d err=%v", found, err)
	}
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale'"); got != 0 {
		t.Fatalf("never-connected node must not alert: got %d node_stale row(s)", got)
	}

	// Backdate e1's last_seen past the default 10-min threshold.
	if _, err := pool.Exec(ctx,
		`UPDATE nodes SET last_seen = now() - interval '20 minutes' WHERE name = 'e1'`); err != nil {
		t.Fatal(err)
	}
	// A build creates a real generation so the heartbeat below is valid.
	doc, _, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// First sweep: opens one open node_stale alert for e1 (subject = node id).
	if _, err := s.SweepStaleNodes(ctx); err != nil {
		t.Fatalf("sweep err: %v", err)
	}
	if got := countRows(t, pool, "operator_alerts",
		"kind = 'node_stale' AND subject = '"+id+"' AND resolved_at IS NULL"); got != 1 {
		t.Fatalf("open node_stale for e1 = %d, want 1", got)
	}

	// Second sweep: deduped — the alert stays single-row (no duplicate insert),
	// even though the silent node is found again.
	if found, err := s.SweepStaleNodes(ctx); err != nil || found != 1 {
		t.Fatalf("dedup sweep: found=%d err=%v, want found=1 (silent node found, alert already open)", found, err)
	}
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale'"); got != 1 {
		t.Fatalf("dedup must not insert a duplicate row: total node_stale = %d, want 1", got)
	}

	// A valid heartbeat stamps last_seen and auto-resolves the alert.
	if code, body := n.do("POST", "/node/v1/heartbeat",
		`{"generation":`+strconv.FormatInt(doc.Generation, 10)+`}`); code != http.StatusOK {
		t.Fatalf("heartbeat: want 200, got %d %s", code, body)
	}
	if got := countRows(t, pool, "operator_alerts",
		"kind = 'node_stale' AND subject = '"+id+"' AND resolved_at IS NULL"); got != 0 {
		t.Fatalf("heartbeat must auto-resolve node_stale: %d still open", got)
	}
	// the row is resolved, not deleted — history of the incident remains
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale'"); got != 1 {
		t.Fatalf("resolved alert row should remain: got %d, want 1", got)
	}

	// a refused heartbeat (unknown generation) must NOT resolve anything:
	// re-silence and confirm a NEW open alert can be raised after resolution.
	if code, _ := n.do("POST", "/node/v1/heartbeat", `{"generation":99999}`); code != http.StatusBadRequest {
		t.Fatalf("unknown generation (refused) heartbeat: want 400, got %d", code)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE nodes SET last_seen = now() - interval '20 minutes' WHERE name = 'e1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SweepStaleNodes(ctx); err != nil {
		t.Fatalf("re-alert sweep err: %v", err)
	}
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale' AND resolved_at IS NULL"); got != 1 {
		t.Fatalf("after re-silence: want 1 open alert, got %d", got)
	}
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale'"); got != 2 {
		t.Fatalf("re-alert must open a fresh row: total node_stale = %d, want 2", got)
	}
}

// TestStaleNodeAlertIgnoresRevokedAndThreshold — a REVOKED node is never
// alerted (it's offline on purpose), and a node within the threshold window is
// not alerted (boundary: staleness is strictly past the limit).
func TestStaleNodeAlertIgnoresRevokedAndThreshold(t *testing.T) {
	pool, a, _, s, _ := nodeSetup(t)
	ctx := context.Background()

	// Revoke e1 and backdate it well past the threshold: revoked → no alert.
	list := a.must("GET", "/v1/nodes", "", http.StatusOK)
	id := nodeIDOf(t, list, "e1")
	a.must("POST", "/v1/nodes/"+id+"/revoke", "", http.StatusOK)
	if _, err := pool.Exec(ctx,
		`UPDATE nodes SET last_seen = now() - interval '1 hour' WHERE name = 'e1'`); err != nil {
		t.Fatal(err)
	}
	if found, err := s.SweepStaleNodes(ctx); err != nil || found != 0 {
		t.Fatalf("revoked stale node must not alert: found=%d err=%v", found, err)
	}
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale'"); got != 0 {
		t.Fatalf("revoked node must not alert: got %d", got)
	}

	// A second, ACTIVE node backdated 9 minutes (under the 10-min threshold)
	// is not yet stale: no alert, no row.
	code, body := a.do("POST", "/v1/nodes", `{"name":"within","role":"edge"}`)
	if code != http.StatusCreated {
		t.Fatalf("node create: %d %s", code, body)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE nodes SET last_seen = now() - interval '9 minutes' WHERE name = 'within'`); err != nil {
		t.Fatal(err)
	}
	if found, err := s.SweepStaleNodes(ctx); err != nil || found != 0 {
		t.Fatalf("under-threshold node must not alert: found=%d err=%v", found, err)
	}
	if got := countRows(t, pool, "operator_alerts", "kind = 'node_stale'"); got != 0 {
		t.Fatalf("under-threshold node must not alert: got %d", got)
	}
}
