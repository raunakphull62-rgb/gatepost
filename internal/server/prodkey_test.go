package server

// B3a: the production snapshot-key gate. ENV anything-but-"development"
// is production (fail-safe); main exits on ProductionGuards' error, so
// these tests drive the boot rules directly.
import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"gatepost/internal/snapshot"
)

// TestProductionSnapshotKeyBoot — production WITH GP_SNAPSHOT_KEY boots,
// and the snapshot verifies with THAT key and not with the dev fallback
// key; a production boot WITHOUT the key refuses (main would log.Fatalf).
func TestProductionSnapshotKeyBoot(t *testing.T) {
	t.Setenv("ENV", "production")
	key := "prod-snapshot-key-0123456789abcdef"

	// refusal-before-server: no key → the message tests would see at boot
	if err := ProductionGuards(Config{}); err == nil || !strings.Contains(err.Error(), "GP_SNAPSHOT_KEY") {
		t.Fatalf("production without GP_SNAPSHOT_KEY must refuse at boot, got %v", err)
	}
	// with the key: boot allowed (the prod key: 34 bytes ≥ the 32-floor)
	if err := ProductionGuards(Config{SnapshotKey: key}); err != nil {
		t.Fatalf("production with GP_SNAPSHOT_KEY set must boot, got %v", err)
	}
	// length floor exactly at the boundary: 31 bytes refused, 32 accepted
	if err := ProductionGuards(Config{SnapshotKey: strings.Repeat("k", 31)}); err == nil || !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("a 31-byte GP_SNAPSHOT_KEY must be refused at boot, got %v", err)
	}
	if err := ProductionGuards(Config{SnapshotKey: strings.Repeat("k", 32)}); err != nil {
		t.Fatalf("a 32-byte GP_SNAPSHOT_KEY must boot, got %v", err)
	}
	// and the loopback hook stays a test-only thing
	if err := ProductionGuards(Config{TestAllowLoopback: true}); err == nil || !strings.Contains(err.Error(), "GP_TEST_ALLOW_LOOPBACK") {
		t.Fatalf("GP_TEST_ALLOW_LOOPBACK must never be a production setting, got %v", err)
	}

	// a production-mode server signing with THAT key: a verified domain
	// with a literal IP origin — no test hooks needed, no dev key involved
	pool := testPool(t)
	a, s := newTestServer(t, pool, func(cfg *Config) { cfg.SnapshotKey = key })
	signupOn(t, pool, a, "prod@x.test")
	f := &fakeDNS{ips: map[string][]net.IP{}} // only the TXT map gets touched
	setResolvers(s, f)
	row := verifiedClaim(t, pool, a, f, "prod.example.com")
	literalOrigin(t, a, row.ID)

	doc, env, err := s.buildSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// (the absolute generation moved during setup — the create-time size
	// gate builds too; carrying the entry is what this test pins)
	if len(doc.Domains) != 1 {
		t.Fatalf("the artifact must carry the entry: %+v", doc.Domains)
	}
	if _, err := snapshot.Verify([]byte(key), env, 0); err != nil {
		t.Fatalf("a production snapshot must verify with GP_SNAPSHOT_KEY: %v", err)
	}
	devKey := "gatepost-development-snapshot-key"
	if _, err := snapshot.Verify([]byte(devKey), env, 0); !errors.Is(err, snapshot.ErrUnknownKey) {
		t.Fatalf("the dev key must NOT open a production snapshot, got %v", err)
	}
}
