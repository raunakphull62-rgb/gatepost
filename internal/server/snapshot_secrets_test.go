package server

// B3a item 5: the serialized artifact must never carry account material —
// no user emails, user IDs, verification tokens or password data. The build
// SELECT names only domain/origin columns; this sweep pins that invariant.
import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
)

// TestSnapshotCarriesNoSecrets — one full account (signup email + password,
// argon2id hash), one verified domain (verification token) with an origin,
// and the exact serialized envelope a node could download: the sweep shows
// none of the account material reaches it.
func TestSnapshotCarriesNoSecrets(t *testing.T) {
	pool, a, f, s := snapshotSetup(t)
	f.ips["sweeps.example.com"] = []net.IP{net.ParseIP("93.184.216.34")}
	row := verifiedClaim(t, pool, a, f, "sweeps.example.com")
	if code, body := originCall(t, a, row.ID, map[string]any{"address": "sweeps.example.com", "port": 80}); code != http.StatusCreated {
		t.Fatalf("origin create: %d %s", code, body)
	}

	ctx := context.Background()
	var uid, pwHash string
	if err := pool.QueryRow(ctx,
		`SELECT id::text, password_hash FROM users WHERE email = 'snap@x.test'`).
		Scan(&uid, &pwHash); err != nil {
		t.Fatal(err)
	}
	var verifyToken string
	if err := pool.QueryRow(ctx,
		`SELECT verify_token FROM domains WHERE id::text = $1`, row.ID).
		Scan(&verifyToken); err != nil {
		t.Fatal(err)
	}

	doc, env, err := s.buildSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Domains) != 1 || doc.Domains[0].Hostname != "sweeps.example.com" {
		t.Fatalf("the artifact must be non-degenerate for this sweep: %+v", doc.Domains)
	}
	blob, err := json.Marshal(env) // the whole thing nodes could download
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(blob)
	for _, secret := range []struct{ kind, value string }{
		{"email (the owner's)", "snap@x.test"},
		{"user id", uid},
		{"domain verification token", verifyToken},
		{"signup password", "secretpw123"},
		{"stored argon2id hash", pwHash},
		{"any at-sign at all", "@"},
	} {
		if strings.Contains(serialized, secret.value) {
			t.Fatalf("the serialized snapshot leaks %s (%s…)", secret.kind, secret.value[:6])
		}
	}
	if !strings.Contains(serialized, "sweeps.example.com") {
		t.Fatalf("sanity: the artifact should carry the hostname it exists for: %s", serialized)
	}
}
