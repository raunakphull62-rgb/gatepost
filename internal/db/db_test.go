package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"testing"

	"gatepost/migrations"
)

// migrationChecksums pins the SHA-256 of every applied migration file.
// Applied migrations are immutable: if a file's checksum changes, this test
// fails and the change must go into a NEW migration file instead (see
// DECISIONS.md "Applied migrations are never edited").
//
// Regenerate by running: go test -run TestMigrationChecksumsStable -update ./internal/db/
var migrationChecksums = map[string]string{
	"001_init.sql":                   "3a89d993ee997661a9ff691343673fcd2ac916949c5ebf275da75d5beab54b4c",
	"002_auth_tables.sql":            "b9cf19f9eb45804e195690afb22fa9bbf23eff50bef7da5827ad04a43442f9f2",
	"003_sessions_id.sql":            "3c63587fcd459dea2a866f509880074ac005369c87ed451c0d1c1ed77cb0df3f",
	"004_domains.sql":                "61ec1de906428b0e579bbceb725f1cd3feb4076e7d9515bef8b87ed3463c07f2",
	"005_domains_ns.sql":             "4fb274c9cc326c2b1b2a0d6345f450013424093afd1bfbff8d51fe1894932cd5",
	"006_records.sql":                "f2a4c241576deb1840449ecca4359dede83ae7de945d32492ddfd1effdcf1ae9",
	"007_nodes.sql":                  "3d0b60fed6b90999ae1c300e2e26b4ed110df342f082ff8a4fd873fb2e294530",
	"008_alerts.sql":                 "70b3e3c378570e2c74d3ca7dfbc7d7e34bacd531264fcac6dfe7bd2400c03b66",
	"009_recheck.sql":                "ab5b58d4e855e7c562679b7342f9519b0a4a1367cf5e8d50bd508270db731b73",
	"010_unresolved_time.sql":        "47dd0efc61614303a554df90dac8d74bbfdc5b3e31610e7cf5fde3f7221cc58f",
	"011_domains_waf.sql":            "43201b1ff05f2f6352f7c811efa089e608daa26b62218b726430c5c5c600f69b",
	"012_snapshot_build_alert.sql":   "ce29c56430c4a9febf724bf6cfdb70e9e90c6172289a63cab355acd75ec03cc0",
	"013_node_stale_alert.sql":       "63efc43bb48dabd99606a562a7437e46f2d930ee5c353727cb169495329777e8",
	"014_waf_config_failed_alert.sql":"361e7e46cb7996419e07dbf5bae30191894988427a7eae269b637bc210299120",
	"015_host_header_lowercase.sql":   "28fc2602ddf7006a70e3b637f20400c11caf7b819bd1d043726c90ac537e7125",
}

func TestMigrationChecksumsStable(t *testing.T) {
	var files []string
	if err := fs.WalkDir(migrations.FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk migrations: %v", err)
	}
	sort.Strings(files)

	for _, f := range files {
		b, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(b))
		if migrationChecksums[f] == "TODO_FILL_IN" {
			t.Logf("UNPINNED %s: %x (set this value in migrationChecksums)", f, sum)
			continue
		}
		if migrationChecksums[f] != sum {
			t.Fatalf("migration %s checksum changed: have %x, want %s — applied migrations are immutable; add a new migration instead", f, sum, migrationChecksums[f])
		}
	}
	t.Logf("pinned %d migration checksums", len(files))
}

// randHex returns n random bytes as lowercase hex, for unique test schema names.
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// strPtr returns a pointer to v, for nullable inserts.
func strPtr(v string) *string { return &v }

// TestMigration015HostHeaderBackfill verifies migration 015: existing
// host_header values are lowercased and any value that is still not a valid
// hostname[:port] is set to NULL.
func TestMigration015HostHeaderBackfill(t *testing.T) {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("no DATABASE_URL (.env) — integration tests skipped")
	}
	schema := "test_" + randHex(6)
	pool, err := OpenSchema(ctx, dbURL, schema)
	if err != nil {
		t.Fatalf("open schema: %v", err)
	}
	// OpenSchema only sets search_path; create the schema explicitly so
	// unqualified names resolve here (Migrate does this, but we run files
	// directly to stop before 015).
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		pool.Close()
	})

	// Apply every migration before 015, so 015 runs against existing data.
	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		if f >= "015" {
			break
		}
		sql, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", f, err)
		}
	}

	// Seed a user and several domains, each with one origin carrying a
	// distinct host_header value. After 015: valid ones are lowercased and
	// kept, invalid ones are NULL.
	var userID string
	if err := pool.QueryRow(ctx, `INSERT INTO users(email) VALUES('mh@example.com') RETURNING id::text`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	type seed struct {
		addr  string
		in    *string // host_header before 015
		want  *string // host_header after 015
		domID string
	}
	seeds := []seed{
		{addr: "93.184.216.34", in: strPtr("SHOP.example.com"), want: strPtr("shop.example.com")},          // lowercased, kept
		{addr: "93.184.216.35", in: strPtr("shop.example.com:443"), want: strPtr("shop.example.com:443")},   // already valid, kept
		{addr: "93.184.216.36", in: strPtr("BAD@HOST"), want: nil},                                          // invalid -> NULL
		{addr: "93.184.216.37", in: strPtr("ok.example.com:99999"), want: nil},                              // bad port -> NULL
		{addr: "93.184.216.38", in: nil, want: nil},                                                          // NULL stays NULL
	}
	for i := range seeds {
		if err := pool.QueryRow(ctx, `INSERT INTO domains(owner_user_id, hostname, verify_token) VALUES($1,$2,$3) RETURNING id::text`, userID, fmt.Sprintf("mh%d.example.com", i), fmt.Sprintf("tok-%d", i)).Scan(&seeds[i].domID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO origins(domain_id, scheme, address, port, host_header) VALUES($1,'https',$2,443,$3)`, seeds[i].domID, seeds[i].addr, seeds[i].in); err != nil {
			t.Fatalf("insert origin: %v", err)
		}
	}

	// Apply migration 015.
	sql15, err := migrations.FS.ReadFile("015_host_header_lowercase.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(sql15)); err != nil {
		t.Fatalf("apply 015: %v", err)
	}

	// Each domain's origin must hold the expected host_header after 015.
	for _, s := range seeds {
		var hh *string
		if err := pool.QueryRow(ctx, `SELECT host_header FROM origins WHERE domain_id=$1`, s.domID).Scan(&hh); err != nil {
			t.Fatalf("read origin for %s: %v", s.addr, err)
		}
		if (hh == nil) != (s.want == nil) {
			t.Fatalf("address %s: host_header = %v, want %v", s.addr, hh, s.want)
		}
		if hh != nil && *hh != *s.want {
			t.Fatalf("address %s: host_header = %q, want %q", s.addr, *hh, *s.want)
		}
	}
}
