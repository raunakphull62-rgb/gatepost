package db

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
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
