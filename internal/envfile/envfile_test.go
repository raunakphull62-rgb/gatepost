package envfile

import (
	"os"
	"testing"
)

// TestProduction — any ENV value other than exactly "development" (prod,
// Production, empty) counts as production; only the exact dev value does not.
func TestProduction(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"", true},
		{"prod", true},
		{"Production", true},
		{"PRODUCTION", true},
		{"production", true},
		{" development ", true}, // not an exact match → production
		{"DEVELOPMENT", true},   // fail-safe: matching is case-sensitive
		{"development", false},
	}
	for _, c := range cases {
		t.Setenv("ENV", c.v)
		if got := Production(); got != c.want {
			t.Errorf("ENV=%q: Production() = %v, want %v", c.v, got, c.want)
		}
	}
}

// TestLoadExistingVarsWin: the file must never override an explicit
// environment (a stale .env would otherwise clobber real production config).
func TestLoadExistingVarsWin(t *testing.T) {
	path := t.TempDir() + "/.env.test"
	write(t, path, "EXPL_TEST=file\nEXPL_TEST2=file\nEXPL_TEST3=file\n")

	t.Setenv("EXPL_TEST", "process")
	t.Setenv("EXPL_TEST2", "") // set-but-empty must win too
	Load(path)

	if got := os.Getenv("EXPL_TEST"); got != "process" {
		t.Errorf("existing var clobbered: got %q", got)
	}
	if got := os.Getenv("EXPL_TEST2"); got != "" {
		t.Errorf("empty process var clobbered: got %q", got)
	}
	if got := os.Getenv("EXPL_TEST3"); got != "file" {
		t.Errorf("new var not loaded: got %q", got)
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
