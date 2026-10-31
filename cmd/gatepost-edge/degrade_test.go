package main

// Tests for item 2c (boot degrade): a missing/empty/unreadable node token no
// longer kills the process — the poller boots, serves its saved snapshot, and
// re-reads the token file every poll so a refilled secret restores polling
// with no restart. The signing key / API base / issuer / WAF-mode / features /
// admin-addr stay FATAL (they are trust anchors, not polling credentials).
import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestBootTokenDistinctReasons — the three failure modes each get a DISTINCT
// reason (missing vs empty vs unreadable) so a deploy typo is diagnosable; the
// env value wins; a populated file is read once and then cleared (env is the
// live source going forward).
func TestBootTokenDistinctReasons(t *testing.T) {
	// Env token present: healthy, no file.
	t.Setenv("GP_EDGE_TOKEN", "env-tok")
	t.Setenv("GP_EDGE_TOKEN_FILE", "")
	tok, f, why := bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tok != "env-tok" || f != "" || why != "" {
		t.Fatalf("env token: tok=%q file=%q why=%q", tok, f, why)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	// Populated file: read once, healthy.
	if err := os.WriteFile(path, []byte("  file-tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GP_EDGE_TOKEN", "")
	t.Setenv("GP_EDGE_TOKEN_FILE", path)
	tok, f, why = bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tok != "file-tok" || f != "" || why != "" {
		t.Fatalf("file token: tok=%q file=%q why=%q", tok, f, why)
	}

	// Empty file: degraded, DISTINCT "empty" reason, file path remembered.
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, f, why = bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tok != "" || f != path || why == "" || !strings.Contains(why, "empty") {
		t.Fatalf("empty file: tok=%q file=%q why=%q — want degraded + an 'empty' reason", tok, f, why)
	}

	// Missing file (var still set to the path): degraded, DISTINCT "unreadable".
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	tok, f, why = bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tok != "" || f != path || why == "" || !strings.Contains(why, "unreadable") {
		t.Fatalf("missing file: tok=%q file=%q why=%q — want degraded + an 'unreadable' reason", tok, f, why)
	}

	// Neither set: DISTINCT "must be set" reason.
	t.Setenv("GP_EDGE_TOKEN_FILE", "")
	tok, f, why = bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tok != "" || f != "" || why == "" || !strings.Contains(why, "must be set") {
		t.Fatalf("missing both: tok=%q file=%q why=%q — want degraded + a 'must be set' reason", tok, f, why)
	}
}

// TestBootTokenFatalForEmptyEnvVar — GP_EDGE_TOKEN="" (an intentional clear)
// does NOT look like "env present": it falls through to the file / degrade path,
// never a silent empty-string token that would 401-loop forever.
func TestBootTokenFatalForEmptyEnvVar(t *testing.T) {
	t.Setenv("GP_EDGE_TOKEN", "")
	t.Setenv("GP_EDGE_TOKEN_FILE", "")
	tok, f, why := bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tok != "" {
		t.Fatalf("blank env token must degrade, got tok=%q", tok)
	}
	if f != "" || why == "" {
		t.Fatalf("blank env: file=%q why=%q — want a degrade reason", f, why)
	}
}

// TestStateDirProbe — writable dir is read-write; a path blocked by a regular
// file with no saved snapshot is fatal.
func TestStateDirProbe(t *testing.T) {
	// Writable dir: not read-only, not fatal.
	ro, fatal, reason := stateDirProbe(t.TempDir())
	if ro || fatal || reason != "" {
		t.Fatalf("writable dir: ro=%v fatal=%v reason=%q", ro, fatal, reason)
	}

	// Path blocked by a regular file, no snapshot: fatal.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ro, fatal, reason = stateDirProbe(blocker + "/sub")
	if !fatal || ro || reason == "" {
		t.Fatalf("file-blocked, no snapshot: ro=%v fatal=%v reason=%q — want fatal", ro, fatal, reason)
	}
}

// TestLoadConfigDegradedTokenDoesNotExit — an empty token FILE at boot is not
// fatal: loadConfig completes with Token="", TokenFile set, and Degraded reason
// populated (the signing key is still provided, so nothing else trips).
func TestLoadConfigDegradedTokenDoesNotExit(t *testing.T) {
	t.Setenv("GP_EDGE_API_BASE", "http://api.test:8080")
	t.Setenv("GP_SNAPSHOT_KEY", string(makeKey(t)))
	t.Setenv("GP_EDGE_TOKEN", "")
	tokFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokFile, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GP_EDGE_TOKEN_FILE", tokFile)
	t.Setenv("GP_EDGE_STATE_DIR", t.TempDir())

	cfg := loadConfig()
	if cfg.Token != "" {
		t.Fatalf("degraded token should be empty, got %q", cfg.Token)
	}
	if cfg.TokenFile != tokFile {
		t.Fatalf("TokenFile = %q, want %q", cfg.TokenFile, tokFile)
	}
	if cfg.Degraded == "" {
		t.Fatal("Degraded reason should be set for an empty token file")
	}
	if !strings.Contains(cfg.Degraded, "empty") {
		t.Fatalf("Degraded reason %q should mention 'empty'", cfg.Degraded)
	}
}

// An empty token file at boot degrades: the poller boots, applies its saved
// snapshot, serves it, does NOT poll (no 401 flood, no backoff streak).
// Restoring the file mid-run re-arms polling within one poll cycle, no restart.
func TestTokenFileEmptyThenRestoredDegradesServesLastGood(t *testing.T) {
	// Shrink the degraded/fatal gaps so the test converges in ms.
	origD, origC := degradedLogGap, criticalStalenessGap
	degradedLogGap, criticalStalenessGap = 20*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { degradedLogGap, criticalStalenessGap = origD, origC })

	key := makeKey(t)
	token := "node-token-degrade"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(newAdminDoc(1, "degrade.example.com"))
	base := fake.serve().URL

	dir := t.TempDir()
	seedArtifact(t, dir, key, newAdminDoc(1, "degrade.example.com"))

	// Token file starts EMPTY: the poller must still boot from the snapshot.
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, base, "", key) // no env token → degraded
	cfg.TokenFile = tokFile
	cfg.Interval = 5 * time.Millisecond
	cfg.BackoffCap = 50 * time.Millisecond
	cfg.StaleLimit = time.Hour // keep staleness quiet during the restore step
	ask := startPoller(t, cfg)

	// Saved snapshot applied at boot, served from memory.
	until(t, 3*time.Second, "saved snapshot applied while degraded", func() bool {
		return hook.count("applied snapshot") >= 1
	})
	if code := askGet(t, ask, "/check?domain=degrade.example.com"); code != http.StatusOK {
		t.Fatalf("degraded ask = %d, want 200 (serving last-good)", code)
	}

	// No poll happened while degraded: the API saw zero config/auth requests.
	if n := len(fake.requests()); n != 0 {
		t.Fatalf("poll requests = %d while degraded, want 0", n)
	}
	if n := hook.count("no node token"); n < 1 {
		t.Fatalf("no 'no node token' degrade log; got:\n%s", hook.all())
	}
	// /health reports the degraded reason, status 200 (no restart loop).
	hc, err := http.Get(ask + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	hb, _ := io.ReadAll(hc.Body)
	hc.Body.Close()
	if hc.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want 200 in degraded mode", hc.StatusCode)
	}
	if !strings.Contains(string(hb), "degraded") {
		t.Fatalf("health body = %q, want the degraded reason", hb)
	}

	// Degraded is NOT a connection failure: the streak must not climb.
	if hook.count("poll failed") != 0 {
		t.Fatalf("degraded must not emit poll-failure lines:\n%s", hook.all())
	}
	if hook.count("backoff") != 0 {
		t.Fatalf("degraded must not touch the backoff ladder:\n%s", hook.all())
	}

	// Restore the token file: the next tick re-reads it and resumes polling.
	if err := os.WriteFile(tokFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.publishDoc(newAdminDoc(2, "degrade.example.com", "restored.example.com"))
	until(t, 3*time.Second, "poll resumed after the token file was refilled", func() bool {
		return len(fake.requests()) >= 1
	})
	until(t, 3*time.Second, "gen2 applied after recovery", func() bool {
		return hook.count("applied snapshot") >= 2
	})
	if code := askGet(t, ask, "/check?domain=restored.example.com"); code != http.StatusOK {
		t.Fatalf("post-restore ask = %d, want 200", code)
	}
}

// A degraded node that stays degraded past StaleLimit logs a CRITICAL line
// every criticalStalenessGap — but never takes itself down (/health stays 200).
func TestDegradedStalenessLogsCritical(t *testing.T) {
	origD, origC := degradedLogGap, criticalStalenessGap
	degradedLogGap, criticalStalenessGap = 20*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { degradedLogGap, criticalStalenessGap = origD, origC })

	key := makeKey(t)
	fake := newFakeAPI(t, key, "node-token-stale")
	base := fake.serve().URL

	dir := t.TempDir()
	seedArtifact(t, dir, key, newAdminDoc(1, "s.example.com"))
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	// Fast, movable clock.
	var nowNs atomic.Int64
	nowNs.Store(time.Unix(1_800_000_000, 0).UnixNano())
	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, base, "", key)
	cfg.TokenFile = tokFile
	cfg.Interval = 5 * time.Millisecond
	cfg.StaleLimit = 50 * time.Millisecond // very short: expired almost immediately
	cfg.Now = func() time.Time { return time.Unix(0, nowNs.Load()) }
	ask := startPoller(t, cfg)

	until(t, 3*time.Second, "degrade logged", func() bool {
		return hook.count("no node token") >= 1
	})

	// Advance past StaleLimit; the CRITICAL line should fire.
	nowNs.Add(int64(200 * time.Millisecond))
	time.Sleep(150 * time.Millisecond) // let a tick observe the advanced clock

	if n := hook.count("CRITICAL: degraded for"); n < 1 {
		t.Fatalf("expected a CRITICAL staleness line, got:\n%s", hook.all())
	}
	// /health must still be 200 (no auto-takedown) and report degraded.
	hc, err := http.Get(ask + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	body, _ := io.ReadAll(hc.Body)
	hc.Body.Close()
	if hc.StatusCode != http.StatusOK {
		t.Fatalf("health in stale degrade = %d, want 200 (never auto-take down)", hc.StatusCode)
	}
	if !strings.Contains(string(body), "degraded") {
		t.Fatalf("health body = %q, want degraded", body)
	}
}
