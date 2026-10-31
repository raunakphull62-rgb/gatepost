// Gatepost edge poller (B3b item 2): the node-side loop that keeps the
// edge's last-good snapshot current. See poller.go for the behavior and
// tests. Configuration comes from env / untracked .env / mounted *_FILE
// (docker secrets). The token and key behind it are never printed.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gatepost/internal/envfile"
	"gatepost/internal/snapshot"
)

func main() {
	envfile.Load(".env") // process env still wins (internal/envfile semantics)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := loadConfig()
	p := NewPoller(cfg)
	loopback := ""
	if cfg.AllowLoopback {
		loopback = " [GP_EDGE_ALLOW_LOOPBACK — TEST/DEMO ONLY]"
	}
	log.Printf("gatepost-edge starting: api=%s state=%s ask=%s admin=%s issuer=%s cert_cap=%d/h access_log=%s%s",
		cfg.APIBase, cfg.StateDir, cfg.AskAddr, cfg.CaddyAdmin, cfg.Issuer, cfg.CertHourlyCap, cfg.CaddyAccessLog, loopback)
	if err := p.Run(ctx); err != nil {
		log.Fatalf("gatepost-edge: %v", err)
	}
	log.Printf("gatepost-edge stopped")
}

// loadConfig reads the knobs; required values missing or garbage values are
// fatal at boot (the repo's fail-loud style). Only the base/state/ask values
// land in the boot summary — never the token or key.
func loadConfig() Config {
	base := strings.TrimSuffix(envRequired("GP_EDGE_API_BASE", "API base URL"), "/")
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		log.Fatalf("GP_EDGE_API_BASE must be http(s), got %q", base)
	}
	// The node token is NON-FATAL if absent/empty/unreadable (item 2c): an
	// edge with a saved snapshot can keep serving while the secret is fixed.
	// The signing key is the opposite — it MUST be present to verify the
	// snapshot at boot, so a missing key is fatal and stays on envOrFile.
	token, tokenFile, tokenReason := bootToken("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	if tokenReason != "" {
		log.Printf("gatepost-edge starting DEGRADED: %s", tokenReason)
	}
	keyStr := envOrFile("GP_SNAPSHOT_KEY", "GP_SNAPSHOT_KEY_FILE", "snapshot signing key")
	stateDir, readOnlyFS := bootStateDir(os.Getenv("GP_EDGE_STATE_DIR"))
	askAddr := firstNonEmpty(os.Getenv("GP_EDGE_ASK_ADDR"), "127.0.0.1:8099")
	accessLog := firstNonEmpty(os.Getenv("GP_EDGE_ACCESS_LOG"), "data/logs/access.json")

	// Issuer: an explicit setting whose DEFAULT is staging — a missing value
	// must never reach production Let's Encrypt. production is opt-in only,
	// and never together with the loopback test hook.
	issuer := strings.ToLower(firstNonEmpty(strings.TrimSpace(os.Getenv("GP_EDGE_ISSUER")), issuerStaging))
	if _, err := issuerConfig(issuer); err != nil {
		log.Fatalf("%v", err)
	}
	allowLoopback := os.Getenv("GP_EDGE_ALLOW_LOOPBACK") == "true"
	if err := issuerBootGuard(issuer, allowLoopback); err != nil {
		log.Fatalf("%v", err)
	}

	return Config{
		APIBase:    base,
		Token:      token,
		TokenFile:  tokenFile,
		Degraded:   tokenReason, // "" = healthy; non-empty = the boot degrade reason
		Key:        []byte(keyStr),
		StateDir:   stateDir,
		ReadOnlyFS: readOnlyFS,
		AskAddr:     askAddr,

		CaddyAdmin: caddyAdminEnv(),
		CaddyHTTP:  firstNonEmpty(os.Getenv("GP_EDGE_HTTP_ADDR"), ":80"),
		CaddyHTTPS: firstNonEmpty(os.Getenv("GP_EDGE_HTTPS_ADDR"), ":443"),

		ReloadCooldown: durEnv("GP_EDGE_RELOAD_COOLDOWN", 60*time.Second),
		AdminGrace:     durEnv("GP_EDGE_ADMIN_GRACE", 15*time.Second),
		AllowLoopback:  allowLoopback,
		Interval:       durEnv("GP_EDGE_POLL_INTERVAL", 5*time.Second),
		BackoffCap:     durEnv("GP_EDGE_BACKOFF_CAP", 60*time.Second),

		Issuer:        issuer,
		CertHourlyCap: intEnv("GP_EDGE_CERT_HOURLY_CAP", 50),

		CaddyAccessLog: accessLog,
		ErrorLogGap:    durEnv("GP_EDGE_ERROR_LOG_GAP", 30*time.Second),

		// B3c item 2c: how long a degraded node serves last-good before a
		// CRITICAL hourly log fires. Default 24h.
		StaleLimit: durEnv("GP_EDGE_STALE_LIMIT", 24*time.Hour),

		// B3c: Coraza edge WAF. Detection-only by default on the dev stack
		// (via deploy/dev compose env); the binary itself defaults OFF so a
		// non-coraza caddy (and tests) get unchanged configs. The dev stack
		// sets GP_EDGE_WAF_MODE=detection, which injects the coraza.waf
		// handler with CRS loaded and audit to a bounded native-format file.
		WAF: wafEnv(),

		// B3c schema gate: the features this build implements.
		Features: mustFeatures(),
	}
}

// mustFeatures wraps featuresEnv for loadConfig — an unknown feature is a
// boot-time fatal (this build refuses to claim a capability it does not have).
func mustFeatures() []string {
	f, err := featuresEnv()
	if err != nil {
		log.Fatalf("%v", err)
	}
	return f
}

// featuresEnv: the snapshot gate's feature list. The default is this build's
// full knowledge; "none" (the sentinel — Go cannot tell an unset env from an
// empty one) selects the old-style empty set that refuses any snapshot with
// required features. The knob can only NARROW the compiled-in set — it can
// never claim a capability the binary does not implement: an unknown name is
// an error returned to loadConfig (which fails loud at boot). Fail-loud, not
// fail-soft, so an operator typo can never silently drop the WAF gate.
func featuresEnv() ([]string, error) {
	if v := os.Getenv("GP_EDGE_FEATURES"); v == "" || v == "none" {
		if v == "none" {
			return nil, nil // old-style node: refuses any snapshot with required features
		}
		return snapshot.KnownFeatures, nil
	}
	var out []string
	for _, name := range strings.Split(os.Getenv("GP_EDGE_FEATURES"), ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		name = strings.ToLower(name)
		if !slices.Contains(snapshot.KnownFeatures, name) {
			return nil, fmt.Errorf("GP_EDGE_FEATURES: unknown feature %q (this build knows %s)",
				name, strings.Join(snapshot.KnownFeatures, ","))
		}
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out, nil
}

// issuerBootGuard: the boot-time refusal around the production issuer.
// GP_EDGE_ISSUER=production IS the explicit opt-in, and it is refused on a
// loopback test/demo node (GP_EDGE_ALLOW_LOOPBACK) — a dev box must never
// mint certificates against production Let's Encrypt. A function (not inline
// log.Fatalf) so the boot test can pin every combination.
func issuerBootGuard(issuer string, allowLoopback bool) error {
	if issuer == issuerProduction && allowLoopback {
		return fmt.Errorf("GP_EDGE_ISSUER=production is refused with GP_EDGE_ALLOW_LOOPBACK (production certs never come from a test/demo node)")
	}
	return nil
}

// caddyAdminEnv: the edge's admin API address, host:port (no scheme). The
// default is loopback 2019 — inside the shared network namespace the poller
// runs in, which is compose-internal and never a published host port.
func caddyAdminEnv() string {
	v := firstNonEmpty(os.Getenv("GP_EDGE_ADMIN_ADDR"), "127.0.0.1:2019")
	if strings.Contains(v, "://") {
		log.Fatalf("GP_EDGE_ADMIN_ADDR is a host:port address, got %q (scheme is added by the poller)", v)
	}
	if _, _, err := net.SplitHostPort(v); err != nil {
		log.Fatalf("GP_EDGE_ADMIN_ADDR must be host:port, got %q", v)
	}
	return v
}

// envRequired: an unset required knob is a boot-time fatal, not a silent guess.
func envRequired(name, what string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		log.Fatalf("%s must be set (%s)", name, what)
	}
	return v
}

// wafEnv: B3c edge WAF config from env. Default mode is OFF in the binary so a
// non-coraza caddy (and the e2e tests) get byte-identical configs; the dev
// stack opts into detection-only via GP_EDGE_WAF_MODE=detection.
func wafEnv() WAFConfig {
	mode := strings.ToLower(strings.TrimSpace(firstNonEmpty(os.Getenv("GP_EDGE_WAF_MODE"), "off")))
	if mode != "off" && mode != "detection" && mode != "blocking" {
		log.Fatalf("GP_EDGE_WAF_MODE=%q (want off|detection|blocking)", mode)
	}
	audit := firstNonEmpty(os.Getenv("GP_EDGE_WAF_AUDIT_LOG"), "data/logs/waf_audit.log")
	limit := int64(intEnv("GP_EDGE_WAF_BODY_LIMIT_MB", 32)) * 1024 * 1024
	par := intEnv("GP_EDGE_WAF_PARANOIA", 1)
	if par < 1 || par > 4 {
		log.Fatalf("GP_EDGE_WAF_PARANOIA=%d (CRS paranoia is 1..4)", par)
	}
	// WAFFailOpen wrapper tunables (B3c item 4).
	timeout := firstNonEmpty(os.Getenv("GP_EDGE_WAF_TIMEOUT"), "250ms")
	if _, err := time.ParseDuration(timeout); err != nil {
		log.Fatalf("GP_EDGE_WAF_TIMEOUT=%q: %v", timeout, err)
	}
	concurrency := intEnv("GP_EDGE_WAF_CONCURRENCY", 64)
	if concurrency < 1 {
		log.Fatalf("GP_EDGE_WAF_CONCURRENCY=%d (must be >= 1)", concurrency)
	}
	wait := firstNonEmpty(os.Getenv("GP_EDGE_WAF_CONCURRENCY_WAIT"), "50ms")
	if _, err := time.ParseDuration(wait); err != nil {
		log.Fatalf("GP_EDGE_WAF_CONCURRENCY_WAIT=%q: %v", wait, err)
	}
	return WAFConfig{
		Mode: mode, AuditLogPath: audit,
		RequestBodyLimit: limit, ParanoiaLevel: par,
		Timeout: timeout, Concurrency: concurrency, ConcurrencyWait: wait,
	}
}

// envOrFile: env value first, else the mounted FILE (docker secrets style);
// if neither, fatal. File contents may carry a trailing newline — trimmed.
// Used only for values that MUST be present at boot (the signing key); the
// node token uses bootToken, which degrades instead of exiting.
func envOrFile(envName, fileEnv, what string) string {
	if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
		return v
	}
	if path := strings.TrimSpace(os.Getenv(fileEnv)); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("%s (%s): %v", fileEnv, what, err)
		}
		if v := strings.TrimSpace(string(b)); v != "" {
			return v
		}
		log.Fatalf("%s (%s) is empty", fileEnv, what)
	}
	log.Fatalf("%s or %s must be set (%s)", envName, fileEnv, what)
	return ""
}

// bootToken resolves the node token. Unlike envOrFile, absent/empty/unreadable
// is NOT fatal: the poller boots, serves its LAST-GOOD snapshot, and re-reads
// the token file every poll cycle (Poller.token) so refilling the secret
// restores polling with no restart (item 2c). The three failure modes each get
// a DISTINCT reason so an empty file never looks like a missing one when an
// operator is hunting a deploy typo. envName takes priority over fileEnv, but
// the file is re-read at runtime (env values can't change without a restart).
func bootToken(envName, fileEnv, what string) (token string, file string, reason string) {
	if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
		return v, "", ""
	}
	path := strings.TrimSpace(os.Getenv(fileEnv))
	if path == "" {
		return "", "", fmt.Sprintf("%s or %s must be set (%s) — serving last-good, not polling until one is provided", envName, fileEnv, what)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", path, fmt.Sprintf("%s (%s) is unreadable (%v) — serving last-good, not polling until the file is fixed", fileEnv, what, err)
	}
	if v := strings.TrimSpace(string(b)); v != "" {
		return v, "", ""
	}
	return "", path, fmt.Sprintf("%s (%s) is empty — serving last-good, not polling until the secret is refilled", fileEnv, what)
}

// bootStateDir resolves the state directory and classifies its writability.
// A writable dir (or one MkdirAll can create) returns readOnly=false. A
// read-only mount that still holds a saved snapshot returns readOnly=true:
// the poller loads that artifact but never writes it back in memory (the
// saved bytes ARE the last good). A dir it cannot create AND that has no
// saved snapshot is fatal — there is nothing to serve and nowhere to start.
func bootStateDir(dir string) (string, bool) {
	dir = firstNonEmpty(dir, "data/snapshots")
	readOnly, fatal, reason := stateDirProbe(dir)
	if fatal {
		log.Fatalf("%s", reason)
	}
	if readOnly {
		log.Printf("%s", reason)
	}
	return dir, readOnly
}

// stateDirProbe is bootStateDir's pure classifier, factored out so the
// read-only / fatal branches are unit-testable without log.Fatalf exiting.
func stateDirProbe(dir string) (readOnly, fatal bool, reason string) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		if _, serr := os.Stat(filepath.Join(dir, snapshotFile)); serr == nil {
			return true, false, fmt.Sprintf("state dir %s not reachable (%v) — loading the saved snapshot read-only", dir, err)
		}
		return false, true, fmt.Sprintf("state dir %s: %v and no saved snapshot to serve", dir, err)
	}
	// A read-only mount of an EXISTING dir defeats MkdirAll (it's a no-op);
	// probe writability directly so we detect it.
	probe := filepath.Join(dir, ".gp-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o600); err != nil {
		if _, serr := os.Stat(filepath.Join(dir, snapshotFile)); serr == nil {
			return true, false, fmt.Sprintf("state dir %s not writable (%v) — loading the saved snapshot read-only", dir, err)
		}
		return false, true, fmt.Sprintf("state dir %s: not writable (%v) and no saved snapshot to serve", dir, err)
	}
	_ = os.Remove(probe)
	return false, false, ""
}

// durEnv parses a time.Duration knob; unset → default, garbage → fatal
// (main's atoiEnv style for integers, borrowed for durations).
func durEnv(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Fatalf("%s must be a positive duration (e.g. 5s), got %q", name, v)
	}
	return d
}

// intEnv parses a positive integer knob; unset → default, garbage → fatal.
func intEnv(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		log.Fatalf("%s must be a positive integer, got %q", name, v)
	}
	return n
}
