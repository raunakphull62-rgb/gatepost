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
	"strconv"
	"strings"
	"syscall"
	"time"

	"gatepost/internal/envfile"
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
	token := envOrFile("GP_EDGE_TOKEN", "GP_EDGE_TOKEN_FILE", "node token")
	keyStr := envOrFile("GP_SNAPSHOT_KEY", "GP_SNAPSHOT_KEY_FILE", "snapshot signing key")
	stateDir := firstNonEmpty(os.Getenv("GP_EDGE_STATE_DIR"), "data/snapshots")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		log.Fatalf("state dir %s: %v", stateDir, err)
	}
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
		APIBase:  base,
		Token:    token,
		Key:      []byte(keyStr),
		StateDir: stateDir,
		AskAddr:  askAddr,

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
	}
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

// envOrFile: env value first, else the mounted FILE (docker secrets style);
// if neither, fatal. File contents may carry a trailing newline — trimmed.
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
