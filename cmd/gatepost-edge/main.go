// Gatepost edge poller (B3b item 2): the node-side loop that keeps the
// edge's last-good snapshot current. See poller.go for the behavior and
// tests. Configuration comes from env / untracked .env / mounted *_FILE
// (docker secrets). The token and key behind it are never printed.
package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
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
	log.Printf("gatepost-edge starting: api=%s state=%s ask=%s admin=%s%s",
		cfg.APIBase, cfg.StateDir, cfg.AskAddr, cfg.CaddyAdmin, loopback)
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
	return Config{
		APIBase:  base,
		Token:    token,
		Key:      []byte(keyStr),
		StateDir: stateDir,
		AskAddr:  firstNonEmpty(os.Getenv("GP_EDGE_ASK_ADDR"), "127.0.0.1:8099"),

		CaddyAdmin: caddyAdminEnv(),
		CaddyHTTP:  firstNonEmpty(os.Getenv("GP_EDGE_HTTP_ADDR"), ":80"),
		CaddyHTTPS: firstNonEmpty(os.Getenv("GP_EDGE_HTTPS_ADDR"), ":443"),

		ReloadCooldown: durEnv("GP_EDGE_RELOAD_COOLDOWN", 60*time.Second),
		AllowLoopback:  os.Getenv("GP_EDGE_ALLOW_LOOPBACK") == "true",
		Interval:       durEnv("GP_EDGE_POLL_INTERVAL", 5*time.Second),
		BackoffCap:     durEnv("GP_EDGE_BACKOFF_CAP", 60*time.Second),
	}
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
