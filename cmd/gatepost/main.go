// Gatepost API server: wires env config, the Postgres pool, migrations and
// the HTTP server. Migrations run on DATABASE_URL_DIRECT (direct endpoint),
// the API pool on DATABASE_URL (pooled on Neon; identical locally).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gatepost/internal/db"
	"gatepost/internal/envfile"
	"gatepost/internal/mailer"
	"gatepost/internal/server"
)

func main() {
	envfile.Load(".env")

	dbURL := os.Getenv("DATABASE_URL")
	dbDirect := os.Getenv("DATABASE_URL_DIRECT")
	if dbURL == "" || dbDirect == "" {
		log.Fatal("DATABASE_URL and DATABASE_URL_DIRECT must be set (.env)")
	}

	ctx := context.Background()
	if applied, err := db.Migrate(ctx, dbDirect, ""); err != nil {
		log.Fatalf("migrate: %v", err)
	} else if applied > 0 {
		log.Printf("applied %d migration(s)", applied)
	}
	pool, err := db.Open(ctx, dbURL)
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer pool.Close()

	mailCfg := mailer.Config{
		Driver:      os.Getenv("GP_MAIL_DRIVER"),
		OutboxDir:   "outbox",
		From:        os.Getenv("GP_MAIL_FROM"),
		Production:  envfile.Production(),
		SMTPHost:    os.Getenv("GP_SMTP_HOST"),
		SMTPPort:    os.Getenv("GP_SMTP_PORT"),
		SMTPUser:    os.Getenv("GP_SMTP_USER"),
		SMTPPass:    os.Getenv("GP_SMTP_PASSWORD"),
		SMTPTLS:     os.Getenv("GP_SMTP_TLS"),
		InsecureTLS: os.Getenv("GP_SMTP_INSECURE") == "true",
	}
	sender, err := mailer.New(pool, mailCfg)
	if err != nil {
		log.Fatalf("mailer: %v", err)
	}
	if !mailCfg.Production && mailCfg.Driver != "smtp" {
		// Outbox hygiene: files and rows older than 7 days are removed at
		// boot and hourly. Unneeded in production (outbox is refused there).
		go func() {
			for {
				if err := mailer.Prune(context.Background(), pool, mailCfg.OutboxDir, 7*24*time.Hour); err != nil {
					log.Printf("outbox prune: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Hour):
				}
			}
		}()
	}

	base := os.Getenv("GP_PUBLIC_BASE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	// Production refuses an http base URL: session cookies set Secure and
	// OAuth redirects must be https (mirrors the outbox refusal in mailer).
	if envfile.Production() && !strings.HasPrefix(base, "https://") {
		log.Fatalf("GP_PUBLIC_BASE_URL must be https in production, got %q", base)
	}
	// The loopback hook and the snapshot key are production boot gates in
	// one testable place (server.ProductionGuards).
	cfg := server.Config{
		Addr:                    firstNonEmpty(os.Getenv("GP_HTTP_ADDR"), ":8080"),
		BaseURL:                 base,
		Mail:                    mailCfg,
		GoogleClientID:          os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:      os.Getenv("GOOGLE_CLIENT_SECRET"),
		GitHubClientID:          os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:      os.Getenv("GITHUB_CLIENT_SECRET"),
		AuthCap:                 atoiEnv("GP_AUTH_CAP"),
		LockoutAfter:            atoiEnv("GP_LOCKOUT_AFTER"),
		DomainMaxTotal:          atoiEnv("GP_DOMAIN_MAX"),
		DomainMaxPending:        atoiEnv("GP_DOMAIN_PENDING"),
		DomainAddCap:            atoiEnv("GP_DOMAIN_ADD_CAP"),
		VerifyCap:               atoiEnv("GP_DOMAIN_VERIFY_CAP"),
		OriginTestCap:           atoiEnv("GP_ORIGIN_TEST_CAP"),
		Ns1:                     strings.TrimSpace(os.Getenv("GP_NS1")),
		Ns2:                     strings.TrimSpace(os.Getenv("GP_NS2")),
		TestZone:                strings.ToLower(strings.TrimSpace(os.Getenv("GP_TEST_ZONE"))),
		AllowSubdomainZones:     boolEnv("GP_ALLOW_SUBDOMAIN_ZONES"),
		MaxRecords:              atoiEnv("GP_MAX_RECORDS"),
		ServiceHostnames:        splitCommas(os.Getenv("GP_SERVICE_HOSTNAMES")),
		DNSResolvers:            splitCommas(os.Getenv("GP_DNS_RESOLVERS")),
		OwnedAddresses:          splitCommas(os.Getenv("GP_OWNED_ADDRESSES")),
		OperatorEmails:          splitCommas(os.Getenv("GP_OPERATOR_EMAILS")),
		TestAllowLoopback:       boolEnv("GP_TEST_ALLOW_LOOPBACK"),
		TrustedProxes:           splitCommas(os.Getenv("GP_TRUSTED_PROXIES")),
		SnapshotKey:             os.Getenv("GP_SNAPSHOT_KEY"),
		OriginUnresolvedMinutes: atoiEnv("GP_ORIGIN_UNRESOLVED_MINUTES"),
		NodePollCap:             atoiEnv("GP_NODE_RATE_CAP"),
		NodeStaleMinutes:        atoiEnv("GP_NODE_STALE_MINUTES"),
		SnapshotTTLSeconds:      atoiEnv("GP_SNAPSHOT_TTL"),
	}
	// the boot gate runs on the fully parsed config: a message and exit
	if err := server.ProductionGuards(cfg); err != nil {
		log.Fatalf("%v", err)
	}
	srv := server.New(cfg, pool, sender)

	// Domain claim expiry runs hourly (live-window: no fixed sleeps).
	go func() {
		for {
			if n, err := srv.ExpireDomainClaims(context.Background()); err != nil {
				log.Printf("domain claim expiry: %v", err)
			} else if n > 0 {
				log.Printf("expired %d domain claim(s)", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Hour):
			}
		}
	}()

	// Stale-node sweep (B3c item 2c Q7a): an active node that stops heartbeating
	// opens a node_stale alert; its next heartbeat resolves it. Runs on its own
	// cadence so staleness is caught even when no snapshot builds — a silent
	// node with no config churn still pages. Sweep interval is fixed (2 min);
	// the staleness threshold is GP_NODE_STALE_MINUTES (default 10). The count
	// is silent nodes FOUND this pass (DB dedup keeps one open alert per node).
	go func() {
		const sweepInterval = 2 * time.Minute
		for {
			if n, err := srv.SweepStaleNodes(context.Background()); err != nil {
				log.Printf("stale-node sweep: %v", err)
			} else if n > 0 {
				log.Printf("stale-node sweep: %d silent active node(s) (open alerts deduped in-DB)", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(sweepInterval):
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              srv.Addr(),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
	}
	log.Printf("gatepost listening on %s (base %s, mail %s)", srv.Addr(), base, firstNonEmpty(mailCfg.Driver, "outbox"))
	log.Fatal(httpSrv.ListenAndServe())
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// splitCommas: shared by the CIDR list and the comma-separated env lists
// (service hostnames, resolvers).
func splitCommas(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// atoiEnv returns 0 when the key is unset; the server falls back to its
// design defaults for 0. Garbage values fail loudly at boot.
// boolEnv parses a boolean env value; anything but true/false is fatal.
func boolEnv(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	switch strings.ToLower(v) {
	case "":
		return false
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		log.Fatalf("%q: set %s=true or %s=false", v, key, key)
		return false
	}
}

func atoiEnv(key string) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("%s must be an integer, got %q", key, v)
	}
	return n
}
