// Gatepost API server: wires env config, the Postgres pool, migrations and
// the HTTP server. Migrations run on DATABASE_URL_DIRECT (direct endpoint),
// the API pool on DATABASE_URL (pooled on Neon; identical locally).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
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
		Driver:     os.Getenv("GP_MAIL_DRIVER"),
		OutboxDir:  "outbox",
		From:       os.Getenv("GP_MAIL_FROM"),
		Production: os.Getenv("ENV") == "production",
		SMTPHost:   os.Getenv("GP_SMTP_HOST"),
		SMTPPort:   os.Getenv("GP_SMTP_PORT"),
		SMTPUser:   os.Getenv("GP_SMTP_USER"),
		SMTPPass:   os.Getenv("GP_SMTP_PASSWORD"),
		SMTPSecure: true,
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
	srv := server.New(server.Config{
		Addr:               firstNonEmpty(os.Getenv("GP_HTTP_ADDR"), ":8080"),
		BaseURL:            base,
		Mail:               mailCfg,
		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GitHubClientID:     os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		TrustedProxes:      splitCIDRs(os.Getenv("GP_TRUSTED_PROXIES")),
	}, pool, sender)

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

func splitCIDRs(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
