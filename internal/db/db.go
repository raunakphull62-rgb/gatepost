// Package db: pgx pool wiring for Neon (pooled URL) and a migration runner
// that runs on the direct URL, with retries so a cold-starting Neon doesn't
// fail a boot or a test run.
package db

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/migrations"
)

const advisoryLockID = 0x67A74E01 // gatepost-migrate

// Connect timeout long enough for a Neon cold start.
const dialTimeout = 30 * time.Second

// Open opens the pooled pgx pool for the API.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	return OpenSchema(ctx, url, "")
}

// OpenSchema is Open with every connection pinned to a schema (tests).
// Neon's pooler (pgbouncer in transaction mode) rejects server-side prepared
// statements, so we pin the simple protocol. Retries a few times for a cold
// start.
func OpenSchema(ctx context.Context, url, schema string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if schema != "" && !safeIdent(schema) {
		return nil, fmt.Errorf("db: unsafe schema name %q", schema)
	}
	if schema != "" {
		cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.MaxConns = 8
	cfg.ConnConfig.ConnectTimeout = dialTimeout

	var pool *pgxpool.Pool
	for attempt := 1; attempt <= 3; attempt++ {
		pool, err = pgxpool.NewWithConfig(ctx, cfg)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return pool, nil
			}
			pool.Close()
		}
		if attempt < 3 {
			log.Printf("db: connect attempt %d failed, retrying: %v", attempt, err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	return nil, fmt.Errorf("db: connect failed after retries: %w", err)
}

// Migrate runs every unapplied migration in gatepost/migrations, in
// lexicographic order, under an advisory lock, against a dedicated direct
// connection (Neon's pooled endpoint can't do session advisory locks or
// multi-statement queries safely). schema != "" scopes everything to that
// schema (tests); "" uses the default search_path (the app).
func Migrate(ctx context.Context, directURL, schema string) (applied int, err error) {
	cfg, err := pgx.ParseConfig(directURL)
	if err != nil {
		return 0, err
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.ConnectTimeout = dialTimeout
	var conn *pgx.Conn
	for attempt := 1; attempt <= 3; attempt++ {
		conn, err = pgx.ConnectConfig(ctx, cfg)
		if err == nil {
			break
		}
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}
	if err != nil {
		return 0, fmt.Errorf("db: migrate connect failed after retries: %w", err)
	}
	defer conn.Close(ctx)

	if schema != "" && !safeIdent(schema) {
		return 0, fmt.Errorf("db: unsafe schema name %q", schema)
	}
	if schema != "" {
		if _, err = conn.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+schema); err != nil {
			return 0, fmt.Errorf("create schema: %w", err)
		}
		if _, err = conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
			return 0, fmt.Errorf("set search_path: %w", err)
		}
	}

	if _, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return 0, fmt.Errorf("schema_migrations: %w", err)
	}
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockID); err != nil {
		return 0, fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockID)
	}()

	done := map[string]bool{}
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return applied, err
		}
		done[v] = true
	}
	rows.Close()

	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return 0, err
	}
	sort.Strings(files)
	for _, f := range files {
		if done[f] {
			continue
		}
		sql, err := migrations.FS.ReadFile(f)
		if err != nil {
			return applied, err
		}
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			return applied, fmt.Errorf("migration %s: %w", f, err)
		}
		if _, err := conn.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", f); err != nil {
			return applied, fmt.Errorf("record %s: %w", f, err)
		}
		applied++
	}
	return applied, nil
}

// safeIdent allows only our own test schema names: test_<alphanumeric>.
func safeIdent(s string) bool {
	if len(s) > 63 {
		return false
	}
	if !strings.HasPrefix(s, "test_") {
		return false
	}
	for _, r := range s[5:] {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}
