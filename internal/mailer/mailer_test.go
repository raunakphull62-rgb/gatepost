// Mailer driver behavior tests:
//   - New refuses the outbox driver under ENV=production (refuses to start)
//   - the SMTP relay gets the mail but nothing is stored anywhere
//   - older than 7 days outbox rows and files are pruned
package mailer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/db"
	"gatepost/internal/envfile"
)

// testPool: throwaway schema per test, dropped afterwards (same pattern as
// the server tests).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	envfile.Load("../../.env")
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("no DATABASE_URL (.env) — integration tests skipped")
	}
	schema := "test_" + randSchemaSuffix(t)
	ctx := context.Background()
	if _, err := db.Migrate(ctx, url, schema); err != nil {
		t.Fatalf("migrate %s: %v", schema, err)
	}
	pool, err := db.OpenSchema(ctx, url, schema)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		pool.Close()
	})
	return pool
}

// randSchemaSuffix: <alnum> that passes the migration runner's schema check.
func randSchemaSuffix(t *testing.T) string {
	t.Helper()
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	s := make([]byte, 8)
	for i, c := range b {
		s[i] = letters[int(c)%len(letters)]
	}
	return string(s)
}

// --- tests -------------------------------------------------------------------

func TestNewRefusesOutboxInProduction(t *testing.T) {
	// ENV=production + outbox → refuse to start
	if sender, err := New(nil, Config{Driver: "outbox", Production: true}); err == nil {
		t.Fatalf("outbox started in production: %T", sender)
	} else if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("wrong refusal error: %v", err)
	}
	// dev (no ENV) → outbox is the default and fine
	if _, err := New(nil, Config{OutboxDir: t.TempDir()}); err != nil {
		t.Fatalf("outbox refused outside production: %v", err)
	}
	// production + smtp with host → fine
	if _, err := New(nil, Config{Driver: "smtp", Production: true, SMTPHost: "relay.example.test"}); err != nil {
		t.Fatalf("smtp refused in production: %v", err)
	}
	// smtp without host → refuse (never fall back to outbox in production)
	if _, err := New(nil, Config{Driver: "smtp", Production: true}); err == nil {
		t.Fatal("smtp without host fell through")
	}
	// unknown driver → refuse
	if _, err := New(nil, Config{Driver: "carrier-pigeon"}); err == nil {
		t.Fatal("unknown driver accepted")
	}
}

type fakeSMTP struct {
	t      *testing.T
	mu     sync.Mutex
	bodies []string
}

func (f *fakeSMTP) listen(t *testing.T) (addr string, done func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	return l.Addr().String(), func() { l.Close(); <-serveDone }
}

// handle speaks just enough SMTP: EHLO (no STARTTLS, no AUTH advertised),
// MAIL/RCPT ok, DATA collected. Bodies needed no TLS because no auth is
// configured (nil auth skip).
func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	var buf bytes.Buffer
	defer func() {
		f.mu.Lock()
		f.bodies = append(f.bodies, buf.String())
		f.mu.Unlock()
	}()
	write := func(s string) { fmt.Fprint(conn, s) }
	write("220 fake ready\r\n")
	for sc.Scan() {
		line := strings.ToUpper(strings.TrimSpace(sc.Text()))
		switch {
		case strings.HasPrefix(line, "EHLO"):
			write("250-fake.local\r\n250 8BITMIME\r\n") // no STARTTLS, no AUTH
		case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"), line == "RSET":
			write("250 ok\r\n")
		case line == "DATA":
			write("354 go ahead\r\n")
			for sc.Scan() {
				b := sc.Text()
				if b == "." {
					write("250 queued\r\n")
					break
				}
				if strings.HasPrefix(b, ".") {
					b = strings.TrimPrefix(b, ".")
				}
				buf.WriteString(b + "\r\n")
			}
		case line == "QUIT":
			write("221 bye\r\n")
			return
		default:
			write("250 ok\r\n")
		}
	}
}

func TestSMTPStoresNoMessageBodies(t *testing.T) {
	pool := testPool(t)
	f := &fakeSMTP{t: t}
	addr, done := f.listen(t)
	defer done()

	dir := t.TempDir()
	s := NewSMTP(Config{Driver: "smtp", SMTPHost: hostOnly(addr), SMTPPort: portOf(addr),
		From: "gatepost@localhost"})
	msg := Message{To: "smtp-user@x.test", Subject: "Verify your Gatepost account",
		TextBody: "Your verification token: tokEND123", Kind: "verify"}
	if err := s.Send(context.Background(), msg); err != nil {
		t.Fatalf("smtp send: %v", err)
	}

	// the relay did receive the message
	f.mu.Lock()
	got := append([]string(nil), f.bodies...)
	f.mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "smtp-user@x.test") ||
		!strings.Contains(got[0], "tokEND123") {
		t.Fatalf("relay got: %q", got)
	}

	// ...and nothing is stored: no outbox rows, no files, ever
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM outbox_messages`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("SMTP driver stored %d outbox rows", n)
	}
	entries, err := os.ReadDir(dir)
	if err == nil && len(entries) != 0 {
		t.Fatalf("SMTP driver wrote files: %v", entries)
	}
}

func hostOnly(addr string) string { host, _, _ := net.SplitHostPort(addr); return host }
func portOf(addr string) string   { _, p, _ := net.SplitHostPort(addr); return p }

func TestOutboxPruneDeletesOlderThan7Days(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	dir := t.TempDir()

	// fresh row + file
	s := NewOutbox(pool, dir)
	if err := s.Send(ctx, Message{To: "fresh@x.test", Kind: "welcome", Subject: "Welcome to Gatepost",
		TextBody: "hi"}); err != nil {
		t.Fatal(err)
	}
	// old row (8 days) + old file (8 days, via Chtimes since names are opaque)
	if _, err := pool.Exec(ctx, `INSERT INTO outbox_messages (to_addr, kind, subject, body, sent_at)
		VALUES ('stale@x.test','welcome','Welcome to Gatepost','old body', now() - interval '8 days')`); err != nil {
		t.Fatal(err)
	}
	oldFile := filepath.Join(dir, "1790000000000000000-stale_x.test.txt")
	if err := os.WriteFile(oldFile, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(oldFile, old, old); err != nil {
		t.Fatal(err)
	}

	if err := Prune(ctx, pool, dir, 7*24*time.Hour); err != nil {
		t.Fatalf("prune: %v", err)
	}

	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM outbox_messages`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rows after prune = %d (want 1: fresh kept, 8d stale gone)", n)
	}
	if _, err := os.Stat(oldFile); !os.IsNotExist(err) {
		t.Fatalf("old file survived: %v", err)
	}
	still, _ := os.ReadDir(dir)
	if len(still) != 1 {
		t.Fatalf("files after prune = %d (want 1)", len(still))
	}
}
