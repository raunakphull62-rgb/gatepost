// Mailer driver behavior tests:
//   - New refuses the outbox driver under ENV=production (refuses to start)
//   - the SMTP relay gets the mail but nothing is stored anywhere
//   - older than 7 days outbox rows and files are pruned
package mailer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
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
	cmds   []string // every command line the relay saw
	mode   string   // "" | "start" (offers STARTTLS) | "implicit" (TLS from accept)
	srvTLS *tls.Config
}

func (f *fakeSMTP) listen(t *testing.T) (addr string, done func()) {
	t.Helper()
	return f.listenMode(t, "")
}

// listenMode also supports "start" (EHLO offers STARTTLS, upgrades on
// command) and "implicit" (accepts a TLS connection directly) — both with a
// self-signed certificate.
func (f *fakeSMTP) listenMode(t *testing.T, mode string) (addr string, done func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.mode = mode
	if mode == "start" || mode == "implicit" {
		cert := selfSigned(t)
		f.srvTLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			if mode == "implicit" {
				conn = tls.Server(conn, f.srvTLS)
			}
			go f.dialogue(conn, true)
		}
	}()
	return l.Addr().String(), func() { l.Close(); <-serveDone }
}

// dialogue speaks just enough SMTP: EHLO (caps depend on the configured
// mode), optional STARTTLS upgrade, AUTH ok, MAIL/RCPT ok, DATA collected.
func (f *fakeSMTP) dialogue(conn net.Conn, greet bool) {
	defer conn.Close()
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	var buf bytes.Buffer
	defer func() {
		f.mu.Lock()
		if buf.Len() > 0 {
			f.bodies = append(f.bodies, buf.String())
		}
		f.mu.Unlock()
	}()
	write := func(s string) { fmt.Fprint(conn, s) }
	if greet {
		write("220 fake ready\r\n")
	}
	for sc.Scan() {
		line := strings.ToUpper(strings.TrimSpace(sc.Text()))
		f.mu.Lock()
		f.cmds = append(f.cmds, line)
		f.mu.Unlock()
		switch {
		case strings.HasPrefix(line, "EHLO"):
			// one 250 space-line only: it must be the LAST of the reply
			caps := "250 8BITMIME\r\n"
			if f.mode == "start" && f.srvTLS != nil {
				caps = "250-STARTTLS\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n"
			} else if f.srvTLS != nil {
				caps = "250-AUTH PLAIN\r\n250 8BITMIME\r\n"
			}
			write("250-fake.local\r\n" + caps)
		case line == "STARTTLS":
			if f.srvTLS == nil || f.mode != "start" {
				write("502 not supported\r\n")
				continue
			}
			write("220 go ahead\r\n")
			tc := tls.Server(conn, f.srvTLS)
			if err := tc.Handshake(); err != nil {
				return
			}
			f.dialogue(tc, false) // continue the protocol inside TLS
			return
		case strings.HasPrefix(line, "AUTH"):
			write("235 ok\r\n")
		case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"), line == "RSET":
			write("250 ok\r\n")
		case line == "DATA":
			write("354 go ahead\r\n")
			for sc.Scan() {
				b := sc.Text()
				f.mu.Lock()
				f.cmds = append(f.cmds, "#body:"+b)
				f.mu.Unlock()
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

// selfSigned generates a throwaway relay certificate for the TLS tests.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gatepost-smtp.test"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
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

// sendSMTPMsg is the shared helper: a complete send, with or without creds.
func sendSMTPMsg(t *testing.T, addr, tlsMode string, insecure, withCreds bool) error {
	t.Helper()
	s := NewSMTP(Config{Driver: "smtp",
		SMTPHost:    hostOnly(addr),
		SMTPPort:    portOf(addr),
		SMTPTLS:     tlsMode,
		InsecureTLS: insecure,
		From:        "gatepost@localhost"})
	if withCreds {
		s.cfg.SMTPUser, s.cfg.SMTPPass = "relay-user", "relay-pass-supersecret"
	}
	return s.Send(context.Background(), Message{To: "user@x.test", Subject: "Verify your Gatepost account",
		TextBody: "token tok123", Kind: "verify"})
}

func sawCommand(t *testing.T, f *fakeSMTP, prefix string) bool {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// TestSMTPCredentialsOnlyOverTLS — a relay with a self-signed certificate
// accepts credentials both on implicit TLS (465 convention) and after a
// required STARTTLS upgrade (587 convention). A relay that cannot upgrade
// gets NO credentials: the client refuses before AUTH and before MAIL.
func TestSMTPCredentialsOnlyOverTLS(t *testing.T) {
	cases := []struct {
		name        string
		relay, dial string // fake relay mode / client TLS knob
	}{
		{"implicit-tls", "implicit", "implicit"},
		{"starttls", "start", "starttls"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeSMTP{t: t}
			addr, done := f.listenMode(t, c.relay)
			defer done()
			if err := sendSMTPMsg(t, addr, c.dial, true, true); err != nil {
				t.Fatalf("send over %s: %v", c.relay, err)
			}
			if !sawCommand(t, f, "AUTH PLAIN") {
				t.Fatal("credentials were not sent over TLS")
			}
			f.mu.Lock()
			bodies := append([]string(nil), f.bodies...)
			f.mu.Unlock()
			if len(bodies) != 1 || !strings.Contains(bodies[0], "token tok123") {
				t.Fatalf("relay got %q", bodies)
			}
		})
	}

	// TLS unavailable (plain relay, no STARTTLS) → credentials refused in
	// place: no AUTH, no MAIL, no message leaves the client.
	f := &fakeSMTP{t: t}
	addr, done := f.listenMode(t, "")
	defer done()
	err := sendSMTPMsg(t, addr, "", false, true)
	if err == nil || !strings.Contains(err.Error(), "refusing to send credentials over an unencrypted connection") {
		t.Fatalf("plain relay with creds: want refusal error, got %v", err)
	}
	if sawCommand(t, f, "AUTH") {
		t.Fatal("credentials leaked to an unencrypted relay")
	}
	if sawCommand(t, f, "MAIL FROM") {
		t.Fatal("message sent despite refused credentials")
	}
}

// TestSMTPNoCredsPlainsStillOK: a credential-less relay (local mail suck
// servers) may stay unencrypted — nothing to protect.
func TestSMTPNoCredsPlainStillOK(t *testing.T) {
	f := &fakeSMTP{t: t}
	addr, done := f.listenMode(t, "")
	defer done()
	if err := sendSMTPMsg(t, addr, "", false, false); err != nil {
		t.Fatalf("no-creds plain send: %v", err)
	}
}

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
