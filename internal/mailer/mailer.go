// Package mailer: a Sender interface with two drivers. The outbox driver
// (default in dev) stores every message in the outbox_messages table and as
// ./outbox/<nanotime>-<to>.txt. The SMTP driver exists for production use and
// is off unless GP_MAIL_DRIVER=smtp.
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Message struct {
	To       string
	Subject  string
	TextBody string
	Kind     string // verify | reset | welcome | test
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

type Config struct {
	Driver     string // "outbox" (default) | "smtp"
	OutboxDir  string
	From       string
	Production bool // ENV=production: outbox is refused (it writes bodies to DB+disk)
	SMTPHost   string
	SMTPPort   string
	SMTPUser   string
	SMTPPass   string
	// SMTP TLS policy: "" = auto (port 465 → implicit TLS, otherwise
	// STARTTLS); "implicit" | "starttls" | "none". InsecureTLS accepts
	// self-signed relay certificates (test/dev only).
	SMTPTLS     string
	InsecureTLS bool
}

var nameUnsafe = regexp.MustCompile(`[^A-Za-z0-9.+-]`)

// SafeName rewrites an email so it is safe as a filename component.
func SafeName(to string) string { return nameUnsafe.ReplaceAllString(to, "_") }

// Outbox implements Sender for dev/tests: DB row + file, both without secrets
// filtering (the outbox IS the dev log of what was sent).
type Outbox struct {
	pool *pgxpool.Pool
	dir  string
}

func NewOutbox(pool *pgxpool.Pool, dir string) *Outbox {
	return &Outbox{pool: pool, dir: dir}
}

func (o *Outbox) Send(ctx context.Context, msg Message) error {
	_, err := o.pool.Exec(ctx, `INSERT INTO outbox_messages (to_addr, subject, body, kind)
		 VALUES ($1, $2, $3, $4)`, msg.To, msg.Subject, msg.TextBody, msg.Kind)
	if err != nil {
		return fmt.Errorf("outbox: db: %w", err)
	}
	if err := os.MkdirAll(o.dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("%d-%s.txt", time.Now().UnixNano(), SafeName(msg.To))
	body := fmt.Sprintf("Subject: %s\nTo: %s\n\n%s\n", msg.Subject, msg.To, msg.TextBody)

	return os.WriteFile(filepath.Join(o.dir, name), []byte(body), 0o600)
}

// SMTP implements Sender. It stores nothing: no outbox rows, no files, no
// message bodies anywhere — the message is handed to the relay and forgotten.
type SMTP struct {
	cfg Config
}

func NewSMTP(cfg Config) *SMTP { return &SMTP{cfg: cfg} }

// Send delivers one message over SMTP. TLS policy: GP_SMTP_TLS=implicit →
// TLS from the first byte (the :465 convention); "starttls" → plaintext
// connect, then require the STARTTLS extension and upgrade (the :587
// convention); "none" → intentionally unencrypted relay (local mailhunt
// servers). Default is auto: 465 → implicit, otherwise starttls.
// Credentials are only ever sent on an encrypted connection: if the relay
// cannot upgrade and credentials are configured, Send refuses rather than
// leak them in the clear.
func (s *SMTP) Send(ctx context.Context, msg Message) error {
	_ = ctx
	port := firstNonEmpty(s.cfg.SMTPPort, "587")
	addr := s.cfg.SMTPHost + ":" + port
	mode := s.cfg.SMTPTLS
	if mode == "" {
		mode = "starttls"
		if port == "465" {
			mode = "implicit"
		}
	}
	tlsCfg := &tls.Config{ServerName: s.cfg.SMTPHost, MinVersion: tls.VersionTLS12}
	if s.cfg.InsecureTLS {
		tlsCfg.InsecureSkipVerify = true // self-signed relays; opt-in only
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	switch mode {
	case "implicit":
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	case "starttls", "none":
		conn, err = dialer.Dial("tcp", addr)
	default:
		return fmt.Errorf("smtp: unknown GP_SMTP_TLS mode %q", mode)
	}
	if err != nil {
		return fmt.Errorf("smtp: dial %s: %w", addr, err)
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, s.cfg.SMTPHost)
	if err != nil {
		return fmt.Errorf("smtp: greeting: %w", err)
	}
	if err := c.Hello("gatepost"); err != nil {
		return fmt.Errorf("smtp: hello: %w", err)
	}
	encrypted := mode == "implicit"
	if mode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("smtp: STARTTLS: %w", err)
			}
			encrypted = true
		}
	}
	if s.cfg.SMTPUser != "" {
		if !encrypted {
			return errors.New("smtp: refusing to send credentials over an unencrypted connection (no TLS available)")
		}
		if err := c.Auth(smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := c.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	if err := c.Rcpt(msg.To); err != nil {
		return fmt.Errorf("smtp: rcpt to: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := w.Write(msg.bytes()); err != nil {
		w.Close()
		return fmt.Errorf("smtp: body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: body end: %w", err)
	}
	return c.Quit()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (m Message) bytes() []byte {
	return []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", m.Subject, m.To, m.Subject, m.TextBody))
}

// New builds the configured driver. The outbox driver writes every message
// body to the database and to disk, so it refuses to start in production
// (ENV=production): bodies must not land on a production system.
func New(pool *pgxpool.Pool, cfg Config) (Sender, error) {
	driver := firstNonEmpty(cfg.Driver, "outbox")
	switch driver {
	case "outbox":
		if cfg.Production {
			return nil, fmt.Errorf("mailer: outbox driver refused in production; set GP_MAIL_DRIVER=smtp with GP_SMTP_HOST")
		}
		return NewOutbox(pool, cfg.OutboxDir), nil
	case "smtp":
		if cfg.SMTPHost == "" {
			return nil, fmt.Errorf("mailer: GP_MAIL_DRIVER=smtp requires GP_SMTP_HOST")
		}
		return NewSMTP(cfg), nil
	default:
		return nil, fmt.Errorf("mailer: unknown driver %q", driver)
	}
}

// Prune deletes outbox artifacts older than maxAge: table rows and files.
// Only meaningful for the outbox driver (SMTP stores nothing).
func Prune(ctx context.Context, pool *pgxpool.Pool, dir string, maxAge time.Duration) error {
	if _, err := pool.Exec(ctx, `DELETE FROM outbox_messages
		WHERE sent_at < now() - make_interval(secs => $1)`, int(maxAge.Seconds())); err != nil {
		return fmt.Errorf("outbox prune rows: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > maxAge {
			if os.Remove(p) != nil {
				continue
			}
		}
	}
	return nil
}
