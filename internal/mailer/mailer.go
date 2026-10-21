// Package mailer: a Sender interface with two drivers. The outbox driver
// (default in dev) stores every message in the outbox_messages table and as
// ./outbox/<nanotime>-<to>.txt. The SMTP driver exists for production use and
// is off unless GP_MAIL_DRIVER=smtp.
package mailer

import (
	"context"
	"fmt"
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
	SMTPSecure bool
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

// SMTP implements Sender over startTLS. It stores nothing: no outbox rows,
// no files, no message bodies anywhere — the message is handed to the relay
// and forgotten.
type SMTP struct {
	cfg Config
}

func NewSMTP(cfg Config) *SMTP { return &SMTP{cfg: cfg} }

func (s *SMTP) Send(ctx context.Context, msg Message) error {
	_ = ctx // smtp.SendMail has no context hook; dev/test servers only
	addr := s.cfg.SMTPHost + ":" + firstNonEmpty(s.cfg.SMTPPort, "587")
	var auth smtp.Auth // no credentials configured → no AUTH handshake
	if s.cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPass, s.cfg.SMTPHost)
	}
	return smtp.SendMail(addr, auth, s.cfg.From, []string{msg.To}, msg.bytes())
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
