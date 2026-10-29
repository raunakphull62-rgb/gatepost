package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"time"
)

var auditValueRe = regexp.MustCompile(`\[(data|uri) "(?:[^"\\]|\\.)*"\]`)

func sanitizeAuditLine(data []byte) []byte {
	return auditValueRe.ReplaceAll(data, []byte(`[$1 ""]`))
}

func sanitizeAuditFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	out := sanitizeAuditLine(b)
	if bytes.Equal(out, b) {
		return nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.Write(out)
	return err
}

const scrubInterval = 2 * time.Second

// scrubAuditLoop sanitizes the configured audit log until ctx is done. It is a
// no-op when the WAF is off/empty; failures are throttled and non-fatal
// (detection-only: audit hygiene is best-effort, never a poller crash).
func (p *Poller) scrubAuditLoop(ctx context.Context) {
	if p.cfg.WAF.Mode == "" || p.cfg.WAF.Mode == "off" || p.cfg.WAF.AuditLogPath == "" {
		return
	}
	t := time.NewTicker(scrubInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := sanitizeAuditFile(p.cfg.WAF.AuditLogPath); err != nil {
			p.logThrottled("warn", "audit-scrub", "waf audit scrub: %v", err)
		}
	}
}
