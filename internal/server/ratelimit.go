// Package server — rate limiting (design §7): Postgres-backed counters keyed
// by real client IP (+ email for login lockout). Windows are 15 minutes; the
// counter resets atomically once a window lapses.
package server

import (
	"context"
	"net/http"
	"time"
)

const (
	rateWindow   = 15 * time.Minute
	authCapPerIP = 20 // POSTs to auth endpoints per IP per window
	lockoutAfter = 5  // failed logins per (IP, email) pair per window
)

// bumpRate increments key's counter (resetting when the window lapses) and
// reports whether count is within limit.
func (s *Server) bumpRate(ctx context.Context, key string, limit int) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `INSERT INTO rate_limits (key, count, window_start)
		VALUES ($1, 1, now())
		ON CONFLICT (key) DO UPDATE SET
		  count = CASE WHEN rate_limits.window_start < now() - interval '15 minutes'
		               THEN 1 ELSE rate_limits.count + 1 END,
		  window_start = CASE WHEN rate_limits.window_start < now() - interval '15 minutes'
		                 THEN now() ELSE rate_limits.window_start END
		RETURNING count`, key).Scan(&n)
	if err != nil {
		return false, err
	}
	return n <= limit, nil
}

// lockedRate reports whether the (IP, email) pair is currently locked out —
// i.e. lockoutAfter failures within an unexpired window.
func (s *Server) lockedRate(ctx context.Context, key string) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count FROM rate_limits
		WHERE key = $1 AND window_start > now() - interval '15 minutes'`, key).Scan(&n)
	if err != nil { // incl. no row: not locked
		return false, nil
	}
	return n >= lockoutAfter, nil
}

func tooMany(w http.ResponseWriter) { fail(w, http.StatusTooManyRequests, "too many requests") }
