// Package server — password account lifecycle (design §3–§4): signup, verify,
// login, logout, password reset. Auth POSTs answer uniformly and never confirm
// whether an email exists.
package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"gatepost/internal/mailer"
	"gatepost/internal/password"
)

type creds struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// validEmail is deliberately loose: an address shape only (domain syntax is
// the mail sender's problem).
func validEmail(e string) bool {
	l, _, ok := strings.Cut(e, "@")
	return ok && l != "" && strings.IndexByte(e[len(l)+1:], '.') > 0 &&
		len(e) <= 254 && !strings.ContainsAny(e, " \t\r\n")
}

func validPassword(p string) bool { return len(p) >= 8 && len(p) <= 128 }

func isUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// isDeadlock — 40P01: two racing verifications cross-lock the two claim
// rows; losing that fight is a benign lost race (the other one wins), so it
// reads as a retryable conflict, never as a 500.
func isDeadlock(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "40P01"
}

// POST /auth/signup {email, password}
func (s *Server) signup(w http.ResponseWriter, r *http.Request) {
	var c creds
	if !readJSON(w, r, &c) {
		return
	}
	if !validEmail(c.Email) || !validPassword(c.Password) {
		fail(w, http.StatusBadRequest, "invalid email or password")
		return
	}
	if ok, err := s.bumpRate(r.Context(), "auth|"+s.clientIP(r), s.cfg.AuthCap); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	} else if !ok {
		tooMany(w)
		return
	}
	// Hash before the insert so existing accounts cost the same as new ones.
	hash, err := password.Hash(c.Password)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	var id string
	err = s.pool.QueryRow(r.Context(), `INSERT INTO users (email, password_hash)
		VALUES ($1, $2) RETURNING id::text`, c.Email, hash).Scan(&id)
	if isUniqueViolation(err) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true,
			"message": "check your inbox to verify your account"})
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.sendEmailToken(r, id, c.Email, "verify",
		"Verify your Gatepost account", verifyEmailText); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true,
		"message": "check your inbox to verify your account"})
}

// done writes the uniform {"ok":true} success body.
func done(w http.ResponseWriter, code int) {
	writeJSON(w, code, map[string]any{"ok": true})
}

// sendEmailToken inserts a 24h token and mails it to `to` via the driver.
func (s *Server) sendEmailToken(r *http.Request, userID, to, kind, subject string, text func(string, string) string) error {
	raw, err := s.newEmailToken(r, userID, kind)
	if err != nil {
		return err
	}
	return s.mail.Send(r.Context(), mailer.Message{
		To: to, Kind: kind, Subject: subject, TextBody: text(s.cfg.BaseURL, raw),
	})
}

// POST /auth/verify {token} — spends the token, marks verified, starts a
// session and sends the welcome message exactly once.
func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	userID, err := s.consumeEmailToken(r, body.Token, "verify")
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	if _, err := s.pool.Exec(r.Context(), `UPDATE users SET email_verified = true,
		updated_at = now() WHERE id = $1`, userID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.newSession(w, r, userID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.welcomeOnce(r, userID)
	done(w, http.StatusOK)
}

// POST /auth/login {email, password} — capped per IP; per-(IP,email) lockout
// counts failures only, and the argon2 run happens only after the lock check.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var c creds
	if !readJSON(w, r, &c) {
		return
	}
	ip := s.clientIP(r)
	ok, err := s.bumpRate(r.Context(), "auth|"+ip, s.cfg.AuthCap)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !ok {
		tooMany(w)
		return
	}
	lockKey := "lock|" + ip + "|" + strings.ToLower(c.Email)
	if locked, _ := s.lockedRate(r.Context(), lockKey); locked {
		tooMany(w)
		return
	}
	var id string
	var pwHash *string
	err = s.pool.QueryRow(r.Context(), `SELECT id::text, password_hash
		FROM users WHERE lower(email) = $1`, strings.ToLower(c.Email)).Scan(&id, &pwHash)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Uniform failure: unknown user or OAuth-only account verifies against a
	// dummy hash so timing does not reveal which.
	stored := s.dummy
	if pwHash != nil {
		stored = *pwHash
	}
	valid, verr := password.Verify(stored, c.Password)
	if err != nil || !valid || verr != nil {
		_, _ = s.bumpRate(r.Context(), lockKey, s.cfg.LockoutAfter)
		fail(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err := s.newSession(w, r, id); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	done(w, http.StatusOK)
}

// POST /auth/logout — deletes the session row, clears the cookie.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	_, th, err := s.principal(r)
	if err != nil {
		fail(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if th != "" {
		if _, err := s.pool.Exec(r.Context(), `DELETE FROM sessions WHERE token_hash = $1`, th); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	s.clearSession(w)
	done(w, http.StatusOK)
}

// POST /auth/password-reset-request {email} — 202 regardless of existence.
func (s *Server) resetRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !validEmail(body.Email) {
		fail(w, http.StatusBadRequest, "invalid email")
		return
	}
	if ok, err := s.bumpRate(r.Context(), "auth|"+s.clientIP(r), s.cfg.AuthCap); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	} else if !ok {
		tooMany(w)
		return
	}
	var id string
	err := s.pool.QueryRow(r.Context(), `SELECT id::text FROM users
		WHERE lower(email) = $1`, strings.ToLower(body.Email)).Scan(&id)
	if err == nil {
		if err := s.sendEmailToken(r, id, body.Email, "reset",
			"Reset your Gatepost password", resetEmailText); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true,
		"message": "if the address exists, a reset link was sent"})
}

// POST /auth/password-change {current_password, new_password} — session
// only. Verifies the current password, sets the new hash, ends every OTHER
// session of the user and rotates the caller's session id. A wrong current
// password counts against the (IP, email) lockout like a failed login.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	p, th, err := s.principal(r)
	if err != nil || th == "" {
		fail(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !validPassword(body.NewPassword) {
		fail(w, http.StatusBadRequest, "invalid password")
		return
	}
	if ok, err := s.bumpRate(r.Context(), "auth|"+s.clientIP(r), s.cfg.AuthCap); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	} else if !ok {
		tooMany(w)
		return
	}
	var hash *string
	err = s.pool.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id = $1`,
		p.UserID).Scan(&hash)
	if err != nil || hash == nil {
		fail(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if valid, verr := password.Verify(*hash, body.CurrentPassword); verr != nil || !valid {
		lockKey := "lock|" + s.clientIP(r) + "|" + strings.ToLower(p.Email)
		_, _ = s.bumpRate(r.Context(), lockKey, s.cfg.LockoutAfter)
		fail(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	newHash, err := password.Hash(body.NewPassword)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `UPDATE users SET password_hash = $1,
		updated_at = now() WHERE id = $2`, newHash, p.UserID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	// end every other session, then rotate this one in place
	if _, err := tx.Exec(r.Context(), `DELETE FROM sessions
		WHERE user_id = $1 AND token_hash <> $2`, p.UserID, th); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := s.rotateSession(r, w, th); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	done(w, http.StatusOK)
}

// GET /auth/sessions — the caller's sessions (id/times + which row is the
// current one). Token hashes never leave the database.
func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	p, th, err := s.principal(r)
	if err != nil || th == "" {
		fail(w, http.StatusUnauthorized, "authentication required")
		return
	}
	rows, err := s.pool.Query(r.Context(), `SELECT id::text, created_at, expires_at,
		token_hash = $2 FROM sessions WHERE user_id = $1 ORDER BY created_at`, p.UserID, th)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	type row struct {
		ID        string    `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		ExpiresAt time.Time `json:"expires_at"`
		Current   bool      `json:"current"`
	}
	list := []row{}
	for rows.Next() {
		var v row
		if err := rows.Scan(&v.ID, &v.CreatedAt, &v.ExpiresAt, &v.Current); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		list = append(list, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

// POST /auth/sessions/{id}/revoke — ends one of the caller's sessions by its
// opaque id. Revoking the current session also clears the cookie; foreign or
// absent ids are the same 404.
func (s *Server) revokeSession(w http.ResponseWriter, r *http.Request) {
	p, th, err := s.principal(r)
	if err != nil || th == "" {
		fail(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var current string
	if th != "" {
		err = s.pool.QueryRow(r.Context(), `SELECT id::text FROM sessions
			WHERE token_hash = $1`, th).Scan(&current)
		if err != nil && err != pgx.ErrNoRows {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	ct, err := s.pool.Exec(r.Context(), `DELETE FROM sessions
		WHERE id = $1 AND user_id = $2`, r.PathValue("id"), p.UserID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ct.RowsAffected() == 0 {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	if r.PathValue("id") == current {
		s.clearSession(w)
	}
	done(w, http.StatusOK)
}

// POST /auth/logout-everywhere — ends every session of the caller.
func (s *Server) logoutEverywhere(w http.ResponseWriter, r *http.Request) {
	p, th, err := s.principal(r)
	if err != nil {
		fail(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if th != "" { // API keys have no sessions; still 200, nothing to end
		if _, err := s.pool.Exec(r.Context(),
			`DELETE FROM sessions WHERE user_id = $1`, p.UserID); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	s.clearSession(w)
	done(w, http.StatusOK)
}

// POST /auth/password-reset {token, new_password} — sets the hash, kills all
// sessions of the user.
func (s *Server) resetComplete(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !validPassword(body.NewPassword) {
		fail(w, http.StatusBadRequest, "invalid password")
		return
	}
	userID, err := s.consumeEmailToken(r, body.Token, "reset")
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid or expired token")
		return
	}
	hash, err := password.Hash(body.NewPassword)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `UPDATE users SET password_hash = $1,
		updated_at = now() WHERE id = $2`, hash, userID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	done(w, http.StatusOK)
}
