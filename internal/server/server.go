// Package server: HTTP API for Gatepost accounts (routing, helpers, principal).
package server

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/mailer"
	"gatepost/internal/password"
	"gatepost/internal/token"
)

const (
	sessionCookie = "gp_session"
	sessionMaxAge = 30 * 24 * time.Hour
)

type Config struct {
	Addr               string
	BaseURL            string // e.g. http://localhost:8080 — cookie Secure flag + OAuth redirects derive from it
	OutboxDir          string
	Mail               mailer.Config
	GoogleClientID     string
	GoogleClientSecret string
	GitHubClientID     string
	GitHubClientSecret string
	// Rate limiting (env in main): max auth POSTs per IP / 15 min, and how
	// many failed logins trigger the per-(IP,email) lockout. Zeros fall back
	// to the design defaults (100 / 5) so tests can leave them unset.
	AuthCap       int
	LockoutAfter  int
	TrustedProxes []string // CIDR list of trusted reverse proxies; default: trust nothing
}

type Principal struct {
	UserID string
	Email  string
}

type Server struct {
	cfg          Config
	pool         *pgxpool.Pool
	mail         mailer.Sender
	mux          *http.ServeMux
	secureCookie bool
	providers    map[string]oauthProvider
	dummy        string // argon2id hash verified against when the user is unknown, for uniform timing
}

func New(cfg Config, pool *pgxpool.Pool, mail mailer.Sender) *Server {
	s := &Server{cfg: cfg, pool: pool, mail: mail, mux: http.NewServeMux(),
		secureCookie: strings.HasPrefix(cfg.BaseURL, "https://")}
	if s.cfg.AuthCap <= 0 {
		s.cfg.AuthCap = 100 // design default: 100 auth POSTs / IP / 15 min
	}
	if s.cfg.LockoutAfter <= 0 {
		s.cfg.LockoutAfter = 5 // design default: 5 failed logins lock the pair
	}
	s.dummy, _ = password.Hash("gatepost-dummy-credentials")
	s.providers = defaultProviders(cfg)
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler { return s.mux }
func (s *Server) Addr() string          { return s.cfg.Addr }

func (s *Server) routes() {
	s.mux.HandleFunc("POST /auth/signup", s.signup)
	s.mux.HandleFunc("POST /auth/verify", s.verify)
	s.mux.HandleFunc("POST /auth/login", s.login)
	s.mux.HandleFunc("POST /auth/logout", s.logout)
	s.mux.HandleFunc("POST /auth/password-reset-request", s.resetRequest)
	s.mux.HandleFunc("POST /auth/password-reset", s.resetComplete)
	s.mux.HandleFunc("POST /auth/api-keys", s.requireSession(s.createAPIKey))
	s.mux.HandleFunc("GET /auth/api-keys", s.requireSession(s.listAPIKeys))
	s.mux.HandleFunc("POST /auth/api-keys/{id}/revoke", s.requireSession(s.revokeAPIKey))
	s.mux.HandleFunc("GET /auth/oauth/{provider}/start", s.oauthStart)
	s.mux.HandleFunc("GET /auth/oauth/{provider}/callback", s.oauthCallback)
	s.mux.HandleFunc("GET /api/me", s.requireAuth(s.me))
	s.mux.HandleFunc("GET /api/user-data", s.requireAuth(s.getUserData))
	s.mux.HandleFunc("PUT /api/user-data", s.requireAuth(s.putUserData))
}

// --- http helpers -----------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 40<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		fail(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// --- client IP ---------------------------------------------------------------

// clientIP returns the real client address: RemoteAddr, unless the direct peer
// is a trusted proxy (then the first untrusted X-Forwarded-For hop wins).
func (s *Server) clientIP(r *http.Request) string {
	peer, _, _ := net.SplitHostPort(r.RemoteAddr)
	if len(s.cfg.TrustedProxes) == 0 || !s.peerIsTrusted(peer, r) {
		return peer
	}
	xff := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(xff) - 1; i >= 0; i-- {
		h := strings.TrimSpace(xff[i])
		if !cidrContains(s.cfg.TrustedProxes, h) {
			return h
		}
	}
	return peer
}

func (s *Server) peerIsTrusted(peer string, r *http.Request) bool {
	return cidrContains(s.cfg.TrustedProxes, peer) && r.Header.Get("X-Forwarded-For") != ""
}

func cidrContains(cidrs []string, ip string) bool {
	pip := net.ParseIP(ip)
	if pip == nil {
		return false
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(pip) {
			return true
		}
	}
	return false
}

// --- principal & sessions ----------------------------------------------------

func (s *Server) bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	if len(tok) < 10 || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

// principal resolves the caller: session cookie first (returns its token hash,
// "" for API keys), then a Bearer API key. Returns errNoPrincipal when neither
// authenticates.
func (s *Server) principal(r *http.Request) (*Principal, string, error) {
	if p, th, err := s.sessionPrincipal(r); err == nil {
		return p, th, nil
	}
	tok, ok := s.bearerToken(r)
	if !ok {
		return nil, "", errNoPrincipal
	}
	var uid string
	err := s.pool.QueryRow(r.Context(), `UPDATE api_keys SET last_used_at = now()
		WHERE key_hash = $1 AND revoked_at IS NULL RETURNING user_id`,
		token.SHA256Hex(tok)).Scan(&uid)
	if err != nil {
		return nil, "", errNoPrincipal
	}
	var p Principal
	if err := s.pool.QueryRow(r.Context(), `
		SELECT id::text, email FROM users u WHERE u.id = $1`, uid).
		Scan(&p.UserID, &p.Email); err != nil {
		return nil, "", errNoPrincipal
	}
	return &p, "", nil
}

func (s *Server) sessionPrincipal(r *http.Request) (*Principal, string, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, "", errNoPrincipal
	}
	hash := token.SHA256Hex(c.Value)
	row := s.pool.QueryRow(r.Context(), `
		SELECT u.id::text, u.email, s.token_hash
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.expires_at > now()`, hash)
	var p Principal
	var th string
	if err := row.Scan(&p.UserID, &p.Email, &th); err != nil {
		return nil, "", errNoPrincipal
	}
	return &p, th, nil
}

var errNoPrincipal = errors.New("no valid session")

func (s *Server) requireAuth(next func(http.ResponseWriter, *http.Request, *Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _, err := s.principal(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r, p)
	}
}

// requireSession keeps API-key management session-only: Bearer keys may use
// /api/* but may not mint or revoke keys.
func (s *Server) requireSession(next func(http.ResponseWriter, *http.Request, *Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, th, err := s.principal(r)
		if err != nil || th == "" {
			fail(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r, p)
	}
}

// newSession stores only the token hash and sets the cookie.
func (s *Server) newSession(w http.ResponseWriter, r *http.Request, userID string) error {
	tok := token.New()
	_, err := s.pool.Exec(r.Context(), `INSERT INTO sessions (token_hash, user_id, expires_at)
		VALUES ($1, $2, now() + interval '30 days')`, token.SHA256Hex(tok), userID)
	if err != nil {
		return err
	}
	// opportunistic cleanup of expired sessions
	_, _ = s.pool.Exec(r.Context(), `DELETE FROM sessions WHERE expires_at < now()`)

	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: tok, Path: "/",
		HttpOnly: true, Secure: s.secureCookie,
		SameSite: http.SameSiteLaxMode, MaxAge: int(sessionMaxAge.Seconds()),
	})
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: s.secureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// --- email templates ---------------------------------------------------------

func verifyEmailText(baseURL, rawToken string) string {
	return "Your verification token: " + rawToken + "\n\n" +
		"POST it to " + baseURL + "/auth/verify to verify your account.\n" +
		"The token expires in 24 hours."
}

func resetEmailText(baseURL, rawToken string) string {
	return "Your password reset token: " + rawToken + "\n\n" +
		"POST it to " + baseURL + "/auth/password-reset to set a new password.\n" +
		"The token expires in 24 hours."
}

// welcomeText is intentionally boring: email, time, one fixed line. No token,
// no link.
func welcomeText(email string, when time.Time) string {
	return "Hello,\n\nThis is the Gatepost account for " + email + ".\n" +
		"Time: " + when.UTC().Format(time.RFC3339) + "\n" +
		"This is a test message from Gatepost.\n"
}

// welcomeOnce sends the welcome message exactly once per user (atomic guard).
func (s *Server) welcomeOnce(r *http.Request, userID string) {
	var email string
	err := s.pool.QueryRow(r.Context(), `UPDATE users SET welcome_sent_at = now()
		WHERE id = $1 AND welcome_sent_at IS NULL RETURNING email`, userID).Scan(&email)
	if err != nil { // already sent, or race lost: nothing to do
		return
	}
	_ = s.mail.Send(r.Context(), mailer.Message{
		To: email, Kind: "welcome", Subject: "Welcome to Gatepost",
		TextBody: welcomeText(email, time.Now()),
	})
}

// --- sessions & tokens -------------------------------------------------------

// newEmailToken stores the token's SHA-256 with a purpose-scoped TTL:
// verification 24 h, password reset 30 min.
func (s *Server) newEmailToken(r *http.Request, userID, purpose string) (string, error) {
	ttl := "24 hours"
	if purpose == "reset" {
		ttl = "30 minutes"
	}
	raw := token.New()
	_, err := s.pool.Exec(r.Context(), `INSERT INTO email_tokens (token_hash, user_id, purpose, expires_at)
		VALUES ($1, $2, $3, now() + interval '`+ttl+`')`, token.SHA256Hex(raw), userID, purpose)
	return raw, err
}

// consumeEmailToken spends a one-time token atomically; non-error means valid.
func (s *Server) consumeEmailToken(r *http.Request, raw, purpose string) (string, error) {
	var userID string
	err := s.pool.QueryRow(r.Context(), `UPDATE email_tokens SET used_at = now()
		WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > now()
		RETURNING user_id`, token.SHA256Hex(raw), purpose).Scan(&userID)
	return userID, err
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
