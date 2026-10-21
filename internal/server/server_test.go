// Integration tests for the Gatepost auth domain. They need a Postgres URL
// (DATABASE_URL in .env at the repo root); each test gets its own throwaway
// schema (test_<rand>) and drops it afterwards. Real-client IPs are spoofed
// per test via X-Forwarded-For (the test server trusts 127.0.0.1), so rate
// counters never collide between tests.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/db"
	"gatepost/internal/envfile"
	"gatepost/internal/mailer"
	"gatepost/internal/token"
)

// --- infrastructure ----------------------------------------------------------

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// testIP is a plausible, test-unique client address.
func testIP(t *testing.T) string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("10.%d.%d.%d", b[0]%255+1, b[1]%255+1, b[2]%255+1)
}

// testPool returns a pool pinned to a fresh schema that is dropped on cleanup.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	envfile.Load("../../.env")
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("no DATABASE_URL (.env) — integration tests skipped")
	}
	ctx := context.Background()
	schema := "test_" + randHex(t, 6)
	if _, err := db.Migrate(ctx, dbURL, schema); err != nil {
		t.Fatalf("migrate %s: %v", schema, err)
	}
	pool, err := db.OpenSchema(ctx, dbURL, schema)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		pool.Close()
	})
	return pool
}

type tc struct {
	t    *testing.T
	base string
	ip   string
	hc   *http.Client
}

// do runs one request; body "" means no body. XFF carries the test IP so the
// server's rate keys are test-scoped.
func (c tc) do(method, path, body string) (int, string) {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.ip != "" {
		req.Header.Set("X-Forwarded-For", c.ip)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

// must asserts the status and returns the body.
func (c tc) must(method, path, body string, want int) string {
	c.t.Helper()
	code, b := c.do(method, path, body)
	if code != want {
		c.t.Fatalf("%s %s: want %d, got %d: %s", method, path, want, code, b)
	}
	return b
}

// newTestServer wires Server + Outbox on the pool; BaseURL points at the
// httptest server. Proxies trust 127.0.0.1 so tests can spoof IPs via XFF.
// Caps are pinned to small values (20/5) so cap tests finish quickly —
// except where a test overrides them via opts.
func newTestServer(t *testing.T, pool *pgxpool.Pool, opts ...func(*Config)) (tc, *Server) {
	t.Helper()
	cfg := Config{
		Addr:          "127.0.0.1:0",
		BaseURL:       "http://placeholder",
		OutboxDir:     t.TempDir(),
		Mail:          mailer.Config{Driver: "outbox"},
		AuthCap:       20,
		LockoutAfter:  5,
		TrustedProxes: []string{"127.0.0.1/32"},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	s := New(cfg, pool, mailer.NewOutbox(pool, t.TempDir()))
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	s.cfg.BaseURL = ts.URL
	jar, _ := cookiejar.New(nil)
	return tc{t: t, base: ts.URL, ip: testIP(t), hc: &http.Client{Jar: jar}}, s
}

// signupVerify walks the password path and returns the verified principal's
// client (session cookie set).
func signupVerify(t *testing.T, pool *pgxpool.Pool, email, pw string) tc {
	t.Helper()
	c, _ := newTestServer(t, pool)
	c.must("POST", "/auth/signup", `{"email":"`+email+`","password":"`+pw+`"}`, http.StatusOK)
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
	c.must("GET", "/api/me", "", http.StatusOK)
	return c
}

// lastEmailToken extracts the raw token from the newest outbox row of kind.
func lastEmailToken(t *testing.T, pool *pgxpool.Pool, kind string) string {
	t.Helper()
	var body string
	if err := pool.QueryRow(context.Background(),
		`SELECT body FROM outbox_messages WHERE kind = $1 ORDER BY id DESC LIMIT 1`, kind).
		Scan(&body); err != nil {
		t.Fatalf("outbox %s: %v", kind, err)
	}
	m := regexp.MustCompile(`token: ([A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token in %s mail: %q", kind, body)
	}
	return m[1]
}

// wantJSON compares JSON semantically (jsonb re-serializes with spaces).
func wantJSON(t *testing.T, got, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		return false
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad want json %q", want)
	}
	return reflect.DeepEqual(g, w)
}

// unfollow returns a twin of c whose client stops at the 302 (no redirect
// following) so an oauth start leaves its state row open.
func unfollow(c tc) tc {
	jar, _ := cookiejar.New(nil)
	return tc{t: c.t, base: c.base, ip: c.ip, hc: &http.Client{Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}}
}

func countRows(t *testing.T, pool *pgxpool.Pool, table, cond string) int {
	t.Helper()
	q := "SELECT count(*) FROM " + table
	if cond != "" {
		q += " WHERE " + cond
	}
	var n int
	if err := pool.QueryRow(context.Background(), q).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// plaintextSweep fails if secret appears as a raw value in any column of
// table, and (optionally) confirms withHash IS stored in hashCol.
func plaintextSweep(t *testing.T, pool *pgxpool.Pool, table, hashCol, secret, withHash string) {
	t.Helper()
	rows, err := pool.Query(context.Background(), "SELECT * FROM "+table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			if fmt.Sprint(v) == secret {
				t.Errorf("plaintext secret found in %s", table)
			}
		}
	}
	if withHash == "" {
		return
	}
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM `+table+` WHERE `+hashCol+` = $1`, withHash).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Errorf("%s: expected stored fingerprint %s…", table, withHash[:12])
	}
}

// --- password flows -----------------------------------------------------------

func TestPasswordFlow(t *testing.T) {
	pool := testPool(t)
	email, pw := "flow@x.test", "correct horse"
	c, _ := newTestServer(t, pool)

	if code, _ := c.do("POST", "/auth/signup", `{"email":"bad","password":"`+pw+`"}`); code != http.StatusBadRequest {
		t.Fatalf("bad email accepted: %d", code)
	}
	if code, _ := c.do("POST", "/auth/signup", `{"email":"x@y.test","password":"short1"}`); code != http.StatusBadRequest {
		t.Fatalf("short password accepted: %d", code)
	}

	c.must("POST", "/auth/signup", `{"email":"`+email+`","password":"`+pw+`"}`, http.StatusOK)
	// re-signup answers identically (no enumeration)
	c.must("POST", "/auth/signup", `{"email":"`+email+`","password":"`+pw+`"}`, http.StatusOK)

	// garbage token → uniform 400
	c.must("POST", "/auth/verify", `{"token":"nope"}`, http.StatusBadRequest)

	tok := lastEmailToken(t, pool, "verify")
	c.must("POST", "/auth/verify", `{"token":"`+tok+`"}`, http.StatusOK)
	// token is one-time
	c.must("POST", "/auth/verify", `{"token":"`+tok+`"}`, http.StatusBadRequest)

	me := c.must("GET", "/api/me", "", http.StatusOK)
	if !strings.Contains(me, email) {
		t.Fatalf("me = %s", me)
	}

	if code, _ := c.do("POST", "/auth/login", `{"email":"`+email+`","password":"wrongwrong"}`); code != http.StatusUnauthorized {
		t.Fatalf("wrong pw = %d", code)
	}
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"`+pw+`"}`, http.StatusOK)

	// welcome exactly once, even after re-login (progress item 6)
	if n := countRows(t, pool, "outbox_messages", "kind = 'welcome'"); n != 1 {
		t.Fatalf("welcome rows = %d", n)
	}
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"`+pw+`"}`, http.StatusOK)
	if n := countRows(t, pool, "outbox_messages", "kind = 'welcome'"); n != 1 {
		t.Fatalf("welcome rows after re-login = %d", n)
	}

	// DB proof: the raw session cookie and verify token appear nowhere; only
	// their SHA-256 fingerprints do.
	u, _ := url.Parse(c.base)
	var cookieVal string
	for _, ck := range c.hc.Jar.Cookies(u) {
		if ck.Name == "gp_session" {
			cookieVal = ck.Value
		}
	}
	if cookieVal == "" {
		t.Fatal("no session cookie after login")
	}
	plaintextSweep(t, pool, "sessions", "token_hash", cookieVal, token.SHA256Hex(cookieVal))
	plaintextSweep(t, pool, "email_tokens", "token_hash", tok, token.SHA256Hex(tok))
	// no plaintext password either; the argon2id PHC hash is not the secret
	plaintextSweep(t, pool, "users", "password_hash", pw, "")
}

func TestLogout(t *testing.T) {
	pool := testPool(t)
	c := signupVerify(t, pool, "logout@x.test", "secretpw123")
	c.must("POST", "/auth/logout", "", http.StatusOK)
	if code, _ := c.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("after logout /api/me = %d", code)
	}
}

// TestExpiredEmailTokens pins the per-purpose TTLs (progress follow-up):
// verification 24 h, password reset 30 min — and proves an expired token is
// rejected while a fresh one still works.
func TestExpiredEmailTokens(t *testing.T) {
	pool := testPool(t)

	// verify token: stored TTL is ~24 h, and backdating kills it
	c, _ := newTestServer(t, pool)
	c.must("POST", "/auth/signup", `{"email":"exp-verify@x.test","password":"secretpw123"}`, http.StatusOK)
	vt := lastEmailToken(t, pool, "verify")
	var ttlCheck bool
	if err := pool.QueryRow(context.Background(),
		`SELECT expires_at < now() + interval '24 hours 1 minute'
		   AND expires_at > now() + interval '23 hours'
		 FROM email_tokens WHERE token_hash = $1`, token.SHA256Hex(vt)).
		Scan(&ttlCheck); err != nil || !ttlCheck {
		t.Fatalf("verify token TTL not ~24h (%v, %v)", ttlCheck, err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE email_tokens SET expires_at = now() - interval '1 minute'
		 WHERE token_hash = $1`, token.SHA256Hex(vt)); err != nil {
		t.Fatal(err)
	}
	c.must("POST", "/auth/verify", `{"token":"`+vt+`"}`, http.StatusBadRequest)
	if n := countRows(t, pool, "users", "email_verified"); n != 0 {
		t.Fatalf("expired token still verified: %d users", n)
	}

	// reset token: stored TTL is ~30 min, and backdating kills it
	c.must("POST", "/auth/signup", `{"email":"exp-reset@x.test","password":"oldpassword1"}`, http.StatusOK)
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
	c.must("POST", "/auth/password-reset-request", `{"email":"exp-reset@x.test"}`, http.StatusAccepted)
	rt := lastEmailToken(t, pool, "reset")
	if err := pool.QueryRow(context.Background(),
		`SELECT expires_at < now() + interval '31 minutes'
		   AND expires_at > now() + interval '29 minutes'
		 FROM email_tokens WHERE token_hash = $1`, token.SHA256Hex(rt)).
		Scan(&ttlCheck); err != nil || !ttlCheck {
		t.Fatalf("reset token TTL not ~30min (%v, %v)", ttlCheck, err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE email_tokens SET expires_at = now() - interval '1 minute'
		 WHERE token_hash = $1`, token.SHA256Hex(rt)); err != nil {
		t.Fatal(err)
	}
	c.must("POST", "/auth/password-reset", `{"token":"`+rt+`","new_password":"brandnewpw1"}`, http.StatusBadRequest)
	c.must("POST", "/auth/login", `{"email":"exp-reset@x.test","password":"oldpassword1"}`, http.StatusOK)
	// a fresh reset token still works (the expiry filter is per-token)
	c.must("POST", "/auth/password-reset-request", `{"email":"exp-reset@x.test"}`, http.StatusAccepted)
	rt2 := lastEmailToken(t, pool, "reset")
	c.must("POST", "/auth/password-reset", `{"token":"`+rt2+`","new_password":"brandnewpw1"}`, http.StatusOK)
	c.must("POST", "/auth/login", `{"email":"exp-reset@x.test","password":"oldpassword1"}`, http.StatusUnauthorized)
	c.must("POST", "/auth/login", `{"email":"exp-reset@x.test","password":"brandnewpw1"}`, http.StatusOK)
}

func TestPasswordReset(t *testing.T) {
	pool := testPool(t)
	email, pw := "reset@x.test", "oldpassword1"
	c := signupVerify(t, pool, email, pw)

	// second session; reset must kill both
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"`+pw+`"}`, http.StatusOK)

	// uniform 202 whether or not the address exists
	c.must("POST", "/auth/password-reset-request", `{"email":"ghost@x.test"}`, http.StatusAccepted)
	c.must("POST", "/auth/password-reset-request", `{"email":"`+email+`"}`, http.StatusAccepted)

	c.must("POST", "/auth/password-reset", `{"token":"junk","new_password":"brandnewpw1"}`, http.StatusBadRequest)

	tok := lastEmailToken(t, pool, "reset")
	var to, body string
	if err := pool.QueryRow(context.Background(),
		`SELECT to_addr, body FROM outbox_messages WHERE kind='reset' ORDER BY id DESC LIMIT 1`).
		Scan(&to, &body); err != nil {
		t.Fatal(err)
	}
	if to != email {
		t.Fatalf("reset mail to_addr = %s", to)
	}
	c.must("POST", "/auth/password-reset", `{"token":"`+tok+`","new_password":"brandnewpw1"}`, http.StatusOK)

	if code, _ := c.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("session survived reset: %d", code)
	}
	if code, _ := c.do("POST", "/auth/login", `{"email":"`+email+`","password":"`+pw+`"}`); code != http.StatusUnauthorized {
		t.Fatalf("old pw still works: %d", code)
	}
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"brandnewpw1"}`, http.StatusOK)
}

// --- rate limits ---------------------------------------------------------------

func TestLoginLockout(t *testing.T) {
	pool := testPool(t)
	email := "lock@x.test"
	c := signupVerify(t, pool, email, "rightpw123")
	lockKey := "lock|" + c.ip + "|" + email

	for i := 0; i < 5; i++ {
		if code, _ := c.do("POST", "/auth/login", `{"email":"`+email+`","password":"wrongwrong"}`); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, code)
		}
	}
	// lockout: even correct credentials are refused for the window
	if code, _ := c.do("POST", "/auth/login", `{"email":"`+email+`","password":"rightpw123"}`); code != http.StatusTooManyRequests {
		t.Fatalf("locked login: want 429, got %d", code)
	}
	if n := countRows(t, pool, "rate_limits", `key = '`+lockKey+`'`); n != 1 {
		t.Fatalf("lock rows = %d", n)
	}
	// window lapse frees the account (state rolled back 16 minutes)
	if _, err := pool.Exec(context.Background(),
		`UPDATE rate_limits SET window_start = now() - interval '16 minutes' WHERE key = $1`, lockKey); err != nil {
		t.Fatal(err)
	}
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"rightpw123"}`, http.StatusOK)
}

// TestAuthCapPerIP participates the DEFAULT cap only via config override; the
// configured cap (100/15min default, lockout 5) shares this exact code path.
func TestAuthCapPerIP(t *testing.T) {
	pool := testPool(t)
	c, _ := newTestServer(t, pool)
	for i := 0; i < 20; i++ {
		e := fmt.Sprintf("cap%d-%s@x.test", i, randHex(t, 4))
		if code, _ := c.do("POST", "/auth/signup", `{"email":"`+e+`","password":"secretpw123"}`); code != http.StatusOK {
			t.Fatalf("signup %d: want 200, got %d", i+1, code)
		}
	}
	if code, _ := c.do("POST", "/auth/signup", `{"email":"over@x.test","password":"secretpw123"}`); code != http.StatusTooManyRequests {
		t.Fatalf("signup 21: want 429, got %d", code)
	}
	// a different IP is unaffected
	c2 := tc{t: t, base: c.base, ip: testIP(t), hc: c.hc}
	if code, _ := c2.do("POST", "/auth/signup", `{"email":"other-ip@x.test","password":"secretpw123"}`); code != http.StatusOK {
		t.Fatalf("other ip: want 200, got %d", code)
	}
}

// TestAuthCapConfigurable proves the env-driven knobs: a server configured
// with AuthCap 2 caps the third auth POST, and LockoutAfter 1 locks the pair
// after a single failure — even for correct credentials. (The two probes
// use different spoofed IPs so the shared 15-min window doesn't mix them.)
func TestAuthCapConfigurable(t *testing.T) {
	pool := testPool(t)
	loosen := func(c *Config) { c.AuthCap = 2; c.LockoutAfter = 1 }
	c, _ := newTestServer(t, pool, loosen)

	check := func(email, pw string, want int) {
		t.Helper()
		if code, _ := c.do("POST", "/auth/signup", `{"email":"`+email+`","password":"`+pw+`"}`); code != want {
			t.Fatalf("signup %s: want %d, got %d", email, want, code)
		}
	}
	check("cfg-1@x.test", "secretpw123", http.StatusOK)
	check("cfg-2@x.test", "secretpw123", http.StatusOK)
	check("cfg-3@x.test", "secretpw123", http.StatusTooManyRequests) // cap: 2

	// lockout knob on a fresh IP: one failure locks this pair
	c2 := tc{t: t, base: c.base, ip: testIP(t), hc: c.hc}
	if code, _ := c2.do("POST", "/auth/login", `{"email":"cfg-2@x.test","password":"wrongwrong"}`); code != http.StatusUnauthorized {
		t.Fatalf("failed login: want 401, got %d", code)
	}
	if code, _ := c2.do("POST", "/auth/login", `{"email":"cfg-2@x.test","password":"secretpw123"}`); code != http.StatusTooManyRequests {
		t.Fatalf("correct login while locked: want 429, got %d", code)
	}
}

// --- API keys -------------------------------------------------------------------

// execSQL runs admin-style SQL in tests (session window backdating etc.).
func execSQL(t *testing.T, pool *pgxpool.Pool, q string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), q); err != nil {
		t.Fatal(err)
	}
}

// sessionTimes reads one session row's window edges.
func sessionTimes(t *testing.T, pool *pgxpool.Pool, email string) (created, expires time.Time) {
	t.Helper()
	err := pool.QueryRow(context.Background(),
		`SELECT s.created_at, s.expires_at FROM sessions s
		 JOIN users u ON u.id = s.user_id WHERE u.email = $1
		 ORDER BY s.created_at DESC LIMIT 1`, email).Scan(&created, &expires)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func columnStrings(t *testing.T, pool *pgxpool.Pool, q string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// TestSessionExpirySlides: sessions slide to now+7d on use, never past
// created_at+30d absolute; once the absolute window lapses the session is
// dead for good.
func TestSessionExpirySlides(t *testing.T) {
	pool := testPool(t)
	email := "slide-" + randHex(t, 4) + "@x.test"
	c := signupVerify(t, pool, email, "secretpw123")

	// fresh session starts at ~7d (not 30d)
	_, exp := sessionTimes(t, pool, email)
	if d := time.Until(exp); d < 167*time.Hour || d > 7*24*time.Hour+time.Minute {
		t.Fatalf("fresh expiry: want ~7d, got %v", d)
	}

	// stale row + use → slides back out to ~7d from now
	execSQL(t, pool, `UPDATE sessions SET expires_at = now() + interval '1 hour'`)
	c.must("GET", "/api/me", "", http.StatusOK)
	_, exp = sessionTimes(t, pool, email)
	if d := time.Until(exp); d < 167*time.Hour {
		t.Fatalf("slid expiry: want ~7d, got %v", d)
	}

	// 29-day-old session: slide capped at created_at+30d (≈ now+1d)
	execSQL(t, pool, `UPDATE sessions SET created_at = now() - interval '29 days',
		expires_at = now() + interval '1 hour'`)
	c.must("GET", "/api/me", "", http.StatusOK)
	_, exp = sessionTimes(t, pool, email)
	if d := time.Until(exp); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("absolute cap: want ~1d, got %v", d)
	}

	// 31-day-old session: absolute window passed → dead, not resurrected
	execSQL(t, pool, `UPDATE sessions SET created_at = now() - interval '31 days',
		expires_at = now() + interval '5 minutes'`)
	if code, _ := c.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("lapsed absolute: want 401")
	}
}

// TestSessionRotation: login always issues a fresh session; password change
// ends every other session and rotates the caller's token in place.
func TestSessionRotation(t *testing.T) {
	pool := testPool(t)
	email := "rot-" + randHex(t, 4) + "@x.test"
	c := signupVerify(t, pool, email, "oldepw12345")
	if n := countRows(t, pool, "sessions", ""); n != 1 {
		t.Fatalf("after verify: want 1 session, got %d", n)
	}

	// login rotates by creating a fresh session (old row stays until cleaned)
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"oldepw12345"}`, http.StatusOK)
	if n := countRows(t, pool, "sessions", ""); n != 2 {
		t.Fatalf("after re-login: want 2 sessions, got %d", n)
	}

	// and a second device gets its own session
	c2 := unfollow(c)
	c2.must("POST", "/auth/login", `{"email":"`+email+`","password":"oldepw12345"}`, http.StatusOK)
	c2.must("GET", "/api/me", "", http.StatusOK)
	before := columnStrings(t, pool, `SELECT token_hash FROM sessions`)
	if len(before) != 3 {
		t.Fatalf("want 3 sessions, got %d", len(before))
	}

	// password-change is session-only: bearer is refused
	key := c.must("POST", "/auth/api-keys", `{"name":"t"}`, http.StatusCreated)
	kid := struct{ Key string }{}
	json.Unmarshal([]byte(key), &kid) //nolint:errcheck — shape covered by TestAPIKeys
	bearer := tc{t: t, base: c.base, ip: c.ip, hc: &http.Client{Transport: bearerRT(kid.Key)}}
	if code, _ := bearer.do("POST", "/auth/password-change",
		`{"current_password":"oldepw12345","new_password":"newpw123456"}`); code != http.StatusUnauthorized {
		t.Fatalf("bearer password-change: want 401, got %d", code)
	}

	// wrong current password → 401, nothing changes
	if code, _ := c.do("POST", "/auth/password-change",
		`{"current_password":"wrongwrong","new_password":"newpw123456"}`); code != http.StatusUnauthorized {
		t.Fatalf("wrong current pw: want 401, got %d", code)
	}
	if n := countRows(t, pool, "sessions", ""); n != 3 {
		t.Fatalf("failed change must not touch sessions, got %d", n)
	}

	// weak new password → 400
	if code, _ := c.do("POST", "/auth/password-change",
		`{"current_password":"oldepw12345","new_password":"short"}`); code != http.StatusBadRequest {
		t.Fatalf("weak new pw: want 400, got %d", code)
	}

	// correct change: current session rotated (hash not in old set), others die
	c.must("POST", "/auth/password-change",
		`{"current_password":"oldepw12345","new_password":"newpw123456"}`, http.StatusOK)
	after := columnStrings(t, pool, `SELECT token_hash FROM sessions`)
	if len(after) != 1 {
		t.Fatalf("after change: want 1 session, got %d", len(after))
	}
	for _, h := range before {
		if h == after[0] {
			t.Fatal("session hash was not rotated")
		}
	}
	if code, _ := c2.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("other session survived password change: %d", code)
	}
	c.must("GET", "/api/me", "", http.StatusOK) // rotated cookie still valid

	// old password dead, new password works
	if code, _ := c.do("POST", "/auth/login", `{"email":"`+email+`","password":"oldepw12345"}`); code != http.StatusUnauthorized {
		t.Fatalf("old password still accepted: %d", code)
	}
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"newpw123456"}`, http.StatusOK)
}

// TestListAndRevokeSessions: list shows metadata + the current flag but no
// token material; revoke ends exactly one session; revoking the current one
// also clears the cookie; absent/foreign ids are the same 404.
func TestListAndRevokeSessions(t *testing.T) {
	pool := testPool(t)
	email := "sess-" + randHex(t, 4) + "@x.test"
	c := signupVerify(t, pool, email, "secretpw123")
	c2 := unfollow(c)
	c2.must("POST", "/auth/login", `{"email":"`+email+`","password":"secretpw123"}`, http.StatusOK)

	// bearer is refused: session management is session-only
	keyBody := c.must("POST", "/auth/api-keys", `{"name":"t"}`, http.StatusCreated)
	var kb struct{ Key string }
	if err := json.Unmarshal([]byte(keyBody), &kb); err != nil {
		t.Fatalf("key json: %v: %s", err, keyBody)
	}
	bearer := tc{t: t, base: c.base, ip: c.ip, hc: &http.Client{Transport: bearerRT(kb.Key)}}
	if code, _ := bearer.do("GET", "/auth/sessions", ""); code != http.StatusUnauthorized {
		t.Fatalf("bearer sessions list: want 401, got %d", code)
	}
	if code, _ := bearer.do("POST", "/auth/sessions/00000000-0000-0000-0000-000000000000/revoke", ""); code != http.StatusUnauthorized {
		t.Fatalf("bearer revoke: want 401, got %d", code)
	}

	body := c.must("GET", "/auth/sessions", "", http.StatusOK)
	var list struct {
		Sessions []struct {
			ID        string    `json:"id"`
			CreatedAt time.Time `json:"created_at"`
			ExpiresAt time.Time `json:"expires_at"`
			Current   bool      `json:"current"`
		}
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("list json: %v: %s", err, body)
	}
	if len(list.Sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(list.Sessions))
	}
	currents, others := 0, []string{}
	for _, s := range list.Sessions {
		if s.ExpiresAt.Before(s.CreatedAt) || time.Until(s.ExpiresAt) < 24*time.Hour {
			t.Fatalf("row %s window nonsense: created %v, expires %v", s.ID, s.CreatedAt, s.ExpiresAt)
		}
		if s.Current {
			currents++
		} else {
			others = append(others, s.ID)
		}
	}
	if currents != 1 || len(others) != 1 {
		t.Fatalf("want 1 current + 1 other, got %d current, %d other", currents, len(others))
	}
	// no token material: stored hashes must not appear in the response body
	for _, h := range columnStrings(t, pool, `SELECT token_hash FROM sessions`) {
		if strings.Contains(body, h) {
			t.Fatal("sessions list leaks token_hash")
		}
	}
	if countRows(t, pool, "sessions", "") != 2 {
		t.Fatal("rows changed during listing")
	}

	// revoke the other session (c2's) from c
	c.must("POST", "/auth/sessions/"+others[0]+"/revoke", "", http.StatusOK)
	if code, _ := c2.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked session still valid: %d", code)
	}
	c.must("GET", "/api/me", "", http.StatusOK)
	if n := countRows(t, pool, "sessions", ""); n != 1 {
		t.Fatalf("want 1 session left, got %d", n)
	}

	// absent id is 404
	if code, _ := c.do("POST", "/auth/sessions/00000000-0000-0000-0000-000000000000/revoke", ""); code != http.StatusNotFound {
		t.Fatalf("absent revoke: want 404, got %d", code)
	}

	// revoking the current session also clears the cookie: caller is logged out
	currentID := ""
	for _, s := range list.Sessions {
		if s.Current {
			currentID = s.ID
		}
	}
	c.must("POST", "/auth/sessions/"+currentID+"/revoke", "", http.StatusOK)
	if code, _ := c.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("current session survived self-revoke: %d", code)
	}
	if code, _ := bearer.do("GET", "/api/me", ""); code != http.StatusOK {
		t.Fatalf("api key should survive session revocation: %d", code)
	}
}

// TestLogoutEverywhere: one request ends every session of the caller.
func TestLogoutEverywhere(t *testing.T) {
	pool := testPool(t)
	email := "wipe-" + randHex(t, 4) + "@x.test"
	c := signupVerify(t, pool, email, "secretpw123")
	c.must("POST", "/auth/login", `{"email":"`+email+`","password":"secretpw123"}`, http.StatusOK)
	c2 := unfollow(c)
	c2.must("POST", "/auth/login", `{"email":"`+email+`","password":"secretpw123"}`, http.StatusOK)
	if n := countRows(t, pool, "sessions", ""); n != 3 {
		t.Fatalf("want 3 sessions, got %d", n)
	}

	c.must("POST", "/auth/logout-everywhere", "", http.StatusOK)
	if code, _ := c.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("caller survived logout-everywhere: %d", code)
	}
	if code, _ := c2.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("other device survived logout-everywhere: %d", code)
	}
	if n := countRows(t, pool, "sessions", ""); n != 0 {
		t.Fatalf("want 0 sessions, got %d", n)
	}
}

func TestAPIKeys(t *testing.T) {
	pool := testPool(t)
	email := "keys@x.test"
	c := signupVerify(t, pool, email, "secretpw123")

	body := c.must("POST", "/auth/api-keys", `{"name":"ci"}`, http.StatusCreated)
	var created struct{ ID, Name, Key, Prefix string }
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("create key: %v: %s", err, body)
	}
	if !strings.HasPrefix(created.Key, "gp_pat_") || len(created.Key) != 50 {
		t.Fatalf("key shape: %q (len %d)", created.Key, len(created.Key))
	}
	if created.Prefix != created.Key[:15] {
		t.Fatalf("prefix mismatch: %q", created.Prefix)
	}

	c.must("GET", "/api/me", "", http.StatusOK)

	// Bearer principal works on /api/*
	bearer := tc{t: t, base: c.base, ip: c.ip, hc: &http.Client{Transport: bearerRT(created.Key)}}
	if code, b := bearer.do("PUT", "/api/user-data", `{"via":"key"}`); code != http.StatusOK {
		t.Fatalf("bearer user-data: %d %s", code, b)
	}

	// API-key management is session-only
	if code, _ := bearer.do("POST", "/auth/api-keys", `{"name":"x"}`); code != http.StatusUnauthorized {
		t.Fatalf("bearer create key: %d", code)
	}

	// list shows metadata only, never the key
	list := c.must("GET", "/auth/api-keys", "", http.StatusOK)
	if strings.Contains(list, created.Key) {
		t.Fatalf("list leaks key: %s", list)
	}

	// revoke is terminal; revocation of foreign/absent keys is the same 404
	c.must("POST", "/auth/api-keys/"+created.ID+"/revoke", "", http.StatusOK)
	c.must("POST", "/auth/api-keys/"+created.ID+"/revoke", "", http.StatusNotFound)
	c.must("POST", "/auth/api-keys/00000000-0000-0000-0000-000000000000/revoke", "", http.StatusNotFound)
	if code, _ := bearer.do("GET", "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked key still works: %d", code)
	}
	if code, _ := bearer.do("GET", "/api/user-data", ""); code != http.StatusUnauthorized {
		t.Fatalf("revoked key user-data: %d", code)
	}

	// DB proof (progress item 4): only hash + inert prefix stored
	hash := token.SHA256Hex(created.Key)
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM api_keys WHERE key_hash = $1`, hash).Scan(&n); err != nil || n != 1 {
		t.Fatalf("key_hash rows = %d (%v)", n, err)
	}
	plaintextSweep(t, pool, "api_keys", "key_hash", created.Key, hash)
}

type bearerRT string

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}

// --- user_data ------------------------------------------------------------------

func TestUserDataIsolation(t *testing.T) {
	pool := testPool(t)
	a := signupVerify(t, pool, "ua@x.test", "secretpw123")
	jar, _ := cookiejar.New(nil)
	b := tc{t: t, base: a.base, ip: testIP(t), hc: &http.Client{Jar: jar}}
	b.must("POST", "/auth/signup", `{"email":"ub@x.test","password":"secretpw123"}`, http.StatusOK)
	b.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)

	// A stores; B sees neither the doc nor its keys (progress item 5)
	a.must("PUT", "/api/user-data", `{"secret":"a-only","n":[1,2,3]}`, http.StatusOK)
	if got := b.must("GET", "/api/user-data", "", http.StatusOK); wantJSON(t, got, `{}`) == false {
		t.Fatalf("B sees A's data: %s", got)
	}
	if got := a.must("GET", "/api/user-data", "", http.StatusOK); wantJSON(t, got,
		`{"secret":"a-only","n":[1,2,3]}`) == false {
		t.Fatalf("A roundtrip: %s", got)
	}
	// B stores their own; A unchanged
	b.must("PUT", "/api/user-data", `{"b":true}`, http.StatusOK)
	got := a.must("GET", "/api/user-data", "", http.StatusOK)
	var aDoc map[string]any
	if err := json.Unmarshal([]byte(got), &aDoc); err != nil || aDoc["b"] != nil || aDoc["secret"] == nil {
		t.Fatalf("A doc polluted or lost: %s (%v)", got, err)
	}
	// proof: exactly one row per user
	if n := countRows(t, pool, "user_data", ""); n != 2 {
		t.Fatalf("user_data rows = %d", n)
	}
	// oversized and invalid bodies rejected (≤32 KiB, must parse)
	big := `{"x":"` + strings.Repeat("z", 33<<10) + `"}`
	if code, _ := a.do("PUT", "/api/user-data", big); code != http.StatusBadRequest {
		t.Fatalf("oversize: %d", code)
	}
	if code, _ := a.do("PUT", "/api/user-data", `{"x":`); code != http.StatusBadRequest {
		t.Fatalf("invalid json: %d", code)
	}
	// bogus bearer rejected
	bb := tc{t: t, base: a.base, ip: a.ip, hc: &http.Client{Transport: bearerRT("bogus")}}
	if code, _ := bb.do("GET", "/api/user-data", ""); code != http.StatusUnauthorized {
		t.Fatalf("bogus bearer: %d", code)
	}
}

// --- OAuth via fake provider ------------------------------------------------------

type fakeGrant struct {
	challenge, redirect, email string
	verified                   bool
	ghID                       int
}

type fakeOAuth struct {
	t        *testing.T
	mu       sync.Mutex
	email    string
	verified bool
	ghID     int
	base     string
	codes    map[string]*fakeGrant // code → grant; deleted on first use
	toks     map[string]*fakeGrant
	lastCode string
}

func newFakeOAuth(t *testing.T) *fakeOAuth {
	f := &fakeOAuth{t: t, codes: map[string]*fakeGrant{}, toks: map[string]*fakeGrant{}}
	ts := httptest.NewServer(f.mux())
	f.base = ts.URL
	t.Cleanup(ts.Close)
	return f
}

func (f *fakeOAuth) setIdentity(email string, verified bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ghID++
	f.email, f.verified = email, verified
}

func (f *fakeOAuth) mux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != "oauth-client" || !strings.HasPrefix(q.Get("redirect_uri"), "http") ||
			q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		code := randHex(f.t, 16)
		f.mu.Lock()
		f.codes[code] = &fakeGrant{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"),
			email: f.email, verified: f.verified, ghID: f.ghID}
		f.lastCode = code
		f.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
	})
	m.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form", http.StatusBadRequest)
			return
		}
		code := r.PostFormValue("code")
		f.mu.Lock()
		g := f.codes[code]
		delete(f.codes, code) // single-use: replay fails here
		f.mu.Unlock()
		if r.PostFormValue("client_id") != "oauth-client" ||
			r.PostFormValue("client_secret") != "oauth-secret" ||
			g == nil || s256(r.PostFormValue("code_verifier")) != g.challenge ||
			r.PostFormValue("redirect_uri") != g.redirect {
			http.Error(w, `{"error":"bad_request"}`, http.StatusForbidden)
			return
		}
		tok := "tok-" + randHex(f.t, 16)
		f.mu.Lock()
		f.toks[tok] = g
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer"}`, tok)
	})
	guard := func(w http.ResponseWriter, r *http.Request) *fakeGrant {
		f.mu.Lock()
		defer f.mu.Unlock()
		g := f.toks[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		if g == nil {
			http.Error(w, "no token", http.StatusUnauthorized)
		}
		return g
	}
	m.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		g := guard(w, r)
		if g == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"sub":"sub-%d","email":%q,"email_verified":%t}`, g.ghID, g.email, g.verified)
	})
	m.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		g := guard(w, r)
		if g == nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":%d,"login":"ll"}`, g.ghID)
	})
	m.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		g := guard(w, r)
		if g == nil {
			return
		}
		// decoy: a verified email that is NOT primary must never be accepted
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `[{"email":"decoy@x.test","primary":false,"verified":true},
			{"email":%q,"primary":true,"verified":%t}]`, g.email, g.verified)
	})
	return m
}

func (f *fakeOAuth) providerOverride() map[string]oauthProvider {
	fb := f.base
	return map[string]oauthProvider{
		"google": {ClientID: "oauth-client", ClientSecret: "oauth-secret",
			AuthURL: fb + "/authorize", TokenURL: fb + "/token",
			Scopes: []string{"openid", "email"}, user: fetchUserinfo(fb + "/userinfo")},
		"github": {ClientID: "oauth-client", ClientSecret: "oauth-secret",
			AuthURL: fb + "/authorize", TokenURL: fb + "/token",
			Scopes: []string{"user:email"}, user: fetchGitHubUser(fb)},
	}
}

// oauthFlow runs start→authorize→callback with redirects followed.
func (c tc) oauthFlow(provider string) (int, string) {
	return c.do("GET", "/auth/oauth/"+provider+"/start", "")
}

// anyOpenState returns the newest unused oauth state row.
func anyOpenState(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var st string
	if err := pool.QueryRow(context.Background(),
		`SELECT state FROM oauth_states WHERE used_at IS NULL ORDER BY created_at DESC LIMIT 1`).
		Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestOAuthGoogleHappyPath(t *testing.T) {
	pool := testPool(t)
	c, s := newTestServer(t, pool)
	f := newFakeOAuth(t)
	f.setIdentity("google-user@x.test", true)
	s.providers = f.providerOverride()

	if code, body := c.oauthFlow("google"); code != http.StatusOK {
		t.Fatalf("flow: %d %s", code, body)
	}
	c.must("GET", "/api/me", "", http.StatusOK)
	if n := countRows(t, pool, "users", ""); n != 1 {
		t.Fatalf("users = %d", n)
	}
	if n := countRows(t, pool, "auth_identities", ""); n != 1 {
		t.Fatalf("identities = %d", n)
	}
	if n := countRows(t, pool, "outbox_messages", "kind = 'welcome'"); n != 1 {
		t.Fatalf("welcome = %d", n)
	}

	// replaying the first code with a fresh state → 403, no second user
	f.mu.Lock()
	firstCode := f.lastCode
	f.mu.Unlock()
	// open a state row WITHOUT completing the flow (302 not followed)
	if code, _ := unfollow(c).do("GET", "/auth/oauth/google/start", ""); code != http.StatusFound {
		t.Fatalf("start w/o follow: %d", code)
	}
	openState := anyOpenState(t, pool)
	if code, body := c.do("GET", "/auth/oauth/google/callback?code="+firstCode+"&state="+openState, ""); code != http.StatusForbidden {
		t.Fatalf("replay: %d %s", code, body)
	}
	if n := countRows(t, pool, "users", ""); n != 1 {
		t.Fatalf("users after replay = %d", n)
	}
}

func TestOAuthStateAndRedirect(t *testing.T) {
	pool := testPool(t)
	c, s := newTestServer(t, pool)
	f := newFakeOAuth(t)
	f.setIdentity("state-user@x.test", true)
	s.providers = f.providerOverride()

	// tampered/unknown state
	if code, _ := c.do("GET", "/auth/oauth/google/callback?code=abc&state=tampered", ""); code != http.StatusForbidden {
		t.Fatalf("unknown state: %d", code)
	}
	// state is bound to its provider: a github state cannot complete google
	// (302 not followed → the state row stays open)
	if code, _ := unfollow(c).oauthFlow("github"); code != http.StatusFound {
		t.Fatalf("github start: %d", code)
	}
	ghState := anyOpenState(t, pool)
	if code, body := c.do("GET", "/auth/oauth/google/callback?code=abc&state="+ghState, ""); code != http.StatusForbidden {
		t.Fatalf("cross-provider state: %d %s", code, body)
	}
	// an attacker-supplied redirect_uri in the state row is rejected
	if _, err := pool.Exec(context.Background(), `INSERT INTO oauth_states
		(state, provider, code_verifier, redirect_uri, expires_at)
		VALUES ('evil-state','google','v','http://evil.test/callback', now() + interval '10 minutes')`); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do("GET", "/auth/oauth/google/callback?code=abc&state=evil-state", ""); code != http.StatusForbidden {
		t.Fatalf("evil redirect: %d", code)
	}
	// nothing was created by any of the attacks
	if n := countRows(t, pool, "users", ""); n != 0 {
		t.Fatalf("users after attacks = %d", n)
	}
	// unknown provider → 404
	if code, _ := c.do("GET", "/auth/oauth/orange/start", ""); code != http.StatusNotFound {
		t.Fatalf("unknown provider: %d", code)
	}
}

func TestOAuthUnverifiedEmails(t *testing.T) {
	pool := testPool(t)
	c, s := newTestServer(t, pool)
	f := newFakeOAuth(t)
	s.providers = f.providerOverride()

	// provider reports an unverified email
	f.setIdentity("nv@x.test", false)
	if code, _ := c.oauthFlow("google"); code != http.StatusForbidden {
		t.Fatalf("unverified google: %d", code)
	}
	// github primary unverified; the verified NON-primary decoy must not save it
	f.setIdentity("nvg@x.test", false)
	if code, _ := c.oauthFlow("github"); code != http.StatusForbidden {
		t.Fatalf("unverified github: %d", code)
	}
	if n := countRows(t, pool, "users", ""); n != 0 {
		t.Fatalf("users created from unverified: %d", n)
	}
	if n := countRows(t, pool, "outbox_messages", "kind = 'welcome'"); n != 0 {
		t.Fatalf("welcome for unverified: %d", n)
	}
}

func TestOAuthLinking(t *testing.T) {
	pool := testPool(t)
	email := "link@x.test"

	c, s := newTestServer(t, pool)
	f := newFakeOAuth(t)
	s.providers = f.providerOverride()

	// local account exists but is unverified → no link, no duplicate
	c.must("POST", "/auth/signup", `{"email":"`+email+`","password":"secretpw123"}`, http.StatusOK)
	f.setIdentity(email, true)
	if code, _ := c.oauthFlow("google"); code != http.StatusForbidden {
		t.Fatalf("link to unverified: %d", code)
	}
	if n := countRows(t, pool, "users", ""); n != 1 {
		t.Fatalf("users: %d", n)
	}
	if n := countRows(t, pool, "auth_identities", ""); n != 0 {
		t.Fatalf("identities: %d", n)
	}

	// verify the local account → oauth links: same user, one identity
	c.must("POST", "/auth/verify", `{"token":"`+lastEmailToken(t, pool, "verify")+`"}`, http.StatusOK)
	if code, body := c.oauthFlow("google"); code != http.StatusOK {
		t.Fatalf("link: %d %s", code, body)
	}
	if n := countRows(t, pool, "users", ""); n != 1 {
		t.Fatalf("users after link: %d", n)
	}
	if n := countRows(t, pool, "auth_identities", ""); n != 1 {
		t.Fatalf("identities after link: %d", n)
	}

	// existing identity → plain login again; no second welcome
	wl := countRows(t, pool, "outbox_messages", "kind = 'welcome'")
	if code, _ := c.oauthFlow("google"); code != http.StatusOK {
		t.Fatalf("re-login: %d", code)
	}
	if n := countRows(t, pool, "outbox_messages", "kind = 'welcome'"); n != wl {
		t.Fatalf("welcome grew on re-login")
	}
}

func TestOAuthTwoProvidersOneUser(t *testing.T) {
	pool := testPool(t)
	email := "twoprov@x.test"
	c, s := newTestServer(t, pool)
	f := newFakeOAuth(t)
	s.providers = f.providerOverride()
	f.setIdentity(email, true)
	if code, body := c.oauthFlow("google"); code != http.StatusOK {
		t.Fatalf("google: %d %s", code, body)
	}
	if code, body := c.oauthFlow("github"); code != http.StatusOK {
		t.Fatalf("github: %d %s", code, body)
	}
	if n := countRows(t, pool, "users", ""); n != 1 {
		t.Fatalf("duplicate users across providers: %d", n)
	}
	if n := countRows(t, pool, "auth_identities", ""); n != 2 {
		t.Fatalf("identities: %d", n)
	}
}
