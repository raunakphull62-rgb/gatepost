// Package server — OAuth (design §5): state + S256 PKCE per attempt, a fixed
// redirect allowlist derived from GP_PUBLIC_BASE_URL, code exchange, and the
// identity→account linking rules. Only verified provider emails are accepted.
// The code exchange is a plain form POST (stdlib) — no oauth2 dependency;
// endpoints are fixed here, tests override s.providers wholesale.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"gatepost/internal/token"
)

var oauthHTTP = &http.Client{Timeout: 15 * time.Second}

type oauthIdentity struct {
	Provider      string
	AccountID     string
	Email         string
	EmailVerified bool
}

type oauthProvider struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       []string
	user         func(ctx context.Context, client *http.Client) (oauthIdentity, error)
}

func defaultProviders(cfg Config) map[string]oauthProvider {
	return map[string]oauthProvider{
		"google": {
			ClientID: cfg.GoogleClientID, ClientSecret: cfg.GoogleClientSecret,
			AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
			Scopes:   []string{"openid", "email"},
			user:     fetchUserinfo("https://openidconnect.googleapis.com/v1/userinfo"),
		},
		"github": {
			ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret,
			AuthURL:  "https://github.com/login/oauth/authorize",
			TokenURL: "https://github.com/login/oauth/access_token",
			Scopes:   []string{"user:email"},
			user:     fetchGitHubUser("https://api.github.com"),
		},
	}
}

// s256 turns a PKCE verifier into its code_challenge.
func s256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// GET /auth/oauth/{provider}/start — 302 to the provider; the state+verifier
// row lives 10 minutes and is single-use.
func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	prov := r.PathValue("provider")
	p, ok := s.providers[prov]
	if !ok || p.ClientID == "" {
		fail(w, http.StatusNotFound, "unknown provider")
		return
	}
	if ok, err := s.bumpRate(r.Context(), "auth|"+s.clientIP(r), s.cfg.AuthCap); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	} else if !ok {
		tooMany(w)
		return
	}
	state, verifier := token.New(), token.New()
	redirect := s.allowlisted(prov)
	_, err := s.pool.Exec(r.Context(), `INSERT INTO oauth_states
		(state, provider, code_verifier, redirect_uri, expires_at)
		VALUES ($1, $2, $3, $4, now() + interval '10 minutes')`,
		state, prov, verifier, redirect)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {strings.Join(p.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {s256(verifier)},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, p.AuthURL+"?"+q.Encode(), http.StatusFound)
}

// GET /auth/oauth/{provider}/callback?code&state — spends the state row, then
// exchanges the code; any failure is a uniform 403.
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	prov := r.PathValue("provider")
	p, ok := s.providers[prov]
	if !ok || p.ClientID == "" {
		fail(w, http.StatusNotFound, "unknown provider")
		return
	}
	code, state := r.URL.Query().Get("code"), r.URL.Query().Get("state")
	if code == "" || state == "" {
		fail(w, http.StatusBadRequest, "missing code or state")
		return
	}
	var verifier, redirect string
	// One-time state spend is atomic; wrong/expired/replayed states fail here.
	err := s.pool.QueryRow(r.Context(), `UPDATE oauth_states
		SET used_at = now() WHERE state = $1 AND provider = $2
		AND used_at IS NULL AND expires_at > now()
		RETURNING code_verifier, redirect_uri`, state, prov).Scan(&verifier, &redirect)
	if err != nil || redirect != s.allowlisted(prov) {
		fail(w, http.StatusForbidden, "invalid oauth state")
		return
	}
	access, err := exchangeCode(r.Context(), p.TokenURL, p, code, verifier, redirect)
	if err != nil {
		fail(w, http.StatusForbidden, "oauth login failed")
		return
	}
	ident, err := p.user(r.Context(), bearerClient(access))
	if err != nil {
		fail(w, http.StatusForbidden, "oauth login failed")
		return
	}
	if ident.Email == "" || !validEmail(ident.Email) {
		fail(w, http.StatusForbidden, "oauth login failed")
		return
	}
	if !ident.EmailVerified {
		// Threat #9: never trust an unverified provider email.
		fail(w, http.StatusForbidden, "provider email is not verified")
		return
	}
	userID, err := s.linkOrLogin(r, prov, ident)
	if err != nil {
		fail(w, http.StatusForbidden, "oauth login failed")
		return
	}
	if err := s.newSession(w, r, userID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.welcomeOnce(r, userID)
	done(w, http.StatusOK)
}

func (s *Server) allowlisted(prov string) string {
	return s.cfg.BaseURL + "/auth/oauth/" + prov + "/callback"
}

// linkOrLogin resolves identity→account (design §5.4):
//   - existing (provider, account) identity → login
//   - verified provider email matching a locally VERIFIED user → link identity
//   - unverified local match → error (no second account, no takeover)
//   - else create a verified user + identity
func (s *Server) linkOrLogin(r *http.Request, prov string, ident oauthIdentity) (string, error) {
	ctx := r.Context()
	var userID string
	err := s.pool.QueryRow(ctx, `SELECT user_id::text FROM auth_identities
		WHERE provider = $1 AND provider_account_id = $2`, prov, ident.AccountID).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	var verified bool
	err = s.pool.QueryRow(ctx, `SELECT id::text, email_verified FROM users
		WHERE lower(email) = $1`, strings.ToLower(ident.Email)).Scan(&userID, &verified)
	if err == nil && verified {
		_, err = s.pool.Exec(ctx, `INSERT INTO auth_identities
			(user_id, provider, provider_account_id, provider_email, provider_email_verified)
			VALUES ($1, $2, $3, $4, $5)`, userID, prov, ident.AccountID, ident.Email, ident.EmailVerified)
		if err == nil {
			return userID, nil
		}
		return "", err
	}
	if err == nil { // local user exists but is not verified (threat #10)
		return "", fmt.Errorf("local account not verified")
	}
	// No local account: create user + identity. The unique constraints make a
	// duplicate impossible; a lost race yields an error, not a second user.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx, `INSERT INTO users (email, email_verified)
		VALUES ($1, true) RETURNING id::text`, ident.Email).Scan(&userID); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth_identities
		(user_id, provider, provider_account_id, provider_email, provider_email_verified)
		VALUES ($1, $2, $3, $4, $5)`, userID, prov, ident.AccountID, ident.Email, ident.EmailVerified); err != nil {
		return "", err
	}
	return userID, tx.Commit(ctx)
}

// exchangeCode POSTs the authorization code (with PKCE verifier) for an
// access token.
func exchangeCode(ctx context.Context, tokenURL string, p oauthProvider, code, verifier, redirect string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirect},
		"client_id":     {p.ClientID},
		"client_secret": {p.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := oauthHTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err := json.Unmarshal(raw, &body); err != nil || body.AccessToken == "" {
		return "", fmt.Errorf("token exchange failed: %s", resp.Status)
	}
	return body.AccessToken, nil
}

func bearerClient(tok string) *http.Client {
	c := *oauthHTTP
	c.Transport = funcRT(func(req *http.Request) (*http.Response, error) {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+tok)
		return http.DefaultTransport.RoundTrip(req)
	})
	return &c
}

type funcRT func(*http.Request) (*http.Response, error)

func (f funcRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// --- provider user-info fetchers --------------------------------------------

func fetchUserinfo(userURL string) func(ctx context.Context, client *http.Client) (oauthIdentity, error) {
	return func(ctx context.Context, client *http.Client) (oauthIdentity, error) {
		var doc struct {
			Sub           string `json:"sub"`
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
		}
		if err := httpGet(ctx, client, userURL, &doc); err != nil {
			return oauthIdentity{}, err
		}
		return oauthIdentity{Provider: "google", AccountID: doc.Sub,
			Email: doc.Email, EmailVerified: doc.EmailVerified}, nil
	}
}

// fetchGitHubUser reads /user for the account id and /user/emails for the
// primary AND verified email — nothing else is acceptable (design §5.4).
func fetchGitHubUser(api string) func(ctx context.Context, client *http.Client) (oauthIdentity, error) {
	return func(ctx context.Context, client *http.Client) (oauthIdentity, error) {
		var doc struct {
			ID int64 `json:"id"`
		}
		if err := httpGet(ctx, client, api+"/user", &doc); err != nil {
			return oauthIdentity{}, err
		}
		var list []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := httpGet(ctx, client, api+"/user/emails", &list); err != nil {
			return oauthIdentity{}, err
		}
		for _, m := range list {
			if m.Primary && m.Verified {
				return oauthIdentity{Provider: "github", AccountID: fmt.Sprint(doc.ID),
					Email: m.Email, EmailVerified: true}, nil
			}
		}
		return oauthIdentity{}, fmt.Errorf("no primary+verified github email")
	}
}

func httpGet(ctx context.Context, client *http.Client, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	return json.Unmarshal(raw, dst)
}
