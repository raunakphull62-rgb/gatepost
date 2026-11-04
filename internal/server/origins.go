// B2 items 5–6: origin settings and the "test connection" endpoint.
// One origin per domain (UNIQUE(domain_id) in the schema); foreign domains
// are a uniform 404 via ownerDomain.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"gatepost/internal/domains"
)

type originRow struct {
	Scheme         string    `json:"scheme"`
	Address        string    `json:"address"`
	Port           int       `json:"port"`
	HostHeader     *string   `json:"host_header"`
	TLSVerify      bool      `json:"tls_verify"`
	HealthPath     string    `json:"health_path"`
	HealthInterval int       `json:"health_interval"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const originCols = `scheme, address, port, host_header, tls_verify, health_path,
	health_interval_secs, created_at, updated_at`

func (s *Server) scanOrigin(row pgx.Row) (originRow, error) {
	var o originRow
	err := row.Scan(&o.Scheme, &o.Address, &o.Port, &o.HostHeader, &o.TLSVerify,
		&o.HealthPath, &o.HealthInterval, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

// lookupIP resolves through the configured resolvers, first answer wins.
func lookupIP(ctx context.Context, resolvers []domains.Resolver, name string) ([]net.IP, error) {
	var last error
	for _, res := range resolvers {
		v, err := res.LookupIP(ctx, name)
		if err == nil {
			return v, nil
		}
		last = err
	}
	return nil, last
}

// checkOrigin validates one origin address end-to-end: syntax and (for
// literals) range checks locally; hostnames are resolved here so no resolved
// IP may fall in a denied range (SSRF). Strict: an unresolvable name is a
// refusal — we cannot prove it safe.
func (s *Server) checkOrigin(w http.ResponseWriter, r *http.Request, addr string) (domains.OriginAddr, bool) {
	o, err := domains.ValidateOrigin(addr, s.owned, s.cfg.TestAllowLoopback)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "origin address: "+err.Error())
		return o, false
	}
	if o.IP != nil { // literal: already range-checked
		return o, true
	}
	cctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	ips, lerr := lookupIP(cctx, s.dnsResolvers, o.Canonical)
	if lerr != nil {
		fail(w, http.StatusUnprocessableEntity, "origin address: cannot resolve "+o.Canonical)
		return o, false
	}
	if len(ips) == 0 {
		fail(w, http.StatusUnprocessableEntity, "origin address: no A/AAAA record for "+o.Canonical)
		return o, false
	}
	for _, ip := range ips {
		if verr := domains.CheckIP(ip, s.owned, s.cfg.TestAllowLoopback); verr != nil {
			fail(w, http.StatusUnprocessableEntity, "origin address: "+verr.Error())
			return o, false
		}
	}
	return o, true
}

// originBody is the strict input; ok=false means a 4xx was already written.
type originBody struct {
	Scheme         string  `json:"scheme"`
	Address        string  `json:"address"`
	Port           int     `json:"port"`
	HostHeader     *string `json:"host_header"`
	TLSVerify      *bool   `json:"tls_verify"`
	HealthPath     *string `json:"health_path"`
	HealthInterval *int    `json:"health_interval"`
}

func (b *originBody) check(w http.ResponseWriter, s *Server, r *http.Request) (scheme, canon string, tlsVerify bool, hostHeader, healthPath string, interval int, ok bool) {
	if b.Scheme != "http" && b.Scheme != "https" {
		fail(w, http.StatusUnprocessableEntity, "scheme must be http or https")
		return
	}
	if err := domains.CheckPort(b.Port); err != nil {
		fail(w, http.StatusUnprocessableEntity, "port: "+err.Error())
		return
	}
	o, valid := s.checkOrigin(w, r, b.Address)
	if !valid {
		return
	}
	canon = o.Canonical // store the validated form, not the raw spelling
	tlsVerify = true
	if b.TLSVerify != nil {
		tlsVerify = *b.TLSVerify
	}
	hostHeader = ""
	if b.HostHeader != nil {
		if err := domains.ValidateHostHeader(*b.HostHeader); err != nil {
			fail(w, http.StatusUnprocessableEntity, "host_header: "+err.Error())
			return
		}
		hostHeader = *b.HostHeader
	}
	healthPath = "/"
	if b.HealthPath != nil {
		p := strings.TrimSpace(*b.HealthPath)
		if p == "" || p[0] != '/' || strings.Contains(p, "..") || len(p) > 512 {
			fail(w, http.StatusUnprocessableEntity, "health_path must start with / (no dots, max 512)")
			return
		}
		healthPath = p
	}
	interval = 60
	if b.HealthInterval != nil {
		if *b.HealthInterval < 10 || *b.HealthInterval > 86400 {
			fail(w, http.StatusUnprocessableEntity, "health_interval must be 10..86400 seconds")
			return
		}
		interval = *b.HealthInterval
	}
	return b.Scheme, canon, tlsVerify, hostHeader, healthPath, interval, true
}

// POST /v1/domains/{id}/origin — create the one origin for the domain.
func (s *Server) addOrigin(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	var body originBody
	if !readJSON(w, r, &body) {
		return
	}
	scheme, canon, tlsVerify, hostHeader, healthPath, interval, ok := body.check(w, s, r)
	if !ok {
		return
	}
	o, err := s.scanOrigin(s.pool.QueryRow(r.Context(), `INSERT INTO origins
		(domain_id, scheme, address, port, host_header, tls_verify, health_path, health_interval_secs)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), $6, $7, $8)
		RETURNING `+originCols,
		d.ID, scheme, canon, body.Port, hostHeader, tlsVerify, healthPath, interval))
	if err != nil {
		if isUniqueViolation(err) {
			fail(w, http.StatusConflict, "origin already set; use PUT")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.invalidateSnapshot() // a new origin joins the next artifact
	writeJSON(w, http.StatusCreated, map[string]any{"origin": o})
}

// GET /v1/domains/{id}/origin
func (s *Server) getOrigin(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	o, err := s.scanOrigin(s.pool.QueryRow(r.Context(),
		`SELECT `+originCols+` FROM origins WHERE domain_id = $1`, d.ID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "no origin set")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"origin": o})
}

// PUT /v1/domains/{id}/origin — replace every field of the stored origin.
func (s *Server) putOrigin(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	var body originBody
	if !readJSON(w, r, &body) {
		return
	}
	scheme, canon, tlsVerify, hostHeader, healthPath, interval, ok := body.check(w, s, r)
	if !ok {
		return
	}
	o, err := s.scanOrigin(s.pool.QueryRow(r.Context(), `UPDATE origins SET
		scheme = $2, address = $3, port = $4, host_header = NULLIF($5,''),
		tls_verify = $6, health_path = $7, health_interval_secs = $8, updated_at = now()
		WHERE domain_id = $1
		RETURNING `+originCols,
		d.ID, scheme, canon, body.Port, hostHeader, tlsVerify, healthPath, interval))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "no origin set; POST to create")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.invalidateSnapshot() // the artifact carries the origin as configured
	writeJSON(w, http.StatusOK, map[string]any{"origin": o})
}

// B2 item 6: "test connection" — resolve the stored origin address,
// re-check every answered IP against the deny rules, connect to the
// resolved IP itself (DNS cannot redirect between check and connect),
// GET the health path, never follow redirects, read at most 64 KB.
// IP itself (DNS can't redirect us between check and connect), GET the
// health path with no redirects, read at most 64 KB, report the truth.

// testResult is the JSON report of one test connection.
type testResult struct {
	Reachable  bool   `json:"reachable"`
	StatusCode int    `json:"status_code,omitempty"`
	TLSOK      bool   `json:"tls_ok"`
	DurationMs int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
}

func writeTest(w http.ResponseWriter, tr testResult, elapsed time.Duration) {
	tr.DurationMs = elapsed.Milliseconds()
	writeJSON(w, http.StatusOK, map[string]any{"test": tr})
}

// reportRefusal writes a reachable=false report with the exact refusal.
func writeTestRefusal(w http.ResponseWriter, err error, elapsed time.Duration) {
	writeTest(w, testResult{Error: err.Error()}, elapsed)
}

// POST /v1/domains/{id}/origin/test — probe the stored origin.
func (s *Server) testOrigin(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !s.domainRate(w, r, p, "origin-test", s.cfg.OriginTestCap) {
		return
	}
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	o, gerr := s.scanOrigin(s.pool.QueryRow(r.Context(),
		`SELECT `+originCols+` FROM origins WHERE domain_id = $1`, d.ID))
	if gerr != nil {
		if errors.Is(gerr, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "no origin set")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	start := time.Now()
	rctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// resolve + re-check every answered IP (the strict rules apply again)
	oAddr, verr := domains.ValidateOrigin(o.Address, s.owned, s.cfg.TestAllowLoopback)
	if verr != nil {
		writeTestRefusal(w, verr, time.Since(start))
		return
	}
	var ips []net.IP
	if oAddr.IP != nil {
		ips = []net.IP{oAddr.IP}
	} else {
		got, lerr := lookupIP(rctx, s.dnsResolvers, oAddr.Canonical)
		if lerr != nil {
			writeTestRefusal(w, fmt.Errorf("origin %s: cannot resolve", oAddr.Canonical), time.Since(start))
			return
		}
		if len(got) == 0 {
			writeTestRefusal(w, fmt.Errorf("origin %s: no A/AAAA record", oAddr.Canonical), time.Since(start))
			return
		}
		for _, ip := range got {
			if cverr := domains.CheckIP(ip, s.owned, s.cfg.TestAllowLoopback); cverr != nil {
				writeTestRefusal(w, cverr, time.Since(start))
				return
			}
		}
		ips = got
	}

	// dial each resolved IP until one answers with an HTTP response
	var last testResult
	for _, ip := range ips {
		last = s.probeOrigin(rctx, o, oAddr.Canonical, ip)
		if last.Reachable {
			writeTest(w, last, time.Since(start))
			return
		}
	}
	writeTest(w, last, time.Since(start))
}

// probeOrigin performs one full attempt against one resolved IP.
func (s *Server) probeOrigin(rctx context.Context, o originRow, canonical string, ip net.IP) testResult {
	portStr := strconv.Itoa(o.Port)
	dialer := &net.Dialer{}
	transport := &http.Transport{
		// Connect to the checked IP itself: a DNS change between the check
		// above and this dial cannot redirect the probe.
		DialContext: func(cctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(cctx, network, net.JoinHostPort(ip.String(), portStr))
		},
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: !o.TLSVerify, ServerName: canonical},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Until(deadlineOf(rctx)),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow redirects
		},
	}
	host := canonical
	if o.HostHeader != nil && *o.HostHeader != "" {
		host = *o.HostHeader
	}
	url := o.Scheme + "://" + host + ":" + portStr + o.HealthPath
	req, rerr := http.NewRequestWithContext(rctx, http.MethodGet, url, nil)
	if rerr != nil {
		return testResult{Error: rerr.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return testResult{Error: err.Error()}
	}
	defer resp.Body.Close()
	tlsOK := resp.TLS != nil && resp.TLS.HandshakeComplete
	// at most 64 KB of the response is ever read
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return testResult{Reachable: true, StatusCode: resp.StatusCode, TLSOK: tlsOK}
}

// deadlineOf extracts a request's deadline (zero when none).
func deadlineOf(ctx context.Context) (d time.Time) {
	d, _ = ctx.Deadline()
	return d
}
