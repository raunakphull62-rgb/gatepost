// B2 items 5–6: origin settings and the "test connection" endpoint.
// One origin per domain (UNIQUE(domain_id) in the schema); foreign domains
// are a uniform 404 via ownerDomain.
package server

import (
	"context"
	"errors"
	"net"
	"net/http"
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

func (b *originBody) check(w http.ResponseWriter, s *Server, r *http.Request) (scheme string, tlsVerify bool, hostHeader, healthPath string, interval int, ok bool) {
	if b.Scheme != "http" && b.Scheme != "https" {
		fail(w, http.StatusUnprocessableEntity, "scheme must be http or https")
		return
	}
	if err := domains.CheckPort(b.Port); err != nil {
		fail(w, http.StatusUnprocessableEntity, "port: "+err.Error())
		return
	}
	if _, valid := s.checkOrigin(w, r, b.Address); !valid {
		return
	}
	tlsVerify = true
	if b.TLSVerify != nil {
		tlsVerify = *b.TLSVerify
	}
	hostHeader = ""
	if b.HostHeader != nil {
		hh := strings.TrimSpace(*b.HostHeader)
		if hh == "" || len(hh) > 255 || strings.ContainsAny(hh, " \t\r\n\x00") {
			fail(w, http.StatusUnprocessableEntity, "host_header empty, too long, or contains spaces")
			return
		}
		hostHeader = hh
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
	return b.Scheme, tlsVerify, hostHeader, healthPath, interval, true
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
	scheme, tlsVerify, hostHeader, healthPath, interval, ok := body.check(w, s, r)
	if !ok {
		return
	}
	o, err := s.scanOrigin(s.pool.QueryRow(r.Context(), `INSERT INTO origins
		(domain_id, scheme, address, port, host_header, tls_verify, health_path, health_interval_secs)
		VALUES ($1, $2, $3, $4, NULLIF($5,''), $6, $7, $8)
		RETURNING `+originCols,
		d.ID, scheme, body.Address, body.Port, hostHeader, tlsVerify, healthPath, interval))
	if err != nil {
		if isUniqueViolation(err) {
			fail(w, http.StatusConflict, "origin already set; use PUT")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
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
	scheme, tlsVerify, hostHeader, healthPath, interval, ok := body.check(w, s, r)
	if !ok {
		return
	}
	o, err := s.scanOrigin(s.pool.QueryRow(r.Context(), `UPDATE origins SET
		scheme = $2, address = $3, port = $4, host_header = NULLIF($5,''),
		tls_verify = $6, health_path = $7, health_interval_secs = $8, updated_at = now()
		WHERE domain_id = $1
		RETURNING `+originCols,
		d.ID, scheme, body.Address, body.Port, hostHeader, tlsVerify, healthPath, interval))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "no origin set; POST to create")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"origin": o})
}
