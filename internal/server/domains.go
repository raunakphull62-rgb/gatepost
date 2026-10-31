// B2 items 1–4: user-owned domain claims. Ownership verification lives in
// domains_verify.go (item 4); origin settings in origins.go (items 5–6).
package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/net/publicsuffix"

	"gatepost/internal/domains"
	"gatepost/internal/snapshot"
	"gatepost/internal/token"
)

const claimTTL = 7 * 24 * time.Hour

// snapshotClaimMargin — headroom for one more domain entry (~240B measured,
// 1KB is generous) when the create-time gate measures the current artifact.
const snapshotClaimMargin = 1 << 10

// domainRow is the JSON shape every domain endpoint replies with. The
// verification token never appears here — only the instructions endpoint
// needs it. Status values: pending | verified | rejected | expired | disabled.
type domainRow struct {
	ID             string   `json:"id"`
	Hostname       string   `json:"hostname"`
	Status         string   `json:"status"`
	SetupType      string   `json:"setup_type"`
	ClaimedAt      time.Time `json:"claimed_at"`
	VerifiedAt     *time.Time `json:"verified_at"`
	ExpiresAt      *time.Time `json:"expires_at"`
	Ns1            string   `json:"ns1"`
	Ns2            string   `json:"ns2"`
	WAFMode        string   `json:"waf_mode"`
	ExcludedRuleIDs []int   `json:"excluded_rule_ids"`
}

const domainCols = `id::text, hostname, status, setup_type, claimed_at, verified_at, expires_at, coalesce(ns1,'') as ns1, coalesce(ns2,'') as ns2, coalesce(waf_mode,'detection') as waf_mode, coalesce(excluded_rule_ids, '{}'::int[]) as excluded_rule_ids`

func (s *Server) scanDomain(row pgx.Row) (domainRow, error) {
	var d domainRow
	err := row.Scan(&d.ID, &d.Hostname, &d.Status, &d.SetupType, &d.ClaimedAt, &d.VerifiedAt, &d.ExpiresAt, &d.Ns1, &d.Ns2, &d.WAFMode, &d.ExcludedRuleIDs)
	return d, err
}

// ownerDomain fetches the caller's own domain, everything else is a uniform
// 404 (presence is not disclosed across users).
func (s *Server) ownerDomain(w http.ResponseWriter, r *http.Request, p *Principal) (domainRow, bool) {
	row, err := s.scanDomain(s.pool.QueryRow(r.Context(),
		`SELECT `+domainCols+` FROM domains WHERE id = $1 AND owner_user_id = $2`,
		r.PathValue("id"), p.UserID))
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusInternalServerError, "internal error")
			return domainRow{}, false
		}
		fail(w, http.StatusNotFound, "not found")
		return domainRow{}, false
	}
	return row, true
}

// domainRate consumes one rate-limit unit for a domain action, per user and
// per IP (B2 item 8). ok=false means a 429 was already written.
func (s *Server) domainRate(w http.ResponseWriter, r *http.Request, p *Principal, action string, limit int) bool {
	ctx := r.Context()
	ok, err := s.bumpRate(ctx, "domains:"+action+"|user:"+p.UserID, limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if !ok {
		fail(w, http.StatusTooManyRequests, "rate limit exceeded for domains:"+action)
		return false
	}
	ok, err = s.bumpRate(ctx, "domains:"+action+"|ip:"+s.clientIP(r), limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if !ok {
		fail(w, http.StatusTooManyRequests, "rate limit exceeded for domains:"+action)
		return false
	}
	return true
}

// POST /v1/domains {hostname} — claim a hostname; repeated claims of one the
// caller already holds return that claim (not a second row).
func (s *Server) addDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	var body struct {
		Hostname  string `json:"hostname"`
		SetupType string `json:"setup_type"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.SetupType == "" {
		body.SetupType = "cname"
	}
	host, err := domains.NormalizeHostname(body.Hostname, s.serviceHostnames)
	if err != nil {
		if errors.Is(err, domains.ErrReservedServiceHostname) {
			fail(w, http.StatusForbidden, "that hostname is a Gatepost service name")
			return
		}
		fail(w, http.StatusUnprocessableEntity, "invalid hostname: "+err.Error())
		return
	}
	var ns1, ns2 string
	switch body.SetupType {
	case "cname":
	case "nameserver":
		if s.cfg.Ns1 == "" || s.cfg.Ns2 == "" {
			fail(w, http.StatusInternalServerError, "nameserver mode is not configured (GP_NS1/GP_NS2 missing)")
			return
		}
		// a nameserver-mode claim must be a registrable domain; a delegated
		// subdomain only when the test-zone flag names it (item 10).
		if reg, rerr := publicsuffix.EffectiveTLDPlusOne(host); rerr != nil || reg != host {
			zoneOK := s.cfg.AllowSubdomainZones && s.cfg.TestZone != "" &&
				(host == strings.ToLower(s.cfg.TestZone) ||
					strings.HasSuffix(host, "."+strings.ToLower(s.cfg.TestZone)))
			if !zoneOK {
				fail(w, http.StatusUnprocessableEntity,
					"nameserver setup needs a registrable domain (delegated subdomains require GP_ALLOW_SUBDOMAIN_ZONES and the GP_TEST_ZONE suffix)")
				return
			}
		}
		ns1, ns2 = s.cfg.Ns1, s.cfg.Ns2
	default:
		fail(w, http.StatusUnprocessableEntity, "setup_type must be cname or nameserver")
		return
	}
	if !s.domainRate(w, r, p, "add", s.cfg.DomainAddCap) {
		return
	}
	ctx := r.Context()

	// caps: active claims (pending/verified/disabled) and pending claims.
	var total, pending int
	if err := s.pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE status IN ('pending','verified','disabled')),
			count(*) FILTER (WHERE status = 'pending')
			FROM domains WHERE owner_user_id = $1`, p.UserID).Scan(&total, &pending); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if total >= s.cfg.DomainMaxTotal {
		fail(w, http.StatusUnprocessableEntity,
			"domain cap reached (max total "+strconv.Itoa(s.cfg.DomainMaxTotal)+")")
		return
	}
	if pending >= s.cfg.DomainMaxPending {
		fail(w, http.StatusUnprocessableEntity,
			"pending claim cap reached (max pending "+strconv.Itoa(s.cfg.DomainMaxPending)+")")
		return
	}

	// Snapshot size gate: the artifact has a hard cap (snapshot.MaxBytes,
	// enforced again at Sign and on every poller's wire read). A claim only
	// reaches the snapshot once verified WITH an origin, but a full or
	// failing artifact means the claim could never be served — refuse it
	// now, with the reason, instead of after the verify step.
	if env, _, err := s.currentSnapshot(ctx); errors.Is(err, snapshot.ErrTooLarge) {
		fail(w, http.StatusUnprocessableEntity,
			"the config snapshot is over its size cap — no new domains until it shrinks")
		return
	} else if err == nil && len(env.Payload)+snapshotClaimMargin > snapshot.MaxBytes {
		fail(w, http.StatusUnprocessableEntity,
			"the config snapshot is within "+strconv.Itoa(snapshotClaimMargin)+
				" bytes of its size cap — no new domains until it shrinks")
		return
	} // any other build error: the alert path logged it; the insert below
	// fails on a broken database anyway

	// another user already verified this hostname: the name is taken.
	var taken bool
	err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM domains
		WHERE hostname = $1 AND status = 'verified' AND owner_user_id <> $2)`,
		host, p.UserID).Scan(&taken)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if taken {
		fail(w, http.StatusConflict, "hostname already verified by another user")
		return
	}

	// one the caller holds (pending/verified/disabled)? return it; a
	// rejected/expired claim flips back to pending with a fresh token.
	if d, ferr := s.scanDomain(s.pool.QueryRow(ctx,
		`SELECT `+domainCols+` FROM domains WHERE owner_user_id = $1 AND hostname = $2`,
		p.UserID, host)); ferr == nil {
		switch d.Status {
		case "pending", "verified": // held: return untouched
			s.writeDomain(w, r, http.StatusOK, d, true)
			return
		case "disabled":
			s.writeDomain(w, r, http.StatusOK, d, true)
			return
		case "rejected", "expired":
			tok := token.New()
			d, uerr := s.scanDomain(s.pool.QueryRow(ctx, `UPDATE domains SET
				status = 'pending', verify_token = $2, claimed_at = now(),
				verified_at = NULL, expires_at = $3
				WHERE id::text = $1 RETURNING `+domainCols,
				d.ID, tok, time.Now().Add(claimTTL)))
			if uerr != nil {
				fail(w, http.StatusInternalServerError, "internal error")
				return
			}
			s.writeDomain(w, r, http.StatusOK, d, true)
			return
		}
	} else if !errors.Is(ferr, pgx.ErrNoRows) {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}

	tok := token.New()
	d, err := s.scanDomain(s.pool.QueryRow(ctx, `INSERT INTO domains
		(owner_user_id, hostname, setup_type, verify_token, expires_at, ns1, ns2)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), NULLIF($7,''))
		RETURNING `+domainCols,
		p.UserID, host, body.SetupType, tok, time.Now().Add(claimTTL), ns1, ns2))
	if err != nil {
		if isUniqueViolation(err) { // lost a race → someone re-claimed first
			if d, gerr := s.scanDomain(s.pool.QueryRow(ctx,
				`SELECT `+domainCols+` FROM domains WHERE owner_user_id = $1 AND hostname = $2`,
				p.UserID, host)); gerr == nil {
				s.writeDomain(w, r, http.StatusOK, d, true)
				return
			}
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.writeDomain(w, r, http.StatusCreated, d, false)
}

// writeDomain answers {domain, existing} for every claim-return path, and
// keeps the one-per-domain zone row of nameserver claims ensured (the
// UNIQUE makes retries a no-op).
func (s *Server) writeDomain(w http.ResponseWriter, r *http.Request, code int, d domainRow, existing bool) {
	// any claim write (verified-rotate, fresh insert, re-claim) may change
	// the artifact's content later — drop the cache now
	s.invalidateSnapshot()
	if d.SetupType == "nameserver" {
		if _, err := s.pool.Exec(r.Context(), `INSERT INTO zones (domain_id)
			VALUES ($1) ON CONFLICT (domain_id) DO NOTHING`, d.ID); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	writeJSON(w, code, map[string]any{"domain": d, "existing": existing})
}

// GET /v1/domains — the caller's claims.
func (s *Server) listDomains(w http.ResponseWriter, r *http.Request, p *Principal) {
	rows, err := s.pool.Query(r.Context(), `SELECT `+domainCols+`
		FROM domains WHERE owner_user_id = $1 ORDER BY claimed_at DESC, id`, p.UserID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	list := []domainRow{}
	for rows.Next() {
		d, err := s.scanDomain(rows)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		list = append(list, d)
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": list})
}

// GET /v1/domains/{id}
func (s *Server) getDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": d})
}

// DELETE /v1/domains/{id} — drops the claim (and its origin) for good.
func (s *Server) deleteDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	if _, err := s.pool.Exec(r.Context(), `DELETE FROM domains WHERE id::text = $1`, d.ID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.invalidateSnapshot() // the entry disappears from the next artifact
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GET /v1/domains/{id}/verification — the DNS instructions the customer
// points at. Cname mode: TXT _gatepost-verify.<hostname> "gatepost-verify=
// <token>". Nameserver mode: the assigned nameserver pair to delegate to.
func (s *Server) domainVerification(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	v := map[string]any{
		"domain_id":  d.ID,
		"hostname":   d.Hostname,
		"setup_type": d.SetupType,
		"status":     d.Status,
		"expires_at": d.ExpiresAt,
	}
	switch d.SetupType {
	case "nameserver":
		if d.Ns1 == "" || d.Ns2 == "" {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		v["nameservers"] = []string{d.Ns1, d.Ns2}
	default:
		var tok string
		if err := s.pool.QueryRow(r.Context(), `SELECT verify_token FROM domains
			WHERE id::text = $1 AND owner_user_id = $2`, d.ID, p.UserID).Scan(&tok); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		v["record_name"] = "_gatepost-verify." + d.Hostname
		v["record_value"] = "gatepost-verify=" + tok
	}
	writeJSON(w, http.StatusOK, map[string]any{"verification": v})
}

// ExpireDomainClaims flips past-TTL pending claims to expired. Wired into
// main's hourly maintenance loop; live-window tested (no sleeps).
func (s *Server) ExpireDomainClaims(ctx context.Context) (int, error) {
	ct, err := s.pool.Exec(ctx, `UPDATE domains SET status = 'expired'
		WHERE status = 'pending' AND expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}
