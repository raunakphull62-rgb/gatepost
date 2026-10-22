// B2 items 1–4: user-owned domain claims. Ownership verification lives in
// domains_verify.go (item 4); origin settings in origins.go (items 5–6).
package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"gatepost/internal/domains"
	"gatepost/internal/token"
)

const claimTTL = 7 * 24 * time.Hour

// domainRow is the JSON shape every domain endpoint replies with. The
// verification token never appears here — only the instructions endpoint
// needs it. Status values: pending | verified | rejected | expired | disabled.
type domainRow struct {
	ID         string     `json:"id"`
	Hostname   string     `json:"hostname"`
	Status     string     `json:"status"`
	SetupType  string     `json:"setup_type"`
	ClaimedAt  time.Time  `json:"claimed_at"`
	VerifiedAt *time.Time `json:"verified_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
}

const domainCols = `id::text, hostname, status, setup_type, claimed_at, verified_at, expires_at`

func (s *Server) scanDomain(row pgx.Row) (domainRow, error) {
	var d domainRow
	err := row.Scan(&d.ID, &d.Hostname, &d.Status, &d.SetupType, &d.ClaimedAt, &d.VerifiedAt, &d.ExpiresAt)
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
	if body.SetupType != "cname" {
		fail(w, http.StatusBadRequest, "only cname setup is supported yet")
		return
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
			writeJSON(w, http.StatusOK, map[string]any{"domain": d, "existing": true})
			return
		case "disabled":
			writeJSON(w, http.StatusOK, map[string]any{"domain": d, "existing": true})
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
			writeJSON(w, http.StatusOK, map[string]any{"domain": d, "existing": true})
			return
		}
	} else if !errors.Is(ferr, pgx.ErrNoRows) {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}

	tok := token.New()
	d, err := s.scanDomain(s.pool.QueryRow(ctx, `INSERT INTO domains
		(owner_user_id, hostname, setup_type, verify_token, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+domainCols,
		p.UserID, host, body.SetupType, tok, time.Now().Add(claimTTL)))
	if err != nil {
		if isUniqueViolation(err) { // lost a race → someone re-claimed first
			if d, gerr := s.scanDomain(s.pool.QueryRow(ctx,
				`SELECT `+domainCols+` FROM domains WHERE owner_user_id = $1 AND hostname = $2`,
				p.UserID, host)); gerr == nil {
				writeJSON(w, http.StatusOK, map[string]any{"domain": d, "existing": true})
				return
			}
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"domain": d, "existing": false})
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
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// GET /v1/domains/{id}/verification — the DNS instructions the customer
// points at: TXT _gatepost-verify.<hostname> "gatepost-verify=<token>".
func (s *Server) domainVerification(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	var tok string
	if err := s.pool.QueryRow(r.Context(), `SELECT verify_token FROM domains
		WHERE id::text = $1 AND owner_user_id = $2`, d.ID, p.UserID).Scan(&tok); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verification": map[string]any{
		"domain_id":    d.ID,
		"hostname":     d.Hostname,
		"setup_type":   d.SetupType,
		"status":       d.Status,
		"record_name":  "_gatepost-verify." + d.Hostname,
		"record_value": "gatepost-verify=" + tok,
		"expires_at":   d.ExpiresAt,
	}})
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
