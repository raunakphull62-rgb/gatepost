// B2 items 4 and 11: ownership verification. Item 4 verifies TXT claims
// (_gatepost-verify.<hostname>), item 11 verifies NS delegation. Both use
// the same one-transaction winning rule: this claim → verified, every other
// pending claim on the hostname → rejected.
package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"gatepost/internal/domains"
)

// dnsResolvers default: the configured public resolvers (GP_DNS_RESOLVERS,
// default 1.1.1.1:53 and 8.8.8.8:53), tried in order, 5 s deadline each.
// Tests swap the slice wholesale (same package) — an injectable seam.
func buildResolvers(list []string) []domains.Resolver {
	if len(list) == 0 {
		list = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	out := make([]domains.Resolver, 0, len(list))
	for _, a := range list {
		if !strings.Contains(a, ":") {
			a += ":53"
		}
		out = append(out, domains.InstalledResolver{Addr: a})
	}
	return out
}

// lookupTXT tries every configured resolver until one answers.
func lookupTXT(ctx context.Context, resolvers []domains.Resolver, name string) ([]string, error) {
	var last error
	for _, res := range resolvers {
		v, err := res.LookupTXT(ctx, name)
		if err == nil {
			return v, nil
		}
		last = err
	}
	return nil, last
}

func lookupNS(ctx context.Context, resolvers []domains.Resolver, name string) ([]string, error) {
	var last error
	for _, res := range resolvers {
		v, err := res.LookupNS(ctx, name)
		if err == nil {
			return v, nil
		}
		last = err
	}
	return nil, last
}

// POST /v1/domains/{id}/verify — TXT-based ownership proof.
func (s *Server) verifyDomain(w http.ResponseWriter, r *http.Request, p *Principal) {
	d, ok := s.ownerDomain(w, r, p)
	if !ok {
		return
	}
	switch {
	case d.Status == "verified": // idempotent: already proved
		writeJSON(w, http.StatusOK, map[string]any{"status": "verified"})
		return
	case d.Status != "pending":
		fail(w, http.StatusGone, "claim is "+d.Status+", not verifiable")
		return
	case d.ExpiresAt != nil && d.ExpiresAt.Before(time.Now()):
		fail(w, http.StatusGone, "claim expired, re-claim it")
		return
	}
	// another user's win → contested, the unique index decides anyway.
	if d.Status == "pending" {
		var contested bool
		if err := s.pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM domains
			WHERE hostname = $1 AND status = 'verified' AND owner_user_id <> $2)`,
			d.Hostname, p.UserID).Scan(&contested); err == nil && contested {
			fail(w, http.StatusConflict, "hostname already verified by another user")
			return
		}
	}
	var tok string
	if err := s.pool.QueryRow(r.Context(), `SELECT verify_token FROM domains
		WHERE id::text = $1 AND owner_user_id = $2`, d.ID, p.UserID).Scan(&tok); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}

	rctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	txts, err := lookupTXT(rctx, s.dnsResolvers, "_gatepost-verify."+d.Hostname)
	if err != nil {
		fail(w, http.StatusBadGateway, "dns lookup failed: "+err.Error())
		return
	}
	want := "gatepost-verify=" + tok
	found := false
	for _, t := range txts {
		if strings.TrimSpace(t) == want { // TXT values are fairly loose: trim
			found = true
			break
		}
	}
	if !found {
		fail(w, http.StatusBadRequest,
			"verification failed: no TXT record "+want+" at _gatepost-verify."+d.Hostname)
		return
	}
	if reason := s.markVerified(r, d, p.UserID); reason != "" {
		fail(w, http.StatusConflict, reason)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "verified"})
}

// markVerified runs the one-transaction win: this claim verified, competing
// pending claims rejected. Returns a user-facing reason on any conflict.
func (s *Server) markVerified(r *http.Request, d domainRow, ownerID string) string {
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		return "internal error"
	}
	defer tx.Rollback(r.Context())
	ct, err := tx.Exec(r.Context(), `UPDATE domains SET status = 'verified',
		verified_at = now(), expires_at = NULL WHERE id::text = $1 AND status = 'pending'`, d.ID)
	if err != nil {
		return "internal error"
	}
	if ct.RowsAffected() == 0 { // we lost some race; say so plainly
		return "claim changed state mid-verification, try again"
	}
	// every other pending claim on this hostname loses (they can re-claim).
	if _, err := tx.Exec(r.Context(), `UPDATE domains SET status = 'rejected', verified_at = NULL
		WHERE hostname = $1 AND status = 'pending' AND owner_user_id <> $2`, d.Hostname, ownerID); err != nil {
		return "internal error"
	}
	if err := tx.Commit(r.Context()); err != nil {
		if isUniqueViolation(err) { // someone else won this exact hostname
			return "hostname already verified by another user"
		}
		return "internal error"
	}
	return ""
}
