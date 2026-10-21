// Package server — API keys (design §6): gp_pat_ + 256-bit random; DB keeps
// only SHA-256(key) and a prefix. Create/list/revoke are session-only; keys
// authenticate /api/* via Bearer.
package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"gatepost/internal/token"
)

const keyPrefixLong = "gp_pat_"

type apiKeyRow struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Key       string     `json:"key,omitempty"` // full key: create response only
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used_at"`
	Revoked   *time.Time `json:"revoked_at"`
}

// POST /auth/api-keys {name} — the full key is returned once and never stored.
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	var body struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 100 {
		fail(w, http.StatusBadRequest, "invalid name")
		return
	}
	rnd := token.New()
	full := keyPrefixLong + rnd // 7 + 43 chars, 256-bit under the hood
	prefix := full[:15]         // "gp_pat_" + first 8, safe to store/show
	var id string
	err := s.pool.QueryRow(r.Context(), `INSERT INTO api_keys (user_id, name, key_hash, prefix)
		VALUES ($1, $2, $3, $4) RETURNING id::text`, p.UserID, name, token.SHA256Hex(full), prefix).
		Scan(&id)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, apiKeyRow{ID: id, Name: name, Key: full, Prefix: prefix})
}

// GET /auth/api-keys — metadata only.
func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request, p *Principal) {
	rows, err := s.pool.Query(r.Context(), `SELECT id::text, name, prefix, created_at,
		last_used_at, revoked_at FROM api_keys WHERE user_id = $1 ORDER BY created_at`, p.UserID)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	keys := []apiKeyRow{}
	for rows.Next() {
		var k apiKeyRow
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsed, &k.Revoked); err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		keys = append(keys, k)
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// POST /auth/api-keys/{id}/revoke — revocation is terminal; not-found is
// uniform for other users' keys.
func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	id := r.PathValue("id")
	var x string
	err := s.pool.QueryRow(r.Context(), `UPDATE api_keys SET revoked_at = now()
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL RETURNING id::text`,
		id, p.UserID).Scan(&x)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	done(w, http.StatusOK)
}
