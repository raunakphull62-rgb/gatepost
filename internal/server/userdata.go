// Package server — per-user JSONB document (design §11): GET/PUT
// /api/user-data, ≤32 KiB, addressed only to the authenticated principal —
// there is no user-id parameter to guess (threat #15).
package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jackc/pgx/v5"
)

const userDataMax = 32 << 10 // 32 KiB

// GET /api/user-data — returns the stored JSON document, {} when none.
func (s *Server) getUserData(w http.ResponseWriter, r *http.Request, p *Principal) {
	var data []byte
	err := s.pool.QueryRow(r.Context(), `SELECT data FROM user_data
		WHERE user_id = $1`, p.UserID).Scan(&data)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		data = []byte("{}")
	case err != nil:
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bytes.TrimSpace(data))
}

// PUT /api/user-data — body must parse as JSON and fit in 32 KiB.
func (s *Server) putUserData(w http.ResponseWriter, r *http.Request, p *Principal) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, userDataMax+1))
	if err != nil || len(body) > userDataMax {
		fail(w, http.StatusBadRequest, "body exceeds 32 KiB")
		return
	}
	if !json.Valid(body) {
		fail(w, http.StatusBadRequest, "body must be valid JSON")
		return
	}
	if _, err := s.pool.Exec(r.Context(), `INSERT INTO user_data (user_id, data, updated_at)
		VALUES ($1, $2::jsonb, now())
		ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
		p.UserID, string(body)); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	done(w, http.StatusOK)
}

// GET /api/me — identity for the authenticated principal.
func (s *Server) me(w http.ResponseWriter, r *http.Request, p *Principal) {
	writeJSON(w, http.StatusOK, p)
}
