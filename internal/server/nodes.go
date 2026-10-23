// B3a item 1: node identity. Operators (verified users whose email is on
// GP_OPERATOR_EMAILS) create, list and revoke edge/dns nodes. A node calls
// node routes with its own bearer token; raw tokens are shown exactly once,
// only the SHA-256 is stored.
package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"gatepost/internal/token"
)

// nodeRow is the JSON shape of a node; the token hash never routes here.
type nodeRow struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Role           string     `json:"role"`
	Status         string     `json:"status"`
	LastSeen       *time.Time `json:"last_seen"`
	AppliedVersion *int64     `json:"applied_version"`
	CreatedAt      time.Time  `json:"created_at"`
}

const nodeCols = `id::text, name, role, status, last_seen, applied_version, created_at`

func (s *Server) scanNode(row pgx.Row) (nodeRow, error) {
	var n nodeRow
	err := row.Scan(&n.ID, &n.Name, &n.Role, &n.Status, &n.LastSeen, &n.AppliedVersion, &n.CreatedAt)
	return n, err
}

// requireOperator — verified user on the GP_OPERATOR_EMAILS list. Sessions
// and API keys are the same principal here; anyone else authenticated is 403,
// the unauthenticated 401 (the requireAuth convention).
func (s *Server) requireOperator(next func(http.ResponseWriter, *http.Request, *Principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _, err := s.principal(r)
		if err != nil {
			fail(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if _, op := s.operators[strings.ToLower(p.Email)]; !op {
			fail(w, http.StatusForbidden, "operator access only")
			return
		}
		next(w, r, p)
	}
}

// POST /v1/nodes {name, role} — mint a token, return it once.
func (s *Server) createNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	var body struct {
		Name string `json:"name"`
		Role string `json:"role"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 50 {
		fail(w, http.StatusUnprocessableEntity, "name must be 1..50 characters")
		return
	}
	if body.Role != "edge" && body.Role != "dns" {
		fail(w, http.StatusUnprocessableEntity, "role must be edge or dns")
		return
	}
	tok := token.New() // 256 random bits, shown once below
	n, err := s.scanNode(s.pool.QueryRow(r.Context(),
		`INSERT INTO nodes (name, role, token_hash) VALUES ($1, $2, $3) RETURNING `+nodeCols,
		body.Name, body.Role, token.SHA256Hex(tok)))
	if err != nil {
		if isUniqueViolation(err) {
			fail(w, http.StatusConflict, "node name already taken")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"node": n, "token": tok})
}

// GET /v1/nodes — the roster; no token material of any kind.
func (s *Server) listNodes(w http.ResponseWriter, r *http.Request, p *Principal) {
	rows, err := s.pool.Query(r.Context(), `SELECT `+nodeCols+` FROM nodes ORDER BY created_at`)
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	ns := []nodeRow{}
	for rows.Next() {
		n, err := s.scanNode(rows)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		ns = append(ns, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": ns})
}

// POST /v1/nodes/{id}/revoke — idempotent; revoked tokens die on their very
// next request (nodeAuth checks status on every call).
func (s *Server) revokeNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	n, err := s.scanNode(s.pool.QueryRow(r.Context(),
		`UPDATE nodes SET status = 'revoked' WHERE id = $1 RETURNING `+nodeCols,
		r.PathValue("id")))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			fail(w, http.StatusNotFound, "not found")
			return
		}
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node": n})
}
