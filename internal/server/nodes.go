// B3a item 1: node identity. Operators (verified users whose email is on
// GP_OPERATOR_EMAILS) create, list and revoke edge/dns nodes. A node calls
// node routes with its own bearer token; raw tokens are shown exactly once,
// only the SHA-256 is stored.
package server

import (
	"errors"
	"net/http"
	"strconv"
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

// --- node poll routes (B3a item 4) -------------------------------------------

// nodeAuth wraps the /node/v1/* routes. The presented bearer token is hashed
// and looked up by hash — the plaintext is never stored or compared, and on
// this path neither is logged. Unknown AND revoked nodes get the same 401;
// only an active node proceeds, through its own rate bucket.
//
//   - Node tokens authenticate ONLY node routes (user routes reject them;
//     mutual 401s); user sessions/API keys never authenticate node routes.
//   - A node sees the snapshot here and nothing else — the helpers below
//     echo no node roster and no other node's record.
func (s *Server) nodeAuth(next func(http.ResponseWriter, *http.Request, nodeRow)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok, ok := s.bearerToken(r)
		if !ok {
			fail(w, http.StatusUnauthorized, "node authentication required")
			return
		}
		n, err := s.scanNode(s.pool.QueryRow(r.Context(),
			`SELECT `+nodeCols+` FROM nodes WHERE token_hash = $1`, token.SHA256Hex(tok)))
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			fail(w, http.StatusUnauthorized, "node authentication required")
			return
		case err != nil:
			fail(w, http.StatusInternalServerError, "internal error")
			return
		case n.Status != "active":
			fail(w, http.StatusUnauthorized, "node authentication required")
			return
		}
		ok, err = s.bumpRate(r.Context(), "node:"+n.ID, s.cfg.NodePollCap)
		if err != nil {
			fail(w, http.StatusInternalServerError, "internal error")
			return
		}
		if !ok {
			fail(w, http.StatusTooManyRequests, "rate limit exceeded for node polls")
			return
		}
		next(w, r, n)
	}
}

// GET /node/v1/config — the current snapshot envelope: payload, signature
// and key ID in the body; the generation is the ETag (and inside the signed
// payload). If-None-Match matching that generation short-circuits to an
// empty 304 so a node can ask for free until content actually changes.
func (s *Server) nodeConfig(w http.ResponseWriter, r *http.Request, n nodeRow) {
	env, gen, err := s.currentSnapshot(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	etag := `"` + strconv.FormatInt(gen, 10) + `"`
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	writeJSON(w, http.StatusOK, env)
}

// POST /node/v1/heartbeat {"generation": N} — last_seen and applied_version
// are stamped ONLY after the payload validates: N must be a snapshot
// generation that exists (a node may honestly report an older one it still
// runs); a version that does not exist is refused and stamps nothing.
func (s *Server) nodeHeartbeat(w http.ResponseWriter, r *http.Request, n nodeRow) {
	var body struct {
		Generation int64 `json:"generation"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Generation <= 0 {
		fail(w, http.StatusBadRequest, "generation must be a positive integer")
		return
	}
	var exists bool
	if err := s.pool.QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM snapshot_versions WHERE generation = $1)`,
		body.Generation).Scan(&exists); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !exists {
		fail(w, http.StatusBadRequest, "unknown snapshot version")
		return
	}
	if _, err := s.pool.Exec(r.Context(),
		`UPDATE nodes SET last_seen = now(), applied_version = $1 WHERE id = $2`,
		body.Generation, n.ID); err != nil {
		fail(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied_generation": body.Generation})
}

// etagMatches — If-None-Match may list candidates or "*" (any); quotes and
// the W/ prefix are irrelevant here (generations are plain integers).
func etagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" {
		return false
	}
	cur := strings.Trim(etag, `"`)
	for _, v := range strings.Split(ifNoneMatch, ",") {
		v = strings.TrimPrefix(strings.TrimSpace(v), "W/")
		if v = strings.Trim(v, `"`); v == "*" || v == cur {
			return true
		}
	}
	return false
}
