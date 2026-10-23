// B3a: the signed config snapshot lives server-side as the version recoder
// (item 3 puts the pure machinery into the standalone snapshot package) and
// from item 2 on, the builder that assembles Documents from verified domains.
package server

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// recordGeneration — the generation follows the LATEST snapshot's content
// hash ONLY: equal keeps the current version, any different content takes
// the next number, even when it reverts to earlier content (A→B→A is 1, 2,
// 3 — version 3 is equal in content to version 1). Older rows are never
// matched again, so a poller's "strictly beyond what I applied" check stays
// meaningful. Serialized by an advisory-locked transaction.
func (s *Server) recordGeneration(ctx context.Context, contentHash string) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('gatepost-snapshot-version'))`); err != nil {
		return 0, err
	}
	var head string
	var gen int64
	err = tx.QueryRow(ctx,
		`SELECT content_hash, generation FROM snapshot_versions ORDER BY generation DESC LIMIT 1`).
		Scan(&head, &gen)
	switch {
	case errors.Is(err, pgx.ErrNoRows): // the first snapshot ever
		err = tx.QueryRow(ctx,
			`INSERT INTO snapshot_versions (content_hash) VALUES ($1) RETURNING generation`,
			contentHash).Scan(&gen)
		if err != nil {
			return 0, err
		}
	case err != nil:
		return 0, err
	case head == contentHash: // unchanged → same version
	default: // any other content — including a revert → the next number
		if err := tx.QueryRow(ctx,
			`INSERT INTO snapshot_versions (content_hash) VALUES ($1) RETURNING generation`,
			contentHash).Scan(&gen); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return gen, nil
}
