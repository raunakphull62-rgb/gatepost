// B3a: the signed config snapshot lives server-side as the version recoder
// (item 3 puts the pure machinery into the standalone snapshot package) and
// from item 2 on, the builder that assembles Documents from verified domains.
package server

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"gatepost/internal/domains"
	"gatepost/internal/snapshot"
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

// buildSnapshot — B3a item 2: one Document from the database. Every VERIFIED
// domain that currently HAS an origin becomes an entry: hostname, setup type,
// origin as configured, and the fixed defaults. Pending, rejected, expired,
// disabled, and verified-without-origin stay out. Each origin is re-validated
// against the SSRF rules at build time; anything that no longer passes is
// dropped from the artifact and logged. The generation moves only when the
// resulting content changes.
func (s *Server) buildSnapshot(ctx context.Context) (snapshot.Document, snapshot.Envelope, error) {
	rows, err := s.pool.Query(ctx, `SELECT d.id::text, d.hostname, d.setup_type,
		o.scheme, o.address, o.port, o.host_header, o.tls_verify
		FROM domains d JOIN origins o ON o.domain_id = d.id
		WHERE d.status = 'verified' ORDER BY d.hostname`)
	if err != nil {
		return snapshot.Document{}, snapshot.Envelope{}, err
	}
	defer rows.Close()

	domainsOut := []snapshot.Domain{}
	for rows.Next() {
		var id, hostname, setupType, scheme, address string
		var port int
		var hh *string
		var tlsVerify bool
		if err := rows.Scan(&id, &hostname, &setupType, &scheme, &address, &port, &hh, &tlsVerify); err != nil {
			return snapshot.Document{}, snapshot.Envelope{}, err
		}
		if reason := s.originNowUnsafe(ctx, address); reason != "" {
			log.Printf("snapshot build: dropped %s (origin %s): %s", hostname, address, reason)
			continue
		}
		domainsOut = append(domainsOut, snapshot.Domain{
			Hostname:  hostname,
			SetupType: setupType,
			Origin: snapshot.Origin{
				Scheme: scheme, Address: address, Port: port,
				HostHeader: hh, TLSVerify: tlsVerify,
			},
		})
	}
	if err := rows.Err(); err != nil {
		return snapshot.Document{}, snapshot.Envelope{}, err
	}
	allowed := make([]string, 0, len(domainsOut))
	for _, d := range domainsOut {
		allowed = append(allowed, d.Hostname)
	}
	defaults := snapshot.Defaults{FirewallMode: "log_only", Cache: true}

	h, err := snapshot.Hash(snapshot.Content{
		SchemaVersion:    snapshot.SchemaVersion,
		Domains:          domainsOut,
		AllowedHostnames: allowed,
		Defaults:         defaults,
	})
	if err != nil {
		return snapshot.Document{}, snapshot.Envelope{}, err
	}
	gen, err := s.recordGeneration(ctx, h)
	if err != nil {
		return snapshot.Document{}, snapshot.Envelope{}, err
	}
	doc := snapshot.Document{
		SchemaVersion:    snapshot.SchemaVersion,
		Generation:       gen,
		BuiltAt:          time.Now().UTC(),
		Domains:          domainsOut,
		AllowedHostnames: allowed,
		Defaults:         defaults,
	}
	env, err := snapshot.Sign([]byte(s.cfg.SnapshotKey), doc)
	if err != nil {
		return snapshot.Document{}, snapshot.Envelope{}, err
	}
	return doc, env, nil
}

// originNowUnsafe re-applies the SSRF rules at build time. Origins may be
// hostnames that MOVED: resolution runs again and every answered IP must be
// outside the deny ranges. Non-empty string = the reason it must be dropped.
func (s *Server) originNowUnsafe(ctx context.Context, address string) string {
	o, err := domains.ValidateOrigin(address, s.owned, s.cfg.TestAllowLoopback)
	if err != nil {
		return err.Error() // range/syntax: refused just like at create time
	}
	if o.IP != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, lerr := lookupIP(cctx, s.dnsResolvers, o.Canonical)
	if lerr != nil {
		return "cannot resolve " + o.Canonical
	}
	if len(ips) == 0 {
		return "no A/AAAA record for " + o.Canonical
	}
	for _, ip := range ips {
		if verr := domains.CheckIP(ip, s.owned, s.cfg.TestAllowLoopback); verr != nil {
			return verr.Error()
		}
	}
	return ""
}
