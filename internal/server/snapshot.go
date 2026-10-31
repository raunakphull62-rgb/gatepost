// B3a: the signed config snapshot lives server-side as the version recoder
// (item 3 puts the pure machinery into the standalone snapshot package) and
// from item 2 on, the builder that assembles Documents from verified domains.
package server

import (
	"context"
	"errors"
	"fmt"
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
		o.scheme, o.address, o.port, o.host_header, o.tls_verify,
		d.waf_mode, d.excluded_rule_ids
		FROM domains d JOIN origins o ON o.domain_id = d.id
		WHERE d.status = 'verified' AND d.waf_mode IS NOT NULL ORDER BY d.hostname`)
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
		var wafMode string
		var excludedRuleIDs []int
		if err := rows.Scan(&id, &hostname, &setupType, &scheme, &address, &port, &hh, &tlsVerify,
			&wafMode, &excludedRuleIDs); err != nil {
			return snapshot.Document{}, snapshot.Envelope{}, err
		}
		verdict := s.originVerdict(ctx, address)
		s.noteVerdict(ctx, id, hostname, verdict)
		switch {
		case verdict.unsafe: // definitely unsafe: it IS in a blocked range now
			log.Printf("snapshot build: dropped %s (origin %s): %s", hostname, address, verdict.reason)
			s.recordAlert(ctx, "origin_unsafe", hostname, verdict.reason)
			continue
		case verdict.keep && verdict.reason != "": // unresolvable: not a verdict
			log.Printf("snapshot build: WARNING %s (origin %s): %s — keeping the current entry, retrying next build",
				hostname, address, verdict.reason)
		}
		domainsOut = append(domainsOut, snapshot.Domain{
			Hostname:        hostname,
			SetupType:       setupType,
			WAFMode:         wafMode,
			ExcludedRuleIDs: excludedRuleIDs,
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
	// The signed capability gate: this artifact requires the WAF feature —
	// an edge that predates it refuses the whole snapshot instead of
	// silently dropping the WAF fields.
	features := []string{snapshot.FeatureWAF}

	h, err := snapshot.Hash(snapshot.Content{
		SchemaVersion:    snapshot.SchemaVersion,
		RequiredFeatures: features,
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
		RequiredFeatures: features,
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

// originVerdict is the build-time read on one stored origin: keep it, it is
// DEFINITELY unsafe (resolved into a blocked address), or it could not be
// re-checked right now (timeout, SERVFAIL, NXDOMAIN after previously ok) —
// then the snapshot keeps the entry from the latest good state and the next
// build retries.
type originVerdict struct {
	unsafe bool   // drop + log + operator alert
	keep   bool   // unresolved → keep the current entry, warn, retry later
	reason string // the message for the log/alert either way
}

// originVerdict re-applies the SSRF rules at build time. A hostname origin
// may have MOVED: resolution runs again and every answered IP must be outside
// the deny ranges. An unresolvable name is NOT a verdict — origins passed
// validation when stored, so the absence of answers today is treated as an
// outage, never as permission to silently unregister a customer.
func (s *Server) originVerdict(ctx context.Context, address string) originVerdict {
	o, err := domains.ValidateOrigin(address, s.owned, s.cfg.TestAllowLoopback)
	if err != nil {
		return originVerdict{unsafe: true, reason: err.Error()} // range/syntax: refused at create too
	}
	if o.IP != nil {
		return originVerdict{keep: true}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, lerr := lookupIP(cctx, s.dnsResolvers, o.Canonical)
	if lerr != nil {
		return originVerdict{keep: true, reason: "cannot resolve " + o.Canonical + ": " + lerr.Error()}
	}
	if len(ips) == 0 {
		return originVerdict{keep: true, reason: "no A/AAAA record (NXDOMAIN?) for " + o.Canonical}
	}
	for _, ip := range ips {
		if verr := domains.CheckIP(ip, s.owned, s.cfg.TestAllowLoopback); verr != nil {
			return originVerdict{unsafe: true, reason: verr.Error()}
		}
	}
	return originVerdict{keep: true}
}

// --- the poll cache (B3a addition) -------------------------------------------

// snapCache — THE artifact polls are served between writes and TTL expiry.
type snapCache struct {
	env   snapshot.Envelope
	gen   int64
	built time.Time
}

// currentSnapshot — what GET /node/v1/config serves. A cache miss or a
// stale artifact (older than SnapshotTTLSeconds, default 30) triggers one
// build; writes invalidate regardless (see invalidateSnapshot), so 100
// polls in a row cost exactly one build. Concurrent misses may both build;
// same content always records the same generation (head-hash rule), the
// last cache write wins.
func (s *Server) currentSnapshot(ctx context.Context) (snapshot.Envelope, int64, error) {
	s.snapMu.Lock()
	if c := s.snapCache; c != nil &&
		time.Since(c.built) < time.Duration(s.cfg.SnapshotTTLSeconds)*time.Second {
		env, gen := c.env, c.gen
		s.snapMu.Unlock()
		return env, gen, nil
	}
	s.snapMu.Unlock() // build outside the lock; a second racer repeats the work, not the damage

	doc, env, err := s.buildSnapshot(ctx)
	if err != nil {
		// A failed build leaves the pollers on their last good artifact —
		// but never silently: one line per failure and an open operator
		// alert that the next successful build auto-resolves.
		log.Printf("snapshot build FAILED: %v", err)
		s.recordAlert(ctx, "snapshot_build_failed", "snapshot", err.Error())
		return snapshot.Envelope{}, 0, err
	}
	s.resolveAlert(ctx, "snapshot_build_failed", "snapshot")
	s.snapMu.Lock()
	s.snapCache = &snapCache{env: env, gen: doc.Generation, built: time.Now()}
	s.snapMu.Unlock()
	return env, doc.Generation, nil
}

// invalidateSnapshot — drop the cached artifact; the next poll rebuilds.
// Called after every domain/origin/verification write.
func (s *Server) invalidateSnapshot() {
	s.snapMu.Lock()
	s.snapCache = nil
	s.snapMu.Unlock()
}

// recordAlert raises one open operator alert; an already-open alert for the
// same (kind, subject) stays alone (dedupe in the database per lessons.md —
// multiple instances would otherwise each fire). Failure to alert is logged,
// never fatal: the snapshot must build.
func (s *Server) recordAlert(ctx context.Context, kind, subject, detail string) {
	if _, err := s.pool.Exec(ctx, `INSERT INTO operator_alerts (kind, subject, detail)
		VALUES ($1, $2, $3) ON CONFLICT (kind, subject) WHERE resolved_at IS NULL DO NOTHING`,
		kind, subject, detail); err != nil {
		log.Printf("snapshot build: alert %s/%s not recorded: %v", kind, subject, err)
	}
}

// resolveAlert clears the open alert(s) for (kind, subject). Called when a
// build finds the origin safe again; failure is logged, never fatal.
func (s *Server) resolveAlert(ctx context.Context, kind, subject string) {
	if _, err := s.pool.Exec(ctx, `UPDATE operator_alerts SET resolved_at = now()
		WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, kind, subject); err != nil {
		log.Printf("snapshot build: alert %s/%s not resolved: %v", kind, subject, err)
	}
}

// noteVerdict records the per-origin re-check bookkeeping: when an origin
// FIRST became unresolvable (state lives in the database per lessons.md —
// wall-clock time, not a build counter, so restarts or a changed cadence
// cannot corrupt the measure), the persistence alert past the threshold,
// and the auto-resolve when a build finds the origin safe again.
func (s *Server) noteVerdict(ctx context.Context, domainID, hostname string, v originVerdict) {
	switch {
	case v.unsafe: // a resolution IS a re-check result — the timer restarts
		if _, err := s.pool.Exec(ctx, `DELETE FROM origin_unresolved WHERE domain_id = $1`, domainID); err != nil {
			log.Printf("snapshot build: unresolved state for %s not cleared: %v", hostname, err)
		}
	case v.keep && v.reason != "": // unresolvable: kept, but not silently
		var first time.Time
		if err := s.pool.QueryRow(ctx, `INSERT INTO origin_unresolved (domain_id, first_unresolved_at, updated_at)
			VALUES ($1, now(), now()) ON CONFLICT (domain_id)
			DO UPDATE SET updated_at = now()
			RETURNING first_unresolved_at`, domainID).Scan(&first); err != nil {
			log.Printf("snapshot build: unresolved state for %s not updated: %v", hostname, err)
		} else if time.Since(first) >= time.Duration(s.cfg.OriginUnresolvedMinutes)*time.Minute {
			s.recordAlert(ctx, "origin_unresolved", hostname, fmt.Sprintf(
				"unresolvable since %s: %s (entry kept)", first.Format(time.RFC3339), v.reason))
		}
	default: // safe again by re-check: clear the marks and the domain's alerts
		if _, err := s.pool.Exec(ctx, `DELETE FROM origin_unresolved WHERE domain_id = $1`, domainID); err != nil {
			log.Printf("snapshot build: unresolved state for %s not cleared: %v", hostname, err)
		}
		s.resolveAlert(ctx, "origin_unsafe", hostname)
		s.resolveAlert(ctx, "origin_unresolved", hostname)
	}
}
