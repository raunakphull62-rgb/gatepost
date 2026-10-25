// Caddy apply (B3b item 3): the one writer that turns a verified snapshot
// into the edge's running config.
//
//   - every apply first Swap()s the egress forwarder so caddy's config never
//     references a port nobody listens on (a sub-second window where caddy
//     still serves the old config through last-good ports fails closed);
//   - the new JSON goes to POST /load on the admin API that lives on the
//     compose-internal address (loopback of the shared network namespace;
//     never a host-published port). /load VALIDATES the config with Caddy
//     itself and applies it atomically: a rejection leaves the last-good
//     config running untouched, and the failure is logged loudly;
//   - reloads only when the snapshot CONTENT changed — the volatile
//     generation/built_at do not count (snapshot.Hash of ToContent, the same
//     fingerprint the server's versioning uses) — and at most once per
//     ReloadCooldown (default 60s), with every later arrival collapsing into
//     the newest pending document. A→B→A within one cooldown therefore
//     reconciles without touching Caddy at all.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"gatepost/internal/snapshot"
)

// startApply builds the forwarder and the apply loop. Without CaddyAdmin
// wired (tests / optional deployments), nothing here runs.
func (p *Poller) startApply(ctx context.Context) {
	if p.cfg.CaddyAdmin == "" {
		return
	}
	p.fwd = newForwarder(p.cfg)
	go p.applyLoop(ctx)
}

// enqueueApply is accept's hook into the apply loop: content-equal to what
// is already RUNNING → nothing pending (the A→B→A rule); otherwise the
// newest document replaces whatever was pending.
func (p *Poller) enqueueApply(d snapshot.Document) {
	if p.cfg.CaddyAdmin == "" {
		return
	}
	hash, err := snapshot.Hash(d.ToContent())
	if err != nil {
		p.log("error", "config content hash: %v", err)
		return
	}
	p.mu.Lock()
	if hash == p.appliedHash {
		p.pending = nil
	} else {
		p.pending = &d
		p.pendingHash = hash
	}
	p.mu.Unlock()
	select {
	case p.applyKick <- struct{}{}:
	default: // the loop is already running a step; it re-reads state
	}
}

func (p *Poller) applyLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.applyKick:
		}
		for p.stepApply(ctx) {
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// stepApply performs at most one /load attempt (false = no pending work).
// The cooldown gates EVERY attempt — success or failure — so a failing
// edge retries at the same "once per 60s" pace it reloads with.
func (p *Poller) stepApply(ctx context.Context) bool {
	p.mu.Lock()
	pend, hash := p.pending, p.pendingHash
	applied, last := p.appliedHash, p.lastLoad
	p.mu.Unlock()
	if pend == nil {
		return false
	}
	if hash == applied {
		return false // already running this content (dropped while we waited)
	}
	if wait := p.cfg.ReloadCooldown - time.Since(last); wait > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
			return true // re-check: the pending set may have changed while we waited
		}
	}
	err := p.applyCaddy(ctx, pend)
	p.mu.Lock()
	p.lastLoad = time.Now()
	if err == nil {
		p.pending = nil
		p.appliedHash = hash
	}
	p.mu.Unlock()
	if err != nil {
		p.log("error", "caddy apply FAILED — keeping the last-good config: %v", err)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(p.cfg.ReloadCooldown): // retry at cooldown pace
		}
	}
	return true
}

// applyCaddy: swap forwarder ports FIRST, generate, POST /load.
func (p *Poller) applyCaddy(ctx context.Context, d *snapshot.Document) error {
	ports, err := p.fwd.Swap(d)
	if err != nil {
		return fmt.Errorf("egress forwarder swap: %w", err)
	}
	cfgBytes, err := Generate(d, CaddyParams{
		HTTPAddr:    p.cfg.CaddyHTTP,
		HTTPSAddr:   p.cfg.CaddyHTTPS,
		AdminAddr:   p.cfg.CaddyAdmin,
		EgressPorts: ports,
	})
	if err != nil {
		return err
	}
	return caddyLoad(ctx, "http://"+p.cfg.CaddyAdmin+"/load", cfgBytes, p.cfg.Client)
}

// caddyLoad POSTs the generated JSON to the admin API. 200 means Caddy
// validated AND applied the config; anything else is its rejection text —
// which the caller logs loudly while the last-good config keeps serving.
func caddyLoad(ctx context.Context, url string, cfgBytes []byte, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(cfgBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("caddy /load: status %d: %s", resp.StatusCode, body)
	}
	return nil
}
