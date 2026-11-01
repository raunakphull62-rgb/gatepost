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
//     reconciles without touching Caddy at all. A transport failure (the
//     admin not answering yet — the joint cold-start race) retries after
//     adminRetryDelay; a config caddy REJECTED retries at the cooldown pace.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gatepost/internal/snapshot"
)

// adminRetryDelay: the retry pace when the caddy admin API is not answering
// (a transport error) — short because the one real cause is the joint
// cold-start race: the poller boots before caddy's admin listens, and the
// edge must converge as soon as caddy is ready, not one cooldown later.
const adminRetryDelay = 2 * time.Second

// errAdminGone: the apply loop's one fatal outcome. The caddy admin has been
// unreachable for the whole AdminGrace window — on the real edge that is the
// shared network namespace dying with a killed edge container (docker
// restarts the EDGE, but this container is left in the dead namespace where
// loopback can never answer again). No retry inside this process can fix it;
// Run returns the error, main log.Fatalf's, and docker's restart policy drops
// the container into the edge's FRESH namespace, where the saved snapshot is
// applied again.
var errAdminGone = errors.New("caddy admin unreachable beyond the grace window")

// adminTransport reports whether err is a failure to REACH caddy's admin API
// (a dial error) rather than caddy answering with a rejection ("caddy
// /load:") or a local forwarder/generator failure. Only a dial failure can
// mean the shared network namespace is gone.
func adminTransport(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return !strings.HasPrefix(s, "caddy /load:") &&
		!strings.HasPrefix(s, "egress forwarder") &&
		!strings.HasPrefix(s, "caddygen:")
}

// adminProbeEvery caps how often the idle poller dials the admin; the real
// cadence is min(this, AdminGrace/3) so the probe clock always outruns the
// grace window.
const adminProbeEvery = 5 * time.Second

// startApply builds the forwarder and the apply loop. Without CaddyAdmin
// wired (tests / optional deployments), nothing here runs.
func (p *Poller) startApply(ctx context.Context) {
	if p.cfg.CaddyAdmin == "" {
		return
	}
	p.fwd = newForwarder(p.cfg)
	p.applyWG.Add(1)
	go func() { defer p.applyWG.Done(); p.applyLoop(ctx) }()
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
	// The idle case matters as much as the apply path: with no pending work
	// nothing in the apply flow dials the admin, so a poller orphaned in a
	// dead network namespace (the docker-kill shape) would sit unnoticed
	// forever. Probe on a cadence that always outruns the grace window.
	probeEvery := p.cfg.AdminGrace / 3
	if probeEvery <= 0 || probeEvery > adminProbeEvery {
		probeEvery = adminProbeEvery
	}
	ticker := time.NewTicker(probeEvery)
	defer ticker.Stop()
	for {
		p.applyTick.Store(p.cfg.Now().UnixNano()) // liveness: /health checks this
		select {
		case <-ctx.Done():
			return
		case <-p.applyKick:
		case <-ticker.C:
			if p.hasPending() {
				continue // stepApply's own accounting covers the busy path
			}
			if gerr := p.adminTouch(p.adminProbe()); gerr != nil {
				return // errAdminGone: Run reports it and the process exits
			}
		}
		for {
			again, err := p.stepApply(ctx)
			if err != nil { // errAdminGone: Run reports it and the process exits
				return
			}
			if !again {
				break
			}
			if ctx.Err() != nil {
				return
			}
		}
	}
}

// hasPending: whether stepApply has work (its own grace accounting runs there).
func (p *Poller) hasPending() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending != nil
}

// adminProbe: any HTTP answer from the admin proves caddy — and this shared
// network namespace — is alive. The status is irrelevant; the body unread.
func (p *Poller) adminProbe() bool {
	resp, err := p.cfg.Client.Get("http://" + p.cfg.CaddyAdmin + "/config/")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// adminTouch records one contact attempt with the caddy admin: ok = the
// admin ANSWERED (or no contact was needed). Transport failures accumulate
// in adminFirstFail; once the window has outlived AdminGrace this returns
// errAdminGone, having logged it and armed adminFail for Run.
func (p *Poller) adminTouch(ok bool) error {
	p.mu.Lock()
	if ok {
		p.adminFirstFail = time.Time{}
		p.mu.Unlock()
		return nil
	}
	if p.adminFirstFail.IsZero() {
		p.adminFirstFail = time.Now()
	}
	waited := time.Since(p.adminFirstFail)
	grace := p.cfg.AdminGrace
	p.mu.Unlock()
	if waited < grace {
		return nil
	}
	// The one fatal case: loopback admin unreachable for the whole grace
	// window. A slow caddy answers long before this; a dead network
	// namespace never will.
	p.log("error", "caddy admin unreachable for %s (grace %s) — exiting so docker's restart policy rejoins the edge's fresh network namespace",
		waited.Round(time.Millisecond), grace)
	select {
	case p.adminFail <- errAdminGone:
	default:
	}
	return errAdminGone
}

// stepApply performs at most one /load attempt ((false, nil) = no pending
// work). The cooldown gates every attempt caddy ANSWERED — success or
// rejection — so a failing edge retries at the same "once per 60s" pace it
// reloads with. A TRANSPORT error (caddy's admin not answering — the joint
// cold-start race, the poller boots faster than caddy listens) opens no
// cooldown window and retries after adminRetryDelay instead: an edge that
// would otherwise sit denied for a cooldown must converge the moment its
// caddy comes up. Transport errors that outlive AdminGrace are fatal:
// (false, errAdminGone), delivered to Run via adminFail.
func (p *Poller) stepApply(ctx context.Context) (bool, error) {
	p.applyTick.Store(p.cfg.Now().UnixNano()) // liveness: /health checks this — refresh even while waiting on cooldown
	p.mu.Lock()
	pend, hash := p.pending, p.pendingHash
	applied, last := p.appliedHash, p.lastLoad
	p.mu.Unlock()
	if pend == nil {
		return false, nil
	}
	if hash == applied {
		return false, nil // already running this content (dropped while we waited)
	}
	if wait := p.cfg.ReloadCooldown - time.Since(last); wait > 0 {
		// Keep applyTick fresh while we wait for the cooldown so /health
		// does not false-positive on a normal cooldown wait (the loop is
		// healthy, not stalled, when it is deliberately pacing reloads).
		ticker := time.NewTicker(healthTickInterval())
		select {
		case <-ctx.Done():
			ticker.Stop()
			return false, nil
		case <-ticker.C:
			p.applyTick.Store(p.cfg.Now().UnixNano())
			return true, nil // re-check: the pending set may have changed
		case <-time.After(wait):
			ticker.Stop()
			return true, nil // re-check: the pending set may have changed while we waited
		}
	}
	err := p.applyConfigWithFallback(ctx, pend)
	p.mu.Lock()
	if err == nil {
		p.pending = nil
		p.appliedHash = hash
	}
	if err == nil || strings.HasPrefix(err.Error(), "caddy /load:") {
		// The cooldown window opens only when caddy ANSWERED (accepted or
		// rejected): a transport failure never reached caddy, so it opens
		// no window — otherwise the head's cooldown check below would turn
		// the fast admin-retry into a full cooldown wait.
		p.lastLoad = time.Now()
	}
	p.mu.Unlock()
	if err == nil {
		_ = p.adminTouch(true) // the admin answered: the grace window starts over
		return true, nil
	}
	p.log("error", "caddy apply FAILED — keeping the last-good config: %v", err)
	if adminTransport(err) {
		if gerr := p.adminTouch(false); gerr != nil {
			return false, gerr
		}
	} else {
		_ = p.adminTouch(true) // a local failure says nothing about the admin
	}
	// caddyLoad wraps every caddy ANSWER (a rejected config) in a
	// "caddy /load:" error; anything else is a transport failure.
	retryAfter := adminRetryDelay
	if strings.HasPrefix(err.Error(), "caddy /load:") {
		retryAfter = p.cfg.ReloadCooldown
	}
	// Refresh applyTick during the retry wait so /health does not flag a
	// cooldown-paced retry as a stalled loop. A 60s retry would otherwise
	// cross the 30s applyStallLimit twice over.
	ticker := time.NewTicker(healthTickInterval())
	defer ticker.Stop()
	deadline := time.NewTimer(retryAfter)
	defer deadline.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, nil
		case <-ticker.C:
			p.applyTick.Store(p.cfg.Now().UnixNano())
		case <-deadline.C:
			return true, nil
		}
	}
}

// applyCaddy: swap forwarder ports FIRST, generate, POST /load.
// wafCfg controls whether the generated config includes the Coraza WAF
// handler; the fallback path passes a WAFConfig with Mode=off to retry
// without the WAF when Caddy rejects the full config.
func (p *Poller) applyCaddy(ctx context.Context, d *snapshot.Document, wafCfg WAFConfig) error {
	ports, err := p.fwd.Swap(d)
	if err != nil {
		return fmt.Errorf("egress forwarder swap: %w", err)
	}
	cfgBytes, err := Generate(d, CaddyParams{
		HTTPAddr:      p.cfg.CaddyHTTP,
		HTTPSAddr:     p.cfg.CaddyHTTPS,
		AdminAddr:     p.cfg.CaddyAdmin,
		EgressPorts:   ports,
		AskURL:        p.cfg.AskURL,
		Issuer:        p.cfg.Issuer,
		AccessLogPath: p.cfg.CaddyAccessLog,
		WAF:           wafCfg,
	})
	if err != nil {
		return err
	}
	return caddyLoad(ctx, "http://"+p.cfg.CaddyAdmin+"/load", cfgBytes, p.cfg.Client)
}

// applyConfigWithFallback tries the full WAF config first. If Caddy rejects
// the config with a 400 (the WAF module's config shape is invalid — e.g. a
// bad SecAction directive, an undefined rule, or a module version mismatch),
// it retries WITHOUT the Coraza handler so the edge keeps serving the
// snapshot's domains, origins and TLS proof. The WAF-off fallback is
// fail-open at the WAF boundary only: unknown hosts still get 421 via the
// ask check. When the next snapshot builds a WAF config Caddy accepts, the
// full config is re-applied and the waf_config_failed alert auto-resolves.
//
// The wafFallback atomic is set so the heartbeat reports the fallback to
// the API server (which records/resolves the operator alert).
func (p *Poller) applyConfigWithFallback(ctx context.Context, d *snapshot.Document) error {
	// Try with full WAF config.
	err := p.applyCaddy(ctx, d, p.cfg.WAF)
	if err == nil {
		p.wafFallback.Store(false)
		return nil
	}

	// Transport failure (Caddy unreachable): don't retry with WAF-off.
	if !strings.HasPrefix(err.Error(), "caddy /load:") {
		return err
	}

	// Only try the WAF-off fallback when WAF is actually enabled.
	if p.cfg.WAF.Mode == "off" || p.cfg.WAF.Mode == "" {
		// WAF is already off — the rejection is a different config issue.
		return err
	}
	p.log("warn", "WAF config rejected by Caddy — retrying without Coraza handler: %v", err)
	wafOff := p.cfg.WAF
	wafOff.Mode = "off"
	err2 := p.applyCaddy(ctx, d, wafOff)
	if err2 != nil {
		return fmt.Errorf("waf-off fallback also failed: %w (original: %v)", err2, err)
	}
	p.wafFallback.Store(true)
	p.log("warn", "WAF disabled — serving WAF-off config; waf_config_failed alert raised")
	return nil
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
