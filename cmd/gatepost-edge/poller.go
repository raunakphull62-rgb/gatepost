// The Gatepost edge poller (B3b item 2). Runs beside the edge (Caddy)
// container and owns the node principal:
//
//   - polls GET /node/v1/config every interval with If-None-Match (a 304
//     means no change); each envelope is verified with internal/snapshot
//     before it is applied — signature, key ID, strictly newer generation
//     and the size cap; an invalid envelope is never applied
//
//   - persists the last good envelope atomically (temp file, fsync, rename,
//     mode 0600) in the state dir and re-verifies it at boot; a corrupt or
//     tampered file means "no snapshot", never a crash
//
//   - cold start with the API unreachable applies the saved snapshot; with
//     no saved snapshot the deny-all shape is pushed to the edge (421 for
//     every host, both listeners) while the loop keeps retrying
//
//   - poll errors back off exponentially (interval → 2^n) capped at
//     GP_EDGE_BACKOFF_CAP, with jitter on every poll so two nodes never
//     poll in lockstep
//
//   - a 401 (revoked/invalid node token) is logged loudly and the last good
//     config keeps serving
//
//   - an envelope with an unknown key ID is skipped with a warning — not
//     applied, and never treated as tampering
//
//   - heartbeats report the generation actually applied, never merely
//     fetched — and only when the API has not acknowledged it yet
//
//   - the apply loop (caddy wiring in apply.go) turns every content change
//     into an egress Swap + generated config pushed to Caddy's admin /load,
//     gated by a content hash and a reload cooldown
//
// The node token and signing key come from env or a mounted *_FILE
// (docker secrets); neither is ever logged. The ask check answers Caddy's
// on-demand-TLS probe locally from the last-good config (lessons.md: a live
// API call fails cold-start TLS during an API outage).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gatepost/internal/domains"
	"gatepost/internal/snapshot"
)

// snapshotFile is the persisted envelope (self-verifying artifact).
const snapshotFile = "snapshot.json"

// Config is the poller's wiring; it is logged only as described in main.go.
type Config struct {
	APIBase    string        // e.g. http://api:8080 (no trailing slash)
	Token      string        // node token, sent as Authorization: Bearer …
	Key        []byte        // snapshot signing key (must match the API's)
	StateDir   string        // the mounted volume; snapshot.json lives here
	AskAddr    string        // ask check listener; "" disables it
	AskURL     string        // Caddy's permission endpoint ("" → derived from AskAddr/AskLn)
	AskLn      net.Listener  // test hook; used instead of AskAddr when set
	Interval   time.Duration // poll cadence on success (default 5s)
	BackoffCap time.Duration // exponential ladder cap (default 60s)
	Client     *http.Client
	Rand01     func() float64                         // jitter source, [0,1)
	Log        func(kind, format string, args ...any) // kind: info|warn|error

	CaddyAdmin     string        // host:port of the edge's admin API; "" = no caddy wiring
	CaddyHTTP      string        // listen addr for HTTP ("" → ":80")
	CaddyHTTPS     string        // listen addr for HTTPS ("" → ":443")
	ReloadCooldown time.Duration // min spacing between caddy /loads (default 60s)
	AllowLoopback  bool          // TEST/DEMO hook: egress may dial loopback origins

	Issuer         string           // staging (default) | internal | production
	CertHourlyCap  int              // on-demand cert approvals per fixed hour window (default 50)
	CaddyAccessLog string           // path of the edge's JSON access log; "" = logging off
	ErrorLogGap    time.Duration    // min spacing of repeated failure lines (default 30s)
	Now            func() time.Time // clock for the cap window (tests)
}

type Poller struct {
	cfg Config

	mu         sync.Mutex
	current    *snapshot.Document // nil: nothing applied / no saved snapshot
	generation int64              // generation of the artifact in current
	acked      int64              // last generation the API acknowledged
	streak     int                // consecutive failed polls

	fwd         *forwarder         // nil until startApply runs (caddy wiring)
	applyKick   chan struct{}      // buffered 1: "the pending set changed"
	pending     *snapshot.Document // newest verified doc not loaded into caddy yet
	pendingHash string             // content hash of pending
	appliedHash string             // content hash of what caddy is running
	lastLoad    time.Time          // last /load attempt (success or failure)

	throttle      *logThrottle // repeated identical failure lines resolve here
	certWindow    time.Time    // start of the current on-demand cap window
	certCount     int          // approvals in certWindow
	certCapWarned bool         // the cap-reached warning was already logged this window
}

// pollOutcome classifies one config poll, so the loop can decide between
// "server is healthy, reset the ladder" and "aim the ladder another step".
type pollOutcome int

const (
	pollOK        pollOutcome = iota // 200 with an envelope (then verified)
	pollUnchanged                    // 304: generation still current
	pollTampered
	pollUnknownKey
	pollTooLarge
	pollBackwards
	pollMalformed
	pollUnauthorized
	pollHTTPError
	pollNetwork
)

// NewPoller applies the defaults the program must always keep regardless of
// what the caller left unset.
func NewPoller(cfg Config) *Poller {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.BackoffCap <= 0 {
		cfg.BackoffCap = 60 * time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.ReloadCooldown <= 0 {
		cfg.ReloadCooldown = 60 * time.Second
	}
	if cfg.Issuer == "" {
		cfg.Issuer = issuerStaging // the default that cannot burn prod rate limits
	}
	if cfg.CertHourlyCap <= 0 {
		cfg.CertHourlyCap = 50 // on-demand cert approvals per hour per node
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ErrorLogGap <= 0 {
		cfg.ErrorLogGap = 30 * time.Second // one failure line per gap is the flood cap
	}
	if cfg.AskURL == "" { // Caddy must reach the ask listener; derive its URL
		switch {
		case cfg.AskAddr != "":
			cfg.AskURL = "http://" + cfg.AskAddr + "/check"
		case cfg.AskLn != nil:
			cfg.AskURL = "http://" + cfg.AskLn.Addr().String() + "/check"
		}
	}
	if cfg.Rand01 == nil {
		cfg.Rand01 = rand.Float64
	}
	if cfg.Log == nil {
		cfg.Log = func(kind, format string, args ...any) {
			switch kind {
			case "info":
				log.Printf(format, args...)
			case "warn":
				log.Printf("WARNING "+format, args...)
			default:
				log.Printf("ERROR "+format, args...)
			}
		}
	}
	return &Poller{cfg: cfg, applyKick: make(chan struct{}, 1), throttle: newLogThrottle()}
}

// Run starts the apply loop (caddy wiring) BEFORE the boot snapshot load so
// the saved artifact can be queued while the loop is live, then loads the
// saved artifact (if any, re-verified), starts the ask check listener and
// loops until ctx is done. It never exits early: poll failures keep
// retrying on the ladder, a corrupt file is "no snapshot", nothing panics
// out of a tick.
func (p *Poller) Run(ctx context.Context) error {
	p.startApply(ctx)
	p.loadSavedSnapshot(ctx)

	askSrv := p.startAskServer(ctx)
	if askSrv != nil {
		defer func() { _ = askSrv.Close() }()
	}

	// First poll happens immediately (cold start should converge as soon
	// as the API answers), then on the computed cadence.
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
		p.tick(ctx)
		timer.Reset(p.nextDelay())
	}
}

// tick: one heartbeat attempt (until acknowledged), one config poll, apply,
// classify for the ladder. A recover keeps a bug in one turn from turning
// the edge into a crash-looping service.
func (p *Poller) tick(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			p.log("error", "poll tick panic recovered: %v", r)
			p.bumpStreak()
		}
	}()
	p.heartbeat(ctx)

	env, outcome := p.poll(ctx)
	switch outcome {
	case pollOK:
		p.consider(ctx, *env)
	case pollUnchanged, pollTampered, pollUnknownKey, pollTooLarge, pollBackwards:
		// The API answered sanely; a refused envelope is a state change to
		// watch for, not a connection problem — the ladder resets.
		p.resetStreak()
	case pollMalformed, pollUnauthorized, pollHTTPError, pollNetwork:
		p.bumpStreak()
	}
	p.ensureDenyAll()
}

// ensureDenyAll pushes the deny-all shape once when nothing has been
// applied: a cold start with no snapshot (API unreachable, empty, or the
// token revoked) must still answer 421 for every host instead of serving
// whatever the bootstrap Caddyfile happens to answer. The zero document IS
// that shape (Generate: a nil or domain-less document = the catch-all 421),
// and enqueueApply's content-hash gate makes repeats no-ops — a node that
// has, or then gets, a real snapshot never re-queues it.
func (p *Poller) ensureDenyAll() {
	if p.appliedGeneration() == 0 && p.pending == nil {
		p.enqueueApply(snapshot.Document{})
	}
}

// consider verifies and (only when valid and strictly newer) applies an
// envelope fetched over the wire.
func (p *Poller) consider(ctx context.Context, env snapshot.Envelope) {
	d, err := p.verify(env, p.appliedGeneration())
	if err != nil {
		return // verify() already logged the reason
	}
	p.accept(ctx, d, env, true)
}

// verify wraps snapshot.Verify for logging: it maps each refusal to its one
// distinctive message and returns the sentinel-tagged outcome.
func (p *Poller) verify(env snapshot.Envelope, prev int64) (snapshot.Document, error) {
	d, err := snapshot.Verify(p.cfg.Key, env, prev)
	switch {
	case err == nil:
		return d, nil
	case errors.Is(err, snapshot.ErrUnknownKey):
		// Refusals REROLL every interval (the ladder resets on a sane reply),
		// so they are throttled like any repeated failure line.
		p.logThrottled("warn", "key", "snapshot skipped: signed with unknown key id %s (rotation window?)", env.KeyID)
		return snapshot.Document{}, err
	case errors.Is(err, snapshot.ErrTampered):
		p.logThrottled("error", "tampered", "snapshot refused: signature verification failed (tampering?)")
		return snapshot.Document{}, err
	case errors.Is(err, snapshot.ErrTooLarge):
		p.logThrottled("warn", "size", "snapshot refused: payload over the %d cap", snapshot.MaxBytes)
		return snapshot.Document{}, err
	case errors.Is(err, snapshot.ErrBackwards):
		// HISTORIC: generation refuses any generation <= last applied.
		p.logThrottled("warn", "backwards", "snapshot skipped: generation %d not strictly newer than applied %d", genOf(env.Payload), prev)
		return snapshot.Document{}, err
	default:
		p.logThrottled("error", "refused", "snapshot refused: %v", err)
		return snapshot.Document{}, err
	}
}

// accept promotes a VERIFIED artifact to the current state: persists first
// (so a crash between memory and disk leaves the file behind or absent,
// never half-promoted), swaps memory, and queues the roster heartbeat.
func (p *Poller) accept(ctx context.Context, d snapshot.Document, env snapshot.Envelope, persist bool) {
	if persist {
		b, err := json.Marshal(env)
		if err != nil {
			p.log("error", "persist: %v", err)
		} else if err := atomicWrite(p.cfg.StateDir, snapshotFile, b); err != nil {
			p.log("error", "persist: atomic write failed (%v) — serving it in memory", err)
		}
	}
	p.mu.Lock()
	p.current = &d
	p.generation = d.Generation
	p.mu.Unlock()
	p.log("info", "applied snapshot generation %d: %d domain(s), %d allowed hostname(s)",
		d.Generation, len(d.Domains), len(d.AllowedHostnames))
	p.enqueueApply(d)
	p.heartbeat(ctx)
}

// loadSavedSnapshot re-verifies the artifact on disk with the same rules as
// the wire path. Anything broken — missing schema, tampered signature,
// unknown key, oversized payload — means "no snapshot": the ask check then
// serves 421 for every host and the poll loop rebuilds us.
func (p *Poller) loadSavedSnapshot(ctx context.Context) {
	path := filepath.Join(p.cfg.StateDir, snapshotFile)
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.log("warn", "saved snapshot unreadable (%v) — treating as none", err)
		}
		return // first boot: nothing saved yet is entirely normal
	}
	var env snapshot.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		p.log("warn", "saved snapshot unusable (corrupt file, %d bytes) — treating as none", len(b))
		return
	}
	p.mu.Lock()
	prev := p.generation
	p.mu.Unlock()
	d, err := p.verify(env, prev)
	if err != nil {
		p.log("warn", "saved snapshot failed verification — treating as none")
		return
	}
	p.accept(ctx, d, env, false /* already on disk */)
	// No persist: re-writing identical bytes adds a window, not information.
}

// poll performs the config GET (with If-None-Match when a generation is
// applied) and classifies the response. Request/response bodies are never
// logged.
func (p *Poller) poll(ctx context.Context) (*snapshot.Envelope, pollOutcome) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.APIBase+"/node/v1/config", nil)
	if err != nil {
		p.logThrottled("error", "poll", "poll request build: %v", err)
		return nil, pollNetwork
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	req.Header.Set("User-Agent", "gatepost-edge")
	if gen := p.appliedGeneration(); gen > 0 {
		req.Header.Set("If-None-Match", `"`+strconvFormatInt(gen)+`"`)
	}

	resp, err := p.cfg.Client.Do(req)
	if err != nil { // bodies of transport errors name the URL, never headers
		p.logThrottled("error", "poll", "poll failed (streak %d): %v", p.streakValue()+1, err)
		return nil, pollNetwork
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, pollUnchanged
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, snapshot.MaxBytes+1))
		if err != nil {
			p.logThrottled("error", "poll", "poll body read: %v", err)
			return nil, pollNetwork
		}
		if len(b) > snapshot.MaxBytes {
			p.logThrottled("warn", "size", "poll body over the %d cap — refusing", snapshot.MaxBytes)
			return nil, pollTooLarge
		}
		var env snapshot.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			p.logThrottled("error", "poll", "poll response is not an envelope — refusing")
			return nil, pollMalformed
		}
		return &env, pollOK
	case http.StatusUnauthorized:
		// LOUD by design: an edge polling a dead token is an operator problem.
		// One line per gap, not one per tick — loud ≠ a flood of identical lines.
		p.logThrottled("error", "401", "401 from API — node token revoked or invalid; keeping the last good config (streak %d)", p.streakValue()+1)
		return nil, pollUnauthorized
	default:
		p.logThrottled("warn", "status", "poll: unexpected status %d (streak %d)", resp.StatusCode, p.streakValue()+1)
		return nil, pollHTTPError
	}
}

// heartbeat tells the API which generation is actually applied — the one in
// memory, not the last fetched attempt — and only when it is newer than the
// last acknowledged. It retries on the next tick until the API answers 200.
func (p *Poller) heartbeat(ctx context.Context) {
	var body struct {
		Generation int64 `json:"generation"`
	}
	gen, acked := p.heartbeats()
	if gen == 0 || gen == acked { // nothing applied, or already acknowledged
		return
	}
	body.Generation = gen
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.APIBase+"/node/v1/heartbeat", strings.NewReader(string(payload)))
	if err != nil {
		p.log("error", "heartbeat build: %v", err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.cfg.Client.Do(req)
	if err != nil {
		p.logThrottled("warn", "heartbeat", "heartbeat (gen %d) failed: %v", gen, err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		p.logThrottled("warn", "heartbeat", "heartbeat (gen %d) not accepted: %d", gen, resp.StatusCode)
		return
	}
	p.mu.Lock()
	p.acked = gen
	p.mu.Unlock()
}

// startAskServer serves the on-demand-TLS ask check the edge consults
// locally: 200 when the hostname is inside the applied snapshot, 421
// otherwise — always, when nothing is applied ("serve nothing (421 for
// every host)"). Loopback by default; no per-request logging (Caddy's own
// logs carry the host names).
func (p *Poller) startAskServer(ctx context.Context) *http.Server {
	if p.cfg.AskAddr == "" && p.cfg.AskLn == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/check", p.serveAsk)
	mux.HandleFunc("/ask", p.serveAsk) // accept either anchor name; item 3 pins one
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln := p.cfg.AskLn
	if ln == nil {
		l, err := net.Listen("tcp", p.cfg.AskAddr)
		if err != nil {
			p.log("error", "ask listener %s: %v", p.cfg.AskAddr, err)
			return nil
		}
		ln = l
	}
	go func() { _ = srv.Serve(ln) }()
	return srv
}

// serveAsk: the on-demand permission gate. Answers 200 only for a hostname
// present in the verified snapshot last accepted into memory, and only while
// this node has certificate budget left in the current hour. Everything else
// — bad syntax, an IP literal, a trailing dot, host:port, a hostname not in
// the snapshot, no snapshot, a corrupt saved snapshot (current == nil) — is
// 421. A bare port in a TLS SNI can never be an enabled hostname, so values
// carrying one are refused rather than "repaired". Case is NOT refused: DNS
// hostnames are case-insensitive, and rejecting a differently-cased SNI
// would break legitimate handshakes.
func (p *Poller) serveAsk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	domain, ok := askHostname(firstNonEmpty(r.URL.Query().Get("domain"), r.URL.Query().Get("hostname")))
	if !ok || !p.hostAllowed(domain) {
		http.Error(w, "hostname not in the applied snapshot", http.StatusMisdirectedRequest)
		return
	}
	if !p.certRoom(p.cfg.Now()) {
		http.Error(w, "on-demand certificate request cap reached", http.StatusTooManyRequests)
		return
	}
	fmt.Fprint(w, "enabled")
}

// askHostname takes the raw query value and returns the comparable lowercase
// hostname. It is deliberately strict: no surrounding space, no trailing dot
// (fully-qualified form is not an SNI), no colon (ports, IPv6 literals), no
// IP literals, and the full hostname rules the API applies at claim time.
func askHostname(raw string) (string, bool) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", false
	}
	if strings.HasSuffix(raw, ".") || strings.Contains(raw, ":") {
		return "", false
	}
	if net.ParseIP(raw) != nil {
		return "", false
	}
	h, err := domains.NormalizeHostname(raw, nil)
	if err != nil {
		return "", false
	}
	return h, true
}

// certRoom reserves one of this node's on-demand certificate approvals. The
// window is fixed (starts at the first approval, resets an hour later), so a
// burst straddling the boundary can briefly approve twice the cap — an abuse
// ceiling, not a billing meter.
// shortcut: fixed hour window, upgrade to a sliding log if exact-per-hour
// enforcement ever matters.
func (p *Poller) certRoom(now time.Time) bool {
	p.mu.Lock()
	if p.cfg.CertHourlyCap <= 0 { // defensive: NewPoller always sets a cap
		p.mu.Unlock()
		return true
	}
	if p.certWindow.IsZero() || !now.Before(p.certWindow.Add(time.Hour)) {
		p.certWindow = now
		p.certCount = 0
		p.certCapWarned = false
	}
	if p.certCount >= p.cfg.CertHourlyCap {
		warn := !p.certCapWarned
		p.certCapWarned = true
		p.mu.Unlock()
		if warn {
			p.log("warn", "on-demand certificate cap reached (%d/hour) — refusing new certificates until the window resets", p.cfg.CertHourlyCap)
		}
		return false
	}
	p.certCount++
	p.mu.Unlock()
	return true
}

// hostAllowed: exact match against the snapshot's allowed-list, or the
// served domains themselves when a build omitted the list.
func (p *Poller) hostAllowed(domain string) bool {
	if domain == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current == nil {
		return false // "serve nothing (421 for every host)"
	}
	for _, h := range p.current.AllowedHostnames {
		if strings.ToLower(h) == domain {
			return true
		}
	}
	for _, d := range p.current.Domains {
		if strings.ToLower(d.Hostname) == domain {
			return true
		}
	}
	return false
}

// nextDelay is the poll cadence: interval on success, interval·2ⁿ under a
// failure streak, capped at BackoffCap — always multiplied by jitter in
// [0.9, 1.1) so two nodes starting together drift apart immediately and
// never fall back into lockstep at the cap.
func (p *Poller) nextDelay() time.Duration {
	return time.Duration(float64(baseDelay(p.streakValue(), p.cfg.Interval, p.cfg.BackoffCap)) * (0.9 + 0.2*p.cfg.Rand01()))
}

// baseDelay is nextDelay without the jitter: the ladder's actual branch.
// It exists so the CAP CROSSING below is a clean threshold, not a jitter roll.
func baseDelay(streak int, interval, cap time.Duration) time.Duration {
	factor := interval
	for i := 0; i < streak && factor < cap; i++ {
		factor *= 2
	}
	if factor > cap {
		factor = cap
	}
	return factor
}

func (p *Poller) appliedGeneration() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation
}

func (p *Poller) streakValue() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.streak
}

func (p *Poller) bumpStreak() {
	p.mu.Lock()
	p.streak++
	n, interval, cap := p.streak, p.cfg.Interval, p.cfg.BackoffCap
	p.mu.Unlock()
	// Exactly ONE line when the ladder reaches the cap: the event an operator
	// should know about is "we are now stuck at the max retry pace", not
	// every step of the climb. Fires once per outage (the condition is a
	// threshold crossing, no state needed).
	if baseDelay(n, interval, cap) == cap && baseDelay(n-1, interval, cap) < cap {
		p.log("warn", "poll failure streak %d — backoff ladder capped at %s; the last good config keeps serving", n, cap)
	}
}

func (p *Poller) resetStreak() {
	p.mu.Lock()
	p.streak = 0
	p.mu.Unlock()
}

func (p *Poller) heartbeats() (gen, acked int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.generation, p.acked
}

func (p *Poller) log(kind, format string, args ...any) {
	p.cfg.Log(kind, format, args...)
}

// logThrottled drops repeats of the same failure brand inside ErrorLogGap —
// a down API would otherwise emit one identical line per tick. The FIRST
// line always gets through; the first noticed after every gap also does.
// Recovery messages ("applied snapshot …") are never throttled.
func (p *Poller) logThrottled(kind, brand, format string, args ...any) {
	if !p.throttle.allow(brand, p.cfg.ErrorLogGap, p.cfg.Now()) {
		return
	}
	p.log(kind, format, args...)
}

// atomicWrite: temp file in the same dir (so rename is atomic on one fs),
// single write, fsync the file, chmod 0600 (the mode the final file must
// have regardless of umask), rename over the target, fsync the directory so
// the rename itself survives a crash.
func atomicWrite(dir, name string, data []byte) error {
	f, err := os.CreateTemp(dir, ".snapshot-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// genOf: the generation from a canonical payload without parsing it as a
// Document (the strict check has already happened); used only for log lines.
func genOf(payload string) int64 {
	var d snapshot.Document
	if err := json.Unmarshal([]byte(payload), &d); err != nil {
		return 0
	}
	return d.Generation
}

func strconvFormatInt(v int64) string {
	return fmt.Sprintf("%d", v)
}
