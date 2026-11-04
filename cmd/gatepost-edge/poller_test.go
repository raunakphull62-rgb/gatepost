package main

// Tests for the edge poller (B3b item 2). Each spec bullet gets a test;
// timings use the poller's configurable Interval/BackoffCap at millisecond
// scale. The fake node API mirrors the real /node/v1/* semantics: bearer
// auth, generation-as-ETag with quoted If-None-Match 304s, and heartbeats
// accepted only for generations the API itself serves.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gatepost/internal/snapshot"
)

// ---- the fake node API -------------------------------------------------

type reqRecord struct {
	at                time.Time
	method, auth, inm string
}

type fakeAPI struct {
	t     *testing.T
	token string
	key   []byte

	mu   sync.Mutex
	doc  snapshot.Document  // what the next publish signs
	env  *snapshot.Envelope // served raw when set
	gen  int64              // generation currently served (ETag anchor)
	reqs []reqRecord
	hb   []int64
	hard bool // always-401 mode (revoked token)
}

func newFakeAPI(t *testing.T, key []byte, token string) *fakeAPI {
	t.Helper()
	return &fakeAPI{t: t, key: key, token: token}
}

func (f *fakeAPI) serve() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(f.ServeHTTP))
	f.t.Cleanup(srv.Close)
	return srv
}

func (f *fakeAPI) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, reqRecord{time.Now(), r.Method, r.Header.Get("Authorization"), r.Header.Get("If-None-Match")})
}

func (f *fakeAPI) requests() []reqRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]reqRecord(nil), f.reqs...)
}

func (f *fakeAPI) setHard(hard bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hard = hard
}

// publish signs `gen` over fresh hostnames and serves it.
func (f *fakeAPI) publish(gen int64, hostnames ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.doc = snapshot.Document{
		SchemaVersion:    snapshot.SchemaVersion,
		Generation:       gen,
		BuiltAt:          time.Now().UTC(),
		AllowedHostnames: hostnames,
		Defaults:         snapshot.Defaults{FirewallMode: "log_only", Cache: true},
	}
	if gen <= 0 {
		f.t.Fatalf("publish: generation must be positive, got %d", gen)
	}
	env, err := snapshot.Sign(f.key, f.doc)
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	f.env, f.gen = &env, gen
}

// envCopy returns the currently served envelope for local tampering.
func (f *fakeAPI) envCopy() snapshot.Envelope {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.env
}

// publishDoc signs and serves doc verbatim (e2e: origins behind the edge).
func (f *fakeAPI) publishDoc(doc snapshot.Document) {
	f.mu.Lock()
	defer f.mu.Unlock()
	env, err := snapshot.Sign(f.key, doc)
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	f.doc, f.env, f.gen = doc, &env, doc.Generation
}

// override serves a raw envelope as-is (tampered / foreign-key cases) with
// the given generation as the ETag anchor.
func (f *fakeAPI) override(env snapshot.Envelope, gen int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.env, f.gen = &env, gen
}

func (f *fakeAPI) heartbeatLog() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.hb...)
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	if want := "Bearer " + f.token; r.Header.Get("Authorization") != want || (func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.hard })() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	env, gen := f.env, f.gen
	etag := `"` + strconv.FormatInt(gen, 10) + `"`
	if r.URL.Path == "/node/v1/heartbeat" && r.Method == http.MethodPost {
		var body struct {
			Generation int64 `json:"generation"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			f.mu.Unlock()
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.hb = append(f.hb, body.Generation)
		accept := body.Generation == gen
		f.mu.Unlock()
		if !accept {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	f.mu.Unlock()
	if r.URL.Path != "/node/v1/config" || r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.Header().Set("ETag", etag) // the server sends it on the 304 too
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if env == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	b, _ := json.Marshal(env)
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// ---- shared helpers ----------------------------------------------------

type logHook struct {
	mu    sync.Mutex
	lines []string
}

func (h *logHook) log(kind, format string, args ...any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lines = append(h.lines, kind+"|"+fmt.Sprintf(format, args...))
}

func (h *logHook) all() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.lines, "\n")
}

func (h *logHook) count(substr string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.lines {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

// makeKey: printable bytes, so a sweep for leaks is meaningful.
func makeKey(t *testing.T) []byte {
	t.Helper()
	return []byte("edge-test-key-0123456789abcdefghij") // 34 bytes
}

func newTestCfg(t *testing.T, hook *logHook, stateDir, baseURL, token string, key []byte) Config {
	t.Helper()
	cfg := Config{
		APIBase:    baseURL,
		Token:      token,
		Key:        key,
		StateDir:   stateDir,
		Interval:   2 * time.Millisecond,
		BackoffCap: 60 * time.Millisecond,
		Client:     &http.Client{Timeout: 2 * time.Second},
		Rand01:     rand.Float64,
		Log:        hook.log,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg.AskLn = ln
	return cfg
}

// startPoller runs the poller in a goroutine; t.Cleanup cancels it.
func startPoller(t *testing.T, cfg Config) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done // wait for the goroutine: it reads package-level test knobs
	})
	go func() { defer close(done); _ = NewPoller(cfg).Run(ctx) }()
	return "http://" + cfg.AskLn.Addr().String()
}

func until(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func savedGeneration(t *testing.T, stateDir string, key []byte) int64 {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(stateDir, snapshotFile))
	if err != nil {
		t.Fatalf("read saved snapshot: %v", err)
	}
	var env snapshot.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("decode saved snapshot: %v", err)
	}
	d, err := snapshot.Verify(key, env, 0)
	if err != nil {
		t.Fatalf("saved snapshot does not verify: %v", err)
	}
	return d.Generation
}

// flipHexChar keeps the hex decodable while changing the signature.
func flipHexChar(sig string) string {
	if len(sig) == 0 {
		return "f"
	}
	if sig[0] == '0' {
		return "1" + sig[1:]
	}
	return "0" + sig[1:]
}

func askGet(t *testing.T, base, path string) int {
	t.Helper()
	resp, err := http.Get(base + path)
	if err != nil {
		t.Fatalf("ask get %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func askOK(t *testing.T, base, path string) bool {
	return askGet(t, base, path) == http.StatusOK
}

// closedPort returns an address whose port is (now) unreachable.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	closeErr := ln.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	return addr
}

// TestVerifyRefusesBadHostHeader: the snapshot verify step mirrors the API
// side host_header rule. A verified envelope whose origin host_header is not
// hostname or hostname:port is refused and never applied.
func TestVerifyRefusesBadHostHeader(t *testing.T) {
	key := makeKey(t)
	p := NewPoller(Config{Key: key})

	badDoc := snapshot.Document{
		SchemaVersion: snapshot.SchemaVersion,
		Generation:    1,
		Domains: []snapshot.Domain{{
			Hostname: "shop.example.test",
			Origin: snapshot.Origin{
				Scheme:      "http",
				Address:     "93.184.216.34",
				Port:        80,
				HostHeader:  hostHeader("{env.PATH}"),
			},
		}},
	}
	env, err := snapshot.Sign(key, badDoc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.verify(env, 0); err == nil {
		t.Fatal("snapshot with bad host_header verified — must be refused")
	}

	// a well-formed host_header verifies
	goodDoc := badDoc
	goodDoc.Domains[0].Origin.HostHeader = hostHeader("backend.example.com")
	genv, _ := snapshot.Sign(key, goodDoc)
	if _, err := p.verify(genv, 0); err != nil {
		t.Fatalf("good snapshot failed verify: %v", err)
	}
}

// ---- tests -------------------------------------------------------------

// The production defaults are exactly the spec: 5s cadence, 60s cap.
func TestConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GP_EDGE_API_BASE", "http://api.test:8080")
	t.Setenv("GP_EDGE_TOKEN", "tok-internal")
	t.Setenv("GP_SNAPSHOT_KEY", string(makeKey(t)))
	t.Setenv("GP_EDGE_STATE_DIR", "")
	orig, err := os.Getwd() // the default state mkdir happens under a temp cwd
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatal(err)
		}
	}()
	cfg := loadConfig()
	if cfg.Interval != 5*time.Second {
		t.Fatalf("default poll interval = %v, want 5s", cfg.Interval)
	}
	if cfg.BackoffCap != 60*time.Second {
		t.Fatalf("default backoff cap = %v, want 60s", cfg.BackoffCap)
	}
	if cfg.AskAddr != "127.0.0.1:8099" {
		t.Fatalf("default ask addr = %q", cfg.AskAddr)
	}
	if cfg.StateDir != "data/snapshots" {
		t.Fatalf("default state dir = %q", cfg.StateDir)
	}
	if cfg.Issuer != issuerStaging {
		t.Fatalf("default issuer = %q, want staging", cfg.Issuer)
	}
	if cfg.CertHourlyCap != 50 {
		t.Fatalf("default cert cap = %d, want 50", cfg.CertHourlyCap)
	}
	if cfg.AllowLoopback {
		t.Fatal("loopback allowed by default")
	}
}

// The production-issuer boot guard: GP_EDGE_ISSUER=production is the
// explicit opt-in, and it is REFUSED at boot on a loopback test/demo node —
// a dev box must never mint against production Let's Encrypt. Staging (the
// default) and internal run fine with the loopback hook.
func TestProductionIssuerBootGuard(t *testing.T) {
	if err := issuerBootGuard(issuerProduction, true); err == nil {
		t.Fatal("production issuer with the loopback hook was accepted at boot")
	}
	for _, c := range []struct {
		issuer   string
		loopback bool
	}{
		{issuerProduction, false}, // the explicit opt-in on a clean node
		{issuerStaging, true},
		{issuerStaging, false},
		{issuerInternal, true},
	} {
		if err := issuerBootGuard(c.issuer, c.loopback); err != nil {
			t.Fatalf("issuerBootGuard(%q, loopback=%v) = %v, want nil", c.issuer, c.loopback, err)
		}
	}
}

// Poll on the interval with Bearer auth; once a generation is applied the
// polls carry If-None-Match; 304 means no change (no re-apply, no re-write);
// a new generation applies and moves the ETag.
func TestPollCadenceAndIfNoneMatch(t *testing.T) {
	key := makeKey(t)
	token := "node-token-cadence"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "one.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))

	until(t, 3*time.Second, "first apply", func() bool { return hook.count("applied snapshot") >= 1 })
	until(t, 3*time.Second, "an If-None-Match poll", func() bool {
		r := fake.requests()
		return len(r) >= 2 && r[len(r)-1].inm == `"1"`
	})

	fake.publish(2, "one.example.com", "two.example.com")
	until(t, 3*time.Second, "second apply", func() bool { return hook.count("applied snapshot") >= 2 })
	until(t, 3*time.Second, "If-None-Match follows the new generation", func() bool {
		r := fake.requests()
		return len(r) >= 3 && r[len(r)-1].inm == `"2"`
	})
	if got := hook.count("applied snapshot"); got != 2 {
		t.Fatalf("applied lines = %d, want exactly 2 (304s must not re-apply)", got)
	}
	if gen := savedGeneration(t, dir, key); gen != 2 {
		t.Fatalf("saved generation = %d, want 2", gen)
	}
	if code := askGet(t, ask, "/check?domain=two.example.com"); code != http.StatusOK {
		t.Fatalf("new host ask = %d, want 200", code)
	}
}

// The artifact is written atomically (no temp leftovers) at mode 0600 and
// re-verifies with the same key.
func TestPersistAtomic0600(t *testing.T) {
	key := makeKey(t)
	token := "node-token-disk"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "disk.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	startPoller(t, newTestCfg(t, hook, dir, base, token, key))
	until(t, 3*time.Second, "apply for the disk test", func() bool { return hook.count("applied snapshot") >= 1 })

	path := filepath.Join(dir, snapshotFile)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved file mode = %v, want 0600", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".snapshot-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	if gen := savedGeneration(t, dir, key); gen != 1 {
		t.Fatalf("saved generation = %d, want 1", gen)
	}

	// A second apply replaces the file in place (rename over the target).
	fake.publish(2, "disk2.example.com")
	until(t, 3*time.Second, "second apply for the disk test", func() bool { return hook.count("applied snapshot") >= 2 })
	if gen := savedGeneration(t, dir, key); gen != 2 {
		t.Fatalf("saved generation after replace = %d, want 2", gen)
	}
	if fi, err = os.Stat(path); err == nil && fi.Mode().Perm() != 0o600 {
		t.Fatalf("replaced file mode = %v, want 0600", fi.Mode())
	}
}

// Boot re-verifies the saved artifact and reports it: heartbeat with the
// actually-applied generation, ask 200 for its hosts, 421 for others, and
// polls continue from that generation.
func TestLoadSavedSnapshotAtBoot(t *testing.T) {
	key := makeKey(t)
	token := "node-token-reload"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "saved.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	startPoller(t, newTestCfg(t, hook, dir, base, token, key))
	until(t, 3*time.Second, "seed apply", func() bool { return hook.count("applied snapshot") >= 1 })

	// A second poller boots from the same volume, as after a restart.
	hook2 := &logHook{}
	cfg := newTestCfg(t, hook2, dir, base, token, key)
	ask := startPoller(t, cfg)
	until(t, 3*time.Second, "boot heartbeat with the applied generation", func() bool {
		hb := fake.heartbeatLog()
		return len(hb) >= 2 && hb[len(hb)-1] == 1
	})
	if code := askGet(t, ask, "/check?domain=saved.example.com"); code != http.StatusOK {
		t.Fatalf("restored host ask = %d, want 200 (cold start must apply the saved snapshot)", code)
	}
	if code := askGet(t, ask, "/check?domain=unknown.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("unknown host ask = %d, want 421", code)
	}
	until(t, 3*time.Second, "If-None-Match from the restored generation", func() bool {
		r := fake.requests()
		return len(r) >= 2 && r[len(r)-1].inm == `"1"`
	})
}

// A tampered ENVELOPE is verified against and never applied.
func TestTamperedEnvelopeRefused(t *testing.T) {
	key := makeKey(t)
	token := "node-token-tamper"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "ok.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))
	until(t, 3*time.Second, "apply gen1", func() bool { return hook.count("applied snapshot") == 1 })

	fake.publish(2, "evil.example.com")
	bad := fake.envCopy()
	bad.Signature = flipHexChar(bad.Signature)
	fake.override(bad, 2)

	until(t, 3*time.Second, "tamper warning", func() bool { return hook.count("signature verification failed") >= 1 })
	if got := hook.count("applied snapshot"); got != 1 {
		t.Fatalf("applied lines = %d, want 1 (gen1 only)", got)
	}
	if gen := savedGeneration(t, dir, key); gen != 1 {
		t.Fatalf("persisted generation = %d, want 1", gen)
	}
	if code := askGet(t, ask, "/check?domain=evil.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("tampered host ask = %d, want 421", code)
	}
	if hb := fake.heartbeatLog(); len(hb) == 0 || hb[len(hb)-1] != 1 {
		t.Fatalf("heartbeats = %v, want only the applied 1", hb)
	}
}

// An unknown key ID is skipped with a warning — never applied, and never
// treated as tampering.
func TestUnknownKeySkipped(t *testing.T) {
	key := makeKey(t)
	other := []byte("some-other-edge-key-0123456789abcdefg")
	token := "node-token-keyswap"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "a.example.com")
	base := fake.serve().URL

	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, t.TempDir(), base, token, key))
	until(t, 3*time.Second, "apply gen1", func() bool { return hook.count("applied snapshot") == 1 })

	gen2 := snapshot.Document{
		SchemaVersion:    snapshot.SchemaVersion,
		Generation:       2,
		BuiltAt:          time.Now().UTC(),
		AllowedHostnames: []string{"b.example.com"},
		Defaults:         snapshot.Defaults{FirewallMode: "log_only", Cache: true},
	}
	env2, err := snapshot.Sign(other, gen2)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	fake.override(env2, 2)

	until(t, 3*time.Second, "unknown key warning", func() bool { return hook.count("unknown key id") >= 1 })
	if ln := hook.all(); strings.Contains(ln, "tampering?") || strings.Contains(ln, "signature verification failed") {
		t.Fatalf("unknown key must not read as tampering:\n%s", ln)
	}
	if got := hook.count("applied snapshot"); got != 1 {
		t.Fatalf("applied lines = %d, want 1", got)
	}
	if code := askGet(t, ask, "/check?domain=b.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign host ask = %d, want 421", code)
	}
	if hb := fake.heartbeatLog(); len(hb) == 0 || hb[len(hb)-1] != 1 {
		t.Fatalf("heartbeats = %v, want only the applied 1", hb)
	}
}

// The schema gate (B3c item 2b), wire path: an OLD-STYLE node (empty feature
// set) refuses a snapshot that requires a feature it does not implement —
// the last good config keeps serving, the refusal logs ONCE per throttle gap
// (not once per poll), and the heartbeat never advances past the applied
// generation.
func TestUnknownFeatureKeepsLastGood(t *testing.T) {
	key := makeKey(t)
	token := "node-token-features"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "old.example.com") // the old-style artifact: no required_features
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, base, token, key)
	cfg.Features = nil // old-style node: knows no features
	ask := startPoller(t, cfg)
	until(t, 3*time.Second, "apply gen1", func() bool { return hook.count("applied snapshot") == 1 })

	// The API moves to the current shape: the artifact now requires "waf".
	fake.publishDoc(snapshot.Document{
		SchemaVersion:    snapshot.SchemaVersion,
		RequiredFeatures: []string{snapshot.FeatureWAF},
		Generation:       2,
		BuiltAt:          time.Now().UTC(),
		Domains: []snapshot.Domain{{
			Hostname:  "new.example.com",
			SetupType: "cname",
			Origin:    snapshot.Origin{Scheme: "http", Address: "93.184.216.34", Port: 80},
		}},
		AllowedHostnames: []string{"new.example.com"},
		Defaults:         snapshot.Defaults{FirewallMode: "log_only", Cache: true},
	})

	until(t, 3*time.Second, "feature refusal", func() bool {
		return hook.count("does not implement") >= 1
	})
	// Many more polls run inside the same throttle gap — still one line.
	time.Sleep(100 * time.Millisecond)
	if n := hook.count("does not implement"); n != 1 {
		t.Fatalf("feature-refusal lines = %d, want 1 per gap", n)
	}
	if got := hook.count("applied snapshot"); got != 1 {
		t.Fatalf("applied lines = %d, want 1 (gen2 never applied)", got)
	}
	if gen := savedGeneration(t, dir, key); gen != 1 {
		t.Fatalf("persisted generation = %d, want 1 (last good kept)", gen)
	}
	if code := askGet(t, ask, "/check?domain=new.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("new host ask = %d, want 421 (last good still serving)", code)
	}
	if hb := fake.heartbeatLog(); len(hb) == 0 || hb[len(hb)-1] != 1 {
		t.Fatalf("heartbeats = %v, want only the applied 1", hb)
	}
}

// The current edge accepts the current snapshot: a required_features list it
// implements verifies and applies like any other.
func TestCurrentEdgeAcceptsRequiredFeatures(t *testing.T) {
	key := makeKey(t)
	token := "node-token-gate-ok"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(snapshot.Document{
		SchemaVersion:    snapshot.SchemaVersion,
		RequiredFeatures: []string{snapshot.FeatureWAF},
		Generation:       1,
		BuiltAt:          time.Now().UTC(),
		Domains: []snapshot.Domain{{
			Hostname:  "gated.example.com",
			SetupType: "cname",
			Origin:    snapshot.Origin{Scheme: "http", Address: "93.184.216.34", Port: 80},
		}},
		AllowedHostnames: []string{"gated.example.com"},
		Defaults:         snapshot.Defaults{FirewallMode: "log_only", Cache: true},
	})
	base := fake.serve().URL

	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	cfg.Features = []string{snapshot.FeatureWAF} // the current build's knowledge
	startPoller(t, cfg)
	until(t, 3*time.Second, "apply gen1", func() bool { return hook.count("applied snapshot") == 1 })
	if hook.count("refused") != 0 {
		t.Fatalf("current snapshot must not be refused:\n%s", hook.all())
	}
}

// A snapshot with a NEWER schema_version than this build understands is
// refused on the wire path — loudly, once per throttle gap, never applied.
func TestNewerSchemaRefusedLogsOnce(t *testing.T) {
	key := makeKey(t)
	token := "node-token-schema"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(snapshot.Document{
		SchemaVersion: snapshot.SchemaVersion + 1,
		Generation:    1,
		BuiltAt:       time.Now().UTC(),
		Domains: []snapshot.Domain{{
			Hostname:  "future.example.com",
			SetupType: "cname",
			Origin:    snapshot.Origin{Scheme: "http", Address: "93.184.216.34", Port: 80},
		}},
		AllowedHostnames: []string{"future.example.com"},
		Defaults:         snapshot.Defaults{FirewallMode: "log_only", Cache: true},
	})
	base := fake.serve().URL

	hook := &logHook{}
	startPoller(t, newTestCfg(t, hook, t.TempDir(), base, token, key))
	until(t, 3*time.Second, "schema refusal", func() bool {
		return hook.count("newer than this build understands") >= 1
	})
	// Many more polls run inside the same throttle gap — still one line.
	time.Sleep(100 * time.Millisecond)
	if n := hook.count("newer than this build understands"); n != 1 {
		t.Fatalf("schema-refusal lines = %d, want 1 per gap", n)
	}
	if got := hook.count("applied snapshot"); got != 0 {
		t.Fatalf("applied lines = %d, want 0 (unknown schema never applied)", got)
	}
}

// A generation that is not strictly newer than the applied one is refused
// (the A→B→A rule: content may repeat, generations may not).
func TestBackwardsGenerationRefused(t *testing.T) {
	key := makeKey(t)
	token := "node-token-backwards"
	fake := newFakeAPI(t, key, token)
	fake.publish(2, "a.example.com")
	base := fake.serve().URL

	hook := &logHook{}
	dir := t.TempDir()
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))

	until(t, 3*time.Second, "apply gen2", func() bool { return hook.count("applied snapshot") == 1 })
	fake.publish(1, "stale.example.com") // content regressed with a LOWER generation
	until(t, 3*time.Second, "backwards refusal", func() bool { return hook.count("not strictly newer") >= 1 })
	if got := hook.count("applied snapshot"); got != 1 {
		t.Fatalf("applied lines = %d, want 1", got)
	}
	if code := askGet(t, ask, "/check?domain=stale.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("stale host ask = %d, want 421", code)
	}
	if gen := savedGeneration(t, dir, key); gen != 2 {
		t.Fatalf("saved generation = %d, want 2 (backwards never applied)", gen)
	}
}

// A body over the size cap is refused before anything is applied, on the
// way in (limit reader) as well as inside verify.
func TestOversizeRefused(t *testing.T) {
	key := makeKey(t)
	token := "node-token-big"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "a.example.com")

	big := snapshot.Envelope{
		Payload:   strings.Repeat("x", snapshot.MaxBytes+16),
		Signature: strings.Repeat("ab", 32),
		KeyID:     "deadbeefdeadbeef",
	}
	fake.override(big, 1)
	base := fake.serve().URL

	hook := &logHook{}
	startPoller(t, newTestCfg(t, hook, t.TempDir(), base, token, key))

	until(t, 3*time.Second, "size refusal", func() bool { return hook.count("cap") >= 1 })
	if got := hook.count("applied snapshot"); got != 0 {
		t.Fatalf("applied lines = %d, want 0", got)
	}
	// The verify gate agrees, for payloads that get past the wire anyway.
	env := fake.envCopy()
	env.Payload = strings.Repeat("y", snapshot.MaxBytes+1)
	p := NewPoller(newTestCfg(t, hook, t.TempDir(), base, token, key))
	if _, err := p.verify(env, 0); err == nil {
		t.Fatal("verify accepted an oversized payload")
	}
}

// Boot with a corrupt file on disk: "no snapshot", 421 for every host, no
// crash — and the poll loop heals the volume from the wire.
func TestCorruptSavedFileIsNoSnapshot(t *testing.T) {
	key := makeKey(t)
	token := "node-token-corrupt"
	fake := newFakeAPI(t, key, token) // nothing published yet: only 503s
	base := fake.serve().URL

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, snapshotFile), []byte("\x00\x01{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))

	until(t, 3*time.Second, "corrupt-file refusal", func() bool { return hook.count("corrupt file") >= 1 })
	until(t, 3*time.Second, "boot denial", func() bool { return askGet(t, ask, "/check?domain=heal.example.com") == http.StatusMisdirectedRequest })

	// The volume stays "no snapshot" while the API is broken.
	time.Sleep(150 * time.Millisecond)
	if code := askGet(t, ask, "/check?domain=heal.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("denial drifted to %d with a broken API", code)
	}

	// Then the wire heals the volume.
	fake.publish(1, "heal.example.com")
	until(t, 3*time.Second, "poll heals from the wire", func() bool { return hook.count("applied snapshot") >= 1 })
	until(t, 3*time.Second, "ask serves after healing", func() bool { return askOK(t, ask, "/check?domain=heal.example.com") })
}

// A tampered file on disk is likewise refused; the next honest artifact
// overwrites it.
func TestTamperedSavedFileIsNoSnapshot(t *testing.T) {
	key := makeKey(t)
	token := "node-token-savetamper"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "old.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	bad := fake.envCopy()
	bad.Signature = flipHexChar(bad.Signature)
	b, err := json.Marshal(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, snapshotFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	fake.publish(7, "fresh.example.com")

	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))

	until(t, 3*time.Second, "disk tamper refused", func() bool { return hook.count("treating as none") >= 1 })
	if code := askGet(t, ask, "/check?domain=old.example.com"); code != http.StatusMisdirectedRequest {
		t.Fatalf("tampered-file host ask = %d, want 421", code)
	}
	until(t, 3*time.Second, "wire heals the volume", func() bool {
		return askGet(t, ask, "/check?domain=fresh.example.com") == http.StatusOK
	})
	if gen := savedGeneration(t, dir, key); gen != 7 {
		t.Fatalf("saved generation = %d, want 7 (honest artifact replaced the tampered one)", gen)
	}
}

// Cold start with the API unreachable and a saved snapshot: applied from
// disk, served from memory, loop keeps retrying, never drops.
func TestColdStartAppliesSavedWhileAPIDown(t *testing.T) {
	key := makeKey(t)
	token := "node-token-coldfile"
	fake := newFakeAPI(t, key, token)
	fake.publish(4, "cold.example.com")

	// The volume holds the last good artifact; the API is unreachable from
	// the very first tick. The file must exist BEFORE the poller boots —
	// the boot load is the only reader.
	dir := t.TempDir()
	env := fake.envCopy()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, snapshotFile), b, 0o600); err != nil {
		t.Fatal(err)
	}

	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, "", token, key)
	ask := startPoller(t, cfg) // empty API base: every poll fails

	until(t, 3*time.Second, "saved snapshot applied while the API is down", func() bool {
		return askOK(t, ask, "/check?domain=cold.example.com")
	})
	time.Sleep(200 * time.Millisecond) // plenty of failed polls happen meanwhile
	if code := askGet(t, ask, "/check?domain=cold.example.com"); code != http.StatusOK {
		t.Fatalf("cold start ask = %d, want 200", code)
	}
}

// Cold start with the API unreachable and NO saved snapshot: 421 for every
// host, retrying the whole time, still alive.
func TestColdStartNoSnapshotServes421(t *testing.T) {
	key := makeKey(t)
	token := "node-token-coldnone"
	addr := closedPort(t)

	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, t.TempDir(), "http://"+addr, token, key))

	// Wait for the ask endpoint to be ready (poller started, apply loop ran).
	// The ask listener starts immediately in startApply, so this confirms
	// the poller is up without relying on a fixed sleep.
	until(t, 5*time.Second, "ask endpoint ready", func() bool {
		_, err := http.Get(ask + "/check?domain=test.example.com")
		return err == nil // 421 is still a valid response; connection success = ready
	})
	for _, q := range []string{"?domain=nothing.example.com", "?domain=", "?_", ""} {
		if code := askGet(t, ask, "/check"+q); code != http.StatusMisdirectedRequest {
			t.Fatalf("no-snapshot ask %q = %d, want 421", q, code)
		}
	}
	if n := hook.count("poll failed"); n < 1 {
		t.Fatalf("no poll failures logged — the loop is not retrying (log):\n%s", hook.all())
	}
}

// Poll failures grow the wait exponentially to the cap; every wait carries
// jitter; two nodes never poll in lockstep.
func TestBackoffLadderWithJitter(t *testing.T) {
	var mu sync.Mutex
	var at []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		mu.Lock()
		at = append(at, now)
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), srv.URL, "tok", makeKey(t))
	cfg.Interval, cfg.BackoffCap = 4*time.Millisecond, 150*time.Millisecond
	startPoller(t, cfg)

	// Walk the ladder: factor = interval·2^streak capped at 150ms →
	// waits 8,16,32,64,128 | 150,150,150…
	// The CADENCE is measured on the server's own timestamps, not on log
	// lines: repeated failure lines are throttled to one per gap on purpose.
	until(t, 5*time.Second, "enough failed polls to walk the ladder", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(at) >= 9
	})

	mu.Lock()
	timestamps := append([]time.Time(nil), at...)
	mu.Unlock()
	if len(timestamps) < 9 {
		t.Fatalf("only %d requests recorded", len(timestamps))
	}
	var gaps []time.Duration
	for i := 1; i < len(timestamps); i++ {
		gaps = append(gaps, timestamps[i].Sub(timestamps[i-1]))
	}
	if gaps[0] > 25*time.Millisecond {
		t.Fatalf("first wait %v, want a small start (~2×2ms)", gaps[0])
	}
	if gaps[0]+gaps[1] >= gaps[2]+gaps[3] {
		t.Fatalf("ladder does not lift: first pairs %v vs %v", gaps[0:2], gaps[2:4])
	}
	for _, g := range gaps[len(gaps)-3:] {
		if g < 120*time.Millisecond || g > 185*time.Millisecond {
			t.Fatalf("capped wait %v, want ≈150ms×[0.9,1.1]", g)
		}
	}

	// nextDelay directly: two "nodes" in the same state must not match.
	twoNodeSpread(t)
}

func twoNodeSpread(t *testing.T) {
	t.Helper()
	interval, cap := 5*time.Second, 60*time.Second
	// Streak 3: factor 40s; jitters in [0.9,1.1)·40s.
	lo, hi := time.Duration(1<<62), time.Duration(0)
	xlo, xhi := time.Duration(1<<62), time.Duration(0)
	for i := 0; i < 200; i++ {
		d := time.Duration(float64(baseDelay(3, interval, cap)) * (0.9 + 0.2*rand.Float64()))
		if d < lo {
			lo = d
		}
		if d > hi {
			hi = d
		}
		// At the cap: factor 60s, jitter keeps it out of lockstep too.
		e := time.Duration(float64(baseDelay(30, interval, cap)) * (0.9 + 0.2*rand.Float64()))
		if e < xlo {
			xlo = e
		}
		if e > xhi {
			xhi = e
		}
	}
	if hi-lo < time.Second {
		t.Fatalf("jitter spread at factor 40s = %v, want ≥ 1s between two nodes", hi-lo)
	}
	if xhi-xlo < time.Second {
		t.Fatalf("jitter spread at the cap = %v, want ≥ 1s", xhi-xlo)
	}
	factor := 40 * time.Second
	if lo < factor*9/10 || hi > factor*11/10 {
		t.Fatalf("delay escapes [0.9,1.1)×factor: %v..%v", lo, hi)
	}
	fc := 60 * time.Second
	if xlo < fc*9/10 || xhi > fc*11/10 {
		t.Fatalf("capped delay escapes [0.9,1.1)×cap: %v..%v", xlo, xhi)
	}
}

// A 401 (revoked token) is LOUD, keeps the last good config, and the node
// recovers by itself once the token works again.
func Test401KeepsServing(t *testing.T) {
	key := makeKey(t)
	token := "node-token-revoke"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "kept.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))
	until(t, 3*time.Second, "apply gen1", func() bool { return hook.count("applied snapshot") == 1 })

	fake.setHard(true) // the token is now revoked
	until(t, 3*time.Second, "loud 401", func() bool { return hook.count("401 from API") >= 1 })
	hbBefore := len(fake.heartbeatLog())
	if code := askGet(t, ask, "/check?domain=kept.example.com"); code != http.StatusOK {
		t.Fatalf("during 401, last good host ask = %d, want 200", code)
	}
	fake.setHard(false)
	if n := hook.count("applied snapshot"); n != 1 {
		t.Fatalf("applied lines = %d, want 1 (a 401 must not fabricate applies)", n)
	}
	if len(fake.heartbeatLog()) > hbBefore {
		t.Fatalf("heartbeats continued during the 401 outage")
	}

	// Heal: token works again, next generation applies, ask follows.
	fake.publish(2, "kept.example.com", "healed.example.com")
	until(t, 3*time.Second, "apply heals after the token revocation", func() bool { return hook.count("applied snapshot") == 2 })
	until(t, 3*time.Second, "ask serves the healed generation", func() bool { return askOK(t, ask, "/check?domain=healed.example.com") })
}

// Heartbeats report the generation actually applied — never the last
// fetched attempt. A refused envelope between applications leaves no
// heartbeat for its (existing, unapplied) generation.
func TestHeartbeatReportsAppliedGeneration(t *testing.T) {
	key := makeKey(t)
	token := "node-token-heartbeat"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "one.example.com")
	base := fake.serve().URL

	hook := &logHook{}
	startPoller(t, newTestCfg(t, hook, t.TempDir(), base, token, key))
	until(t, 3*time.Second, "apply gen1", func() bool { return hook.count("applied snapshot") == 1 })
	until(t, 3*time.Second, "heartbeat 1 acknowledged", func() bool {
		hb := fake.heartbeatLog()
		return len(hb) >= 1 && hb[len(hb)-1] == 1
	})

	// Now the API offers gen 2 (it exists server-side), but it is tampered:
	// never applied, so never heartbeated.
	fake.publish(2, "tampered.example.com")
	bad := fake.envCopy()
	bad.Signature = flipHexChar(bad.Signature)
	fake.override(bad, 2)
	until(t, 3*time.Second, "tamper refusal", func() bool { return hook.count("signature verification failed") >= 1 })

	// gen 3 arrives honestly and is applied; the heartbeat must be 3.
	fake.publish(3, "three.example.com")
	until(t, 3*time.Second, "apply gen3", func() bool { return hook.count("applied snapshot") == 2 })
	until(t, 3*time.Second, "heartbeat 3 sent", func() bool {
		hb := fake.heartbeatLog()
		return len(hb) == 2 && hb[0] == 1 && hb[1] == 3
	})
}

// The ask gate's full matrix (item 4): only a valid hostname present in the
// applied snapshot gets 200. Case is deliberately NOT denied — DNS names are
// case-insensitive and a legitimate ClientHello may carry any case. Ports,
// IP literals (v4/v6), trailing dots and non-hostnames are 421.
func TestAskHostMatrix(t *testing.T) {
	key := makeKey(t)
	token := "node-token-ask"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "one.example.com")
	base := fake.serve().URL

	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, t.TempDir(), base, token, key))
	until(t, 3*time.Second, "apply for the ask test", func() bool { return hook.count("applied snapshot") >= 1 })

	for _, path := range []string{
		"/check?domain=one.example.com",
		"/check?domain=One.Example.com",   // DNS is case-insensitive; we return 200
		"/check?domain=ONE.EXAMPLE.COM",   // same
		"/ask?domain=one.example.com",     // either anchor
		"/check?hostname=one.example.com", // hostname variant
	} {
		if code := askGet(t, ask, path); code != http.StatusOK {
			t.Fatalf("ask %q = %d, want 200", path, code)
		}
	}
	for _, path := range []string{
		"/check?domain=star.example.com",          // not in the snapshot
		"/check",                                  // missing
		"/check?domain=",                          // empty
		"/check?domain=one.example.com.",          // trailing dot is not an SNI
		"/check?domain=one.example.com:443",       // ports never belong to SNI
		"/check?domain=one.example.com:80",        // same
		"/check?hostname=one.example.com:8443",    // port via the other anchor
		"/check?domain=127.0.0.1",                 // IP literal
		"/check?domain=169.254.169.254",           // metadata, just in case
		"/check?domain=[::1]",                     // IPv6 literal
		"/check?domain=::1",                       // bare IPv6 literal
		"/check?domain=one.example.com.evil.test", // suffix trick
		"/check?domain=*.example.com",             // wildcard
	} {
		if code := askGet(t, ask, path); code != http.StatusMisdirectedRequest {
			t.Fatalf("ask %q = %d, want 421", path, code)
		}
	}
}

// The hourly cap is per node and applies only to APPROVED hostnames: denied
// requests cost nothing. Once exhausted, new certificates are refused with
// 429 until the window rolls over.
func TestAskCertCapPerHour(t *testing.T) {
	key := makeKey(t)
	token := "node-token-cap"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "cap.example.com", "other.example.com")
	base := fake.serve().URL

	nowNs := atomic.Int64{}
	nowNs.Store(time.Unix(1_800_000_000, 0).UnixNano())
	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	cfg.CertHourlyCap = 2
	cfg.Now = func() time.Time { return time.Unix(0, nowNs.Load()) }
	ask := startPoller(t, cfg)
	until(t, 3*time.Second, "apply for the cap test", func() bool { return hook.count("applied snapshot") >= 1 })

	// Denials do not consume budget.
	for i := 0; i < 5; i++ {
		if code := askGet(t, ask, "/check?domain=denied.example.com"); code != http.StatusMisdirectedRequest {
			t.Fatalf("denied ask = %d, want 421 (and no cap consumed)", code)
		}
	}
	// Two approvals, then 429.
	for i := 0; i < 2; i++ {
		if code := askGet(t, ask, "/check?domain=cap.example.com"); code != http.StatusOK {
			t.Fatalf("approval %d = %d, want 200", i+1, code)
		}
	}
	if code := askGet(t, ask, "/check?domain=other.example.com"); code != http.StatusTooManyRequests {
		t.Fatalf("over-cap ask = %d, want 429", code)
	}
	if hook.count("certificate cap reached") != 1 {
		t.Fatalf("cap warning count = %d, want exactly 1 (no log spam):\n%s",
			hook.count("certificate cap reached"), hook.all())
	}

	// An hour later the window resets and approvals flow again.
	nowNs.Add(int64(time.Hour))
	if code := askGet(t, ask, "/check?domain=other.example.com"); code != http.StatusOK {
		t.Fatalf("post-window ask = %d, want 200", code)
	}
}

// Secrets never appear in logs or errors, across an event-rich run.
func TestSecretsNeverLogged(t *testing.T) {
	key := []byte("edge-secret-key-ABCDEF0123456789-32b-")
	token := "edge-secret-node-token-9a8b7c6d5e"
	fake := newFakeAPI(t, key, token)
	fake.publish(1, "sweep.example.com")
	base := fake.serve().URL

	dir := t.TempDir()
	hook := &logHook{}
	ask := startPoller(t, newTestCfg(t, hook, dir, base, token, key))
	until(t, 3*time.Second, "seed apply", func() bool { return hook.count("applied snapshot") == 1 })

	// Refusals: tampering, then a revoked token.
	fake.publish(2, "sweep2.example.com")
	bad := fake.envCopy()
	bad.Signature = flipHexChar(bad.Signature)
	fake.override(bad, 2)
	until(t, 3*time.Second, "tamper seen", func() bool { return hook.count("signature verification failed") >= 1 })
	fake.setHard(true)
	until(t, 3*time.Second, "401 seen", func() bool { return hook.count("401 from API") >= 1 })
	// And an unreachable API afterwards (ask survives; errors carry only the URL).
	_ = askOK(t, ask, "/check?domain=sweep.example.com")

	out := hook.all()
	if strings.Contains(out, token) {
		t.Fatalf("node token leaked into logs:\n%s", out)
	}
	if strings.Contains(out, string(key)) {
		t.Fatalf("signing key leaked into logs:\n%s", out)
	}
}
