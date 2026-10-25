package main

// Tests for the apply path (B3b item 3): a fake Caddy admin API implementing
// the /load contract (200 = validated AND applied; 400 = rejected, while the
// last-good config keeps running). Every reload-gate rule is measured here
// against the running poller.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gatepost/internal/snapshot"
)

// ---- fake admin API ----------------------------------------------------

type adminLoad struct {
	mu         sync.Mutex
	reqs       []string // Content-Type|body per request
	nextStatus int      // the status the NEXT request gets (0 → 200)
}

func (a *adminLoad) serve() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/load" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		a.mu.Lock()
		a.reqs = append(a.reqs, r.Header.Get("Content-Type")+"|"+string(b))
		st := a.nextStatus
		if st == 0 {
			st = http.StatusOK
		}
		a.nextStatus = 0 // one-shot reject
		a.mu.Unlock()
		w.WriteHeader(st)
		if st != http.StatusOK {
			_, _ = w.Write([]byte("caddy rejected this configuration (fake)"))
		}
	}))
	return srv
}

func (a *adminLoad) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.reqs)
}

func (a *adminLoad) lastBody() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := len(a.reqs); n > 0 {
		parts := strings.SplitN(a.reqs[n-1], "|", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return ""
}

func (a *adminLoad) firstContentType(t *testing.T) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.reqs) == 0 {
		t.Fatal("no /load requests recorded")
	}
	return strings.SplitN(a.reqs[0], "|", 2)[0]
}

// rejectNext: the NEXT /load request gets `status` instead of 200.
func (a *adminLoad) rejectNext(status int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nextStatus = status
}

// ---- helpers ------------------------------------------------------------

const listenKey = `"listen": "`

// genBodyListenerOf: the admin.listen string inside a generated body.
func genBodyListenerOf(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, listenKey)
	if i < 0 {
		t.Fatalf("no admin.listen in body:\n%s", body)
	}
	rest := body[i+len(listenKey):]
	return rest[:strings.Index(rest, `"`)]
}

// genBodyDialPortOf: the first egress dial port inside a generated body.
func genBodyDialPortOf(t *testing.T, body string) int {
	t.Helper()
	const key = `"dial": "127.0.0.1:`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("no egress dial in body:\n%s", body)
	}
	rest := body[i+len(key):]
	n, err := strconv.Atoi(rest[:strings.Index(rest, `"`)])
	if err != nil {
		t.Fatalf("dial port parse: %v", err)
	}
	return n
}

// newAdminDoc: one plain-http loopback origin per hostname. The port belongs
// to the HOSTNAME (not the generation) so identical content hashes equal —
// the reload gate in these tests is exercised deliberately.
func newAdminDoc(gen int64, hostnames ...string) snapshot.Document {
	domains := make([]snapshot.Domain, 0, len(hostnames))
	for _, h := range hostnames {
		domains = append(domains, snapshot.Domain{
			Hostname: h,
			Origin: snapshot.Origin{
				Scheme: "http", Address: "127.0.0.1", Port: 30000 + len(domains) + 1,
			},
		})
	}
	return snapshot.Document{
		SchemaVersion:    snapshot.SchemaVersion,
		Generation:       gen,
		BuiltAt:          time.Now().UTC(),
		Domains:          domains,
		AllowedHostnames: hostnames,
		Defaults:         snapshot.Defaults{FirewallMode: "log_only", Cache: true},
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seedArtifact signs doc and writes the envelope as the saved snapshot —
// what a previous boot of this node would have left behind.
func seedArtifact(t *testing.T, dir string, key []byte, doc snapshot.Document) {
	t.Helper()
	env, err := snapshot.Sign(key, doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, snapshotFile), mustMarshal(t, env), 0o600); err != nil {
		t.Fatal(err)
	}
}

// withAdmin wires a fake admin API into the config.
func withAdmin(t *testing.T, cfg Config, admin *httptest.Server) Config {
	t.Helper()
	cfg.CaddyAdmin = strings.TrimPrefix(admin.URL, "http://")
	return cfg
}

func startPollerRaw(t *testing.T, cfg Config) *Poller {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := NewPoller(cfg)
	go func() { _ = p.Run(ctx) }()
	return p
}

// fwdPort (test helper): the forwarder's port for an origin key, or -1.
func (p *Poller) fwdPort(key string) int {
	if p.fwd == nil {
		return -1
	}
	p.fwd.mu.Lock()
	defer p.fwd.mu.Unlock()
	if l, ok := p.fwd.active[key]; ok {
		return l.port
	}
	return -1
}

// ---- tests --------------------------------------------------------------

// Boot from a saved snapshot: caddy receives the generated config exactly
// once — JSON, wired admin addr, one host route, catch-all 421, limits —
// and its dial port is one the forwarder allocated. Identical content (only
// generation/built_at moved) never re-loads; new content does.
func TestApplyBootLoadsGeneratedConfig(t *testing.T) {
	key := makeKey(t)
	token := "node-token-admin"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(newAdminDoc(1, "boothost.a.test"))
	base := fake.serve().URL

	al := &adminLoad{}
	adminSrv := al.serve()
	t.Cleanup(adminSrv.Close)

	dir := t.TempDir()
	seedArtifact(t, dir, key, newAdminDoc(1, "boothost.a.test"))

	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, base, token, key)
	cfg = withAdmin(t, cfg, adminSrv)
	cfg.ReloadCooldown = 30 * time.Millisecond
	p := startPollerRaw(t, cfg)

	until(t, 5*time.Second, "first /load", func() bool { return al.count() == 1 })

	if ct := al.firstContentType(t); ct != "application/json" {
		t.Fatalf("load Content-Type = %q, want application/json", ct)
	}
	body := al.lastBody()
	if got := genBodyListenerOf(t, body); got != cfg.CaddyAdmin {
		t.Fatalf("generated admin.listen = %q, want the wired %q", got, cfg.CaddyAdmin)
	}
	for _, want := range []string{
		"boothost.a.test",           // host route for the snapshot domain
		`"status_code": "421"`,      // catch-all for unknown hosts
		`"max_header_bytes": 16384`, // limits baked in
		`"read_timeout": "60s"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("generated config missing %q:\n%s", want, body)
		}
	}
	dial := genBodyDialPortOf(t, body)
	if key := originKey(snapshot.Origin{Scheme: "http", Address: "127.0.0.1", Port: 30001}); p.fwdPort(key) != dial {
		t.Fatalf("dial port %d is not the forwarder's port for the boot origin", dial)
	}

	// Identical content (new gen, same domains) must NOT reload.
	fake.publishDoc(newAdminDoc(2, "boothost.a.test"))
	time.Sleep(300 * time.Millisecond)
	if n := al.count(); n != 1 {
		t.Fatalf("/load requests = %d, want 1 — identical content must not reload", n)
	}
	if applied := hook.count("applied snapshot"); applied != 2 {
		t.Fatalf("applied lines = %d, want 2 (the snapshot DID move in memory)", applied)
	}

	// New content reloads, under the cooldown.
	fake.publishDoc(newAdminDoc(3, "boothost.a.test", "otherhost.b.test"))
	until(t, 5*time.Second, "second /load after content change", func() bool {
		return al.count() == 2
	})
	if body := al.lastBody(); !strings.Contains(body, "otherhost.b.test") {
		t.Fatalf("second load missing the new host:\n%s", body)
	}
}

// Boot with a saved snapshot must load on the FIRST tick even when the
// configured cooldown is the production 60s. A zero lastLoad opens the gate;
// a cooldown applied at boot would leave a restarted edge serving deny-all
// for a minute.
func TestApplyBootNotDelayedByCooldown(t *testing.T) {
	key := makeKey(t)
	token := "node-token-bootcooldown"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(newAdminDoc(1, "bootfast.a.test"))
	base := fake.serve().URL

	al := &adminLoad{}
	adminSrv := al.serve()
	t.Cleanup(adminSrv.Close)

	dir := t.TempDir()
	seedArtifact(t, dir, key, newAdminDoc(1, "bootfast.a.test"))

	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, base, token, key)
	cfg = withAdmin(t, cfg, adminSrv)
	cfg.ReloadCooldown = 60 * time.Second // production cooldown
	start := time.Now()
	startPollerRaw(t, cfg)

	until(t, 5*time.Second, "first /load after restart", func() bool { return al.count() == 1 })
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("first /load took %v with a saved snapshot and 60s cooldown — boot waited out the cooldown", elapsed)
	}
	if body := al.lastBody(); !strings.Contains(body, "bootfast.a.test") {
		t.Fatalf("boot load missing the saved hostname:\n%s", body)
	}
}

// A→B→A plus B, all inside one cooldown: arrivals collapse into the newest
// pending document; content whose fingerprint equals the RUNNING config
// never reconciles — burst does not touch caddy a second time.
func TestApplyCooldownCollapsesBurst(t *testing.T) {
	key := makeKey(t)
	token := "node-token-flap"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(newAdminDoc(1, "a.test"))
	base := fake.serve().URL

	al := &adminLoad{}
	adminSrv := al.serve()
	t.Cleanup(adminSrv.Close)

	dir := t.TempDir()
	seedArtifact(t, dir, key, newAdminDoc(1, "a.test"))

	hook := &logHook{}
	cfg := newTestCfg(t, hook, dir, base, token, key)
	cfg = withAdmin(t, cfg, adminSrv)
	cfg.ReloadCooldown = 100 * time.Millisecond
	startPollerRaw(t, cfg)

	until(t, 5*time.Second, "boot /load", func() bool { return al.count() == 1 })

	// Immediately (inside the cooldown window) burst B, then A-content again.
	fake.publishDoc(newAdminDoc(2, "b.test"))
	fake.publishDoc(newAdminDoc(3, "a.test"))
	time.Sleep(500 * time.Millisecond)
	if n := al.count(); n != 1 {
		t.Fatalf("/load requests = %d, want 1 — the burst must collapse into the pending set only", n)
	}

	// Then a genuinely different content changes once, after cooldown.
	fake.publishDoc(newAdminDoc(4, "c.test"))
	until(t, 5*time.Second, "post-cooldown /load", func() bool { return al.count() >= 2 })
}

// /load failure: caddy keeps the last-good config (fake 400), the poller
// logs LOUDLY and retries the SAME pending document after the cooldown
// until caddy accepts. Retry cadence stays inside the cooldown window.
func TestApplyFailureKeepsServing(t *testing.T) {
	key := makeKey(t)
	token := "node-token-fail"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(newAdminDoc(1, "failed.a.test"))
	base := fake.serve().URL

	al := &adminLoad{}
	al.rejectNext(http.StatusBadRequest)
	adminSrv := al.serve()
	t.Cleanup(adminSrv.Close)

	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	cfg = withAdmin(t, cfg, adminSrv)
	cfg.ReloadCooldown = 60 * time.Millisecond
	ask := startPoller(t, cfg)

	until(t, 5*time.Second, "first /load (rejected)", func() bool { return al.count() == 1 })
	until(t, 5*time.Second, "loud failure logged", func() bool {
		return hook.count("caddy apply FAILED — keeping the last-good config") >= 1
	})
	if body := al.lastBody(); !strings.Contains(body, "failed.a.test") {
		t.Fatalf("rejected body unexpected:\n%s", body)
	}

	// The retry of the SAME pending doc after the cooldown gets the 200.
	until(t, 5*time.Second, "retry after cooldown accepted", func() bool {
		return al.count() == 2
	})

	// NEW content, caddy rejects again → attempt + cooldown-paced retries
	// (never two within one cooldown), converging once caddy accepts.
	fake.publishDoc(newAdminDoc(5, "failed.a.test", "late.b.test"))
	al.rejectNext(http.StatusBadRequest)
	until(t, 5*time.Second, "third attempt went out", func() bool { return al.count() == 3 })
	until(t, 5*time.Second, "converged retry", func() bool { return al.count() >= 4 })
	time.Sleep(300 * time.Millisecond)
	if n := al.count(); n != 4 {
		t.Fatalf("/load attempts = %d after convergence, want 4 (no retry storm)", n)
	}
	if last := al.lastBody(); !strings.Contains(last, "late.b.test") {
		t.Fatalf("retried config missing the new host:\n%s", last)
	}

	// The ask check reflects the in-memory state the whole time (memory
	// swapped at accept, even when caddy's side was still failing).
	if code := askGet(t, ask, "/check?domain=late.b.test"); code != http.StatusOK {
		t.Fatalf("ask = %d, want 200 (in-memory state is newer than caddy)", code)
	}
}

// Without caddy wiring there is no /load and no forwarder, ever.
func TestNoCaddyNoApply(t *testing.T) {
	key := makeKey(t)
	token := "node-token-nocaddy"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(newAdminDoc(1, "quiet.a.test"))
	base := fake.serve().URL

	admin := &adminLoad{}
	adminSrv := admin.serve()
	t.Cleanup(adminSrv.Close)

	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	p := startPollerRaw(t, cfg)

	until(t, 5*time.Second, "snapshot applied in memory", func() bool {
		return hook.count("applied snapshot") == 1
	})
	time.Sleep(100 * time.Millisecond)
	if n := admin.count(); n != 0 {
		t.Fatalf("admin calls = %d, want 0 (no caddy wired)", n)
	}
	if p.fwd != nil {
		t.Fatal("forwarder created without caddy wiring")
	}
}
