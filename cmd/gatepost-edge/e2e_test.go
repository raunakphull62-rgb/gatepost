package main

// Requirement 5's "real test through the running edge": TestEdgeEndToEnd
// starts a REAL caddy subprocess (the pinned version — GP_TEST_CADDY or
// PATH), the real forwarder, a real fake node API and two real origins
// behind the edge, then drives the flow end to end:
//
//	poll → verify → egress Swap → Generate → POST /load → proxied request
//
// It asserts what the edge actually serves on both listeners: the https
// origin reached through the tunnel, spoofed X-Forwarded-For replaced by
// the real client IP, and unknown hosts answered 421 on both ports (HTTPS
// via the fallback certificate). Skipped on machines without a caddy
// binary; regress.sh sets GP_TEST_CADDY so it runs there.

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gatepost/internal/snapshot"
)

// caddyBin: the caddy executable to use (GP_TEST_CADDY first, then PATH).
func caddyBin() string {
	if v := strings.TrimSpace(os.Getenv("GP_TEST_CADDY")); v != "" {
		return v
	}
	return "caddy"
}

// hostOf / portOf split an "ip:port" origin address into its parts.
func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("origin addr %q: %v", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("origin addr %q: %v", addr, err)
	}
	return n
}

// freePort: an ephemeral port a listener leases; the record of assigned
// ports is this test's own (it is the only one choosing these).
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("free port close: %v", err)
	}
	return port
}

type originEcho struct {
	mu   sync.Mutex
	seen []string
}

func (o *originEcho) serveHTTP(w http.ResponseWriter, r *http.Request) {
	xff := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if xff == "" {
		xff = "(none)"
	}
	line := fmt.Sprintf("host=%s xff=%s proto=%s", r.Host, xff, r.Proto)
	o.mu.Lock()
	o.seen = append(o.seen, line)
	o.mu.Unlock()
	fmt.Fprintf(w, "edge-ok %s", line)
}

func (o *originEcho) last() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.seen) == 0 {
		return ""
	}
	return o.seen[len(o.seen)-1]
}

func TestEdgeEndToEnd(t *testing.T) {
	caddyPath := caddyBin()
	if _, err := exec.LookPath(caddyPath); err != nil {
		t.Skipf("no caddy binary at %q (set GP_TEST_CADDY): %v", caddyPath, err)
	}

	// --- real origins ------------------------------------------------------
	httpOrigin := &originEcho{}
	httpSrv := httptest.NewServer(http.HandlerFunc(httpOrigin.serveHTTP))
	t.Cleanup(httpSrv.Close)
	httpsOrigin := &originEcho{}
	httpsSrv := httptest.NewTLSServer(http.HandlerFunc(httpsOrigin.serveHTTP))
	t.Cleanup(httpsSrv.Close)
	httpAddr := strings.TrimPrefix(httpSrv.URL, "http://")
	httpsAddr := strings.TrimPrefix(httpsSrv.URL, "https://") // ip:port

	// --- ports + the snapshot serving those origins ------------------------
	httpPort, httpsPort := freePort(t), freePort(t)
	adminAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))

	key := makeKey(t)
	token := "node-token-e2e"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(snapshot.Document{
		SchemaVersion: snapshot.SchemaVersion,
		Generation:    1,
		BuiltAt:       time.Now().UTC(),
		Domains: []snapshot.Domain{
			{
				Hostname: "shop.example.test",
				Origin: snapshot.Origin{
					Scheme: "http", Address: hostOf(httpAddr), Port: portOf(t, httpAddr),
				},
			},
			{
				Hostname: "vault.example.test",
				Origin: snapshot.Origin{
					Scheme: "https", Address: hostOf(httpsAddr), Port: portOf(t, httpsAddr),
					TLSVerify: false, // self-signed origin cert → insecure transport
				},
			},
		},
	})
	base := fake.serve().URL

	// --- caddy subprocess on a deny-all bootstrap config --------------------
	tmp := t.TempDir()
	boot, err := Generate(nil, CaddyParams{
		HTTPAddr:  net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
		HTTPSAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort)),
		AdminAddr: adminAddr,
	})
	if err != nil {
		t.Fatalf("generate bootstrap: %v", err)
	}
	bootPath := filepath.Join(tmp, "bootstrap.json")
	if err := os.WriteFile(bootPath, boot, 0o644); err != nil {
		t.Fatal(err)
	}
	caddyLog := filepath.Join(tmp, "caddy.log")
	logf, err := os.Create(caddyLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logf.Close() })

	caddyCmd := exec.Command(caddyPath, "run", "--config", bootPath)
	caddyCmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+filepath.Join(tmp, "data"), // certs incl. local CA stay in the test's dir
		"XDG_CONFIG_HOME="+filepath.Join(tmp, "config"),
	)
	caddyCmd.Stdout, caddyCmd.Stderr = logf, logf
	if err := caddyCmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		_ = caddyCmd.Process.Kill()
		_ = caddyCmd.Wait()
	})
	caddyFail := func(what string) { // include caddy's log on failures below
		b, _ := os.ReadFile(caddyLog)
		t.Fatalf("%s (caddy log:\n%s)", what, b)
	}

	adminBase := "http://" + adminAddr
	until(t, 10*time.Second, "caddy admin API", func() bool {
		resp, err := http.Get(adminBase + "/config/")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	})

	// The bootstrap config already enforces the deny-all posture.
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if code := edgeStatus(t, client, httpPort, "anything.example.test"); code != http.StatusMisdirectedRequest {
		caddyFail(fmt.Sprintf("before any snapshot: unknown host = %d, want 421", code))
	}

	// --- the poller takes over --------------------------------------------
	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	cfg.CaddyAdmin = adminAddr
	cfg.CaddyHTTP = net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort))
	cfg.CaddyHTTPS = net.JoinHostPort("127.0.0.1", strconv.Itoa(httpsPort))
	cfg.ReloadCooldown = 50 * time.Millisecond
	cfg.AllowLoopback = true // TEST ONLY: the origins of this test are loopback
	startPoller(t, cfg)
	until(t, 15*time.Second, "caddy /load of the snapshot", func() bool {
		return hook.count("applied snapshot") >= 1
	})

	// Through the edge, plain http origin: caddy replaced the spoofed
	// X-Forwarded-For with the real client IP (127.0.0.1, no proxies trusted).
	until(t, 15*time.Second, "proxied to the http origin", func() bool {
		return edgeStatus(t, client, httpPort, "shop.example.test") == http.StatusOK
	})
	if last := httpOrigin.last(); !strings.Contains(last, "host=shop.example.test") ||
		!strings.Contains(last, "xff=127.0.0.1") {
		caddyFail("http origin saw " + last + " (want host=shop.example.test xff=127.0.0.1 …)")
	}
	if _, body := edgeDo(t, client, httpPort, false, "shop.example.test", "9.9.9.9"); strings.Contains(body, "9.9.9.9") {
		caddyFail("spoofed X-Forwarded-For SURVIVED the edge: " + body)
	}

	// Through the edge, https origin via the forwarder's tunnel.
	until(t, 15*time.Second, "proxied to the https origin", func() bool {
		return edgeStatusTLS(t, client, httpsPort, true, "vault.example.test") == http.StatusOK
	})
	if last := httpsOrigin.last(); !strings.Contains(last, "host=vault.example.test") ||
		!strings.Contains(last, "xff=127.0.0.1") {
		caddyFail("https origin saw " + last)
	}

	// Unknown hosts → 421 from Caddy itself, on both ports. The https one
	// completes its TLS handshake with the fallback certificate first.
	if code := edgeStatus(t, client, httpPort, "unknown.example.test"); code != http.StatusMisdirectedRequest {
		caddyFail(fmt.Sprintf("unknown host over http = %d, want 421", code))
	}
	if code := edgeStatusTLS(t, client, httpsPort, true, "unknown.example.test"); code != http.StatusMisdirectedRequest {
		caddyFail(fmt.Sprintf("unknown host over https = %d, want 421 (fallback cert)", code))
	}
}

// edgeDo: one request THROUGH the running edge (loopback port), Host set to
// the virtual hostname, optional spoofed XFF in.
func edgeDo(t *testing.T, client *http.Client, port int, tlsPort bool, host, xff string) (int, string) {
	t.Helper()
	scheme := "http"
	if tlsPort {
		scheme = "https"
	}
	url := scheme + "://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "network error: " + err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	return resp.StatusCode, string(b)
}

func edgeStatus(t *testing.T, client *http.Client, port int, host string) int {
	t.Helper()
	return edgeStatusTLS(t, client, port, false, host)
}

func edgeStatusTLS(t *testing.T, client *http.Client, port int, tlsPort bool, host string) int {
	t.Helper()
	for i := 0; i < 10; i++ {
		if code, _ := edgeDo(t, client, port, tlsPort, host, ""); code != 0 {
			return code
		}
		time.Sleep(5 * time.Millisecond)
	}
	return 0
}
