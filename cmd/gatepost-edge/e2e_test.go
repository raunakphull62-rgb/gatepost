package main

// Requirement 5's "real test through the running edge": TestEdgeEndToEnd
// starts a REAL caddy subprocess (the pinned version — GP_TEST_CADDY or
// PATH), the real forwarder, a real fake node API and three real origins
// behind the edge, then drives the flow end to end:
//
//	poll → verify → egress Swap → Generate → POST /load → proxied request
//
// It asserts what the edge actually serves on both listeners: the https
// origin reached through the tunnel with spoofed X-Forwarded-For replaced by
// the real client IP, and unknown hosts answered 421 on both ports (HTTPS
// via the fallback certificate).
//
// Item 3 check 1's origin-TLS evidence lives here too. The https origins
// carry certificates from a throwaway test CA that is mounted into caddy via
// SSL_CERT_FILE (Go's system-cert loading on Linux; the generated transport
// leaves RootCAs nil, so the system pool — and only it — decides):
//
//   - vault: a CA-signed cert for "localhost", the CONFIGURED origin address.
//     The edge must verify it with SNI pinned to that same name and actually
//     reach the origin — no insecure_skip_verify anywhere in the config.
//   - impostor: a CA-signed cert for someone-else.test. Same trust chain,
//     same SNI; only the name on the cert is wrong. Verification must refuse
//     the handshake: the edge answers 502 and the impostor's handler NEVER
//     runs. That refusal is the proof verification is real — with
//     insecure_skip_verify the connection would have succeeded.
//
// The origin-verification requests ride the HTTP listener: on the HTTPS one,
// a known hostname now triggers on-demand issuance (real ACME — cannot
// succeed on a test box), so it is reserved for the unknown-SNI fallback
// check. Skipped on machines without a caddy binary; regress.sh sets
// GP_TEST_CADDY so it runs there.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
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

// makeTestCA: a throwaway CA for the e2e's origin certificates. Its PEM is
// all caddy gets beyond the system roots (SSL_CERT_FILE).
func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gatepost e2e origin CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ca parse: %v", err)
	}
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// leafCert: one server certificate for name, signed by the test CA, carrying
// the chain caddy has to verify.
func leafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("leaf cert for %s: %v", name, err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
}

type originEcho struct {
	mu   sync.Mutex
	seen []string
	snis []string // ClientHello server names, recorded even on failed handshakes
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

func (o *originEcho) noteSNI(s string) {
	o.mu.Lock()
	o.snis = append(o.snis, s)
	o.mu.Unlock()
}

func (o *originEcho) lastSNI() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.snis) == 0 {
		return ""
	}
	return o.snis[len(o.snis)-1]
}

// newTLSOrigin: an https origin on 127.0.0.1 serving cert, recording the
// server name of every ClientHello — the SNI the edge actually sent.
func newTLSOrigin(t *testing.T, cert tls.Certificate, o *originEcho) string {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		o.noteSNI(chi.ServerName)
		return cfg, nil
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(o.serveHTTP),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tls origin listen: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	return ln.Addr().String()
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
	httpAddr := strings.TrimPrefix(httpSrv.URL, "http://")

	// The https origins are named "localhost" — the address the snapshot
	// configures, so it is both the SNI caddy must send and the name the
	// vault certificate carries. The impostor's cert carries a different
	// name: same CA, same SNI, verification must still refuse it.
	ca, caKey, caPEM := makeTestCA(t)
	vaultOrigin := &originEcho{}
	vaultAddr := newTLSOrigin(t, leafCert(t, ca, caKey, "localhost"), vaultOrigin)
	impostorOrigin := &originEcho{}
	impostorAddr := newTLSOrigin(t, leafCert(t, ca, caKey, "someone-else.test"), impostorOrigin)

	// --- the snapshot serving those origins ---------------------------------
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
					Scheme: "https", Address: "localhost", Port: portOf(t, vaultAddr),
					TLSVerify: true, // the edge verifies: CA-signed cert, SNI = this address
				},
			},
			{
				Hostname: "impostor.example.test",
				Origin: snapshot.Origin{
					Scheme: "https", Address: "localhost", Port: portOf(t, impostorAddr),
					TLSVerify: true,
				},
			},
		},
	})
	base := fake.serve().URL

	// --- caddy subprocess on a deny-all bootstrap config --------------------
	caFile := filepath.Join(t.TempDir(), "origin-ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	ec := startEdgeCaddy(t,
		"SSL_CERT_FILE="+caFile, // the only extra root caddy's ORIGIN TLS trusts
	)

	// The bootstrap config already enforces the deny-all posture.
	client := &http.Client{Transport: edgeTransport(&tls.Config{InsecureSkipVerify: true})}
	if code := edgeStatus(t, client, ec.httpPort, "anything.example.test"); code != http.StatusMisdirectedRequest {
		ec.fail(fmt.Sprintf("before any snapshot: unknown host = %d, want 421", code))
	}

	// --- the poller takes over --------------------------------------------
	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	cfg.CaddyAdmin = ec.admin
	cfg.CaddyHTTP = net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpPort))
	cfg.CaddyHTTPS = net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpsPort))
	cfg.ReloadCooldown = 50 * time.Millisecond
	cfg.AllowLoopback = true // TEST ONLY: the origins of this test are loopback
	startPoller(t, cfg)
	until(t, 15*time.Second, "caddy /load of the snapshot", func() bool {
		return hook.count("applied snapshot") >= 1
	})

	// Through the edge, plain http origin: caddy replaced the spoofed
	// X-Forwarded-For with the real client IP (127.0.0.1, no proxies trusted).
	until(t, 15*time.Second, "proxied to the http origin", func() bool {
		return edgeStatus(t, client, ec.httpPort, "shop.example.test") == http.StatusOK
	})
	if last := httpOrigin.last(); !strings.Contains(last, "host=shop.example.test") ||
		!strings.Contains(last, "xff=127.0.0.1") {
		ec.fail("http origin saw " + last + " (want host=shop.example.test xff=127.0.0.1 …)")
	}
	if _, body := edgeDo(t, client, ec.httpPort, false, "shop.example.test", "9.9.9.9"); strings.Contains(body, "9.9.9.9") {
		ec.fail("spoofed X-Forwarded-For SURVIVED the edge: " + body)
	}

	// Through the edge, https origin via the forwarder's tunnel: the
	// CA-signed cert for the configured origin address VERIFIES (SSL_CERT_FILE
	// is the only extra root), and the SNI the origin saw is that same
	// configured address — not the tunnel's dial address, not the public
	// hostname.
	until(t, 15*time.Second, "proxied to the https origin", func() bool {
		return edgeStatus(t, client, ec.httpPort, "vault.example.test") == http.StatusOK
	})
	if last := vaultOrigin.last(); !strings.Contains(last, "host=vault.example.test") ||
		!strings.Contains(last, "xff=127.0.0.1") {
		ec.fail("https origin saw " + last)
	}
	if s := vaultOrigin.lastSNI(); s != "localhost" {
		ec.fail("https origin handshake SNI = " + s + ", want localhost (the configured origin address)")
	}

	// The impostor: same CA, same SNI, wrong name on the certificate. The
	// edge must REFUSE the TLS handshake (502 to the client) and the
	// impostor's handler must never run — the certificate did not verify.
	// With insecure_skip_verify this request would have connected.
	if code, body := edgeDo(t, client, ec.httpPort, false, "impostor.example.test", ""); code != http.StatusBadGateway {
		ec.fail(fmt.Sprintf("wrong-name origin = %d %q, want 502 (origin certificate must not verify)", code, body))
	}
	if s := impostorOrigin.lastSNI(); s != "localhost" {
		ec.fail("impostor handshake SNI = " + s + ", want localhost (the refusal is the cert name, not the SNI)")
	}
	if last := impostorOrigin.last(); last != "" {
		ec.fail("the unverified origin was REACHED: " + last)
	}

	// Unknown hosts → 421 from Caddy itself, on both ports. The https one
	// completes its TLS handshake with the fallback certificate first.
	if code := edgeStatus(t, client, ec.httpPort, "unknown.example.test"); code != http.StatusMisdirectedRequest {
		ec.fail(fmt.Sprintf("unknown host over http = %d, want 421", code))
	}
	if code := edgeStatusTLS(t, client, ec.httpsPort, true, "unknown.example.test"); code != http.StatusMisdirectedRequest {
		ec.fail(fmt.Sprintf("unknown host over https = %d, want 421 (fallback cert)", code))
	}
}

// edgeDo: one request THROUGH the running edge (loopback port), Host set to
// the virtual hostname, optional spoofed XFF in. On the TLS port the URL
// carries the virtual hostname — SNI and (for verifying clients) certificate
// checks follow it — so the client's transport must rewrite the dial to the
// loopback listener (edgeTransport does).
func edgeDo(t *testing.T, client *http.Client, port int, tlsPort bool, host, xff string) (int, string) {
	t.Helper()
	url := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/"
	if tlsPort {
		url = "https://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	}
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

// edgeTransport: an http.Transport whose dial is rewritten to the edge's
// loopback listener, so the URL may carry the virtual hostname (SNI,
// certificate verification) while the connection goes to 127.0.0.1.
func edgeTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			return (&net.Dialer{Timeout: 5 * time.Second}).
				DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}
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

// startEdgeCaddy boots a REAL caddy subprocess on a fresh deny-all bootstrap
// config (fresh ports, state under its own temp dir so certs and the local
// CA never touch the machine) and waits for its admin API. extraEnv lines
// are appended to its environment (the origin-TLS test mounts its CA via
// SSL_CERT_FILE).
type edgeCaddy struct {
	admin     string
	httpPort  int
	httpsPort int
	dataDir   string // XDG_DATA_HOME: caddy's local CA and issued certs
	logPath   string // caddy's captured stderr (runtime +, unguarded, access twins)
	fail      func(what string)
}

func startEdgeCaddy(t *testing.T, extraEnv ...string) edgeCaddy {
	t.Helper()
	ec := edgeCaddy{
		httpPort:  freePort(t),
		httpsPort: freePort(t),
		admin:     net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))),
	}

	tmp := t.TempDir()
	ec.dataDir = filepath.Join(tmp, "data")
	boot, err := Generate(nil, CaddyParams{
		HTTPAddr:  net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpPort)),
		HTTPSAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpsPort)),
		AdminAddr: ec.admin,
	})
	if err != nil {
		t.Fatalf("generate bootstrap: %v", err)
	}
	bootPath := filepath.Join(tmp, "bootstrap.json")
	if err := os.WriteFile(bootPath, boot, 0o644); err != nil {
		t.Fatal(err)
	}
	caddyLog := filepath.Join(tmp, "caddy.log")
	ec.logPath = caddyLog
	logf, err := os.Create(caddyLog)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logf.Close() })

	cmd := exec.Command(caddyBin(), "run", "--config", bootPath)
	cmd.Env = append(os.Environ(),
		"XDG_DATA_HOME="+ec.dataDir, // certs incl. local CA stay in the test's dir
		"XDG_CONFIG_HOME="+filepath.Join(tmp, "config"),
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	ec.fail = func(what string) {
		b, _ := os.ReadFile(caddyLog)
		t.Fatalf("%s (caddy log:\n%s)", what, b)
	}
	until(t, 10*time.Second, "caddy admin API", func() bool {
		resp, err := http.Get("http://" + ec.admin + "/config/")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode == http.StatusOK
	})
	return ec
}

// storedCertPaths: caddy's on-disk certificate paths whose file name carries
// the given hostname. Issuance persists there; a denial leaves nothing.
func (ec edgeCaddy) storedCertPaths(name string) []string {
	var hits []string
	_ = filepath.WalkDir(ec.dataDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(filepath.Base(p), name) {
			hits = append(hits, p)
		}
		return nil
	})
	return hits
}

// TestEdgeOnDemandTLS — item 4's evidence with a REAL caddy: a certificate
// is issued only when the poller's loopback ask answers 200 for a hostname in
// the APPLIED snapshot, and only up to the per-node hourly cap (unit-tested;
// not exercised here). The issuer is GP_EDGE_ISSUER's — internal for this
// test, so issuance is instant and no ACME is involved. The client VERIFIES
// against caddy's own local CA root (the fallback cert, edge.invalid, is
// signed by it too — but it is valid for edge.invalid only), so a completed,
// verified request can only ride a certificate minted FOR that host:
//
//   - live.example.test: in the applied snapshot, ask 200 → certificate
//     ISSUED from caddy's internal CA, persisted under XDG_DATA_HOME →
//     verified handshake → origin reached.
//   - doomed.example.test: still a subject of the config caddy RUNS (the 60s
//     reload cooldown deliberately holds caddy one generation back) but the
//     ask answers 421 — the applied snapshot dropped it. Caddy 2.11.7 then
//     ABORTS the handshake (remote error: tls internal error): no HTTP
//     response, no certificate minted, nothing persisted. A verifying
//     client never sees the fallback cert here — an aborted handshake has
//     no certificate to verify at all.
//   - late.example.test: allowed by the snapshot, but the ask listener is
//     GONE → no answer is a denial → same abort, nothing persisted.
func TestEdgeOnDemandTLS(t *testing.T) {
	caddyPath := caddyBin()
	if _, err := exec.LookPath(caddyPath); err != nil {
		t.Skipf("no caddy binary at %q (set GP_TEST_CADDY): %v", caddyPath, err)
	}

	origin := &originEcho{}
	originSrv := httptest.NewServer(http.HandlerFunc(origin.serveHTTP))
	t.Cleanup(originSrv.Close)
	originAddr := strings.TrimPrefix(originSrv.URL, "http://")
	doc := func(gen int64, hosts ...string) snapshot.Document {
		doms := make([]snapshot.Domain, 0, len(hosts))
		for _, h := range hosts {
			doms = append(doms, snapshot.Domain{Hostname: h, Origin: snapshot.Origin{
				Scheme: "http", Address: hostOf(originAddr), Port: portOf(t, originAddr),
			}})
		}
		return snapshot.Document{
			SchemaVersion: snapshot.SchemaVersion, Generation: gen,
			BuiltAt: time.Now().UTC(), Domains: doms, AllowedHostnames: hosts,
		}
	}

	ec := startEdgeCaddy(t)

	key := makeKey(t)
	token := "node-token-ondemand"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(doc(1, "live.example.test", "doomed.example.test", "late.example.test"))
	base := fake.serve().URL

	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), base, token, key)
	cfg.CaddyAdmin = ec.admin
	cfg.CaddyHTTP = net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpPort))
	cfg.CaddyHTTPS = net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpsPort))
	cfg.ReloadCooldown = 60 * time.Second // hold caddy one generation back on purpose
	cfg.Issuer = issuerInternal           // instant local issuance; no ACME here
	cfg.AllowLoopback = true              // TEST ONLY: the origin of this test is loopback
	ask := startPoller(t, cfg)
	until(t, 15*time.Second, "caddy /load of the snapshot", func() bool {
		return hook.count("applied snapshot") >= 1
	})

	// A client that VERIFIES against caddy's own local CA root. The root
	// appears when caddy first issues (the bootstrap /load mints the fallback
	// cert with it), so it is there by the time we read it.
	rootPath := filepath.Join(ec.dataDir, "caddy", "pki", "authorities", "local", "root.crt")
	until(t, 5*time.Second, "caddy local CA root", func() bool {
		_, err := os.Stat(rootPath)
		return err == nil
	})
	rootPEM, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read caddy root: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("caddy root is not a PEM certificate")
	}
	client := &http.Client{Transport: edgeTransport(&tls.Config{RootCAs: roots})}

	// Allowed: ask 200 → on-demand certificate issued → the handshake
	// VERIFIES (the fallback cert never would) → origin reached.
	deadline := time.Now().Add(15 * time.Second)
	for {
		code, body := edgeDo(t, client, ec.httpsPort, true, "live.example.test", "")
		if code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			ec.fail(fmt.Sprintf("on-demand handshake for live.example.test = %d %q", code, body))
		}
		time.Sleep(20 * time.Millisecond)
	}
	if last := origin.last(); !strings.Contains(last, "host=live.example.test") {
		ec.fail("allowed host completed verified TLS but the origin saw " + last)
	}
	if got := ec.storedCertPaths("live.example.test"); len(got) == 0 {
		ec.fail("no certificate for live.example.test in caddy's storage — it was never issued")
	}

	// Denied: dropped from the applied snapshot while caddy still lists it
	// as an on-demand subject → ask 421 → caddy ABORTS the handshake: no
	// HTTP response (code 0), no certificate, nothing persisted. A status
	// (200 or 421) would mean the handshake completed — only a certificate
	// minted for the name, i.e. an ask approval, could do that.
	fake.publishDoc(doc(2, "live.example.test", "late.example.test"))
	until(t, 5*time.Second, "ask denies the dropped host", func() bool {
		return askGet(t, ask, "/check?domain=doomed.example.test") == http.StatusMisdirectedRequest
	})
	if code, body := edgeDo(t, client, ec.httpsPort, true, "doomed.example.test", ""); code != 0 {
		ec.fail(fmt.Sprintf("denied host over https = %d %q, want the handshake aborted", code, body))
	}
	if got := ec.storedCertPaths("doomed.example.test"); len(got) > 0 {
		ec.fail(fmt.Sprintf("a certificate was issued for the DENIED host: %v", got))
	}

	// Ask unreachable: allowed host, but nobody answers the ask → no answer
	// is a denial → same abort, nothing persisted.
	_ = cfg.AskLn.Close()
	if code, body := edgeDo(t, client, ec.httpsPort, true, "late.example.test", ""); code != 0 {
		ec.fail(fmt.Sprintf("host with a dead ask over https = %d %q, want the handshake aborted", code, body))
	}
	if got := ec.storedCertPaths("late.example.test"); len(got) > 0 {
		ec.fail(fmt.Sprintf("a certificate was issued while the ask was unreachable: %v", got))
	}
}

// secret values a request may carry; the access log must contain NONE of
// them (values AND header names, under ANY name — headers are not logged at
// all, and no query string survives anywhere).
const (
	secretAuth      = "Bearer tr0ub4dor-SUPERSECRET-AUTH"
	secretCookie    = "session=TOPSECRET-COOKIE-VALUE"
	secretSetCookie = "dough=CLASSIFIED-SET-COOKIE"
	secretAPIKey    = "KEY-CLASSIFIED-API-9999"
	secretReferer   = "http://tracker.example.test/r?sid=REFSECRET-42"
	forgedPayload   = `{"level":"critical","msg":"forged-line"}` // log-injection attempt
	testUA          = "gatepost-e2e-ua/1.0"
	// the query the user's item-6 correction pins: neither value may appear.
	queryToken = "SECRET123"
	queryCode  = "abc"
)

// TestEdgeAccessLogs — item 6's evidence with a REAL caddy: the applied
// config's logging app writes ONE json line per request to
// cfg.CaddyAccessLog (the file writer even creates its nested directory),
// and NO header or query ever reaches the file. Proven here:
//
//   - neither the secret VALUES (Authorization, Cookie, X-Api-Key, Referer,
//     Set-Cookie, the ?token=SECRET123&code=abc query) nor their header NAMES
//     appear anywhere in the file, under any field name;
//   - the request>uri field (caddy's native query carrier) and the whole
//     request>headers / resp_headers objects are ABSENT from every line —
//     structurally gone, not masked;
//   - a path percent-encoding a newline plus a whole forged `{"level":...}`
//     payload stays ONE JSON string inside ONE physical line (zap escapes it;
//     no line can be forged, the line count does not grow);
//   - every kept field is present and shaped: request_id (caddy's uuid,
//     distinct per request), path WITHOUT the query, user_agent (the one
//     header item 6 keeps), origin (the vars-stamped identity, "-" on the
//     421 catch-all), and the native ts/status/size/duration/host/method/
//     remote_ip.
func TestEdgeAccessLogs(t *testing.T) {
	caddyPath := caddyBin()
	if _, err := exec.LookPath(caddyPath); err != nil {
		t.Skipf("no caddy binary at %q (set GP_TEST_CADDY): %v", caddyPath, err)
	}

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", secretSetCookie) // the response side the filter must also delete
		_, _ = w.Write([]byte("origin-ok"))
	}))
	t.Cleanup(origin.Close)
	originAddr := strings.TrimPrefix(origin.URL, "http://")
	host := "www.accesstest.test"

	ec := startEdgeCaddy(t)
	key := makeKey(t)
	token := "node-token-accesslogs"
	fake := newFakeAPI(t, key, token)
	fake.publishDoc(snapshot.Document{
		SchemaVersion: snapshot.SchemaVersion,
		Generation:    1,
		BuiltAt:       time.Now().UTC(),
		Domains: []snapshot.Domain{{
			Hostname: host,
			Origin:   snapshot.Origin{Scheme: "http", Address: hostOf(originAddr), Port: portOf(t, originAddr)},
		}},
		AllowedHostnames: []string{host},
	})

	hook := &logHook{}
	cfg := newTestCfg(t, hook, t.TempDir(), fake.serve().URL, token, key)
	cfg.CaddyAdmin = ec.admin
	cfg.CaddyHTTP = net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpPort))
	cfg.CaddyHTTPS = net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpsPort))
	cfg.CaddyAccessLog = filepath.Join(t.TempDir(), "logs", "nested", "access.json") // writer must MkdirAll
	cfg.Issuer = issuerInternal
	cfg.AllowLoopback = true // TEST ONLY: the origin of this test is loopback
	startPoller(t, cfg)
	// Caddy's /load swap is atomic but ASYNC relative to the poller's
	// success line (TestEdgeOnDemandTLS hits the same race). The right wait
	// is caddy's own live config: the logged route must be there before any
	// request — every request from here on is logged, and the line-count
	// assertion below depends on there being exactly one per request.
	until(t, 15*time.Second, "caddy live config carries the logged route", func() bool {
		live, err := http.Get("http://" + ec.admin + "/config/")
		if err != nil {
			return false
		}
		lb, err := io.ReadAll(io.LimitReader(live.Body, 1<<20))
		_ = live.Body.Close()
		return err == nil &&
			strings.Contains(string(lb), host) &&
			strings.Contains(string(lb), filepath.Base(cfg.CaddyAccessLog))
	})

	client := &http.Client{Timeout: 5 * time.Second}
	proxy := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(ec.httpPort))

	// 1) A well-behaved request carrying every hostile input at once: the
	//    correction's query (?token=SECRET123&code=abc), all four
	//    credential-bearing headers, and a Referer — none of which may
	//    reach the log. The fixed User-Agent is the one header value that
	//    MUST appear (as the appended user_agent field).
	req, err := http.NewRequest(http.MethodGet, proxy+"/docs?token="+queryToken+"&code="+queryCode, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	req.Header.Set("User-Agent", testUA)
	req.Header.Set("Authorization", secretAuth)
	req.Header.Set("Cookie", secretCookie)
	req.Header.Set("X-Api-Key", secretAPIKey)
	req.Header.Set("Referer", secretReferer)
	resp, err := client.Do(req)
	if err != nil {
		ec.fail("proxied request: " + err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		ec.fail(fmt.Sprintf("proxied request = %d, want 200", resp.StatusCode))
	}
	_ = resp.Body.Close()

	// 2) The injection attempt: a newline plus a complete forged log line,
	//    percent-encoded so the request line itself stays legal. Caddy
	//    decodes it into the path it logs; the JSON encoder must keep it
	//    trapped inside that one string value on one physical line.
	evil, err := http.NewRequest(http.MethodGet,
		proxy+"/p/%0A%7B%22level%22%3A%22critical%22%2C%22msg%22%3A%22forged-line%22%7D?q=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	evil.Host = host
	resp, err = client.Do(evil)
	if err != nil {
		ec.fail("hostile path request: " + err.Error())
	}
	_ = resp.Body.Close()

	// 3) An unknown Host: the catch-all 421, logged with origin "-".
	if code, _ := edgeDo(t, client, ec.httpPort, false, "stranger.example.test", ""); code != http.StatusMisdirectedRequest {
		ec.fail(fmt.Sprintf("unknown host = %d, want 421", code))
	}

	// Wait for the log writer to flush exactly 3 lines (3 requests = 3 lines).
	// Caddy's access log is async; polling avoids the flaky immediate read.
	var raw string
	until(t, 10*time.Second, "access log has exactly 3 lines", func() bool {
		b, err := os.ReadFile(cfg.CaddyAccessLog)
		if err != nil {
			return false
		}
		raw = string(b)
		rows := strings.Split(strings.TrimRight(raw, "\n"), "\n")
		return len(rows) == 3
	})
	rows := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	// The secrets are gone — values AND header names, the correction's two
	// query values, the injected payload's level too ("info" is the only
	// level these requests produce).
	for _, poison := range []string{
		secretAuth, secretCookie, secretSetCookie, secretAPIKey, secretReferer,
		queryToken, "code=" + queryCode, "token=", "q=1",
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key", "Referer",
		`"level":"critical"`,
	} {
		if strings.Contains(raw, poison) {
			ec.fail(fmt.Sprintf("access log leaks %q:\n%s", poison, raw))
		}
	}

	var lines []map[string]any
	for i, row := range rows {
		m := map[string]any{}
		if err := json.Unmarshal([]byte(row), &m); err != nil {
			ec.fail(fmt.Sprintf("access-log line %d is not ONE valid json object: %v\n%s", i+1, err, row))
		}
		lines = append(lines, m)
	}
	serving, injected, refused := lines[0], lines[1], lines[2]

	get := func(m map[string]any, key string) any {
		v, ok := m[key]
		if !ok {
			ec.fail(fmt.Sprintf("access line lacks %q: %v", key, m))
		}
		return v
	}
	str := func(m map[string]any, key, why string) string {
		s, ok := get(m, key).(string)
		if !ok || s == "" {
			ec.fail(fmt.Sprintf("access line %s is absent/empty: %v (%s)", key, m, why))
		}
		return s
	}
	// The fields item 6 promises, on the served line: time (caddy ts),
	// status/size/duration/remote_ip native, and the three appended ones.
	_ = get(serving, "ts").(float64)
	if v, _ := get(serving, "status").(float64); v != 200 {
		ec.fail(fmt.Sprintf("served line status = %v, want 200", serving["status"]))
	}
	if _, ok := serving["size"].(float64); !ok {
		ec.fail("served line has no size")
	}
	if _, ok := serving["duration"].(float64); !ok {
		ec.fail("served line has no duration")
	}
	if ip, _ := get(serving, "request").(map[string]any); ip["remote_ip"] != "127.0.0.1" {
		ec.fail(fmt.Sprintf("served line client ip = %v, want 127.0.0.1", ip["remote_ip"]))
	}
	if ip, _ := serving["request"].(map[string]any); ip["method"] != "GET" || ip["host"] != host {
		ec.fail(fmt.Sprintf("served line method/host = %v/%v, want GET/%s", ip["method"], ip["host"], host))
	}
	if m := str(serving, "request_id", "appended"); !strings.Contains(m, "-") {
		ec.fail("request_id is not a uuid-shaped string: " + m)
	}
	wantOrigin := "http://" + originAddr // originKey of the snapshot's origin
	if got := str(serving, "origin", "appended"); got != wantOrigin {
		ec.fail(fmt.Sprintf("served line origin = %q, want %q", got, wantOrigin))
	}
	// path: no query — neither query value may ride ANY field; caddy's
	// native request>uri (the query's only carrier) is deleted by the
	// filter, and the appended path is the query-free form.
	if p := serving["path"]; p != "/docs" {
		ec.fail(fmt.Sprintf("served line path = %v, want /docs (no query)", p))
	}
	if got := str(serving, "user_agent", "the one header value item 6 keeps"); got != testUA {
		ec.fail(fmt.Sprintf("served line user_agent = %q, want %q", got, testUA))
	}

	// The injected path: still exactly one line, its newline escaped; status
	// is the proxied 200 and the request_id differs from the first request
	// (caddy's per-request uuid really is per-request).
	if v, _ := get(injected, "status").(float64); v != 200 {
		ec.fail(fmt.Sprintf("injected line status = %v, want 200", injected["status"]))
	}
	if p, _ := injected["path"].(string); !strings.HasPrefix(p, "/p/\n") {
		ec.fail(fmt.Sprintf("injected line path = %q, want the decoded newline kept INSIDE the string", p))
	}
	if str(injected, "request_id", "appended") == str(serving, "request_id", "appended") {
		ec.fail("request_id collided between two requests")
	}

	// No header logging AT ALL and no query carrier, under any name: every
	// line's request object lacks `headers` and `uri`, and no line carries
	// resp_headers — deleted whole by the filter, not masked.
	for i, m := range lines {
		reqm, _ := m["request"].(map[string]any)
		for _, gone := range []string{"headers", "uri"} {
			if _, ok := reqm[gone]; ok {
				ec.fail(fmt.Sprintf("access line %d still carries request>%s — it must be deleted whole:\n%v", i+1, gone, m))
			}
		}
		if _, ok := m["resp_headers"]; ok {
			ec.fail(fmt.Sprintf("access line %d still carries resp_headers:\n%v", i+1, m))
		}
	}

	// The short query value gets the strictest sweep: everything logged here
	// is deterministic EXCEPT caddy's random uuids, so scrub the
	// request_ids first — "abc" anywhere else would be a real leak.
	scrubbed := raw
	for _, m := range lines {
		if id, ok := m["request_id"].(string); ok {
			scrubbed = strings.ReplaceAll(scrubbed, id, "")
		}
	}
	if strings.Contains(scrubbed, queryCode) {
		ec.fail(fmt.Sprintf("access log leaks the query value %q:\n%s", queryCode, raw))
	}

	// The stderr twin must be DEAD: caddy tees every access entry to the
	// default (stderr) logger as well — the file was clean while the
	// container log still carried every query string and header (probed
	// against 2.11.7). The generated config redefines "default" with an
	// exclude, so not one access entry may appear on stderr.
	stderr, err := os.ReadFile(ec.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stderr), `"msg":"handled request"`) {
		ec.fail(fmt.Sprintf("access entries leaked to caddy's stderr (the container log):\n%s", stderr))
	}

	// Catch-all: 421, origin "-" (no origin reached), and the same shape.
	if v, _ := get(refused, "status").(float64); v != 421 {
		ec.fail(fmt.Sprintf("catch-all line status = %v, want 421", refused["status"]))
	}
	if got := refused["origin"]; got != "-" {
		ec.fail(fmt.Sprintf("catch-all origin = %v, want \"-\"", got))
	}
	// edgeDo's client sends Go's default User-Agent, so presence — not the
	// value — is what the catch-all chain proves here.
	_ = str(refused, "user_agent", "appended on the catch-all chain too")
	if h, _ := refused["request"].(map[string]any); h["host"] != "stranger.example.test" {
		ec.fail(fmt.Sprintf("catch-all line host = %v, want stranger.example.test", h["host"]))
	}
}
