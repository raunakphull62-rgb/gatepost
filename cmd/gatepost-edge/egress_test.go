package main

// Tests for the egress forwarder (B3b item 3). The guard matrix proves the
// dial-time rule with a fake resolver + fake dialer: every resolved IP must
// pass domains.CheckIP before it can reach the dialer, and only validated
// addresses are dialed — by the address, not the name. The swap test runs
// REAL listeners to pin the port lifecycle; the pipe test proves an actual
// round trip through the tunnel.

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gatepost/internal/snapshot"
)

// deadConn: net.Conn whose reads end immediately and whose writes are
// discarded — the "origin side" the pipe pumps into.
type deadConn struct{}

func (deadConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (deadConn) Write(b []byte) (int, error)        { return len(b), nil }
func (deadConn) Close() error                       { return nil }
func (deadConn) LocalAddr() net.Addr                { return nil }
func (deadConn) RemoteAddr() net.Addr               { return nil }
func (deadConn) SetDeadline(t time.Time) error      { return nil }
func (deadConn) SetReadDeadline(t time.Time) error  { return nil }
func (deadConn) SetWriteDeadline(t time.Time) error { return nil }

type dialSpy struct {
	mu    sync.Mutex
	addrs []string
}

func (s *dialSpy) rec(addr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addrs = append(s.addrs, addr)
	return nil
}

func (s *dialSpy) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.addrs...)
}

// TestEgressGuardDialsOnlyAllowedIPs: the dialer sees ONLY addresses that
// passed domains.CheckIP (allowLoopback waives exactly the loopback range —
// and nothing when false). Every forbidden IP is refused with a warning; a
// host with no allowed IP closes the proxied connection (fail closed).
func TestEgressGuardDialsOnlyAllowedIPs(t *testing.T) {
	origin := snapshot.Origin{Scheme: "https", Address: "flip.example.com", Port: 443}
	mkIPs := func(strs ...string) func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return func(context.Context, string) ([]net.IPAddr, error) {
			out := make([]net.IPAddr, 0, len(strs))
			for _, s := range strs {
				out = append(out, net.IPAddr{IP: net.ParseIP(s)})
			}
			return out, nil
		}
	}

	cases := []struct {
		name          string
		ips           []string
		allowLoopback bool
		wantDial      []string
	}{
		{"skips loopback/private/metadata", []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "8.8.8.8"},
			false, []string{"8.8.8.8:443"}},
		{"loopback hook allows exactly 127/8", []string{"127.0.0.1", "10.0.0.5", "169.254.169.254", "8.8.8.8"},
			true, []string{"127.0.0.1:443"}},
		{"v6 loopback under the hook", []string{"::1", "fe80::1"},
			true, []string{"[::1]:443"}},
		{"all forbidden → dialer never fires", []string{"169.254.169.254", "10.0.0.5"},
			false, nil},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			hook := &logHook{}
			spy := &dialSpy{}
			f := &forwarder{
				allowLoopback: tc.allowLoopback,
				resolve:       mkIPs(tc.ips...),
				dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if err := spy.rec(addr); err != nil {
						return nil, err
					}
					return deadConn{}, nil
				},
				log: hook.log,
			}
			c, other := net.Pipe()
			done := make(chan struct{})
			go func() { f.pipe(c, origin); close(done) }()
			_ = other.Close() // the "client" side is irrelevant here
			until(t, 2*time.Second, "pipe finished", func() bool {
				select {
				case <-done:
					return true
				default:
					return false
				}
			})
			_ = c.Close()

			got := spy.all()
			if len(got) != len(tc.wantDial) {
				t.Fatalf("dialed %v, want exactly %v", got, tc.wantDial)
			}
			for i, want := range tc.wantDial {
				if got[i] != want {
					t.Fatalf("dial %d = %q, want %q (a forbidden address reached the dialer)", i, got[i], want)
				}
			}
			if len(tc.wantDial) == 0 && hook.count("no allowed address reachable") == 0 {
				t.Fatalf("expected the fail-closed log line:\n%s", hook.all())
			}
			// Refusals are logged with the IP — but only for addresses the
			// pipe actually evaluated: it stops at the first allowed one.
			// Everything up to the dialed address must have logged its
			// refusal; after it, skipping is correct behavior.
			wantDialedHosts := map[string]bool{}
			for _, w := range tc.wantDial {
				host, _, err := net.SplitHostPort(w)
				if err != nil {
					t.Fatalf("wantDial %q: %v", w, err)
				}
				wantDialedHosts[host] = true
			}
			stop := len(tc.ips)
			for idx, ip := range tc.ips {
				if wantDialedHosts[ip] {
					stop = idx
					break
				}
			}
			refusals := hook.all()
			for _, ip := range tc.ips[:stop] {
				if wantDialedHosts[ip] {
					continue // dialed by design: no refusal line
				}
				if !strings.Contains(refusals, ip) {
					t.Fatalf("refusal of %s not logged:\n%s", ip, refusals)
				}
			}
		})
	}
}

// originsAsDoc: one http loopback origin per numeric port.
func originsAsDoc(ports ...int) *snapshot.Document {
	domains := make([]snapshot.Domain, 0, len(ports))
	for _, p := range ports {
		domains = append(domains, snapshot.Domain{
			Hostname: "swap" + strconv.Itoa(p) + ".test",
			Origin:   snapshot.Origin{Scheme: "http", Address: "127.0.0.1", Port: p},
		})
	}
	return &snapshot.Document{Domains: domains}
}

// TestEgressSwapPortLifecycle: real listeners. An origin's port stays
// stable while the origin is in any config; a dropped origin keeps
// listening ONE extra swap (caddy may still serve the old config around
// the /load) and is pruned by the swap after that — dial-time proof.
func TestEgressSwapPortLifecycle(t *testing.T) {
	hook := &logHook{}
	f := newForwarder(Config{AllowLoopback: true, Log: hook.log})

	keyA := "http://127.0.0.1:30101"
	keyB := "http://127.0.0.1:30102"
	keyC := "http://127.0.0.1:30103"
	keyD := "http://127.0.0.1:30104"

	p1, err := f.Swap(originsAsDoc(30101, 30102)) // A, B
	if err != nil {
		t.Fatalf("swap1: %v", err)
	}
	if p1[keyA] == 0 || p1[keyB] == 0 || p1[keyA] == p1[keyB] {
		t.Fatalf("swap1 ports = %v", p1)
	}
	if !dialPortLive(t, p1[keyA]) || !dialPortLive(t, p1[keyB]) {
		t.Fatalf("listeners unreachable after swap1: %v", p1)
	}

	p2, err := f.Swap(originsAsDoc(30102, 30103)) // B retained, C arrives
	if err != nil {
		t.Fatalf("swap2: %v", err)
	}
	if p2[keyB] != p1[keyB] {
		t.Fatalf("port of the retained origin changed: %d → %d", p1[keyB], p2[keyB])
	}
	if p2[keyA] != 0 {
		t.Fatalf("dropped origin A still in the NEW config's port map: %v", p2)
	}
	if !dialPortLive(t, p1[keyA]) {
		t.Fatal("dropped origin A stopped listening during the reload window")
	}

	p3, err := f.Swap(originsAsDoc(30103, 30104)) // the swap AFTER the drop
	if err != nil {
		t.Fatalf("swap3: %v", err)
	}
	if p3[keyA] != 0 {
		t.Fatalf("pruned origin A reappeared: %v", p3)
	}
	if dialPortLive(t, p1[keyA]) {
		t.Fatal("A was not pruned by the swap after its last appearance")
	}
	if !dialPortLive(t, p2[keyC]) {
		t.Fatal("C lost its listener")
	}
	if p3[keyC] != p2[keyC] || p3[keyD] == 0 {
		t.Fatalf("swap3 ports wrong: %v", p3)
	}
}

// TestEgressPipeRoundTrip: a real TCP echo behind the guard (allowLoopback
// hook on), a fresh resolve per connection, and data both ways.
func TestEgressPipeRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	echoNum, _ := strconv.Atoi(portStr)
	go func() { // echo with a prefix
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				n, _ := c.Read(buf)
				if n > 0 {
					_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
				}
			}(c)
		}
	}()

	hook := &logHook{}
	f := newForwarder(Config{AllowLoopback: true, Log: hook.log})
	ports, err := f.Swap(&snapshot.Document{Domains: []snapshot.Domain{{
		Hostname: "echo.test",
		Origin:   snapshot.Origin{Scheme: "http", Address: "127.0.0.1", Port: echoNum},
	}}})
	if err != nil {
		t.Fatalf("swap: %v", err)
	}

	tunnelDial, err := net.DialTimeout("tcp",
		"127.0.0.1:"+strconv.Itoa(ports[originKey(snapshot.Origin{
			Scheme: "http", Address: "127.0.0.1", Port: echoNum,
		})]), time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	defer tunnelDial.Close()
	if _, err := tunnelDial.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	_ = tunnelDial.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := tunnelDial.Read(buf)
	if err != nil || string(buf[:n]) != "echo:ping" {
		t.Fatalf("round trip = %q err %v, want echo:ping", buf[:n], err)
	}
	if got := hook.all(); strings.Contains(got, "refused") {
		t.Fatalf("guard refused a legitimate loopback origin:\n%s", got)
	}
}

// dialPortLive: can 127.0.0.1:<port> accept a connection right now?
func dialPortLive(t *testing.T, port int) bool {
	t.Helper()
	c, err := (&net.Dialer{Timeout: 300 * time.Millisecond}).
		DialContext(context.Background(), "tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
