// The egress TCP forwarder (B3b item 3). Caddy's reverse_proxy has no way to
// run a custom dial hook, so the poller exposes one loopback TCP port per
// tunnelled origin: the forwarder accepts a connection, resolves the origin's
// hostname FRESH for that connection, runs every resolved IP through
// domains.CheckIP — the exact ranges the API enforces at build time (private,
// loopback, link-local incl. cloud metadata, CGNAT, …) — and dials the
// VALIDATED IP directly. Because we dial the address we checked, a hostname
// whose DNS later turns hostile cannot smuggle an unvalidated address between
// check and dial: there is no TOCTOU window. Nothing here trusts the build
// time either: the dial guard is the rule that matters.
//
// shortcut: the poller process owns these listeners — its downtime 502s
// (crash ~0.3s via restart policy; docker kill waits for the supervisor);
// deterministic ports would only shave the ~0.3s re-apply, not the downtime.
//
// Port lifecycle across reloads: Swap assigns a port when an origin first
// appears and keeps it stable while that origin remains in any config. A
// dropped origin's port keeps LISTENING for exactly one more swap (caddy may
// still serve the old config around a /load) and is pruned by the next swap
// after that. Test/demo hook: allowLoopback permits exactly the loopback
// range (nothing else is waived), mirroring the API's GP_TEST_ALLOW_LOOPBACK.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gatepost/internal/domains"
	"gatepost/internal/snapshot"
)

type egressListener struct {
	origin snapshot.Origin
	port   int
	ln     net.Listener
	gen    int // number of the last Swap this listener served
}

type forwarder struct {
	allowLoopback bool
	resolve       func(ctx context.Context, host string) ([]net.IPAddr, error)
	dial          func(ctx context.Context, network, addr string) (net.Conn, error)
	log           func(kind string, format string, args ...any)

	mu        sync.Mutex
	active    map[string]*egressListener // origins of the CURRENT config
	fading    map[string]*egressListener // dropped recently; pruned at the next swap
	gen       int
	unhealthy atomic.Bool // an accept loop died; /health fails it until the next Swap
}

func newForwarder(cfg Config) *forwarder {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return &forwarder{
		allowLoopback: cfg.AllowLoopback,
		resolve: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return net.DefaultResolver.LookupIPAddr(ctx, host)
		},
		dial:   d.DialContext,
		log:    cfg.Log,
		active: map[string]*egressListener{},
		fading: map[string]*egressListener{},
	}
}

// Swap adapts the listener set to the new document and returns its port map
// (originKey → 127.0.0.1:<port>) for Generate. Starting a listener only ever
// fails because the local port space is broken: an error aborts the whole
// swap (the config must never reference a port nobody listens on) and closes
// anything just created.
func (f *forwarder) Swap(d *snapshot.Document) (map[string]int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gen++

	desired := map[string]*egressListener{}
	ports := map[string]int{}
	var fresh []*egressListener // created this swap; closed if the swap aborts
	defer func() {              // the success path clears `fresh` before it returns
		for _, l := range fresh {
			_ = l.ln.Close()
		}
	}()

	for _, dm := range d.Domains {
		key := originKey(dm.Origin)
		if l, ok := desired[key]; ok {
			ports[key] = l.port // two domains, one origin, one port
			continue
		}
		l, ok := f.active[key]
		if !ok {
			if l, ok = f.fading[key]; ok { // back in the config before its prune
				delete(f.fading, key)
			} else {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					return nil, fmt.Errorf("egress listener (after %d ok): %w", len(fresh), err)
				}
				l = &egressListener{
					origin: dm.Origin,
					port:   ln.Addr().(*net.TCPAddr).Port,
					ln:     ln,
					gen:    f.gen,
				}
				fresh = append(fresh, l)
				go l.serve(f)
			}
		}
		l.gen = f.gen
		desired[key] = l
		ports[key] = l.port
	}

	for k, l := range f.active { // dropped this reload → fade, keep listening
		if _, keep := desired[k]; !keep {
			f.fading[k] = l
		}
	}
	for k, l := range f.fading { // dropped through the previous reload too?
		if l.gen <= f.gen-2 { // the reload that removed it has fully settled
			delete(f.fading, k)
			_ = l.ln.Close()
		}
	}
	f.active = desired
	f.unhealthy.Store(false) // every desired origin has a live listener now
	fresh = nil
	return ports, nil
}

func (l *egressListener) serve(f *forwarder) {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Nothing sane recovers a dead accept loop: log loudly and
			// retire so the next Swap allocates a fresh port. Connections
			// dialled meanwhile fail closed.
			f.log("error", "egress listener for %s died: %v", originKey(l.origin), err)
			f.unhealthy.Store(true) // /health fails until the next Swap rebuilds this listener
			f.retire(l)
			return
		}
		go f.pipe(c, l.origin)
	}
}

// retire forgets a dead listener wherever it lives; the maps' keys are the
// only references handed out by Swap, so this unblocks reallocation.
func (f *forwarder) retire(l *egressListener) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range []map[string]*egressListener{f.active, f.fading} {
		for k, e := range m {
			if e == l {
				delete(m, k)
			}
		}
	}
	_ = l.ln.Close()
}

// pipe: the accepted side is Caddy's reverse_proxy hop. Resolve, validate
// EVERY resolved IP at dial time, dial the validated IP, pump both ways.
// No deadlines after dial: request/response timing belongs to caddy's
// server and transport knobs; the tunnel just moves bytes until one side
// hangs up.
func (f *forwarder) pipe(c net.Conn, origin snapshot.Origin) {
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ips, err := f.resolve(ctx, origin.Address)
	if err != nil {
		f.log("warn", "egress: cannot resolve %s: %v", origin.Address, err)
		return
	}
	var up net.Conn
	for _, ip := range ips {
		if err := domains.CheckIP(ip.IP, nil, f.allowLoopback); err != nil {
			f.log("warn", "egress: refused %s while proxying to %s (%v)", ip.IP, origin.Address, err)
			continue
		}
		up, err = f.dial(ctx, "tcp", net.JoinHostPort(ip.IP.String(), strconv.Itoa(origin.Port)))
		if err == nil {
			break
		}
		f.log("warn", "egress: cannot dial %s for %s: %v", ip.IP, origin.Address, err)
	}
	if up == nil {
		f.log("warn", "egress: no allowed address reachable for %s — closing proxied connection", origin.Address)
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); up.Close(); done <- struct{}{} }() // client → origin
	go func() { _, _ = io.Copy(c, up); up.Close(); done <- struct{}{} }() // origin → client
	<-done
	<-done
}
