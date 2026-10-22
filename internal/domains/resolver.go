// B2 item 4: pluggable DNS resolvers. Verification reads public DNS through
// this interface; tests inject fakes (no network).
package domains

import (
	"context"
	"net"
	"strings"
	"time"
)

func lowercaseHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

// Resolver is the slice of net.Resolver the verification flows use. Each
// implementation must impose its own (short) deadline.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]string, error) // item 10/11
	LookupIP(ctx context.Context, name string) ([]net.IP, error) // item 5/6 origin rules
}

// InstalledResolver answers through one fixed recursive server, e.g.
// 1.1.1.1:53, with a 5-second deadline.
type InstalledResolver struct {
	Addr string // host[:port] of the upstream resolver
}

func (r InstalledResolver) lookup(ctx context.Context) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(dctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dctx, network, r.Addr)
	}}
}

func (r InstalledResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return r.lookup(ctx).LookupTXT(cctx, name)
}

func (r InstalledResolver) LookupNS(ctx context.Context, name string) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ns, err := r.lookup(ctx).LookupNS(cctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ns))
	for _, h := range ns {
		out = append(out, lowercaseHost(h.Host))
	}
	return out, nil
}

func (r InstalledResolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := r.lookup(ctx).LookupIPAddr(cctx, name)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(ips))
	for _, a := range ips {
		out = append(out, a.IP)
	}
	return out, nil
}
