// B2 item 5: origin address rules. Everything an origin may be — the loop-
// back, private, link-local, CGNAT, metadata and other deny ranges have to
// stay unreachable, directly or after resolving a hostname.
package domains

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

var (
	// ErrForbiddenOrigin marks an origin we refuse to talk to.
	ErrForbiddenOrigin = errors.New("forbidden origin")
	// ErrInvalidOrigin marks a malformed origin address.
	ErrInvalidOrigin = errors.New("invalid origin")
)

// forbidden-octet ranges for IPv4 literals (and v4-mapped v6).
var forbidV4 = []string{
	"0.0.0.0/8",       // "this network" / unspecified
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local incl. cloud metadata 169.254.169.254
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved
}

var forbidV4Nets = mustCIDRs(forbidV4)

// IPv6: loopback (single), unique-local, link-local, v4-mapped handled by the
// To4() path above.
var forbidV6Nets = mustCIDRs([]string{"::/8", "fe00::/9", "fe80::/10", "fc00::/7", "ff00::/8"})

func mustCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, c := range list {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("domains: bad built-in CIDR " + c)
		}
		out = append(out, n)
	}
	return out
}

// PortDeny — well-known and infrastructure ports a customer origin may not
// use (the item list plus "similar"): shell/cpu/…, mail, databases, caches,
// brokers, docker, vnc. Fixed in code, commented here for visibility.
var PortDeny = map[int]struct{}{
	21: {}, 22: {}, 23: {}, 25: {}, 110: {}, 135: {}, 137: {}, 139: {}, 143: {},
	161: {}, 389: {}, 445: {}, 465: {}, 514: {}, 587: {}, 636: {}, 691: {},
	993: {}, 995: {}, 1433: {}, 1521: {}, 2049: {}, 2181: {}, 2375: {},
	2376: {}, 3128: {}, 3306: {}, 3389: {}, 5432: {}, 5555: {}, 5900: {},
	5985: {}, 5986: {}, 6379: {}, 6380: {}, 11211: {}, 27017: {},
	27018: {}, 27019: {},
}

// CheckPort rejects the deny list; everything else in 1..65535 is fine.
func CheckPort(p int) error {
	if p <= 0 || p > 65535 {
		return fmt.Errorf("%w: port %d out of range", ErrInvalidOrigin, p)
	}
	if _, hit := PortDeny[p]; hit {
		return fmt.Errorf("%w: port %d is on the deny list", ErrForbiddenOrigin, p)
	}
	return nil
}

// OwnedAddresses is our own infrastructure, parsed once at boot from the env
// list: IP literals to refuse exactly, and hostnames normalised for
// case/trailing-dot comparisons.
type OwnedAddresses struct {
	IPs   map[string]struct{}
	Hosts map[string]struct{}
}

// ParseOwned builds the comparator set from a comma-split env list.
func ParseOwned(list []string) *OwnedAddresses {
	o := &OwnedAddresses{IPs: map[string]struct{}{}, Hosts: map[string]struct{}{}}
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		e = strings.TrimSuffix(e, ".")
		if ip := net.ParseIP(e); ip != nil {
			o.IPs[ip.String()] = struct{}{}
		} else {
			o.Hosts[e] = struct{}{}
		}
	}
	return o
}

// CheckIP refuses every denied range (or our own IPs). allowLoopback is the
// TEST hook only — it may never leak outside test/demo binaries.
func CheckIP(ip net.IP, owned *OwnedAddresses, allowLoopback bool) error {
	if ip == nil {
		return fmt.Errorf("%w: not an IP", ErrInvalidOrigin)
	}
	if owned != nil {
		if _, hit := owned.IPs[ip.String()]; hit {
			return fmt.Errorf("%w: %s is a Gatepost address", ErrForbiddenOrigin, ip)
		}
	}
	if t4 := ip.To4(); t4 != nil {
		for _, n := range forbidV4Nets {
			if n.Contains(t4) {
				if allowLoopback && n.String() == "127.0.0.0/8" {
					continue // test hook: loopback only, nothing else is waived
				}
				return fmt.Errorf("%w: %s is inside %s", ErrForbiddenOrigin, ip, n)
			}
		}
		return nil
	}
	for _, n := range forbidV6Nets {
		if n.Contains(ip) {
			if allowLoopback && n.String() == "::/8" && ip.IsLoopback() {
				continue // test hook: ::1 only
			}
			return fmt.Errorf("%w: %s is inside %s", ErrForbiddenOrigin, ip, n)
		}
	}
	return nil
}

var hostLike = regexp.MustCompile(`^[a-z0-9._-]+$`)

// OriginAddr is the validated origin address: either a canonical IP literal
// or a normalised hostname.
type OriginAddr struct {
	Canonical string
	IP        net.IP // non-nil for literals
}

// ValidateOrigin accepts an IP literal (range-checked here) or a hostname
// (syntax-checked here; its resolution is checked by the caller, which owns
// the resolver).
func ValidateOrigin(raw string, owned *OwnedAddresses, allowLoopback bool) (OriginAddr, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return OriginAddr{}, fmt.Errorf("%w: empty", ErrInvalidOrigin)
	}
	if strings.Contains(s, ":") { // v6 literal or stray port
		ip := net.ParseIP(strings.Trim(s, "[]"))
		if ip == nil {
			return OriginAddr{}, fmt.Errorf("%w: %q is not an IPv6 literal", ErrInvalidOrigin, raw)
		}
		if err := CheckIP(ip, owned, allowLoopback); err != nil {
			return OriginAddr{}, err
		}
		return OriginAddr{Canonical: ip.String(), IP: ip}, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if err := CheckIP(ip, owned, allowLoopback); err != nil {
			return OriginAddr{}, err
		}
		return OriginAddr{Canonical: ip.String(), IP: ip}, nil
	}
	// hostname form: structural syntax here (public-suffix rules of customer
	// domains do NOT apply — origins may be internal names that a resolver
	// will answer or not).
	if !hostLike.MatchString(s) {
		return OriginAddr{}, fmt.Errorf("%w: %q is not a plain hostname", ErrInvalidOrigin, raw)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return OriginAddr{}, fmt.Errorf("%w: bad label %q in %q", ErrInvalidOrigin, label, raw)
		}
	}
	if len(s) > 253 {
		return OriginAddr{}, fmt.Errorf("%w: longer than 253 octets", ErrInvalidOrigin)
	}
	if owned != nil {
		if _, hit := owned.Hosts[s]; hit {
			return OriginAddr{}, fmt.Errorf("%w: %s is a Gatepost address", ErrForbiddenOrigin, s)
		}
	}
	return OriginAddr{Canonical: s}, nil
}
