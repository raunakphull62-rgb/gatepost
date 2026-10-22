// Package domains: hostname normalization/validation and the origin-address
// rules (B2 items 2 and 5). Everything returns descriptive errors — handlers
// map any error here to a 4xx with the message attached.
package domains

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var (
	// ErrInvalidHostname marks a hostname the customer may not claim —
	// malformed, reserved, or a bare public suffix.
	ErrInvalidHostname = errors.New("invalid hostname")
	// ErrReservedServiceHostname marks one of our own service hostnames.
	ErrReservedServiceHostname = errors.New("reserved service hostname")
)

// Normalize turns a customer-supplied claim into the stored, comparable
// form: lowercased, no trailing dot, punycode for IDN. Everything else
// fails with ErrInvalidHostname (or ErrReservedServiceHostname).
func NormalizeHostname(raw string, reserved map[string]struct{}) (string, error) {
	reject := func(format string, args ...any) (string, error) {
		return "", fmt.Errorf("%w: "+format, append([]any{ErrInvalidHostname}, args...)...)
	}
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return reject("empty")
	}
	if strings.Contains(s, ":") { // IPv6 literals and stray ports
		return reject("colon not allowed in a hostname")
	}
	if ip := net.ParseIP(s); ip != nil {
		return reject("IP addresses are not domains")
	}
	puny, err := idna.Lookup.ToASCII(s)
	if err != nil {
		return reject("%q (%v) — also covers wildcards and reserved script forms", raw, err)
	}
	if len(puny) > 253 {
		return reject("longer than 253 octets")
	}
	for _, label := range strings.Split(puny, ".") {
		if label == "" {
			return reject("empty label in %q", raw)
		}
		if len(label) > 63 {
			return reject("label longer than 63 octets")
		}
	}
	if puny == "localhost" || strings.HasSuffix(puny, ".localhost") {
		return reject("localhost is not a domain")
	}
	if !strings.Contains(puny, ".") {
		return reject("single-label name %q (needs a dot)", raw)
	}
	suffix, _ := publicsuffix.PublicSuffix(puny) // (suffix, icann)
	if suffix == puny {
		return reject("%q is a bare public suffix", raw)
	}
	if reserved != nil {
		if _, hit := reserved[puny]; hit {
			return "", fmt.Errorf("%w: %s", ErrReservedServiceHostname, puny)
		}
	}
	return puny, nil
}
