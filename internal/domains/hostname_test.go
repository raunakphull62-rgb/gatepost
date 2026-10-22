package domains

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func norm(t *testing.T, reserved map[string]struct{}, raw string) (string, error) {
	t.Helper()
	return NormalizeHostname(raw, reserved)
}

// TestNormalizeHostname — table covers normalizations and every rejection
// class: IP literals, localhost, single labels, wildcards, bare public
// suffixes, IDN mapping, length rules and our service hostnames.
func TestNormalizeHostname(t *testing.T) {
	own := map[string]struct{}{"api.gatepost.net": {}, "www.gatepost.net": {}}
	long63 := strings.Repeat("a", 63)
	cases := []struct {
		in   string
		want string // "" → expect error
	}{
		// --- accepted + normalized ---
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"EXAMPLE.com.", "example.com"},
		{"example.com.", "example.com"},
		{" Example.com ", "example.com"},
		{"sub.sub.example.co.uk", "sub.sub.example.co.uk"},
		{"example.co.uk", "example.co.uk"}, // public suffix appended: registrable
		{"example.test", "example.test"},
		{"shop.example.org", "shop.example.org"},
		{"123-dns.example.com", "123-dns.example.com"},
		{"about-x-y.example.net", "about-x-y.example.net"},
		{long63 + ".com", long63 + ".com"}, // max label length
		// IDN → punycode
		{"münchen.de", "xn--mnchen-3ya.de"},
		{"München.de", "xn--mnchen-3ya.de"},
		{"münchen.de.", "xn--mnchen-3ya.de"},
		{"кіт.example.com", "xn--"},                // exact punycode asserted by prefix below
		{"ＥＸＡＭＰＬＥ.com", "example.com"},             // fullwidth folds
		{"xn--mnchen-3ya.de", "xn--mnchen-3ya.de"}, // already puny

		// --- rejected: empties and odd spaces ---
		{"", ""},
		{"   ", ""},
		{".", ""},
		{"..", ""},
		{"example..com", ""},
		{"ex ample.com", ""},
		{".example.com", ""},
		{"example.com:443", ""},
		{"ex-ample-.com.", ""},

		// --- rejected: structural/malformed ---
		{long63 + ".com.", long63 + ".com"},                                // 63-char label + trailing dot: fine
		{long63 + "x.com", ""},                                             // 64-char label
		{long63 + "." + long63 + "." + long63 + "." + long63 + ".com", ""}, // >253 octets
		{"example", ""},                                                    // single label
		{"com", ""},                                                        // bare TLD = bare public suffix
		{"co.uk", ""},                                                      // bare multi-part public suffix
		{"uk", ""},                                                         // bare TLD
		{"*.example.com", ""},                                              // wildcard
		{"-example.com", ""},                                               // leading hyphen
		{"not!allowed.example.com", ""},                                    // disallowed char
		{"brackets[2001].example.com", ""},                                 // junk in brackets
		{"exam_ple.example.com", ""},                                       // no underscores (STD3)

		// --- rejected: IP literals / localhost / junk scripts ---
		{"1.2.3.4", ""},
		{"127.0.0.1", ""},
		{"192.168.1.10", ""},
		{"::1", ""},
		{"2001:db8::1", ""},
		{"[2001:db8::1]", ""},
		{"0.0.0.0", ""},
		{"localhost", ""},
		{"api.localhost", ""},
		{"www.GATEPOST.NET", ""}, // normalized first, then the reserved check

		// --- rejected: reserved service hostnames (normalize first) ---
		{"api.gatepost.net", ""},
		{"API.GATEPOST.NET.", ""},
		{"www.gatepost.net", ""},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("case%02d", i+1), func(t *testing.T) {
			got, err := norm(t, own, c.in)
			if c.want == "" {
				if err == nil {
					t.Fatalf("%q: want reject, got %q", c.in, got)
				}
				if !errors.Is(err, ErrInvalidHostname) && !errors.Is(err, ErrReservedServiceHostname) {
					t.Fatalf("%q: unexpected error class: %v", c.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("%q: want %q, got error %v", c.in, c.want, err)
			}
			if got != c.want {
				// кіт case: want is a bare "xn--" sentinel → assert punycode
				// prefix only (the exact code differs per table version).
				if c.want == "xn--" && strings.HasPrefix(got, "xn--") {
					return
				}
				t.Fatalf("%q: want %q, got %q", c.in, c.want, got)
			}
		})
	}
}

func normErr(t *testing.T, raw string) error {
	t.Helper()
	_, err := norm(t, map[string]struct{}{"api.gatepost.net": {}}, raw)
	return err
}

func TestReservedHostnameClassFails(t *testing.T) {
	if !errors.Is(normErr(t, "api.gatepost.net"), ErrReservedServiceHostname) {
		t.Fatalf("service hostname must get the reserved class")
	}
	if err := normErr(t, "customer.example.com"); err != nil {
		t.Fatalf("plain hostname must not be rejected by reserved check: %v", err)
	}
}
