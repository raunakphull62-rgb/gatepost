package domains

import (
	"errors"
	"net"
	"testing"
)

// TestCheckPort — the item list plus "similar" well-known/danger ports.
func TestCheckPort(t *testing.T) {
	bad := []int{22, 25, 110, 143, 3306, 5432, 6379, 27017, // the item list
		21, 23, 135, 139, 137, 161, 445, 465, 514, 587, 636, 691, 993, 995,
		1433, 1521, 2049, 2181, 2375, 2376, 3128, 3389, 5555, 5900, 5985,
		5986, 6380, 11211, 27018, 27019,
		0, -1, 65536}
	seen := map[int]bool{}
	for _, p := range bad {
		if seen[p] {
			t.Fatalf("port deny list duplicated %d", p)
		}
		seen[p] = true
		if err := CheckPort(p); err == nil {
			t.Fatalf("port %d must be refused", p)
		}
	}
	good := []int{1, 80, 443, 8080, 8443, 3000, 9000, 65535}
	for _, p := range good {
		if err := CheckPort(p); err != nil {
			t.Fatalf("port %d should be allowed: %v", p, err)
		}
	}
}

// TestCheckIP — every IP denial class, mapped v6, and the test hook that
// waives loopback and nothing else.
func TestCheckIP(t *testing.T) {
	owned := ParseOwned([]string{"203.0.113.9", "edge.gatepost.net"})
	cases := []struct {
		ip       net.IP
		hook     bool
		wantNull bool // true → allowed
	}{
		{net.ParseIP("93.184.216.34"), false, true},        // public: fine
		{net.ParseIP("8.8.8.8"), false, true},              // public: fine
		{net.ParseIP("2606:4700:4700::1111"), false, true}, // public v6: fine
		{net.ParseIP("127.0.0.1"), false, false},
		{net.ParseIP("127.9.9.9"), false, false},
		{net.ParseIP("10.0.0.5"), false, false},
		{net.ParseIP("172.16.0.1"), false, false},
		{net.ParseIP("172.31.255.255"), false, false},
		{net.ParseIP("172.32.0.1"), false, true}, // outside the /12
		{net.ParseIP("192.168.1.1"), false, false},
		{net.ParseIP("169.254.169.254"), false, false}, // metadata
		{net.ParseIP("169.254.1.1"), false, false},
		{net.ParseIP("100.64.0.1"), false, false}, // CGNAT
		{net.ParseIP("100.127.255.255"), false, false},
		{net.ParseIP("100.128.0.1"), false, true}, // outside CGNAT
		{net.ParseIP("0.0.0.0"), false, false},
		{net.ParseIP("::1"), false, false},
		{net.ParseIP("::"), false, false},
		{net.ParseIP("::ffff:127.0.0.1"), false, false},       // mapped loopback
		{net.ParseIP("::ffff:169.254.169.254"), false, false}, // mapped metadata
		{net.ParseIP("::ffff:93.184.216.34"), false, true},    // mapped public
		{net.ParseIP("fc00::1"), false, false},                // ULA
		{net.ParseIP("fd12::1"), false, false},                // ULA
		{net.ParseIP("fe80::1"), false, false},                // link-local
		{net.ParseIP("fe00::"), false, false},                 // ::/8 edge
		{net.ParseIP("ff02::1"), false, false},                // multicast v6
		{net.ParseIP("2001:db8::1"), false, true},             // doc range: allowed here
		{net.ParseIP("127.0.0.1"), true, true},                // TEST HOOK: loopback waived
		{net.ParseIP("::1"), true, true},                      // TEST HOOK: loopback waived
		{net.ParseIP("10.1.2.3"), true, false},                // hook must NOT waive private
		{net.ParseIP("169.254.169.254"), true, false},         // hook must NOT waive metadata
		{net.ParseIP("192.168.0.10"), true, false},            // hook must NOT waive private
		{net.ParseIP("203.0.113.9"), false, false},            // our own IP
		{net.ParseIP("203.0.113.9"), true, false},             // hook does not waive owned
	}
	for _, c := range cases {
		err := CheckIP(c.ip, owned, c.hook)
		if c.wantNull && err != nil {
			t.Errorf("CheckIP(%s, hook=%v) = %v, want nil", c.ip, c.hook, err)
		}
		if !c.wantNull && err == nil {
			t.Errorf("CheckIP(%s, hook=%v) allowed, want refused", c.ip, c.hook)
		}
	}
}

// TestValidateOrigin — literal canonicalisation, hostname syntax, and our
// owned-hostname refusal. (Resolution happens at the server layer.)
func TestValidateOrigin(t *testing.T) {
	owned := ParseOwned([]string{"edge.gatepost.net", "203.0.113.77"})
	cases := []struct {
		in       string
		hook     bool
		want     string
		wantNull bool
	}{
		{"93.184.216.34", false, "93.184.216.34", true},
		{" 93.184.216.34 ", false, "93.184.216.34", true},
		{"93.184.216.34.", false, "93.184.216.34", true},
		{"198.41.0.4", false, "198.41.0.4", true},
		{"2606:4700:4700::1111", false, "2606:4700:4700::1111", true},
		{"[2606:4700:4700::1111]", false, "2606:4700:4700::1111", true},
		{"origin.example.com", false, "origin.example.com", true},
		{"Origin.Example.Com.", false, "origin.example.com", true},
		{"bgp-server.internal", false, "bgp-server.internal", true}, // internal name: syntax ok
		{"backend", false, "backend", true},                         // single label: allowed (resolution decides)
		{"loopback-hook.test", true, "loopback-hook.test", true},    // hook irrelevant to names
		// refusals
		{"", false, "", false},
		{"   ", false, "", false},
		{"127.0.0.1", false, "", false},
		{"10.0.0.1", false, "", false},
		{"192.168.0.1", false, "", false},
		{"169.254.169.254", false, "", false},
		{"100.64.0.2", false, "", false},
		{"0.0.0.0", false, "", false},
		{"224.0.0.1", false, "", false},       // multicast
		{"203.0.113.5", false, "", false},     // TEST-NET-3 (similar-range rule)
		{"198.51.100.7", false, "", false},    // TEST-NET-2
		{"::ffff:10.0.0.9", false, "", false}, // mapped private
		{"not_a hostname!", false, "", false},
		{"-bad.example.com", false, "", false},
		{"bad-.example.com", false, "", false},
		{"ex..ample.com", false, "", false},
		{"203.0.113.77", false, "", false},       // owned IP
		{"EDGE.Gatepost.NET.", false, "", false}, // owned hostname, normalised
	}
	for _, c := range cases {
		got, err := ValidateOrigin(c.in, owned, c.hook)
		if c.wantNull {
			if err != nil {
				t.Errorf("ValidateOrigin(%q) = %v err=%v", c.in, got.Canonical, err)
				continue
			}
			if got.Canonical != c.want {
				t.Errorf("ValidateOrigin(%q): want %q, got %q", c.in, c.want, got.Canonical)
			}
			continue
		}
		if err == nil {
			t.Errorf("ValidateOrigin(%q) accepted %q, want refused", c.in, got.Canonical)
		}
		if !errors.Is(err, ErrForbiddenOrigin) && !errors.Is(err, ErrInvalidOrigin) {
			t.Errorf("ValidateOrigin(%q): wrong error class: %v", c.in, err)
		}
	}
}
