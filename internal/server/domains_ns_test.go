package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func claimNS(t *testing.T, c tc, host, setup string) (int, string) {
	t.Helper()
	if setup == "" {
		setup = "cname"
	}
	return c.do("POST", "/v1/domains", `{"hostname":"`+host+`","setup_type":"`+setup+`"}`)
}

func nsCfg(on bool) func(*Config) {
	return func(cfg *Config) {
		cfg.Ns1, cfg.Ns2 = "ns1.gatepost.test", "ns2.gatepost.test"
		cfg.TestZone = "gatepost.test"
		cfg.AllowSubdomainZones = on
	}
}

// TestNameserverSetup — registry-level rules for nameserver-mode claims
// (item 10): registrable domains only, delegated subdomains only inside the
// configured test zone and only with the flag on, and the assigned pair
// comes back on claim rows and instructions.
func TestNameserverSetup(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool, nsCfg(true))
	signupOn(t, pool, a, "ns@x.test")

	// registrable domain: claim stores the assigned pair
	reg1 := strings.ToLower(randHex(t, 4)) + "-c1.com"
	code, body := claimNS(t, a, reg1, "nameserver")
	if code != http.StatusCreated {
		t.Fatalf("registrable claim: %d %s", code, body)
	}
	if !strings.Contains(body, `"ns1":"ns1.gatepost.test"`) || !strings.Contains(body, `"ns2":"ns2.gatepost.test"`) {
		t.Fatalf("assigned pair missing: %s", body)
	}

	// subdomain OUTSIDE the test zone: refused even with the flag on
	if code, body := claimNS(t, a, "www."+reg1, "nameserver"); code != http.StatusUnprocessableEntity {
		t.Fatalf("outside-zone subdomain: want 422, got %d: %s", code, body)
	}

	// delegated subdomain INSIDE the test zone: allowed with the flag
	code, body = claimNS(t, a, "shop.gatepost.test", "nameserver")
	if code != http.StatusCreated {
		t.Fatalf("test-zone subdomain: %d %s", code, body)
	}

	// re-add returns the held claim with its pair
	if code, body := claimNS(t, a, reg1, "nameserver"); code != http.StatusOK || !strings.Contains(body, `"ns1":"ns1.gatepost.test"`) {
		t.Fatalf("re-add: %d %s", code, body)
	}

	// garbage setup_type
	if code, body := claimNS(t, a, "x-other.example.com", "zonefile"); code != http.StatusUnprocessableEntity || !strings.Contains(body, "cname or nameserver") {
		t.Fatalf("setup_type: %d %s", code, body)
	}

	// cname claims never carry a pair
	code, body = claimNS(t, a, "plain-cname.example.com", "")
	if code != http.StatusCreated {
		t.Fatalf("cname claim: %d %s", code, body)
	}
	var got struct {
		Domain domainRow `json:"domain"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Domain.Ns1 != "" || got.Domain.Ns2 != "" || got.Domain.SetupType != "cname" {
		t.Fatalf("cname row carries ns data: %+v", got.Domain)
	}
	// instructions: cname keeps the TXT recipe
	v := a.must("GET", "/v1/domains/"+got.Domain.ID+"/verification", "", http.StatusOK)
	if !strings.Contains(v, "record_name") || strings.Contains(v, "nameservers") {
		t.Fatalf("cname instructions wrong: %s", v)
	}

	// instructions: nameserver mode lists the pair, never a TXT token leak
	dns := claimRow(t, a, "instr.example.com") // cname row
	reg2 := strings.ToLower(randHex(t, 4)) + "-instr.com"
	dnsv, ok := claimNSRow(t, a, reg2)
	if !ok {
		t.Fatal("nameserver claim for instructions missing")
	}
	vns := a.must("GET", "/v1/domains/"+dnsv+"/verification", "", http.StatusOK)
	if !strings.Contains(vns, `"nameservers":["ns1.gatepost.test","ns2.gatepost.test"]`) || strings.Contains(vns, "gatepost-verify=") {
		t.Fatalf("nameserver instructions wrong: %s", vns)
	}
	vc := a.must("GET", "/v1/domains/"+dns.ID+"/verification", "", http.StatusOK)
	if !strings.Contains(vc, "_gatepost-verify.instr.example.com") {
		t.Fatalf("cname instructions broken by ns mode: %s", vc)
	}
	_ = v
}

// TestNameserverSetupRestrictive — flag off: no delegated subdomains even in
// the test zone; and a nameserver claim cannot work without the pair.
func TestNameserverSetupRestrictive(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool, nsCfg(false))
	signupOn(t, pool, a, "nsr@x.test")
	if code, body := claimNS(t, a, "shop.gatepost.test", "nameserver"); code != http.StatusUnprocessableEntity {
		t.Fatalf("flag must gate subdomains: %d %s", code, body)
	}
	if code, body := claimNS(t, a, "shop.gatepost.test", ""); code != http.StatusCreated {
		t.Fatalf("cname on test zone still fine: %d %s", code, body)
	}

	// nameserver mode with no assigned pair configured: operator error → 500
	pool2 := testPool(t)
	b, _ := newTestServer(t, pool2)
	signupOn(t, pool2, b, "nsx@x.test")
	if code, body := claimNS(t, b, "nopair.example.com", "nameserver"); code != http.StatusInternalServerError {
		t.Fatalf("missing pair: want 500, got %d %s", code, body)
	}
}

func claimNSRow(t *testing.T, c tc, host string) (string, bool) {
	t.Helper()
	code, body := claimNS(t, c, host, "nameserver")
	if code != http.StatusCreated {
		return "", false
	}
	var got struct {
		Domain domainRow `json:"domain"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	return got.Domain.ID, true
}
