package server

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"gatepost/internal/domains"
)

// originDNS: the fake's hostname→IP answers for the server-side rule table.
func originDNS() *fakeDNS {
	return &fakeDNS{ips: map[string][]net.IP{
		"ok.example.com":      {net.ParseIP("93.184.216.34")},
		"v6.example.com":      {net.ParseIP("2606:4700:4700::1111")},
		"loop.example.com":    {net.ParseIP("127.0.0.1")},
		"meta.example.com":    {net.ParseIP("169.254.169.254")},
		"priv.example.com":    {net.ParseIP("192.168.0.10")},
		"multi.example.com":   {net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.7")}, // one good, one bad
		"bothbad.example.com": {net.ParseIP("127.0.0.1"), net.ParseIP("169.254.169.254")},
	}}
}

func originSetup(t *testing.T) (*pgxpool.Pool, tc, *Server) {
	t.Helper()
	pool := testPool(t)
	a, s := newTestServer(t, pool)
	signupOn(t, pool, a, "orig@x.test")
	setResolvers(s, originDNS())
	return pool, a, s
}

func originJSON(t *testing.T, body string) originRow {
	t.Helper()
	var got struct {
		Origin originRow `json:"origin"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("origin json: %v: %s", err, body)
	}
	return got.Origin
}

// originCall posts {"scheme":..., "address":..., "port":...} plus overrides.
func originCall(t *testing.T, c tc, domID string, args map[string]any) (int, string) {
	t.Helper()
	if _, ok := args["scheme"]; !ok {
		args["scheme"] = "https"
	}
	if _, ok := args["port"]; !ok {
		args["port"] = 443
	}
	b, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return c.do("POST", "/v1/domains/"+domID+"/origin", string(b))
}

// TestOriginValidationRules — the strict address/port/field rules end-to-end
// (item 5's server-side table; the deny-range math itself is unit-tested in
// internal/domains). Accepted rows land on a fresh domain each, since one
// origin per domain is a hard rule.
func TestOriginValidationRules(t *testing.T) {
	pool, a, _ := originSetup(t)
	ref := claimRow(t, a, "ref.example.com").ID // refusals share one domain

	cases := []struct {
		name string
		args map[string]any
		want int
	}{
		// happy paths (fresh domain per case)
		{"literal ok", map[string]any{"address": "93.184.216.34"}, http.StatusCreated},
		{"canonical stored", map[string]any{"address": "93.184.216.34"}, http.StatusCreated},
		{"hostname resolves public", map[string]any{"address": "ok.example.com"}, http.StatusCreated},
		{"ipv6 literal", map[string]any{"address": "2606:4700:4700::1111"}, http.StatusCreated},
		{"custom port", map[string]any{"address": "v6.example.com", "port": 8080}, http.StatusCreated},
		// range refusals, literals
		{"loopback", map[string]any{"address": "127.0.0.1"}, http.StatusUnprocessableEntity},
		{"private", map[string]any{"address": "10.1.2.3"}, http.StatusUnprocessableEntity},
		{"cgnat", map[string]any{"address": "100.64.0.9"}, http.StatusUnprocessableEntity},
		{"metadata", map[string]any{"address": "169.254.169.254"}, http.StatusUnprocessableEntity},
		{"unspecified", map[string]any{"address": "0.0.0.0"}, http.StatusUnprocessableEntity},
		{"mapped loopback", map[string]any{"address": "::ffff:127.0.0.1"}, http.StatusUnprocessableEntity},
		// resolution refusals, hostnames
		{"resolves loopback", map[string]any{"address": "loop.example.com"}, http.StatusUnprocessableEntity},
		{"resolves metadata", map[string]any{"address": "meta.example.com"}, http.StatusUnprocessableEntity},
		{"resolves private", map[string]any{"address": "priv.example.com"}, http.StatusUnprocessableEntity},
		{"one vip resolves private", map[string]any{"address": "multi.example.com"}, http.StatusUnprocessableEntity},
		{"all ips bad", map[string]any{"address": "bothbad.example.com"}, http.StatusUnprocessableEntity},
		{"no record", map[string]any{"address": "absent.example.com"}, http.StatusUnprocessableEntity},
		{"garbage host", map[string]any{"address": "-nope.example.com"}, http.StatusUnprocessableEntity},
		{"colon port in addr", map[string]any{"address": "ok.example.com:443"}, http.StatusUnprocessableEntity},
		// ports
		{"ssh", map[string]any{"address": "ok.example.com", "port": 22}, http.StatusUnprocessableEntity},
		{"smtp", map[string]any{"address": "ok.example.com", "port": 25}, http.StatusUnprocessableEntity},
		{"mysql", map[string]any{"address": "ok.example.com", "port": 3306}, http.StatusUnprocessableEntity},
		{"pg", map[string]any{"address": "ok.example.com", "port": 5432}, http.StatusUnprocessableEntity},
		{"redis", map[string]any{"address": "ok.example.com", "port": 6379}, http.StatusUnprocessableEntity},
		{"mongo", map[string]any{"address": "ok.example.com", "port": 27017}, http.StatusUnprocessableEntity},
		{"docker", map[string]any{"address": "ok.example.com", "port": 2375}, http.StatusUnprocessableEntity},
		{"port 0", map[string]any{"address": "ok.example.com", "port": 0}, http.StatusUnprocessableEntity},
		{"port big", map[string]any{"address": "ok.example.com", "port": 70000}, http.StatusUnprocessableEntity},
		// field rules
		{"bad scheme", map[string]any{"address": "ok.example.com", "scheme": "ftp"}, http.StatusUnprocessableEntity},
		{"empty host header", map[string]any{"address": "ok.example.com", "host_header": "  "}, http.StatusUnprocessableEntity},
		{"bad health path", map[string]any{"address": "ok.example.com", "health_path": "../etc"}, http.StatusUnprocessableEntity},
		{"bad interval", map[string]any{"address": "ok.example.com", "health_interval": 3}, http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			domID := ref
			if c.want == http.StatusCreated {
				slug := strings.NewReplacer(" ", "-", "_", "-", "/", "-").Replace(c.name)
				domID = claimRow(t, a, slug+"-rule.example.com").ID
			}
			code, body := originCall(t, a, domID, c.args)
			if code != c.want {
				t.Fatalf("want %d, got %d: %s", c.want, code, body)
			}
			if c.want == http.StatusCreated {
				// free the claim (cascade drops the origin) so caps stay clear
				a.must("DELETE", "/v1/domains/"+domID, "", http.StatusOK)
			}
		})
	}

	// once one origin exists, further creates are 409 (one per domain)
	if code, _ := originCall(t, a, ref, map[string]any{"address": "v6.example.com"}); code != http.StatusCreated {
		t.Fatalf("first origin on ref: %d", code)
	}
	if code, body := originCall(t, a, ref, map[string]any{"address": "v6.example.com"}); code != http.StatusConflict {
		t.Fatalf("second origin: want 409, got %d: %s", code, body)
	}
	_ = pool
}

// TestOriginSettingsFlow — create/get/update with ownership 404s, field
// defaults, and the stored shape.
func TestOriginSettingsFlow(t *testing.T) {
	pool, a, s := originSetup(t)
	b := secondUser(t, pool, a, "orig-b@x.test") // foreign user, same server

	domID := claimRow(t, a, "flow.example.com").ID
	code, body := originCall(t, a, domID, map[string]any{"address": "ok.example.com", "host_header": "internal"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	o := originJSON(t, body)
	if o.TLSVerify != true || o.HealthPath != "/" || o.HealthInterval != 60 {
		t.Fatalf("defaults wrong: %+v", o)
	}
	if o.Address != "ok.example.com" || o.HostHeader == nil || *o.HostHeader != "internal" {
		t.Fatalf("stored fields wrong: %+v", o)
	}

	// GET mine / foreign
	if got := a.must("GET", "/v1/domains/"+domID+"/origin", "", http.StatusOK); !strings.Contains(got, `"address":"ok.example.com"`) {
		t.Fatalf("get: %s", got)
	}
	if code, _ := b.do("GET", "/v1/domains/"+domID+"/origin", ""); code != http.StatusNotFound {
		t.Fatalf("foreign get: want 404, got %d", code)
	}
	if code, _ := b.do("POST", "/v1/domains/"+domID+"/origin", `{"scheme":"https","address":"93.184.216.34","port":443}`); code != http.StatusNotFound {
		t.Fatalf("foreign create: want 404, got %d", code)
	}
	if code, _ := b.do("PUT", "/v1/domains/"+domID+"/origin", `{"scheme":"https","address":"93.184.216.34","port":443}`); code != http.StatusNotFound {
		t.Fatalf("foreign update: want 404, got %d", code)
	}
	// foreign claim of the same HOSTNAME is fine (many-pending) but never
	// gets to see a's origins
	if code, _ := b.do("GET", "/v1/domains/"+domID+"/origin", ""); code != http.StatusNotFound {
		t.Fatalf("foreign origin get: want 404, got %d", code)
	}

	// update every field, incl. dropping the host header (explicit null)
	upd := `{"scheme":"http","address":"93.184.216.34","port":80,"host_header":null,"tls_verify":false,"health_path":"/live","health_interval":300}`
	code, body = a.do("PUT", "/v1/domains/"+domID+"/origin", upd)
	if code != http.StatusOK {
		t.Fatalf("update: %d %s", code, body)
	}
	o = originJSON(t, body)
	if o.Scheme != "http" || o.Port != 80 || o.TLSVerify != false || o.HealthPath != "/live" || o.HealthInterval != 300 {
		t.Fatalf("update fields wrong: %+v", o)
	}
	if o.HostHeader != nil {
		t.Fatalf("host_header must drop to null: %+v", o)
	}

	// no origin yet on a fresh domain → GET/PUT are 404
	fresh := claimRow(t, a, "freshflow.example.com")
	if code, _ := a.do("GET", "/v1/domains/"+fresh.ID+"/origin", ""); code != http.StatusNotFound {
		t.Fatalf("empty origin get: want 404, got %d", code)
	}
	if code, _ := a.do("PUT", "/v1/domains/"+fresh.ID+"/origin", upd); code != http.StatusNotFound {
		t.Fatalf("empty origin put: want 404, got %d", code)
	}
	// Gatepost-owned hostname refused as an origin address
	s.owned = domains.ParseOwned([]string{"dots.gatepost.net"})
	if code, _ := originCall(t, a, fresh.ID, map[string]any{"address": "dots.gatepost.net"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("owned origin address: want 422, got %d", code)
	}
}
