package main

// Golden tests for the Caddy config generator (B3b item 3). Each fixture
// documents exactly what the edge pushes to /load for a given verified
// snapshot. GOLDEN_UPDATE=1 rewrites the files (review the diff, then commit
// it); the fixture docs here are the canonical definitions.
//
// The hostile fixture is requirement 8's injection attempt: a snapshot
// hostname carrying quotes, newlines, NUL, template braces, a wildcard and
// a backslash. It must appear in ONE place — the host matcher of ONE route
// — as a single JSON string, never as config structure.

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gatepost/internal/snapshot"
)

// evilHost carries the classic injection shapes: JSON quote+structure, a
// newline, a NUL, Go/html template braces, a host-matcher wildcard and a
// backslash escape.
var evilHost = "bad\"}\n\x00{{define}}" + "\t*." + "\\host.evil.test"

func hostHeader(s string) *string { return &s }

func fixtureDoc(name string) *snapshot.Document {
	switch name {
	case "deny":
		return nil
	case "single":
		return &snapshot.Document{
			SchemaVersion: snapshot.SchemaVersion,
			Generation:    11,
			Domains: []snapshot.Domain{{
				Hostname: "www.customer-one.test",
				Origin: snapshot.Origin{
					Scheme: "http", Address: "origin-one.internal", Port: 8443,
					HostHeader: hostHeader("backend-one"),
				},
			}},
		}
	case "multi":
		return &snapshot.Document{
			SchemaVersion: snapshot.SchemaVersion,
			Generation:    12,
			Domains: []snapshot.Domain{
				{
					Hostname: "shop.customer-two.test",
					Origin: snapshot.Origin{
						Scheme: "https", Address: "shop-origin.internal", Port: 443,
						TLSVerify: true,
					},
				},
				{
					Hostname: "blog.customer-two.test", // SAME origin as shop
					Origin: snapshot.Origin{
						Scheme: "https", Address: "shop-origin.internal", Port: 443,
						TLSVerify: true, HostHeader: hostHeader("shop-origin.internal"),
					},
				},
				{
					Hostname: "api.customer-three.test",
					Origin: snapshot.Origin{
						Scheme: "https", Address: "api-origin.internal", Port: 8443,
						TLSVerify: false, // self-signed origin → insecure_skip_verify
					},
				},
			},
		}
	case "hostile":
		return &snapshot.Document{
			SchemaVersion: snapshot.SchemaVersion,
			Generation:    13,
			Domains: []snapshot.Domain{{
				Hostname: evilHost,
				Origin:   snapshot.Origin{Scheme: "http", Address: "origin-x.internal", Port: 8001},
			}},
		}
	default:
		panic("unknown fixture " + name)
	}
}

func fixturePorts() map[string]int {
	return map[string]int{
		originKey(snapshot.Origin{Scheme: "http", Address: "origin-one.internal", Port: 8443}):  20101,
		originKey(snapshot.Origin{Scheme: "https", Address: "shop-origin.internal", Port: 443}): 20102,
		originKey(snapshot.Origin{Scheme: "https", Address: "api-origin.internal", Port: 8443}): 20103,
		originKey(snapshot.Origin{Scheme: "http", Address: "origin-x.internal", Port: 8001}):    20104,
	}
}

// TestGenerateGolden pins the generator's output per fixture.
func TestGenerateGolden(t *testing.T) {
	for _, name := range []string{"deny", "single", "multi", "hostile"} {
		name := name
		t.Run(name, func(t *testing.T) {
			got, err := Generate(fixtureDoc(name), CaddyParams{EgressPorts: fixturePorts()})
			if err != nil {
				t.Fatalf("generate: %v", err)
			}
			golden := filepath.Join("testdata", "golden", name+".json")
			if os.Getenv("GOLDEN_UPDATE") != "" {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("golden file (%s?): %v — regenerate with GOLDEN_UPDATE=1", err, golden)
			}
			if string(got) != string(want) {
				t.Fatalf("output %s does not match golden %s\nGOT:\n%s\nWANT:\n%s", name, golden, got, want)
			}
		})
	}
}

// TestGenerateHostileIsOneHostString: the injection shape cannot become
// structure — exactly two routes (the one host route + the catch-all), the
// hostile name inside a single matcher value, everything else intact.
func TestGenerateHostileIsOneHostString(t *testing.T) {
	cfgBytes, err := Generate(fixtureDoc("hostile"), CaddyParams{EgressPorts: fixturePorts()})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var cfg struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match  []map[string]any `json:"match"`
						Handle []map[string]any `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("generated config is not valid JSON (%v): the generator broke under a hostile hostname", err)
	}
	srv := cfg.Apps.HTTP.Servers["edge"]
	if len(srv.Routes) != 2 {
		t.Fatalf("routes = %d, want exactly 2 (host route + catch-all) — hostile input spawned structure", len(srv.Routes))
	}
	m0 := srv.Routes[0].Match
	var hosts []any
	for _, m := range m0 {
		if h, ok := m["host"].([]any); ok {
			hosts = append(hosts, h...)
		}
	}
	if len(hosts) != 1 || hosts[0] != evilHost {
		t.Fatalf("host matcher = %#v, want exactly [%q] as ONE JSON string value", hosts, evilHost)
	}
	// The catch-all must still be a plain static_response 421, untouched.
	ha := srv.Routes[1].Handle
	if len(ha) != 1 || ha[0]["handler"] != "static_response" || ha[0]["status_code"] != "421" {
		t.Fatalf("catch-all = %#v, want a single static_response 421", ha)
	}
}

// TestGenerateDetectsBrokenInput: generator refuses to emit a config whose
// origins it cannot tunnel (fail loud, keep last-good) — unknown scheme, or
// a port missing from the forwarder's allocations.
func TestGenerateDetectsBrokenInput(t *testing.T) {
	d := fixtureDoc("single")
	d.Domains[0].Origin.Scheme = "gopher"
	if _, err := Generate(d, CaddyParams{EgressPorts: fixturePorts()}); err == nil {
		t.Fatal("unknown origin scheme accepted")
	}
	d.Domains[0].Origin.Scheme = "http"
	if _, err := Generate(d, CaddyParams{EgressPorts: map[string]int{}}); err == nil {
		t.Fatal("missing egress port accepted — caddy would dial an unlistened port")
	}
}

// TestCaddyValidateGenerated: Caddy ITSELF (the binary of the version pinned
// in the edge image) validates every generated shape — including the hostile
// one. Skipped where no caddy binary is available (GP_TEST_CADDY or PATH).
func TestCaddyValidateGenerated(t *testing.T) {
	caddy, err := exec.LookPath(caddyBin())
	if err != nil {
		t.Skipf("no caddy binary (%s): %v", caddyBin(), err)
	}
	for _, name := range []string{"deny", "single", "multi", "hostile"} {
		cfgBytes, err := Generate(fixtureDoc(name), CaddyParams{EgressPorts: fixturePorts()})
		if err != nil {
			t.Fatalf("generate %s: %v", name, err)
		}
		path := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(path, cfgBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(caddy, "validate", "--config", path).CombinedOutput()
		if err != nil {
			t.Errorf("caddy validate %s failed: %v\n%s", name, err, out)
		} else if !strings.Contains(string(out), "Valid configuration") {
			t.Errorf("caddy validate %s: unexpected output:\n%s", name, out)
		}
	}
}
