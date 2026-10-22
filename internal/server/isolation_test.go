package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// isolationRoutes — every route whose path carries a foreign-referencing
// domain id, with a representative body. The item-7 rule: another user's id
// is a uniform 404 and no data leaks. Later phases (items 10–12, phase B3…)
// append their routes to this table rather than inventing their own test.
var isolationRoutes = []struct {
	name string
	meth string
	path string // {id} is the victim's domain id
	body string
}{
	{"get domain", "GET", "/v1/domains/{id}", ""},
	{"delete domain", "DELETE", "/v1/domains/{id}", ""},
	{"verify claim", "POST", "/v1/domains/{id}/verify", ""},
	{"verification instructions", "GET", "/v1/domains/{id}/verification", ""},
	{"origin create", "POST", "/v1/domains/{id}/origin",
		`{"scheme":"https","address":"93.184.216.34","port":443}`},
	{"origin get", "GET", "/v1/domains/{id}/origin", ""},
	{"origin update", "PUT", "/v1/domains/{id}/origin",
		`{"scheme":"https","address":"93.184.216.34","port":443}`},
	{"origin test", "POST", "/v1/domains/{id}/origin/test", ""},
	{"records create", "POST", "/v1/domains/{id}/records", `{"name":"@","type":"A","value":"93.184.216.34"}`},
	{"records list", "GET", "/v1/domains/{id}/records", ""},
}

// recordIsolationRoutes — routes that also carry a record id: the runner
// gives the victim a nameserver-mode claim (zone exists) with one record.
var recordIsolationRoutes = []struct {
	name string
	meth string
	path string
	body string
}{
	{"record view+history", "GET", "/v1/domains/{id}/records/{rid}", ""},
	{"record patch", "PATCH", "/v1/domains/{id}/records/{rid}", `{"ttl":300}`},
	{"record delete", "DELETE", "/v1/domains/{id}/records/{rid}", ""},
}

// TestDomainOriginIsolationTable — for every listed route, a second user
// calling it with the victim's domain id gets 404 and no data.
func TestDomainOriginIsolationTable(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool, nsCfg(true)) // ns pair needed for the zone-claim victim
	signupOn(t, pool, a, "victim-iso@x.test")
	b := secondUser(t, pool, a, "attacker-iso@x.test")

	// the victim's material: claim + origin (literal → no resolver involved)
	da := claimRow(t, a, "iso-victim.example.com")
	if code, body := originCall(t, a, da.ID, map[string]any{
		"scheme": "https", "address": "93.184.216.34",
	}); code != http.StatusCreated {
		t.Fatalf("victim origin: %d %s", code, body)
	}
	secrets := []string{da.ID, "iso-victim.example.com", "93.184.216.34"}

	for _, rt := range isolationRoutes {
		t.Run(rt.name, func(t *testing.T) {
			route := strings.Replace(rt.path, "{id}", da.ID, 1)
			code, body := b.do(rt.meth, route, rt.body)
			if code != http.StatusNotFound {
				t.Fatalf("%s %s: want 404, got %d: %s", rt.meth, route, code, body)
			}
			for _, s := range secrets {
				if strings.Contains(body, s) {
					t.Fatalf("%s %s leaks %q in body %s", rt.meth, route, s, body)
				}
			}
		})
	}

	// the rid-based routes need a zone: a nameserver-mode claim (its own
	// registrable hostname) with one record
	dz, okz := claimNSRow(t, a, strings.ToLower("iso-zone-"+randHex(t, 3))+".test")
	if !okz {
		t.Fatal("victim zone claim missing")
	}
	if code, body := recordCall(t, a, dz, `{"name":"www","type":"A","value":"93.184.216.34"}`); code != http.StatusCreated {
		t.Fatalf("victim record: %d %s", code, body)
	}
	var rec struct {
		Records []recordRow `json:"records"`
	}
	if err := json.Unmarshal([]byte(a.must("GET", "/v1/domains/"+dz+"/records", "", http.StatusOK)), &rec); err != nil {
		t.Fatal(err)
	}
	if len(rec.Records) != 1 {
		t.Fatalf("victim zone must hold exactly one record: %s", a.must("GET", "/v1/domains/"+dz+"/records", "", http.StatusOK))
	}
	rid := rec.Records[0].ID

	client := b
	for _, rt := range recordIsolationRoutes {
		t.Run(rt.name, func(t *testing.T) {
			route := strings.NewReplacer("{id}", dz, "{rid}", rid).Replace(rt.path)
			code, body := client.do(rt.meth, route, rt.body)
			if code != http.StatusNotFound {
				t.Fatalf("%s %s: want 404, got %d: %s", rt.meth, route, code, body)
			}
			for _, s := range secrets {
				if strings.Contains(body, s) {
					t.Fatalf("%s %s leaks %q in body %s", rt.meth, route, s, body)
				}
			}
		})
	}

	// the attacker's own actions on the same surface are fine (they only
	// ever see their own rows)
	lown := b.must("GET", "/v1/domains", "", http.StatusOK)
	if !containsNone(lown, secrets...) {
		t.Fatalf("attacker list shows the victim's data: %s", lown)
	}
	// and the victim's resources are untouched by all the foreign calls
	if got := a.must("GET", "/v1/domains/"+da.ID+"/origin", "", http.StatusOK); !strings.Contains(got, `"address":"93.184.216.34"`) {
		t.Fatalf("victim origin damaged: %s", got)
	}
	if got := a.must("GET", "/v1/domains/"+dz+"/records", "", http.StatusOK); strings.Count(got, `"type":"A"`) != 1 {
		t.Fatalf("victim record damaged: %s", got)
	}
	if code, _ := a.do("DELETE", "/v1/domains/"+da.ID, ""); code != http.StatusOK {
		t.Fatalf("victim delete: %d", code)
	}
}

func containsNone(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}
