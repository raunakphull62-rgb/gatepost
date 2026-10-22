package server

import (
	"net/http"
	"strings"
	"testing"
)

// isolationRoutes — every route whose path carries a foreign-referencing id,
// with a representative body. The item-7 rule: another user's id is a
// uniform 404 and no data leaks. Later phases (items 10–12, phase B3…)
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

// TestDomainOriginIsolationTable — for every listed route, a second user
// calling it with the victim's domain id gets 404 and no data.
func TestDomainOriginIsolationTable(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool)
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
