package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// zoneSetup — a nameserver-mode claim (its zone row exists) with default caps.
func zoneSetup(t *testing.T) (*pgxpool.Pool, tc, string) {
	t.Helper()
	pool := testPool(t)
	a, _ := newTestServer(t, pool, nsCfg(true))
	signupOn(t, pool, a, "zone@x.test")
	_, dom := regNS(t, a, "z"+strings.ToLower(randHex(t, 3)))
	return pool, a, dom
}

func recordCall(t *testing.T, c tc, domID, body string) (int, string) {
	t.Helper()
	return c.do("POST", "/v1/domains/"+domID+"/records", body)
}

func recordID(t *testing.T, body string) string {
	t.Helper()
	var got struct {
		Record recordRow `json:"record"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("record json: %v: %s", err, body)
	}
	return got.Record.ID
}

// TestRecordValidation — per-type value rules, name rules, ttl/priority
// ranges, and the valid forms they sit among.
func TestRecordValidation(t *testing.T) {
	_, a, dom := zoneSetup(t)

	cases := []struct {
		name string
		body string
		want int
	}{
		// accepted forms
		{"a record", `{"name":"@","type":"A","value":"93.184.216.34"}`, http.StatusCreated},
		{"aaaa okay", `{"name":"v6","type":"AAAA","value":"2606:4700::1111"}`, http.StatusCreated},
		{"mx okay", `{"name":"@","type":"MX","value":"mail.example.net","priority":10}`, http.StatusCreated},
		{"srv okay", `{"name":"_sip._tcp","type":"SRV","value":"5 5060 sip.example.net","priority":2}`, http.StatusCreated},
		{"caa okay", `{"name":"@","type":"CAA","value":"0 issue \"letsencrypt.org\""}`, http.StatusCreated},
		{"underscore name", `{"name":"_dmarc","type":"TXT","value":"v=DMARC1; p=none"}`, http.StatusCreated},
		{"explicit ttl", `{"name":"ttly","type":"TXT","value":"hi","ttl":600}`, http.StatusCreated},
		{"ns apex", `{"name":"@","type":"NS","value":"ns.customer2.example.net."}`, http.StatusCreated},
		{"internally addressed a", `{"name":"lan","type":"A","value":"10.0.0.9"}`, http.StatusCreated},
		// name rules
		{"space name", `{"name":"a b","type":"A","value":"1.2.3.4"}`, http.StatusUnprocessableEntity},
		{"empty label", `{"name":"a..b","type":"A","value":"1.2.3.4"}`, http.StatusUnprocessableEntity},
		{"dash label", `{"name":"-ab","type":"A","value":"1.2.3.4"}`, http.StatusUnprocessableEntity},
		{"huge name", `{"name":"` + strings.Repeat("x", 101) + `","type":"A","value":"1.2.3.4"}`, http.StatusUnprocessableEntity},
		// value rules per type
		{"a with v6", `{"name":"bad1","type":"A","value":"::1"}`, http.StatusUnprocessableEntity},
		{"a garbage", `{"name":"bad2","type":"A","value":"notanip"}`, http.StatusUnprocessableEntity},
		{"aaaa with v4", `{"name":"bad3","type":"AAAA","value":"1.2.3.4"}`, http.StatusUnprocessableEntity},
		{"cname url", `{"name":"bad4","type":"CNAME","value":"https://x.example.net"}`, http.StatusUnprocessableEntity},
		{"cname dash", `{"name":"bad5","type":"CNAME","value":"-bad.example.net"}`, http.StatusUnprocessableEntity},
		{"mx no priority", `{"name":"bad6","type":"MX","value":"mail.example.net"}`, http.StatusUnprocessableEntity},
		{"mx priority range", `{"name":"bad7","type":"MX","value":"mail.example.net","priority":70000}`, http.StatusUnprocessableEntity},
		{"txt too long", `{"name":"bad8","type":"TXT","value":"` + strings.Repeat("x", 256) + `"}`, http.StatusUnprocessableEntity},
		{"txt control", `{"name":"bad9","type":"TXT","value":"one\ntwo"}`, http.StatusUnprocessableEntity},
		{"srv garbage", `{"name":"bad10","type":"SRV","value":"round port are rusted","priority":1}`, http.StatusUnprocessableEntity},
		{"srv no priority", `{"name":"bad11","type":"SRV","value":"5 5060 sip.example.net"}`, http.StatusUnprocessableEntity},
		{"caa flag range", `{"name":"bad12","type":"CAA","value":"999 issue \"letsencrypt.org\""}`, http.StatusUnprocessableEntity},
		{"caa tag", `{"name":"bad13","type":"CAA","value":"0 gamble \"letsencrypt.org\""}`, http.StatusUnprocessableEntity},
		{"unknown type", `{"name":"bad14","type":"WIFI","value":"x"}`, http.StatusUnprocessableEntity},
		{"ttl low", `{"name":"bad15","type":"TXT","value":"x","ttl":30}`, http.StatusUnprocessableEntity},
		{"ttl high", `{"name":"bad16","type":"TXT","value":"x","ttl":90000}`, http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, body := recordCall(t, a, dom, c.body)
			if code != c.want {
				t.Fatalf("want %d, got %d: %s", c.want, code, body)
			}
		})
	}

	// the refusals must not have half-landed: exactly the accepted rows exist
	list := a.must("GET", "/v1/domains/"+dom+"/records", "", http.StatusOK)
	for _, want := range []string{`"type":"A"`, `"type":"AAAA"`, `"type":"MX"`, `"type":"SRV"`, `"type":"CAA"`, `"type":"TXT"`, `"type":"NS"`} {
		if !strings.Contains(list, want) {
			t.Fatalf("accepted %s missing from zone: %s", want, list)
		}
	}
	if got := strings.Count(list, `"id":"`); got != 9 {
		t.Fatalf("want 9 live records, got %d: %s", got, list)
	}
}

// TestRecordCNAMEExclusivity — a CNAME name carries nothing else, and
// deleting the CNAME frees the name again.
func TestRecordCNAMEExclusivity(t *testing.T) {
	_, a, dom := zoneSetup(t)

	if code, body := recordCall(t, a, dom, `{"name":"dual","type":"A","value":"1.2.3.4"}`); code != http.StatusCreated {
		t.Fatalf("a at dual: %d %s", code, body)
	}
	if code, body := recordCall(t, a, dom, `{"name":"dual","type":"CNAME","value":"other.example.net"}`); code != http.StatusConflict {
		t.Fatalf("cname over a: want 409, got %d %s", code, body)
	}
	if code, body := recordCall(t, a, dom, `{"name":"wc","type":"CNAME","value":"other.example.net"}`); code != http.StatusCreated {
		t.Fatalf("cname: %d %s", code, body)
	}
	if code, body := recordCall(t, a, dom, `{"name":"wc","type":"A","value":"1.2.3.4"}`); code != http.StatusConflict {
		t.Fatalf("a over cname: want 409, got %d %s", code, body)
	}

	// deleting frees the name
	cid := ""
	if code, body := a.do("GET", "/v1/domains/"+dom+"/records", ""); code == http.StatusOK {
		var got struct {
			Records []recordRow `json:"records"`
		}
		if err := json.Unmarshal([]byte(body), &got); err != nil {
			t.Fatal(err)
		}
		for _, r := range got.Records {
			if r.Name == "wc" && r.Type == "CNAME" {
				cid = r.ID
			}
		}
	}
	if cid == "" {
		t.Fatal("cname row missing")
	}
	a.must("DELETE", "/v1/domains/"+dom+"/records/"+cid, "", http.StatusOK)
	if code, body := recordCall(t, a, dom, `{"name":"wc","type":"A","value":"1.2.3.4"}`); code != http.StatusCreated {
		t.Fatalf("cname deletion must free the name: %d %s", code, body)
	}
}

// TestRecordPatchAndHistory — type/name immutable, value/ttl/priority
// patchable, history rows create-before-update with old/new values.
func TestRecordPatchAndHistory(t *testing.T) {
	_, a, dom := zoneSetup(t)

	code, body := recordCall(t, a, dom, `{"name":"mx","type":"MX","value":"mail1.example.net","priority":5}`)
	if code != http.StatusCreated {
		t.Fatalf("mx create: %d %s", code, body)
	}
	rid := recordID(t, body)

	// value patch keeps the stored priority
	code, body = a.do("PATCH", "/v1/domains/"+dom+"/records/"+rid,
		`{"value":"mail2.example.net"}`)
	if code != http.StatusOK {
		t.Fatalf("value patch: %d %s", code, body)
	}
	var got struct {
		Record recordRow `json:"record"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Record.Value != "mail2.example.net" || got.Record.Priority == nil || *got.Record.Priority != 5 {
		t.Fatalf("patched mx wrong: %+v", got.Record)
	}

	// unknown fields are refused outright (name/type immutability)
	if code, _ := a.do("PATCH", "/v1/domains/"+dom+"/records/"+rid, `{"name":"other"}`); code != http.StatusBadRequest {
		t.Fatalf("name in patch: want 400, got %d", code)
	}
	// invalid value: state untouched
	if code, _ := a.do("PATCH", "/v1/domains/"+dom+"/records/"+rid, `{"value":"1.2.3.4","ttl":300}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("v4 into mx: want 422, got %d", code)
	}
	// priority-only patch
	if code, body := a.do("PATCH", "/v1/domains/"+dom+"/records/"+rid, `{"priority":10}`); code != http.StatusOK || !strings.Contains(body, `"priority":10`) {
		t.Fatalf("priority patch: %d %s", code, body)
	}

	// history: create then two updates, old/new in order
	view := a.must("GET", "/v1/domains/"+dom+"/records/"+rid, "", http.StatusOK)
	if strings.Count(view, `"action":"create"`) != 1 || strings.Count(view, `"action":"update"`) != 2 {
		t.Fatalf("history wrong: %s", view)
	}
	if !strings.Contains(view, `"old_value":"mail1.example.net"`) || !strings.Contains(view, `"new_value":"mail2.example.net"`) {
		t.Fatalf("history values wrong: %s", view)
	}

	// delete: row gone, id 404s afterwards, history rows stay in the table
	a.must("DELETE", "/v1/domains/"+dom+"/records/"+rid, "", http.StatusOK)
	if code, _ := a.do("GET", "/v1/domains/"+dom+"/records/"+rid, ""); code != http.StatusNotFound {
		t.Fatalf("deleted record get: %d", code)
	}
	if got := a.must("GET", "/v1/domains/"+dom+"/records", "", http.StatusOK); strings.Contains(got, `"mail1.example.net"`) {
		t.Fatalf("deleted value still listed: %s", got)
	}
}

// TestRecordZoneRules — the per-zone cap, cname domains have no records,
// and the zone row actually exists per nameserver claim.
func TestRecordZoneRules(t *testing.T) {
	pool := testPool(t)
	a, _ := newTestServer(t, pool, func(cfg *Config) {
		nsc := nsCfg(true)
		nsc(cfg)
		cfg.MaxRecords = 2
	})
	signupOn(t, pool, a, "cap@x.test")
	_, dom := regNS(t, a, "cap")

	if code, _ := recordCall(t, a, dom, `{"name":"one","type":"A","value":"1.2.3.4"}`); code != http.StatusCreated {
		t.Fatal("r1")
	}
	if code, _ := recordCall(t, a, dom, `{"name":"two","type":"A","value":"1.2.3.5"}`); code != http.StatusCreated {
		t.Fatal("r2")
	}
	if code, body := recordCall(t, a, dom, `{"name":"three","type":"A","value":"1.2.3.6"}`); code != http.StatusUnprocessableEntity {
		t.Fatalf("cap: want 422, got %d %s", code, body)
	}

	// a cname-mode claim has no zone: records management is refused
	cn := claimRow(t, a, strings.ToLower("cn-dom-"+randHex(t, 3))+".example.com")
	if code, body := recordCall(t, a, cn.ID, `{"name":"@","type":"A","value":"1.2.3.4"}`); code != http.StatusConflict {
		t.Fatalf("cname domain records: want 409, got %d %s", code, body)
	}

	// foreign user sees nothing (full table coverage is the item-13 test)
	b := secondUser(t, pool, a, "zone-b@x.test")
	if code, _ := b.do("GET", "/v1/domains/"+dom+"/records", ""); code != http.StatusNotFound {
		t.Fatalf("foreign list: want 404, got %d", code)
	}
	if code, _ := b.do("POST", "/v1/domains/"+dom+"/records", `{"name":"@","type":"A","value":"1.2.3.4"}`); code != http.StatusNotFound {
		t.Fatalf("foreign create: want 404, got %d", code)
	}
}
