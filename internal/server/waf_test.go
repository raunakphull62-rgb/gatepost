// B3c item 2: tests for per-domain WAF validation.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"gatepost/internal/snapshot"
)

func TestCheckWAF(t *testing.T) {
	cases := []struct {
		name    string
		mode    string
		ids     []int
		wantMsg string
	}{
		{"empty mode defaults to detection (no error)", "", nil, ""},
		{"valid detection", "detection", nil, ""},
		{"valid blocking", "blocking", nil, ""},
		{"valid off", "off", nil, ""},
		{"invalid mode", "paranoid", nil, "mode must be"},
		{"rule ID zero", "blocking", []int{0}, "out of range"},
		{"rule ID negative", "blocking", []int{-1}, "out of range"},
		{"rule ID overflow", "blocking", []int{1000000}, "out of range"},
		{"valid rule IDs", "blocking", []int{1, 942100, 999999}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := checkWAF(wafBody{Mode: tc.mode, ExcludedRuleIDs: tc.ids})
			if tc.wantMsg == "" && msg != "" {
				t.Errorf("expected no error, got %q", msg)
			}
			if tc.wantMsg != "" && !strings.Contains(msg, tc.wantMsg) {
				t.Errorf("expected error containing %q, got %q", tc.wantMsg, msg)
			}
		})
	}
}

func TestValidateHostForWAF(t *testing.T) {
	valid := []string{
		"example.com",
		"test.example.com",
		"a-b.example.org",
		"sub.domain.example.co.uk",
	}
	for _, h := range valid {
		if !validateHostForWAF(h) {
			t.Errorf("host %q should be valid", h)
		}
	}
	hostile := []string{
		"",
		"host\x00name.com",
		"host\nname.com",
		"host\rname.com",
		"host\"name.com",
		"host\\name.com",
		"-example.com",
		"example-.com",
		"ho st.com",
		strings.Repeat("a", 64) + ".com",
		"UPPER.example.com",
		"host_underscore.example.com",
	}
	for _, h := range hostile {
		if validateHostForWAF(h) {
			t.Errorf("host %q should be INVALID", h)
		}
	}
}

func TestSnapshotDomainWAF(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{"", "detection"},
		{"detection", "detection"},
		{"blocking", "blocking"},
		{"off", "off"},
		{"INVALID", "detection"},
	}
	for _, tc := range cases {
		d := snapshot.Domain{Hostname: "test.example.com", WAFMode: tc.mode}
		if got := snapshotDomainWAF(d); got != tc.want {
			t.Errorf("mode %q: got %q, want %q", tc.mode, got, tc.want)
		}
	}
}

// TestPutWAFNilExclusions — a PUT body without excluded_rule_ids decodes to
// a nil slice; the handler must coerce it to an empty array before the NOT NULL
// column, otherwise the UPDATE fails with 500.
func TestPutWAFNilExclusions(t *testing.T) {
	pool := testPool(t)
	c, _ := newTestServer(t, pool)
	signupOn(t, pool, c, "waf-nil@x.test")
	dom := claimRow(t, c, "waf-nil.example.com")

	// mode only, no excluded_rule_ids in the body → nil slice
	code, body := c.do("PUT", "/v1/domains/"+dom.ID+"/waf", `{"mode":"blocking"}`)
	if code != http.StatusOK {
		t.Fatalf("WAF PUT (nil exclusions): want 200, got %d: %s", code, body)
	}
	// the stored value must be an empty array, not NULL
	var resp struct {
		Domain domainRow `json:"domain"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("response json: %v: %s", err, body)
	}
	if resp.Domain.ExcludedRuleIDs == nil || len(resp.Domain.ExcludedRuleIDs) != 0 {
		t.Fatalf("excluded_rule_ids should be empty, got %v", resp.Domain.ExcludedRuleIDs)
	}
	if resp.Domain.WAFMode != "blocking" {
		t.Fatalf("waf_mode should be blocking, got %q", resp.Domain.WAFMode)
	}

	// verify via direct DB read too
	var wafMode string
	var ids []int
	if err := pool.QueryRow(context.Background(),
		`SELECT waf_mode, excluded_rule_ids FROM domains WHERE id::text = $1`, dom.ID).
		Scan(&wafMode, &ids); err != nil {
		t.Fatal(err)
	}
	if wafMode != "blocking" {
		t.Errorf("DB waf_mode = %q, want blocking", wafMode)
	}
	if ids == nil || len(ids) != 0 {
		t.Errorf("DB excluded_rule_ids = %v, want empty", ids)
	}
}

// TestPutWAFValidationAndIsolation tests the API requirements from item 4:
// - another user's domain gives 404
// - bad mode gives 400
// - rule id outside 1..999999 gives 400
func TestPutWAFValidationAndIsolation(t *testing.T) {
	pool := testPool(t)
	c1, _ := newTestServer(t, pool)
	signupOn(t, pool, c1, "waf-user1@x.test")
	dom1 := claimRow(t, c1, "waf-user1.example.com")

	c2, _ := newTestServer(t, pool)
	signupOn(t, pool, c2, "waf-user2@x.test")

	// 1. Another user's domain gives 404 (tenant isolation)
	code, body := c2.do("PUT", "/v1/domains/"+dom1.ID+"/waf", `{"mode":"blocking"}`)
	if code != http.StatusNotFound {
		t.Fatalf("another user's domain: want 404, got %d: %s", code, body)
	}

	// 2. Bad mode gives 400
	code, body = c1.do("PUT", "/v1/domains/"+dom1.ID+"/waf", `{"mode":"invalid_mode"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("bad mode: want 400, got %d: %s", code, body)
	}

	// 3. Rule ID outside 1..999999 gives 400
	for _, badID := range []int{0, -1, 1000000} {
		payload, _ := json.Marshal(map[string]any{
			"mode":              "blocking",
			"excluded_rule_ids": []int{badID},
		})
		code, body = c1.do("PUT", "/v1/domains/"+dom1.ID+"/waf", string(payload))
		if code != http.StatusBadRequest {
			t.Fatalf("rule ID %d: want 400, got %d: %s", badID, code, body)
		}
	}

	// 4. Valid mode and rules give 200
	code, body = c1.do("PUT", "/v1/domains/"+dom1.ID+"/waf", `{"mode":"blocking","excluded_rule_ids":[942100]}`)
	if code != http.StatusOK {
		t.Fatalf("valid WAF PUT: want 200, got %d: %s", code, body)
	}
}
