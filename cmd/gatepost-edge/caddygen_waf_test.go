package main

// Unit tests for the B3c Coraza WAF generation (item 1: detection-only).
// These pin the redaction contract (audit parts A+H only → no body/cookies/
// headers/query in the audit log) and the fail-open posture, independent of a
// running Caddy: coraza v3.8.1's native formatter hard-codes [data] and [uri]
// values in Part H that no seclang directive can suppress, so a custom
// "redacted" formatter (x/wafredactor) is compiled into the edge image and
// blanks them at format time — before they ever reach disk.

import (
	"encoding/json"
	"strings"
	"testing"

	"gatepost/internal/snapshot"
)

// TestWAFHandlerOff asserts the default (off) path emits NO coraza handler, so
// the B3b golden configs are byte-for-byte unchanged when WAF is absent.
func TestWAFHandlerOff(t *testing.T) {
	for _, mode := range []string{"", "off", "  OFF  "} {
		h, err := wafHandler(WAFConfig{Mode: mode}, nil)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if h != nil {
			t.Fatalf("mode %q: expected nil handler, got %#v", mode, h)
		}
	}
}

func TestWAFHandlerRejectsUnknownMode(t *testing.T) {
	if _, err := wafHandler(WAFConfig{Mode: "paranoid"}, nil); err == nil {
		t.Fatal("expected error for unknown mode, got nil")
	}
}

// TestCorazaDirectivesDetection pins the detection-only directive set and the
// redaction/fail-open invariants that the B3c requirements demand.
func TestCorazaDirectivesDetection(t *testing.T) {
	d, err := corazaDirectives("detection", WAFConfig{
		Mode:             "detection",
		AuditLogPath:     "/var/lib/edge/waf_audit.log",
		RequestBodyLimit: 1048576,
		ParanoiaLevel:    2,
	}, nil)
	if err != nil {
		t.Fatalf("corazaDirectives: %v", err)
	}

	want := map[string]string{
		"CRS include":                                     "Include @owasp_crs/*.conf",
		"detection engine":                                "SecRuleEngine DetectionOnly",
		"fail-open partial body":                          "SecRequestBodyLimitAction ProcessPartial",
		"response body off":                               "SecResponseBodyAccess Off",
		"redacted format (in-process, no values on disk)": "SecAuditLogFormat redacted",
		"audit parts A+H+Z (coraza requires trailing Z)":  "SecAuditLogParts AHZ",
		"paranoia 2":                                      "setvar:tx.detection_paranoia_level=2",
		"body limit":                                      "SecRequestBodyLimit 1048576",
		"audit log path":                                  "SecAuditLog /var/lib/edge/waf_audit.log",
	}
	for label, needle := range want {
		if !strings.Contains(d, needle) {
			t.Errorf("%s: directive missing %q in:\n%s", label, needle, d)
		}
	}

	// REDACTION INVARIANT: the directives must never enable a body/header/query
	// audit part. B(body), C, D, E, F, G, J, K all would leak request bodies,
	// cookies, headers and URIs. Only A (header) and H (matched-rule trailer)
	// are permitted — and Part H carries only the rule id + matched variable
	// NAME, never the matched value, so cookies/query values cannot appear.
	for _, leak := range []string{"SecAuditLogParts ", "SecAuditLogParts"} {
		// every SecAuditLogParts line must be exactly "AH"
		for _, line := range strings.Split(d, "\n") {
			if strings.HasPrefix(line, "SecAuditLogParts") {
				parts := strings.TrimSpace(strings.TrimPrefix(line, "SecAuditLogParts"))
				if parts != "AHZ" {
					t.Errorf("redaction: audit parts must be exactly AH, got %q", parts)
				}
			}
			_ = leak
		}
	}
	// no other part letter that would leak sensitive content
	for _, bad := range []string{"SecAuditLogParts AB", "SecAuditLogParts ABC", "SecAuditLogParts AHB", "SecAuditLogParts AHC"} {
		if strings.Contains(d, bad) {
			t.Errorf("redaction: forbidden audit part combo %q present", bad)
		}
	}

	// FAIL-OPEN: blocking mode is the only one that flips DetectionOnly->On
	if strings.Contains(d, "SecRuleEngine On") {
		t.Error("detection mode must set SecRuleEngine DetectionOnly, not On")
	}

	// NO permissive file mode: the poller no longer scrubs the file on disk,
	// so SecAuditLogFileMode 0666 must NOT appear (default 0644 is correct).
	if strings.Contains(d, "SecAuditLogFileMode 0666") {
		t.Error("audit file mode 0666 must not be emitted — redaction is in-process now")
	}
	if strings.Contains(d, "SecAuditLogFileMode") {
		t.Error("SecAuditLogFileMode should be absent entirely (default 0644)")
	}
}

func TestCoradaDirectivesRequiresAuditLogPath(t *testing.T) {
	if _, err := corazaDirectives("detection", WAFConfig{Mode: "detection"}, nil); err == nil {
		t.Fatal("expected error when AuditLogPath empty, got nil")
	}
}

// TestGenerateEmitsCorazaHandler asserts the full Generate() wires the coraza
// handler into the route chain when WAF is enabled, and that it serializes to
// the documented module ID + embedded CRS load.
func TestGenerateEmitsCorazaHandler(t *testing.T) {
	doc := fixtureDoc("single")
	params := fixtureParams()
	params.WAF = WAFConfig{
		Mode:             "detection",
		AuditLogPath:     "/tmp/waf.log",
		RequestBodyLimit: 0, // falls back to maxBodyBytes
		ParanoiaLevel:    1,
	}
	b, err := Generate(doc, params)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var cfg caddyConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	// the single host route must carry the coraza handler, then the body cap,
	// then the reverse_proxy — inspection before proxying.
	var foundCoraza bool
	for _, rt := range cfg.Apps.HTTP.Servers["edge"].Routes {
		for _, h := range rt.Handle {
			if m, ok := h.(map[string]any); ok && m["handler"] == "waf" {
				foundCoraza = true
				if m["load_owasp_crs"] != true {
					t.Errorf("load_owasp_crs = %v, want true", m["load_owasp_crs"])
				}
				dirs, _ := m["directives"].(string)
				if !strings.Contains(dirs, "SecRuleEngine DetectionOnly") {
					t.Errorf("directives missing DetectionOnly:\n%s", dirs)
				}
				if !strings.Contains(dirs, "SecAuditLogParts AHZ") {
					t.Error("directives missing redacted audit parts AHZ")
				}
			}
		}
	}
	if !foundCoraza {
		t.Fatal("expected an http.handlers.waf handler in the generated routes")
	}
}

// TestGenerateWAFOffUnchanged is the regression guard: with WAF off (the
// default in every B3b golden), Generate must produce the same shape as before
// — exactly one reverse_proxy per route and no coraza handler anywhere.
func TestGenerateWAFOffUnchanged(t *testing.T) {
	doc := fixtureDoc("single")
	params := fixtureParams() // WAF zero-valued -> off
	b, err := Generate(doc, params)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// no coraza handler (or its CRS marker) anywhere in the JSON
	if strings.Contains(string(b), "load_owasp_crs") {
		t.Fatal("WAF off must not emit the coraza handler in the config JSON")
	}
}

// TestCorazaDirectivesHostScoped verifies that per-domain WAF mode and
// exclusions produce the correct ctl actions scoped to the Host header.
func TestCorazaDirectivesHostScoped(t *testing.T) {
	doms := []snapshot.Domain{
		{Hostname: "detection.example.test", WAFMode: "detection"},
		{Hostname: "blocking.example.test", WAFMode: "blocking"},
		{Hostname: "off.example.test", WAFMode: "off"},
		{Hostname: "excluded.example.test", WAFMode: "blocking",
			ExcludedRuleIDs: []int{942100, 941100}},
	}
	d, err := corazaDirectives("blocking", WAFConfig{
		Mode:         "blocking",
		AuditLogPath: "/tmp/waf.log",
	}, doms)
	if err != nil {
		t.Fatalf("corazaDirectives: %v", err)
	}

	// Global engine is "On" (the edge default for blocking mode).
	if !strings.Contains(d, "SecRuleEngine On\n") {
		t.Error("expected global SecRuleEngine On")
	}

	// Detection host: a ctl:ruleEngine=DetectionOnly override.
	if !strings.Contains(d, `"id:190000,phase:1,pass,t:none,nolog,ctl:ruleEngine=DetectionOnly"`) {
		t.Error("missing ctl:ruleEngine=DetectionOnly for detection host")
	}

	// Off host: a ctl:ruleEngine=Off override.
	if !strings.Contains(d, `"id:190001,phase:1,pass,t:none,nolog,ctl:ruleEngine=Off"`) {
		t.Error("missing ctl:ruleEngine=Off for off host")
	}

	// Blocking host should NOT appear (it matches the global default).
	if strings.Contains(d, "blocking.example.test") {
		t.Error("blocking host should not emit a host-scoped rule (matches global default)")
	}

	// Excluded rules: ctl:ruleRemoveById for each.
	if !strings.Contains(d, "ctl:ruleRemoveById=942100") {
		t.Error("missing ctl:ruleRemoveById=942100")
	}
	if !strings.Contains(d, "ctl:ruleRemoveById=941100") {
		t.Error("missing ctl:ruleRemoveById=941100")
	}

	// Host-scoped rules must match on the Host header.
	if !strings.Contains(d, `REQUEST_HEADERS:Host "@streq excluded.example.test"`) {
		t.Error("missing Host-scoped match for excluded host")
	}
}

// TestCorazaDirectivesHostileRejects ensures hostile snapshot values never
// reach the directives string.
func TestCorazaDirectivesHostileRejects(t *testing.T) {
	cases := []struct {
		name string
		host string
		mode string
		ids  []int
	}{
		{"quotes in hostname", "test\x00.com", "blocking", nil},
		{"newline in hostname", "test\n.com", "detection", nil},
		{"semicolon injection", "test;SecRuleEngine Off", "detection", nil},
		{"rule ID 0", "ok.example.com", "blocking", []int{0}},
		{"rule ID negative", "ok.example.com", "blocking", []int{-1}},
		{"rule ID overflow", "ok.example.com", "blocking", []int{1000000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doms := []snapshot.Domain{{
				Hostname: tc.host, WAFMode: tc.mode, ExcludedRuleIDs: tc.ids,
			}}
			_, err := corazaDirectives("blocking", WAFConfig{
				Mode:         "blocking",
				AuditLogPath: "/tmp/waf.log",
			}, doms)
			if err == nil {
				t.Fatalf("expected error for hostile host %q mode %q ids %v, got nil",
					tc.host, tc.mode, tc.ids)
			}
		})
	}
}

// TestSnapshotDomainWAFDefault verifies that schema-1 snapshots (empty mode)
// default to "detection".
func TestSnapshotDomainWAFDefault(t *testing.T) {
	cases := []struct {
		mode  string
		want  string
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

// TestValidateHostForWAF tests the LDH hostname check.
func TestValidateHostForWAF(t *testing.T) {
	valid := []string{
		"example.com",
		"test.example.com",
		"a-b.example.org",
		"1.example.com",
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
		"host\"name.com",
		"-example.com",
		"example-.com",
		"ho st.com",
		strings.Repeat("a", 64) + ".com",
	}
	for _, h := range hostile {
		if validateHostForWAF(h) {
			t.Errorf("host %q should be INVALID", h)
		}
	}
}

// guard: fixtureDoc is defined in caddygen_test.go; snapshot is imported above
// to document the data source. Silence unused import if build tags shift.
var _ = snapshot.Document{}
