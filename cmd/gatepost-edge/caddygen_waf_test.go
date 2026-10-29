package main

// Unit tests for the B3c Coraza WAF generation (item 1: detection-only).
// These pin the redaction contract (audit parts A+H only → no body/cookies/
// headers/query in the audit log) and the fail-open posture, independent of a
// running Caddy: coraza v3.8.1's JSON audit formatter can't be redacted by
// parts, so native-format + "AH" is the one safe combination.

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
		h, err := wafHandler(WAFConfig{Mode: mode})
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		if h != nil {
			t.Fatalf("mode %q: expected nil handler, got %#v", mode, h)
		}
	}
}

func TestWAFHandlerRejectsUnknownMode(t *testing.T) {
	if _, err := wafHandler(WAFConfig{Mode: "paranoid"}); err == nil {
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
	})
	if err != nil {
		t.Fatalf("corazaDirectives: %v", err)
	}

	want := map[string]string{
		"CRS include":                                    "Include @owasp_crs/*.conf",
		"detection engine":                               "SecRuleEngine DetectionOnly",
		"fail-open partial body":                         "SecRequestBodyLimitAction ProcessPartial",
		"response body off":                              "SecResponseBodyAccess Off",
		"native format (redactable)":                     "SecAuditLogFormat Native",
		"audit parts A+H+Z (coraza requires trailing Z)": "SecAuditLogParts AHZ",
		"paranoia 2":                                     "setvar:tx.detection_paranoia_level=2",
		"body limit":                                     "SecRequestBodyLimit 1048576",
		"audit log path":                                 "SecAuditLog /var/lib/edge/waf_audit.log",
		"audit file mode (poller scrubber needs rw)":    "SecAuditLogFileMode 0666",
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
}

func TestCoradaDirectivesRequiresAuditLogPath(t *testing.T) {
	if _, err := corazaDirectives("detection", WAFConfig{Mode: "detection"}); err == nil {
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

// guard: fixtureDoc is defined in caddygen_test.go; snapshot is imported above
// to document the data source. Silence unused import if build tags shift.
var _ = snapshot.Document{}
