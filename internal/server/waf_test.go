// B3c item 2: tests for per-domain WAF validation.
package server

import (
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
