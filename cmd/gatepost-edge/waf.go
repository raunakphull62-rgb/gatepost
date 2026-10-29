// B3c item 2: per-domain WAF helpers for the edge (shared with the API server
// in internal/server/waf.go, but duplicated here because the edge package
// (package main) does not import the API server package).
package main

import (
	"strings"

	"gatepost/internal/snapshot"
)

var validWAFModes = map[string]bool{
	"off":       true,
	"detection": true,
	"blocking":  true,
}

// validateHostForWAF checks that a hostname is safe to embed in a coraza
// SecRule match: strict LDH labels, no quotes, no newlines, no control chars.
// Runs at generation time on snapshot domains (already normalized at claim
// time), but belt-and-suspenders: a hostile snapshot value never reaches the
// directives string.
func validateHostForWAF(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, "\"\r\n\x00\\") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// snapshotDomainWAF returns the WAF mode for a domain, defaulting to
// "detection" for old schema-1 snapshots that omit the field.
func snapshotDomainWAF(d snapshot.Domain) string {
	if d.WAFMode == "" {
		return "detection"
	}
	if !validWAFModes[d.WAFMode] {
		return "detection"
	}
	return d.WAFMode
}
