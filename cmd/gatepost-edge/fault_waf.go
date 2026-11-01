//go:build gatepost_edge_fault

package main

import (
	"os"
	"strings"
)

// faultWAFDirectives is the fault-only hook compiled with
// -tags gatepost_edge_fault (never in the production image): when the fault
// file named by GP_EDGE_FAULT_WAF_FILE exists, its contents replace the
// generated WAF directives — an invalid SecAction makes Caddy reject the
// whole config with a 400, which drives applyConfigWithFallback. Deleting
// the file makes the next snapshot valid again (the auto-resolve case) with
// no restart. Production builds never see this symbol.
func faultWAFDirectives(generated string) string {
	path := os.Getenv("GP_EDGE_FAULT_WAF_FILE")
	if path == "" {
		return generated
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return generated // no fault file: pass the real directives through
	}
	return strings.TrimSpace(string(b))
}
