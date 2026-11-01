//go:build !gatepost_edge_fault

package main

// faultWAFDirectives is a no-op without the gatepost_edge_fault build tag:
// the generated WAF directives pass through untouched.
func faultWAFDirectives(generated string) string { return generated }
