// Package wafredactor registers a Coraza audit-log formatter ("redacted") that
// reproduces coraza v3.8.1's native format byte-for-byte but blanks the two
// value-bearing fields in Part H that no seclang directive can suppress:
//
//	[data "Matched Data: <value> found within ARGS:key: <value>"]
//	[uri "/path?query"]
//
// coraza's nativeFormatter writes ErrorMessage() verbatim (escaping only CR/LF
// for log-forgery safety, never redacting values), and corala-caddy v2.6.2
// exposes no audit filter hook. This formatter runs in-process at format time
// (compiled into the edge image via xcaddy --with), so no request-derived
// value or URI query ever reaches the audit file.
package wafredactor

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// auditLogWithErrMesg mirrors coraza's internal interface (internal/auditlog/
// formats.go) so we can call ErrorMessage() — the native Part H line that
// carries [data "..."] and [uri "..."] with attacker-controlled values.
type auditLogWithErrMesg interface{ ErrorMessage() string }

// auditValueRe matches [data "..."] and [uri "..."] in a ModSecurity-style
// trailer line. coraza serializes these as Go %-quoted strings (%q), so inner
// quotes/backslashes are escaped as \". The (?:[^"\\]|\\.)* subpattern consumes
// either a non-quote/non-backslash byte or any escaped byte pair, ensuring
// hostile values containing quotes, brackets, newlines or very long strings
// cannot break out of the quoted span.
var auditValueRe = regexp.MustCompile(`\[(data|uri) "(?:[^"\\]|\\.)*"\]`)

// logEscaper mirrors coraza's nativeFormatter escaping (GHSA-prpw-wwv7-xjjr)
// so the redacted formatter output matches native byte-for-byte except for the
// blanked [data]/[uri] fields.
var logEscaper = strings.NewReplacer(`\`, `\\`, "\r", `\r`, "\n", `\n`)

func init() {
	plugins.RegisterAuditLogFormatter("redacted", &redactedNativeFormatter{})
}

// redactedNativeFormatter produces Native-format audit output identical to
// coraza's "native" formatter, except Part H's [data "..."] and [uri "..."]
// are emitted as [data ""] and [uri ""] — blanking the matched value and the
// URI query so the audit log contains only: timestamp, transaction id,
// client IP, host, rule id, severity, action and variable NAMES (e.g.
// ARGS:id) — never a request-derived value, never a URI query string.
type redactedNativeFormatter struct{}

func (f *redactedNativeFormatter) Format(al plugintypes.AuditLog) ([]byte, error) {
	if len(al.Parts()) == 0 {
		return nil, nil
	}

	boundaryPrefix := "--" + randomBoundary() + "-"
	var res strings.Builder

	for _, part := range al.Parts() {
		res.WriteString(boundaryPrefix)
		res.WriteByte(byte(part))
		res.WriteString("--\n")

		switch part {
		case types.AuditLogPartHeader:
			tx := al.Transaction()
			// Part A: timestamp + txid + client IP/port + server IP/port (no HTTP data)
			fmt.Fprintf(&res, "[%s] %s %s %d %s %d\n",
				tx.Timestamp(),
				logEscaper.Replace(tx.ID()),
				logEscaper.Replace(tx.ClientIP()),
				tx.ClientPort(),
				logEscaper.Replace(tx.HostIP()),
				tx.HostPort())
		case types.AuditLogPartAuditLogTrailer:
			// Part H: matched-rule trailer. ErrorMessage() carries [data "..."]
			// and [uri "..."] with attacker-controlled values — sanitize them.
			for _, alEntry := range al.Messages() {
				if alWithErrMsg, ok := alEntry.(auditLogWithErrMesg); ok && alWithErrMsg.ErrorMessage() != "" {
					res.WriteString(sanitizeLine(logEscaper.Replace(alWithErrMsg.ErrorMessage())))
					res.WriteByte('\n')
				}
			}
		case types.AuditLogPartEndMarker:
			// Part Z: empty terminator (coraza requires the parts string to end with Z)
		}
	}

	return []byte(res.String()), nil
}

func (f *redactedNativeFormatter) MIME() string {
	return "application/x-coraza-auditlog-native-redacted"
}

// sanitizeLine blanks [data "..."] and [uri "..."] in a ModSecurity trailer
// line. Handles hostile values (quotes, brackets, newlines via logEscaper,
// non-ASCII, very long strings) because the regex matches Go %-quoted escaped
// strings: (?:[^"\\]|\\.)* consumes either a non-quote/non-backslash byte or
// any escaped byte pair, so no value can break out of the quoted span.
func sanitizeLine(line string) string {
	return auditValueRe.ReplaceAllString(line, "[$1 \"\"]")
}

// randomBoundary returns a deterministic 16-char string for the audit boundary.
// coraza uses crypto/rand; we use FNV-1a so Format() output is reproducible in
// tests (and the real edge does not depend on randomness in the audit format).
func randomBoundary() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	h := fnv1a([]byte("waf-redactor"))
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[int(h%uint64(len(letters)))]
		h *= 1099511628217
	}
	return string(b)
}

// fnv1a: FNV-1a 64-bit (offset basis 14695981039649018699, prime 1099511628217).
func fnv1a(b []byte) uint64 {
	h := uint64(14695981039649018699)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628217
	}
	return h
}
