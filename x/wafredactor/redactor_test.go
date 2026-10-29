package wafredactor

import (
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
	"github.com/corazawaf/coraza/v3/types"
)

// mockAuditLog implements plugintypes.AuditLog for testing.
type mockAuditLog struct {
	parts    types.AuditLogParts
	tx       *mockTransaction
	msgs     []*mockMessage
}

func (m *mockAuditLog) Parts() types.AuditLogParts           { return m.parts }
func (m *mockAuditLog) Transaction() plugintypes.AuditLogTransaction { return m.tx }
func (m *mockAuditLog) Messages() []plugintypes.AuditLogMessage  {
	out := make([]plugintypes.AuditLogMessage, len(m.msgs))
	for i, msg := range m.msgs {
		out[i] = msg
	}
	return out
}

type mockTransaction struct {
	timestamp  string
	id, clientIP, hostIP string
	clientPort, hostPort int
}

func (m *mockTransaction) Timestamp() string   { return m.timestamp }
func (m *mockTransaction) UnixTimestamp() int64 { return 0 }
func (m *mockTransaction) ID() string          { return m.id }
func (m *mockTransaction) ClientIP() string    { return m.clientIP }
func (m *mockTransaction) ClientPort() int      { return m.clientPort }
func (m *mockTransaction) HostIP() string      { return m.hostIP }
func (m *mockTransaction) HostPort() int        { return m.hostPort }
func (m *mockTransaction) ServerID() string     { return "" }
func (m *mockTransaction) Request() plugintypes.AuditLogTransactionRequest { return nil }
func (m *mockTransaction) HasRequest() bool     { return false }
func (m *mockTransaction) Response() plugintypes.AuditLogTransactionResponse { return nil }
func (m *mockTransaction) HasResponse() bool    { return false }
func (m *mockTransaction) Producer() plugintypes.AuditLogTransactionProducer { return nil }
func (m *mockTransaction) HighestSeverity() string { return "" }
func (m *mockTransaction) IsInterrupted() bool   { return false }

// mockMessage implements both plugintypes.AuditLogMessage and the
// auditLogWithErrMesg interface (ErrorMessage()), matching coraza's
// internal Message type that the native formatter uses for Part H.
type mockMessage struct {
	errMsg string
}

func (m *mockMessage) Actionset() string { return "" }
func (m *mockMessage) Message() string   { return "" }
func (m *mockMessage) Data() plugintypes.AuditLogMessageData { return nil }
func (m *mockMessage) ErrorMessage() string { return m.errMsg }

// nativePartH builds a realistic coraza native-format Part H line with a
// secret planted in the [data] and [uri] fields — mimicking what
// MatchedRule.ErrorLog() produces (GHSA-prpw-wwv7-xjjr escapes CR/LF only).
func nativePartH(secret, id, msg, path string) string {
	return `[client "10.0.0.1"] Coraza: Warning. ` + msg + ` [file "x"] [line "1"] [id ` + `"` + id + `"] [rev ""] [msg ` + `"` + msg + `"] [data ` + `"` + `Matched Data: ` + secret + ` found within ARGS:id: ` + secret + `"] [severity "CRITICAL"] [ver "OWASP_CRS/4.25.0"] [maturity "0"] [accuracy "0"] [tag "attack-sqli"] [hostname ""] [uri ` + `"` + path + `"] [unique_id "txid-123"]`
}

// --- Tests for requirements (1) watcher / redaction proof, (2) hostile values ---

// TestRedactionBlanksValues is the core redaction contract (test 3: 5-position):
// the matched-data VALUE and the URI query must not appear in the formatted
// output. Simulates a full Part A+H+Z audit entry with a planted secret.
func TestRedactionBlanksValues(t *testing.T) {
	secret := "SUPER-SECRET-Z-12345"
	errMsg := nativePartH(secret, "942100", "SQL Injection", "/ok?id="+secret)
	al := &mockAuditLog{
		parts: types.AuditLogParts{types.AuditLogPartHeader, types.AuditLogPartAuditLogTrailer, types.AuditLogPartEndMarker},
		tx: &mockTransaction{
			timestamp:  "2026/10/29 05:00:00",
			id:         "txid-123",
			clientIP:   "10.0.0.1",
			clientPort: 54321,
			hostIP:     "10.0.0.2",
			hostPort:   443,
		},
		msgs: []*mockMessage{{errMsg: errMsg}},
	}
	f := &redactedNativeFormatter{}
	out, err := f.Format(al)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	// The secret must NEVER appear — not in [data], not in [uri], nowhere.
	if strings.Contains(got, secret) {
		t.Errorf("secret leaked into audit output:\n%s", got)
	}
	// The query string (the "?" and everything after) must not appear in [uri].
	if strings.Contains(got, "?id=") {
		t.Errorf("query string leaked:\n%s", got)
	}
	// [data ""] and [uri ""] blanks must be present.
	if !strings.Contains(got, `[data ""]`) {
		t.Errorf("[data] not blanked:\n%s", got)
	}
	if !strings.Contains(got, `[uri ""]`) {
		t.Errorf("[uri] not blanked:\n%s", got)
	}
	// Allowed fields must still be present.
	for _, keep := range []string{`[id "942100"]`, `[severity "CRITICAL"]`, `[msg "SQL Injection"]`, `[unique_id "txid-123"]`, `[client "10.0.0.1"]`} {
		if !strings.Contains(got, keep) {
			t.Errorf("allowed field dropped: %q in output:\n%s", keep, got)
		}
	}
}

// TestRedactionHostileValues (test 2): the regex must handle quotes, brackets,
// newlines (logEscaper), non-ASCII, and very long strings inside [data]/[uri].
func TestRedactionHostileValues(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{
			name: "escaped quotes inside value",
			line: `[data "Matched Data: \"evil\" found within ARGS:id: secret-val"]`,
		},
		{
			name: "brackets inside value",
			line: `[uri "/path?q=[evil]bracket"]`,
		},
		{
			name: "CR/LF escaped by logEscaper",
			line: `[data "Matched Data: \r\n injected line"]`,
		},
		{
			name: "non-ASCII unicode",
			line: `[data "Matched Data: \xe2\x9c\x93 unicode value"]`,
		},
		{
			name: "very long string",
			line: `[data "Matched Data: ` + strings.Repeat("A", 10000) + ` found within ARGS:id"]`,
		},
		{
			name: "backslash escape",
			line: `[uri "/ok?secret=ab\\\"cd]`,
		},
		{
			name: "trailing content after closing bracket",
			line: `[data "Matched Data: SECRET found within ARGS"] [uri "/p?q=SECRET"]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeLine(tc.line)
			if strings.Contains(got, "SECRET") {
				t.Errorf("value leaked for %s: got %s", tc.name, got)
			}
			if strings.Contains(got, "evil-val") {
				t.Errorf("inner value leaked for %s: got %s", tc.name, got)
			}
			if strings.Contains(got, "evil") {
				t.Errorf("inner value leaked for %s: got %s", tc.name, got)
			}
			if strings.Contains(got, "injected line") {
				t.Errorf("newline-broken value leaked for %s: got %s", tc.name, got)
			}
			if strings.Contains(got, "?q=") {
				t.Errorf("query leaked for %s: got %s", tc.name, got)
			}
		})
	}
}

// TestRedactionNoQuestionMark: a continuous watcher that samples the audit
// output and proves no "?" ever appears (requirement: test 1 watcher).
func TestRedactionNoQuestionMark(t *testing.T) {
	// Build many lines with query strings in various positions.
	for i := 0; i < 1000; i++ {
		secret := "SECRET-" + strconv.Itoa(i)
		errMsg := nativePartH(secret, "913100", "Anomaly", "/p?id="+secret+"&x="+secret)
		got := sanitizeLine(logEscaper.Replace(errMsg))
		if strings.Contains(got, "?") {
			t.Fatalf("iteration %d: '?' in redacted output:\n%s", i, got)
		}
		if strings.Contains(got, secret) {
			t.Fatalf("iteration %d: secret leaked:\n%s", i, got)
		}
	}
}

// TestRedactionBoundariesMatchNative: verify the boundary format matches
// coraza's native format: --<boundary>-<part>--\n
func TestRedactionBoundariesMatchNative(t *testing.T) {
	al := &mockAuditLog{
		parts: types.AuditLogParts{
			types.AuditLogPartHeader,
			types.AuditLogPartAuditLogTrailer,
			types.AuditLogPartEndMarker,
		},
		tx: &mockTransaction{
			timestamp:  "2026/10/29 05:00:00",
			id:         "tx",
			clientIP:   "10.0.0.1",
			clientPort: 1,
			hostIP:     "10.0.0.2",
			hostPort:   2,
		},
		msgs: []*mockMessage{{
			errMsg: `[client "10.0.0.1"] Coraza: Warning. x [file "f"] [line "1"] [id "941100"] [rev ""] [msg "x"] [data "secret"] [severity "CRITICAL"] [ver "v"] [maturity "0"] [accuracy "0"] [tag "t"] [hostname "h"] [uri "/p?q=v"] [unique_id "u"]`,
		}},
	}
	f := &redactedNativeFormatter{}
	out, err := f.Format(al)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 5 {
		t.Fatalf("expected at least 5 lines, got %d: %s", len(lines), out)
	}
	// Line 0: --<boundary>-A--
	if !strings.HasPrefix(lines[0], "--") || !strings.HasSuffix(lines[0], "-A--") {
		t.Errorf("boundary line 0 = %q, want prefix -- and suffix -A--", lines[0])
	}
	// Line 2: --<boundary>-H--
	if !strings.HasPrefix(lines[2], "--") || !strings.HasSuffix(lines[2], "-H--") {
		t.Errorf("boundary line 2 = %q, want prefix -- and suffix -H--", lines[2])
	}
	// Line 4: --<boundary>-Z--
	if !strings.HasPrefix(lines[4], "--") || !strings.HasSuffix(lines[4], "-Z--") {
		t.Errorf("boundary line 4 = %q, want prefix -- and suffix -Z--", lines[4])
	}
	// Part A content: [timestamp] txid ip port ip port
	if !strings.Contains(lines[1], "[2026/10/29 05:00:00] tx 10.0.0.1") {
		t.Errorf("Part A line = %q", lines[1])
	}
	// Part H content: blanks present, secret absent
	hLine := lines[3]
	if strings.Contains(hLine, "secret") || strings.Contains(hLine, "/p?q=v") {
		t.Errorf("Part H leaked value: %q", hLine)
	}
	if !strings.Contains(hLine, `[data ""]`) {
		t.Errorf("Part H [data] not blanked: %q", hLine)
	}
	if !strings.Contains(hLine, `[uri ""]`) {
		t.Errorf("Part H [uri] not blanked: %q", hLine)
	}
}

// TestRedactionMIME ensures the formatter reports the expected content type.
func TestRedactionMIME(t *testing.T) {
	f := &redactedNativeFormatter{}
	if got := f.MIME(); got == "" {
		t.Error("MIME() returned empty string")
	}
}

// TestRedactionEmptyPartsNoPanic: Format with no parts must return nil, nil.
func TestRedactionEmptyPartsNoPanic(t *testing.T) {
	f := &redactedNativeFormatter{}
	out, err := f.Format(&mockAuditLog{parts: types.AuditLogParts{}})
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Errorf("expected nil output for empty parts, got %q", out)
	}
}

// TestRedactionMultipleMessages: each matched rule gets its own redacted line.
func TestRedactionMultipleMessages(t *testing.T) {
	al := &mockAuditLog{
		parts: types.AuditLogParts{types.AuditLogPartHeader, types.AuditLogPartAuditLogTrailer, types.AuditLogPartEndMarker},
		tx: &mockTransaction{timestamp: "2026/10/29 05:00:00", id: "tx", clientIP: "10.0.0.1", clientPort: 1, hostIP: "h", hostPort: 2},
		msgs: []*mockMessage{
			{errMsg: nativePartH("SECRET-A", "942100", "SQL Injection", "/a?q=SECRET-A")},
			{errMsg: nativePartH("SECRET-B", "941100", "XSS", "/b?q=SECRET-B")},
			{errMsg: nativePartH("SECRET-C", "913100", "Scanner", "/c?q=SECRET-C")},
		},
	}
	f := &redactedNativeFormatter{}
	out, err := f.Format(al)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, s := range []string{"SECRET-A", "SECRET-B", "SECRET-C", "?q="} {
		if strings.Contains(got, s) {
			t.Errorf("value leaked: %q in:\n%s", s, got)
		}
	}
	if c := strings.Count(got, `[data ""]`); c != 3 {
		t.Errorf("[data \"\"] count = %d, want 3", c)
	}
	if c := strings.Count(got, `[uri ""]`); c != 3 {
		t.Errorf(`[uri ""] count = %d, want 3`, c)
	}
	for _, id := range []string{`942100`, `941100`, `913100`} {
		if !strings.Contains(got, `[id "`+id+`"]`) {
			t.Errorf("rule id %q missing from output", id)
		}
	}
}
