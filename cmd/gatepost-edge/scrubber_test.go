package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeAuditLineBlanksValues(t *testing.T) {
	in := []byte("[client \"10.0.0.1\"] Coraza: Warning. SQLi [id \"942100\"] [data \"Matched Data: s&sos found within ARGS:id: SECRET-Z\"] [severity \"critical\"] [uri \"/ok?id=SECRET-Z\"] [unique_id \"txid\"]")
	out := sanitizeAuditLine(in)
	got := string(out)
	for _, secret := range []string{"SECRET-Z", "data \"Matched"} {
		if strings.Contains(got, secret) {
			t.Errorf("value leaked: %q in:\n%s", secret, got)
		}
	}
	if strings.Contains(got, "?id=") {
		t.Errorf("query leaked in:\n%s", got)
	}
	if !strings.Contains(got, "[data \"\"]") {
		t.Errorf("[data] not blanked:\n%s", got)
	}
	if !strings.Contains(got, "[uri \"\"]") {
		t.Errorf("[uri] not blanked:\n%s", got)
	}
	for _, keep := range []string{"[id \"942100\"]", "[severity \"critical\"]", "[unique_id \"txid\"]", "[client \"10.0.0.1\"]"} {
		if !strings.Contains(got, keep) {
			t.Errorf("allowed field dropped: %q", keep)
		}
	}
}

func TestSanitizeAuditFileInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "waf_audit.log")
	content := []byte("--tx-A--\n[client \"1.2.3.4\"] [id \"913110\"] [data \"Matched Data: SECRET-Z found within ARGS:q\"] [uri \"/ok?SECRET-Z\"] [unique_id \"tx\"]\n--tx-Z--\n")
	if err := os.WriteFile(path, content, 0666); err != nil { t.Fatal(err) }
	fh, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil { t.Fatal(err) }
	if err := sanitizeAuditFile(path); err != nil { t.Fatal(err) }
	if _, err := fh.WriteString("--post-scrub-append--\n"); err != nil { t.Fatal(err) }
	fh.Close()
	got := string(mustReadFile(path))
	for _, s := range []string{"SECRET-Z", "data \"Matched", "?SECRET"} {
		if strings.Contains(got, s) { t.Errorf("leaked: %q in:\n%s", s, got) }
	}
	if !strings.Contains(got, "--post-scrub-append--") { t.Errorf("O_APPEND fd orphaned (inode changed):\n%s", got) }
	if !strings.Contains(got, "[id \"913110\"]") { t.Errorf("rule id dropped:\n%s", got) }
}

func mustReadFile(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil { panic(err) }
	return b
}
