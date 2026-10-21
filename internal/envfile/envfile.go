// Package envfile loads KEY=VALUE pairs from a file (e.g. .env) into the
// environment, existing variables winning. No quoting; comments (#) allowed.
package envfile

import (
	"os"
	"strings"
)

func Load(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return // file optional; explicit env still works
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if _, set := os.LookupEnv(k); !set && k != "" {
			_ = os.Setenv(k, v)
		}
	}
}

// Production reports whether the process runs in production: any ENV value
// other than exactly "development" counts (unset, prod, Production …) — a
// fail-safe default so a typo or forgotten variable cannot ship dev settings.
func Production() bool {
	return os.Getenv("ENV") != "development"
}
