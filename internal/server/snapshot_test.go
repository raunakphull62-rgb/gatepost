package server

import (
	"context"
	"testing"

	"gatepost/internal/snapshot"
)

// TestVersionByHeadHash — the recoder compares against the LATEST hash only:
// A→B→A is versions 1, 2, 3 with the third equal in content to the first
// (never matched back to version 1's row), an unchanged head keeps its
// version, and the count keeps advancing on every real change after it.
func TestVersionByHeadHash(t *testing.T) {
	pool := testPool(t)
	_, s := newTestServer(t, pool)
	ctx := context.Background()
	cA := snapshot.Content{SchemaVersion: 1, AllowedHostnames: []string{"a.test"}}
	cB := snapshot.Content{SchemaVersion: 1, AllowedHostnames: []string{"b.test"}}
	for _, c := range []struct {
		name    string
		want    int64
		content snapshot.Content
	}{
		{"A first", 1, cA},
		{"B next", 2, cB},
		{"A again", 3, cA}, // equal in content to version 1, next number anyway
		{"A unchanged head", 3, cA},
		{"B again", 4, cB},
	} {
		h, err := snapshot.Hash(c.content)
		if err != nil {
			t.Fatalf("%s: content hash: %v", c.name, err)
		}
		gen, err := s.recordGeneration(ctx, h)
		if err != nil {
			t.Fatalf("%s: recordGeneration: %v", c.name, err)
		}
		if gen != c.want {
			t.Fatalf("%s: want generation %d, got %d", c.name, c.want, gen)
		}
	}
}
