package snapshot

import (
	"errors"
	"testing"
	"time"
)

// TestVerifyAccepts3After2 — the hardening rule end to end: A(1) → B(2) →
// A(3). Version 3 is equal in CONTENT to version 1 (only generation and
// built_at differ) yet verifies after 2, because content that returns to an
// earlier shape is still a real change. An equal or older generation is
// refused.
func TestVerifyAccepts3After2(t *testing.T) {
	key := []byte("test-snapshot-key")
	mk := func(gen int64, host string) Envelope {
		d := Document{
			SchemaVersion:    1,
			Generation:       gen,
			BuiltAt:          time.Unix(1_700_000_000+gen, 0).UTC(),
			AllowedHostnames: []string{host},
		}
		e, err := Sign(key, d)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e1, e2, e3 := mk(1, "a.test"), mk(2, "b.test"), mk(3, "a.test")

	d3, err := Verify(key, e3, 2)
	if err != nil {
		t.Fatalf("version 3 after 2 must verify: %v", err)
	}
	d1, err := Verify(key, e1, 0)
	if err != nil {
		t.Fatal(err)
	}
	h3, err := Hash(d3.ToContent())
	if err != nil {
		t.Fatal(err)
	}
	h1, err := Hash(d1.ToContent())
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h3 {
		t.Fatalf("version 3 must hash equal in content to version 1 (%s vs %s)", h1, h3)
	}
	if d3.Generation != 3 {
		t.Fatalf("generation carried over: %d", d3.Generation)
	}

	// the monotonic rules around it
	if _, err := Verify(key, e2, 1); err != nil {
		t.Fatalf("2 after 1 must verify: %v", err)
	}
	if _, err := Verify(key, e3, 3); !errors.Is(err, ErrBackwards) {
		t.Fatalf("re-apply of 3: want ErrBackwards, got %v", err)
	}
	if _, err := Verify(key, e1, 3); !errors.Is(err, ErrBackwards) {
		t.Fatalf("old version 1 after 3: want ErrBackwards, got %v", err)
	}
}

// TestCanonicalStableAndSorted — the hash/signature input may never depend
// on map-iteration or encoding drift: same value, same bytes, keys sorted.
func TestCanonicalStableAndSorted(t *testing.T) {
	a, err := Canonical(map[string]any{"z": 1, "a": map[string]any{"k": int64(42), "b": true}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Canonical(map[string]int64{"a": 42})
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != `{"a":{"b":true,"k":42},"z":1}` {
		t.Fatalf("canonical must sort keys and stay exact: %s", a)
	}
	if string(b) != `{"a":42}` {
		t.Fatalf("int64 must not become float: %s", b)
	}
	// repeated calls may not change the bytes
	a2, _ := Canonical(map[string]any{"z": 1, "a": map[string]any{"k": int64(42), "b": true}})
	if string(a2) != string(a) {
		t.Fatal("canonical is not stable across calls")
	}
}
