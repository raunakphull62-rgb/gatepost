package snapshot

import (
	"errors"
	"strings"
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

// TestTamperRefused — the artifact is authenticated byte-for-byte: one
// flipped payload character breaks the HMAC (before the content is ever
// read), one flipped signature character does too, and equal/older
// generations are refused outright.
func TestTamperRefused(t *testing.T) {
	key := []byte("test-snapshot-key")
	mk := func(gen int64, host string) Envelope {
		e, err := Sign(key, Document{
			SchemaVersion: 1, Generation: gen,
			BuiltAt:          time.Unix(1_700_000_000+gen, 0).UTC(),
			AllowedHostnames: []string{host},
		})
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	env := mk(3, "a.test")
	if _, err := Verify(key, env, 2); err != nil {
		t.Fatalf("untouched must verify after 2: %v", err)
	}
	// a key the node does not hold: "not my artifact", never tampering
	if _, err := Verify([]byte("another-key"), env, 2); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("foreign key must be ErrUnknownKey, got %v", err)
	}

	// one byte flipped in the payload
	mutated := env
	mutated.Payload = strings.Replace(env.Payload, `"generation":3`, `"generation":4`, 1)
	if mutated.Payload == env.Payload {
		t.Fatal("tamper target not found in the canonical payload")
	}
	if _, err := Verify(key, mutated, 2); !errors.Is(err, ErrTampered) {
		t.Fatalf("one-byte payload tamper must be ErrTampered, got %v", err)
	}

	// one nibble flipped in the signature
	sig := []byte(env.Signature)
	sig[0] = '0'
	if sig[0] == env.Signature[0] {
		sig[0] = '1'
	}
	bad := env
	bad.Signature = string(sig)
	if _, err := Verify(key, bad, 2); !errors.Is(err, ErrTampered) {
		t.Fatalf("signature tamper must be ErrTampered, got %v", err)
	}

	// equal AND lower generations refused, not just strictly-lower ones
	if _, err := Verify(key, mk(3, "a.test"), 3); !errors.Is(err, ErrBackwards) {
		t.Fatalf("re-applying the same generation must be ErrBackwards, got %v", err)
	}
	if _, err := Verify(key, mk(2, "b.test"), 3); !errors.Is(err, ErrBackwards) {
		t.Fatalf("older generation after newer must be ErrBackwards, got %v", err)
	}
}

// TestSizeLimitBothSides — the cap refuses before anything parses: Sign
// refuses to produce an oversized artifact, and Verify refuses an oversized
// envelope before it even touches the payload's bytes.
func TestSizeLimitBothSides(t *testing.T) {
	key := []byte("test-snapshot-key")
	big := Document{
		SchemaVersion: 1, Generation: 1,
		BuiltAt:          time.Unix(1_700_000_003, 0).UTC(),
		AllowedHostnames: []string{strings.Repeat("a", MaxBytes)},
	}
	if _, err := Sign(key, big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized Sign must be ErrTooLarge, got %v", err)
	}
	over := Envelope{Payload: strings.Repeat(" ", MaxBytes+1), Signature: "00"}
	if _, err := Verify(key, over, 0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized Verify must be ErrTooLarge before any parsing, got %v", err)
	}
}

// TestSchemaGateRefusals — the schema gate (B3c item 2b): a snapshot whose
// signed required_features name something the verifier does not know, or
// whose schema_version is newer than this build, is REFUSED. The old
// "unknown fields are ignored" behavior would silently drop the WAF behind
// the feature; the gate keeps the last good snapshot instead. Older schemas
// and feature-less snapshots stay accepted (backward compatibility).
func TestSchemaGateRefusals(t *testing.T) {
	key := []byte("test-key-32-bytes-long-minimum!")
	current := Document{
		SchemaVersion:    SchemaVersion,
		RequiredFeatures: []string{FeatureWAF},
		Generation:       10,
		BuiltAt:          time.Now().UTC(),
		Domains: []Domain{
			{
				Hostname:        "example.com",
				SetupType:       "cname",
				Origin:          Origin{Scheme: "http", Address: "1.2.3.4", Port: 80},
				WAFMode:         "blocking",
				ExcludedRuleIDs: []int{942100},
			},
		},
		AllowedHostnames: []string{"example.com"},
	}
	env, err := Sign(key, current)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// The current edge (full knowledge) accepts the current snapshot.
	d, err := Verify(key, env, 9)
	if err != nil {
		t.Fatalf("current build must accept the current snapshot: %v", err)
	}
	if d.SchemaVersion != SchemaVersion || len(d.Domains) != 1 || d.Domains[0].WAFMode != "blocking" {
		t.Fatalf("wrong document: %+v", d)
	}

	// An old-style verifier (knows no features) refuses it — the WAF fields
	// would otherwise be silently dropped.
	if _, err := VerifyWith(key, env, 9, nil); !errors.Is(err, ErrUnknownFeature) {
		t.Fatalf("old-style verifier must refuse a required feature, got %v", err)
	}

	// A newer schema_version is refused even with full knowledge.
	newer := current
	newer.SchemaVersion = SchemaVersion + 1
	newer.Generation = 11
	env3, err := Sign(key, newer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(key, env3, 9); !errors.Is(err, ErrNewerSchema) {
		t.Fatalf("newer schema must be refused, got %v", err)
	}

	// An OLDER schema stays accepted: schema-1 shape, no required_features.
	oldStyle := Document{
		SchemaVersion:    1,
		Generation:       12,
		BuiltAt:          time.Now().UTC(),
		Domains:          []Domain{{Hostname: "example.com", SetupType: "cname", Origin: Origin{Scheme: "http", Address: "1.2.3.4", Port: 80}}},
		AllowedHostnames: []string{"example.com"},
	}
	env1, err := Sign(key, oldStyle)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Verify(key, env1, 9); err != nil {
		t.Fatalf("older schema must stay accepted: %v", err)
	}
}
