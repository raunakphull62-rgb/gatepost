// Package snapshot builds, signs and verifies the configuration snapshot
// that edge and DNS nodes poll. It touches no database: the API assembles a
// Document and keeps the generation counter in nodes-side storage (the
// recorder compares only with the LATEST content — see server.recordGeneration),
// while a node imports just this package to verify what it downloaded.
// B3a items 2–3.
package snapshot

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// MaxBytes caps the canonical payload — far above any plausible config, far
// below anything that could hurt a small edge-side parser.
const MaxBytes = 256 << 10

// Content is what versioning hashes: the snapshot's meaning, WITHOUT the
// volatile bookkeeping (generation, built_at) — an identical rebuild hashes
// to the same content.
type Content struct {
	SchemaVersion    int      `json:"schema_version"`
	RequiredFeatures []string `json:"required_features,omitempty"` // signed capability gate (schema gate)
	Domains          []Domain `json:"domains"`
	AllowedHostnames []string `json:"allowed_hostnames"`
	Defaults         Defaults `json:"defaults"`
}

// Document is the full snapshot a node applies; its canonical JSON is what
// the signature covers.
type Document struct {
	SchemaVersion    int       `json:"schema_version"`
	RequiredFeatures []string  `json:"required_features,omitempty"` // signed capability gate (schema gate)
	Generation       int64     `json:"generation"`
	BuiltAt          time.Time `json:"built_at"`
	Domains          []Domain  `json:"domains"`
	AllowedHostnames []string  `json:"allowed_hostnames"`
	Defaults         Defaults  `json:"defaults"`
}

// ToContent strips the volatile fingerprint inputs.
func (d Document) ToContent() Content {
	return Content{
		SchemaVersion:    d.SchemaVersion,
		RequiredFeatures: d.RequiredFeatures,
		Domains:          d.Domains,
		AllowedHostnames: d.AllowedHostnames,
		Defaults:         d.Defaults,
	}
}

// SchemaVersion — bump when the snapshot shape changes meaningfully;
// consumers pin to one.
const SchemaVersion = 2

// FeatureWAF gates the per-host WAF fields (waf_mode, excluded_rule_ids) —
// the first entry of required_features. A node that does not know a required
// feature must refuse the snapshot, never silently drop the fields behind it.
const FeatureWAF = "waf"

// KnownFeatures is everything THIS schema version's consumers implement;
// Verify (the full-knowledge form) gates against it.
var KnownFeatures = []string{FeatureWAF}

// Defaults carries the fixed site posture of this version.
type Defaults struct {
	FirewallMode string `json:"firewall_mode"` // log_only at B3a
	Cache        bool   `json:"cache"`
}

// Origin is one origin exactly as configured (address is the canonical form).
type Origin struct {
	Scheme     string  `json:"scheme"`
	Address    string  `json:"address"`
	Port       int     `json:"port"`
	HostHeader *string `json:"host_header"`
	TLSVerify  bool    `json:"tls_verify"`
}

// Domain is one verified-and-served customer hostname.
type Domain struct {
	Hostname        string `json:"hostname"`
	SetupType       string `json:"setup_type"`
	Origin          Origin `json:"origin"`
	WAFMode         string `json:"waf_mode"`         // "off" (default) | "detection" | "blocking"
	ExcludedRuleIDs []int  `json:"excluded_rule_ids"` // CRS rule IDs to skip for this host
}

var (
	// ErrTampered — signature check failed (or the envelope is deformed).
	ErrTampered = errors.New("snapshot: signature verification failed")
	// ErrUnknownKey — the envelope names a different key ID. A verifying
	// node treats this as "not an artifact of my keys" (skip it during a
	// rotation window), never as tampering.
	ErrUnknownKey = errors.New("snapshot: envelope is signed with a different key")
	// ErrBackwards — the generation is not strictly beyond the last applied.
	ErrBackwards = errors.New("snapshot: generation must not go backwards")
	// ErrTooLarge — payload above MaxBytes, refused before anything parses.
	ErrTooLarge = errors.New("snapshot: exceeds the size limit")
	// ErrNewerSchema — the schema_version is newer than this build
	// understands: keep the last good snapshot, never apply (schema gate).
	ErrNewerSchema = errors.New("snapshot: schema_version is newer than this build understands")
	// ErrUnknownFeature — the signed required_features name something this
	// build does not implement: keep the last good snapshot, never apply.
	ErrUnknownFeature = errors.New("snapshot: requires a feature this build does not implement")
)

// Envelope is what the API serves and the poller fetches: the canonical
// payload verbatim, its HMAC, and the ID of the signing key — nodes map a
// key ID to each key they hold and only verify when the ID matches one.
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"` // hex HMAC-SHA256(Payload)
	KeyID     string `json:"key_id"`    // short ID of the signing key, derived from the key itself
}

// keyID — a short stable identifier derived from the key material itself:
// every holder of a key maps it to the same ID with zero configuration, so
// a node can always tell WHICH of its held keys signed an artifact
// (rotation, design §15: two keys → two IDs, both verify in transition).
func keyID(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])[:16]
}

// Canonical is THE encoding for hashing and signing: JSON re-marshalled with
// every object level key-sorted (marshal → decode with exact numbers →
// re-marshal), compact and stable across processes.
func Canonical(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber() // never push 64-bit ints through a float
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	return json.Marshal(tree)
}

// Hash fingerprints content for the generation bookkeeping.
func Hash(c Content) (string, error) {
	b, err := Canonical(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Sign canonicalizes the document, enforces the size limit, and HMACs.
func Sign(key []byte, d Document) (Envelope, error) {
	payload, err := Canonical(d)
	if err != nil {
		return Envelope{}, err
	}
	if len(payload) > MaxBytes {
		return Envelope{}, ErrTooLarge
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(payload)
	return Envelope{
		Payload:   string(payload),
		Signature: hex.EncodeToString(mac.Sum(nil)),
		KeyID:     keyID(key),
	}, nil
}

// Verify authenticates the envelope, then enforces the "must not go
// backwards" rule: the generation has to be strictly beyond prevGeneration
// (0 = fresh start). Real content that repeats earlier content still carries
// a HIGHER generation (A→B→A is 1, 2, 3) and therefore verifies. It gates
// against the full feature knowledge of this build.
func Verify(key []byte, env Envelope, prevGeneration int64) (Document, error) {
	return VerifyWith(key, env, prevGeneration, KnownFeatures)
}

// VerifyWith is Verify with the caller's feature knowledge: a node refuses
// any snapshot whose signed required_features go beyond `known` (and any
// schema_version beyond SchemaVersion) — the last good snapshot keeps
// serving, the new one is never applied. An OLDER schema_version is still
// accepted (backward compatibility); a nil/empty `known` is the old-style
// node that refuses any snapshot requiring any feature at all.
func VerifyWith(key []byte, env Envelope, prevGeneration int64, known []string) (Document, error) {
	if len(env.Payload) > MaxBytes {
		return Document{}, ErrTooLarge
	}
	if env.KeyID != keyID(key) { // a held key always names itself
		return Document{}, ErrUnknownKey
	}
	want, err := hex.DecodeString(env.Signature)
	if err != nil {
		return Document{}, ErrTampered
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(env.Payload))
	if !hmac.Equal(want, mac.Sum(nil)) {
		return Document{}, ErrTampered
	}
	var d Document
	if err := json.Unmarshal([]byte(env.Payload), &d); err != nil {
		return Document{}, ErrTampered // can only be wrong if we signed junk
	}
	if d.SchemaVersion > SchemaVersion {
		return Document{}, fmt.Errorf("%w: got %d, this build understands up to %d",
			ErrNewerSchema, d.SchemaVersion, SchemaVersion)
	}
	if missing := unknownFeatures(d.RequiredFeatures, known); len(missing) > 0 {
		return Document{}, fmt.Errorf("%w: %s", ErrUnknownFeature, strings.Join(missing, " "))
	}
	if d.Generation <= prevGeneration {
		return Document{}, ErrBackwards
	}
	return d, nil
}

// unknownFeatures returns the required features absent from known.
func unknownFeatures(required, known []string) []string {
	var missing []string
	for _, f := range required {
		if !slices.Contains(known, f) {
			missing = append(missing, f)
		}
	}
	return missing
}
