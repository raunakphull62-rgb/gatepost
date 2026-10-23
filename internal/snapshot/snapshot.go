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
	Domains          []Domain `json:"domains"`
	AllowedHostnames []string `json:"allowed_hostnames"`
	Defaults         Defaults `json:"defaults"`
}

// Document is the full snapshot a node applies; its canonical JSON is what
// the signature covers.
type Document struct {
	SchemaVersion    int       `json:"schema_version"`
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
		Domains:          d.Domains,
		AllowedHostnames: d.AllowedHostnames,
		Defaults:         d.Defaults,
	}
}

// SchemaVersion — bump when the snapshot shape changes meaningfully;
// consumers pin to one.
const SchemaVersion = 1

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
	Hostname  string `json:"hostname"`
	SetupType string `json:"setup_type"`
	Origin    Origin `json:"origin"`
}

var (
	// ErrTampered — signature check failed (or the envelope is deformed).
	ErrTampered = errors.New("snapshot: signature verification failed")
	// ErrBackwards — the generation is not strictly beyond the last applied.
	ErrBackwards = errors.New("snapshot: generation must not go backwards")
	// ErrTooLarge — payload above MaxBytes, refused before anything parses.
	ErrTooLarge = errors.New("snapshot: exceeds the size limit")
)

// Envelope is what the API serves and the poller fetches: the canonical
// payload verbatim plus its HMAC, so verification hashes bytes, and the
// re-encoding can never drift.
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"` // hex HMAC-SHA256(Payload)
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
	}, nil
}

// Verify authenticates the envelope, then enforces the "must not go
// backwards" rule: the generation has to be strictly beyond prevGeneration
// (0 = fresh start). Real content that repeats earlier content still carries
// a HIGHER generation (A→B→A is 1, 2, 3) and therefore verifies.
func Verify(key []byte, env Envelope, prevGeneration int64) (Document, error) {
	if len(env.Payload) > MaxBytes {
		return Document{}, ErrTooLarge
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
	if d.Generation <= prevGeneration {
		return Document{}, ErrBackwards
	}
	return d, nil
}
