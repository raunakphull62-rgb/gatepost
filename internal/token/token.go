// Package token: random opaque tokens and their SHA-256 fingerprints.
// Plaintext tokens are returned once; only SHA256Hex(token) goes to the DB.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

// New returns a 256-bit random token, base64url, unpadded (43 chars).
func New() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("token.New: crypto/rand: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// SHA256Hex is the only form of a token ever stored.
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
