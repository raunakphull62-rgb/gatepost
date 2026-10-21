// Package password: argon2id hashing per OWASP (m=19456 KiB, t=2, p=1).
// Hashes are stored in PHC string format.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	timeCost = 2
	memory   = 19456 // KiB
	threads  = 1
	keyLen   = 32
	saltLen  = 16
)

var b64 = base64.RawStdEncoding

func Hash(pw string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, timeCost, memory, threads, keyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, timeCost, threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

func Verify(stored, pw string) (bool, error) {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("argon2: malformed hash")
	}
	var m, t uint32
	var p, v int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("argon2: malformed params: %w", err)
	}
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != 19 {
		return false, fmt.Errorf("argon2: unsupported version %s", parts[2])
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("argon2: salt: %w", err)
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("argon2: key: %w", err)
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
