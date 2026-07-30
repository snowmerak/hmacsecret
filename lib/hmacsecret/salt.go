//go:build cgo

package hmacsecret

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SaltSize is the hmac-secret salt length required by CTAP2.
const SaltSize = 32

// ParseSalt decodes a 32-byte hex salt, or generates a random salt when value is empty.
// generated is true only when a new salt was created.
func ParseSalt(value string) (salt []byte, generated bool, err error) {
	if value == "" {
		result := make([]byte, SaltSize)
		if _, err := rand.Read(result); err != nil {
			return nil, false, fmt.Errorf("generate salt: %w", err)
		}
		return result, true, nil
	}

	result, err := hex.DecodeString(value)
	if err != nil {
		return nil, false, fmt.Errorf("salt must be valid hex: %w", err)
	}
	if len(result) != SaltSize {
		return nil, false, fmt.Errorf("salt must be exactly %d bytes (%d hex chars)", SaltSize, SaltSize*2)
	}
	return result, false, nil
}

func validateSalt(salt []byte) error {
	if len(salt) != SaltSize {
		return fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	return nil
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}
