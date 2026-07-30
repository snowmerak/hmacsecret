//go:build cgo

package hmacsecret

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSalt(t *testing.T) {
	t.Run("generate", func(t *testing.T) {
		salt, generated, err := ParseSalt("")
		if err != nil {
			t.Fatal(err)
		}
		if !generated {
			t.Fatal("generated = false, want true")
		}
		if len(salt) != SaltSize {
			t.Fatalf("len(salt) = %d, want %d", len(salt), SaltSize)
		}
	})

	t.Run("decode", func(t *testing.T) {
		input := strings.Repeat("ab", SaltSize)
		salt, generated, err := ParseSalt(input)
		if err != nil {
			t.Fatal(err)
		}
		if generated {
			t.Fatal("generated = true, want false")
		}
		if got := hex.EncodeToString(salt); got != input {
			t.Fatalf("salt = %q, want %q", got, input)
		}
	})

	t.Run("reject wrong length", func(t *testing.T) {
		if _, _, err := ParseSalt("abcd"); err == nil {
			t.Fatal("expected an error")
		}
	})

	t.Run("reject invalid hex", func(t *testing.T) {
		if _, _, err := ParseSalt(strings.Repeat("zz", SaltSize)); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestMakeClientDataJSON(t *testing.T) {
	challenge := []byte{0x00, 0x01, 0xfe, 0xff}
	encoded, err := MakeClientDataJSON("webauthn.get", challenge, "example.com")
	if err != nil {
		t.Fatal(err)
	}

	var clientData struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(encoded, &clientData); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if clientData.Type != "webauthn.get" {
		t.Errorf("type = %q", clientData.Type)
	}
	if clientData.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
		t.Errorf("challenge = %q", clientData.Challenge)
	}
	if clientData.Origin != "https://example.com" {
		t.Errorf("origin = %q", clientData.Origin)
	}
	if clientData.CrossOrigin {
		t.Error("crossOrigin = true")
	}
}
