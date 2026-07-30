//go:build windows

package webauthn

import "testing"

func TestLoadAndVersion(t *testing.T) {
	api, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if version := api.Version(); version < APIVersionPRF {
		t.Fatalf("WebAuthn API version=%d, PRF requires >= %d", version, APIVersionPRF)
	} else {
		t.Logf("WebAuthn API version: %d", version)
	}
}

func TestErrorName(t *testing.T) {
	api, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if name := api.ErrorName(S_OK); name == "" {
		t.Fatal("empty error name for S_OK")
	}
}
