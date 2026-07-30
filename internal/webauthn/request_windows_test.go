//go:build windows

package webauthn

import (
	"errors"
	"testing"
)

func TestMakeCredentialRejectsInvalidInputBeforeUI(t *testing.T) {
	api, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	tests := []MakeCredentialRequest{
		{},
		{RPID: "example.com"},
		{RPID: "example.com", UserID: []byte{1}, UserName: "user"},
	}
	for _, request := range tests {
		if _, err := api.MakeCredential(request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("MakeCredential(%+v) error=%v, want ErrInvalidInput", request, err)
		}
	}
}

func TestGetAssertionRejectsInvalidInputBeforeUI(t *testing.T) {
	api, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	tests := []GetAssertionRequest{
		{},
		{RPID: "example.com"},
		{RPID: "example.com", CredentialID: []byte{1}},
		{RPID: "example.com", CredentialID: []byte{1}, Salt: make([]byte, HMACSecretLength)},
	}
	for _, request := range tests {
		if _, err := api.GetAssertion(request); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("GetAssertion(%+v) error=%v, want ErrInvalidInput", request, err)
		}
	}
}
