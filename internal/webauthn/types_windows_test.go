//go:build windows

package webauthn

import (
	"testing"
	"unsafe"
)

func TestRequiredStructureLayouts64Bit(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("Windows WebAuthn pure-Go backend currently supports 64-bit targets")
	}

	tests := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"RPEntityInformation", unsafe.Sizeof(RPEntityInformation{}), 32},
		{"UserEntityInformation", unsafe.Sizeof(UserEntityInformation{}), 40},
		{"ClientData", unsafe.Sizeof(ClientData{}), 24},
		{"COSECredentialParameter", unsafe.Sizeof(COSECredentialParameter{}), 24},
		{"COSECredentialParameters", unsafe.Sizeof(COSECredentialParameters{}), 16},
		{"Credential", unsafe.Sizeof(Credential{}), 24},
		{"Credentials", unsafe.Sizeof(Credentials{}), 16},
		{"Extension", unsafe.Sizeof(Extension{}), 24},
		{"Extensions", unsafe.Sizeof(Extensions{}), 16},
		{"HMACSecretSalt", unsafe.Sizeof(HMACSecretSalt{}), 32},
		{"CredentialWithHMACSecretSalt", unsafe.Sizeof(CredentialWithHMACSecretSalt{}), 24},
		{"HMACSecretSaltValues", unsafe.Sizeof(HMACSecretSaltValues{}), 24},
		{"MakeCredentialOptionsV6", unsafe.Sizeof(MakeCredentialOptionsV6{}), 104},
		{"GetAssertionOptionsV6", unsafe.Sizeof(GetAssertionOptionsV6{}), 120},
		{"CredentialAttestation", unsafe.Sizeof(CredentialAttestation{}), 192},
		{"Assertion", unsafe.Sizeof(Assertion{}), 168},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("size=%d, want %d", test.got, test.want)
			}
		})
	}
}

func TestCriticalStructureOffsets64Bit(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("Windows WebAuthn pure-Go backend currently supports 64-bit targets")
	}

	if got := unsafe.Offsetof(MakeCredentialOptionsV6{}.EnablePRF); got != 96 {
		t.Fatalf("MakeCredentialOptionsV6.EnablePRF offset=%d, want 96", got)
	}
	if got := unsafe.Offsetof(GetAssertionOptionsV6{}.HMACSecretSaltValues); got != 104 {
		t.Fatalf("GetAssertionOptionsV6.HMACSecretSaltValues offset=%d, want 104", got)
	}
	if got := unsafe.Offsetof(CredentialAttestation{}.CredentialID); got != 88 {
		t.Fatalf("CredentialAttestation.CredentialID offset=%d, want 88", got)
	}
	if got := unsafe.Offsetof(CredentialAttestation{}.PRFEnabled); got != 128 {
		t.Fatalf("CredentialAttestation.PRFEnabled offset=%d, want 128", got)
	}
	if got := unsafe.Offsetof(Assertion{}.HMACSecret); got != 112 {
		t.Fatalf("Assertion.HMACSecret offset=%d, want 112", got)
	}
}
