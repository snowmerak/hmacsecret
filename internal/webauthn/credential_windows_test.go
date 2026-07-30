//go:build windows

package webauthn

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestHMACSecretExtensionEnabled(t *testing.T) {
	name, err := windows.UTF16PtrFromString("hmac-secret")
	if err != nil {
		t.Fatal(err)
	}
	enabled := int32(1)
	extension := Extension{
		Identifier: unsafe.Pointer(name),
		ValueSize:  uint32(unsafe.Sizeof(enabled)),
		Value:      unsafe.Pointer(&enabled),
	}
	extensions := Extensions{
		Count:      1,
		Extensions: unsafe.Pointer(&extension),
	}
	if !hmacSecretExtensionEnabled(extensions) {
		t.Fatal("enabled hmac-secret output was not detected")
	}

	enabled = 0
	if hmacSecretExtensionEnabled(extensions) {
		t.Fatal("disabled hmac-secret output was accepted")
	}
}

func TestHMACSecretExtensionEnabledRejectsInvalidList(t *testing.T) {
	if hmacSecretExtensionEnabled(Extensions{Count: 1}) {
		t.Fatal("nil extension list was accepted")
	}
	if hmacSecretExtensionEnabled(Extensions{Count: 65, Extensions: unsafe.Pointer(new(Extension))}) {
		t.Fatal("unreasonably large extension list was accepted")
	}
}
