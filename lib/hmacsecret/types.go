// Package hmacsecret derives deterministic secrets using the FIDO2
// hmac-secret extension or the Windows WebAuthn PRF API.
package hmacsecret

import "errors"

// SaltSize is the hmac-secret salt length required by CTAP2.
const SaltSize = 32

// Sentinel errors for callers.
var (
	ErrInvalidArgument    = errors.New("invalid argument")
	ErrNoDevice           = errors.New("no FIDO2 device found")
	ErrNoSelectableDevice = errors.New("no selectable FIDO2 device")
	ErrDeviceSearch       = errors.New("FIDO2 device search failed")
	ErrOpenDevice         = errors.New("open FIDO2 device failed")
	ErrNotFIDO2           = errors.New("device does not support FIDO2/CTAP2")
	ErrEmptyHMACSecret    = errors.New("authenticator returned empty hmac-secret")
	ErrUnsupportedBuild   = errors.New("hmacsecret requires Windows WebAuthn or CGO with native libfido2")
)

// DeviceInfo describes a discovered FIDO2 authenticator.
type DeviceInfo struct {
	Index        int
	Path         string
	Product      string
	Manufacturer string
	ProductID    int16
	VendorID     int16
	WindowsHello bool
}

// ListOptions controls device discovery.
type ListOptions struct {
	// ExcludeWindowsWebAuthn excludes the windows://hello WebAuthn broker.
	// Windows only; ignored elsewhere. Zero value keeps WebAuthn enabled.
	ExcludeWindowsWebAuthn bool
}

// CreateOptions configures non-discoverable hmac-secret credential creation.
type CreateOptions struct {
	// RPID is required and binds the credential to a relying party id.
	RPID string
	// RPName is optional display name for the RP.
	RPName string
	// UserName is required by many authenticators.
	UserName string
	// UserDisplayName defaults to UserName when empty.
	UserDisplayName string
	// UserID defaults to 32 random bytes when empty.
	UserID []byte
	// PIN is the authenticator PIN. Windows WebAuthn uses Security UI instead.
	PIN string
	// ClientDataJSON overrides auto-generated webauthn.create client data.
	ClientDataJSON []byte
}

// DeriveOptions configures hmac-secret derivation from an existing credential.
type DeriveOptions struct {
	// RPID must match the RP id used at credential creation.
	RPID string
	// CredentialID is the non-discoverable credential id to assert.
	CredentialID []byte
	// Salt must be exactly SaltSize bytes.
	Salt []byte
	// PIN is the authenticator PIN. Windows WebAuthn uses Security UI instead.
	PIN string
	// UserPresence requests UP during assertion. Default true when unset via Derive.
	// Use UserPresenceSet to force false.
	UserPresence    bool
	UserPresenceSet bool
	// ClientDataJSON overrides auto-generated webauthn.get client data.
	ClientDataJSON []byte
}

// Credential is a created hmac-secret-enabled credential.
type Credential struct {
	ID     []byte
	RPID   string
	PubKey []byte
}

// Secret is a derived hmac-secret value plus the inputs needed to reproduce it.
type Secret struct {
	CredentialID []byte
	Salt         []byte
	HMACSecret   []byte
}
