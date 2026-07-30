//go:build windows

package webauthn

import "unsafe"

// The structures in this file mirror the 64-bit Windows WebAuthn ABI.
// DWORD is uint32, BOOL and LONG are int32, and native pointers are
// unsafe.Pointer so Go keeps input backing storage alive across syscall calls.

type RPEntityInformation struct {
	Version uint32
	ID      unsafe.Pointer
	Name    unsafe.Pointer
	Icon    unsafe.Pointer
}

type UserEntityInformation struct {
	Version     uint32
	IDLength    uint32
	ID          unsafe.Pointer
	Name        unsafe.Pointer
	Icon        unsafe.Pointer
	DisplayName unsafe.Pointer
}

type ClientData struct {
	Version       uint32
	JSONLength    uint32
	JSON          unsafe.Pointer
	HashAlgorithm unsafe.Pointer
}

type COSECredentialParameter struct {
	Version        uint32
	CredentialType unsafe.Pointer
	Algorithm      int32
}

type COSECredentialParameters struct {
	Count      uint32
	Parameters unsafe.Pointer
}

type Credential struct {
	Version        uint32
	IDLength       uint32
	ID             unsafe.Pointer
	CredentialType unsafe.Pointer
}

type Credentials struct {
	Count       uint32
	Credentials unsafe.Pointer
}

type Extension struct {
	Identifier unsafe.Pointer
	ValueSize  uint32
	Value      unsafe.Pointer
}

type Extensions struct {
	Count      uint32
	Extensions unsafe.Pointer
}

type HMACSecretSalt struct {
	FirstLength  uint32
	First        unsafe.Pointer
	SecondLength uint32
	Second       unsafe.Pointer
}

type CredentialWithHMACSecretSalt struct {
	CredentialIDLength uint32
	CredentialID       unsafe.Pointer
	Salt               unsafe.Pointer
}

type HMACSecretSaltValues struct {
	GlobalSalt          unsafe.Pointer
	CredentialSaltCount uint32
	CredentialSalts     unsafe.Pointer
}

// MakeCredentialOptionsV6 contains exactly the fields available through
// WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6.
type MakeCredentialOptionsV6 struct {
	Version                         uint32
	TimeoutMilliseconds             uint32
	CredentialList                  Credentials
	Extensions                      Extensions
	AuthenticatorAttachment         uint32
	RequireResidentKey              int32
	UserVerificationRequirement     uint32
	AttestationConveyancePreference uint32
	Flags                           uint32
	CancellationID                  unsafe.Pointer
	ExcludeCredentialList           unsafe.Pointer
	EnterpriseAttestation           uint32
	LargeBlobSupport                uint32
	PreferResidentKey               int32
	BrowserInPrivateMode            int32
	EnablePRF                       int32
}

// GetAssertionOptionsV6 contains exactly the fields available through
// WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6.
type GetAssertionOptionsV6 struct {
	Version                     uint32
	TimeoutMilliseconds         uint32
	CredentialList              Credentials
	Extensions                  Extensions
	AuthenticatorAttachment     uint32
	UserVerificationRequirement uint32
	Flags                       uint32
	U2FAppID                    unsafe.Pointer
	U2FAppIDUsed                unsafe.Pointer
	CancellationID              unsafe.Pointer
	AllowCredentialList         unsafe.Pointer
	LargeBlobOperation          uint32
	LargeBlobLength             uint32
	LargeBlob                   unsafe.Pointer
	HMACSecretSaltValues        unsafe.Pointer
	BrowserInPrivateMode        int32
}

// CredentialAttestation mirrors the current WebAuthn result structure. Fields
// added after the returned Version must not be read.
type CredentialAttestation struct {
	Version                    uint32
	FormatType                 unsafe.Pointer
	AuthenticatorDataLength    uint32
	AuthenticatorData          unsafe.Pointer
	AttestationLength          uint32
	Attestation                unsafe.Pointer
	AttestationDecodeType      uint32
	AttestationDecode          unsafe.Pointer
	AttestationObjectLength    uint32
	AttestationObject          unsafe.Pointer
	CredentialIDLength         uint32
	CredentialID               unsafe.Pointer
	Extensions                 Extensions
	UsedTransport              uint32
	EnterpriseAttestation      int32
	LargeBlobSupported         int32
	ResidentKey                int32
	PRFEnabled                 int32
	UnsignedExtensionLength    uint32
	UnsignedExtension          unsafe.Pointer
	HMACSecret                 unsafe.Pointer
	ThirdPartyPayment          int32
	Transports                 uint32
	ClientDataJSONLength       uint32
	ClientDataJSON             unsafe.Pointer
	RegistrationResponseLength uint32
	RegistrationResponse       unsafe.Pointer
}

// Assertion mirrors the current WebAuthn assertion result structure. Fields
// added after the returned Version must not be read.
type Assertion struct {
	Version                      uint32
	AuthenticatorDataLength      uint32
	AuthenticatorData            unsafe.Pointer
	SignatureLength              uint32
	Signature                    unsafe.Pointer
	Credential                   Credential
	UserIDLength                 uint32
	UserID                       unsafe.Pointer
	Extensions                   Extensions
	LargeBlobLength              uint32
	LargeBlob                    unsafe.Pointer
	LargeBlobStatus              uint32
	HMACSecret                   unsafe.Pointer
	UsedTransport                uint32
	UnsignedExtensionLength      uint32
	UnsignedExtension            unsafe.Pointer
	ClientDataJSONLength         uint32
	ClientDataJSON               unsafe.Pointer
	AuthenticationResponseLength uint32
	AuthenticationResponse       unsafe.Pointer
}
