//go:build windows

package webauthn

const (
	APIVersionPRF = 6

	RPEntityInformationVersion     = 1
	UserEntityInformationVersion   = 1
	ClientDataVersion              = 1
	COSECredentialParameterVersion = 1
	CredentialVersion              = 1

	MakeCredentialOptionsVersionPRF = 6
	GetAssertionOptionsVersionPRF   = 6

	AuthenticatorAttachmentAny           = 0
	AuthenticatorAttachmentPlatform      = 1
	AuthenticatorAttachmentCrossPlatform = 2

	UserVerificationAny         = 0
	UserVerificationRequired    = 1
	UserVerificationPreferred   = 2
	UserVerificationDiscouraged = 3

	AttestationConveyanceAny      = 0
	AttestationConveyanceNone     = 1
	AttestationConveyanceIndirect = 2
	AttestationConveyanceDirect   = 3

	COSEAlgorithmES256 int32 = -7

	AuthenticatorHMACSecretValuesFlag = 0x00100000
	HMACSecretLength                  = 32
)

const (
	S_OK HRESULT = 0

	NTEInvalidParameter HRESULT = 0x80090027
	NTENotSupported     HRESULT = 0x80090029
	NTEDeviceNotFound   HRESULT = 0x80090035
	NTEUserCancelled    HRESULT = 0x80090036
	NTENotFound         HRESULT = 0x80090011
	HRESULTCancelled    HRESULT = 0x800704c7
)
