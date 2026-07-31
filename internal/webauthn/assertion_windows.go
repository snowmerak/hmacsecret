//go:build windows

package webauthn

import (
	"bytes"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/awnumar/memguard"
)

type GetAssertionRequest struct {
	RPID           string
	CredentialID   []byte
	Salt           []byte
	ClientDataJSON []byte
	Timeout        time.Duration
}

type GetAssertionResult struct {
	CredentialID      []byte
	AuthenticatorData []byte
	HMACSecret        *memguard.Enclave
}

func (a *API) GetAssertion(request GetAssertionRequest) (*GetAssertionResult, error) {
	if a == nil || a.getAssertion == nil {
		return nil, ErrUnavailable
	}
	if version := a.Version(); version < APIVersionPRF {
		return nil, fmt.Errorf("%w: API version %d, PRF requires >= %d", ErrUnsupported, version, APIVersionPRF)
	}
	if request.RPID == "" {
		return nil, fmt.Errorf("%w: RP ID is required", ErrInvalidInput)
	}
	if len(request.CredentialID) == 0 {
		return nil, fmt.Errorf("%w: credential ID is required", ErrInvalidInput)
	}
	if len(request.Salt) != HMACSecretLength {
		return nil, fmt.Errorf("%w: salt must contain %d bytes", ErrInvalidInput, HMACSecretLength)
	}
	if len(request.ClientDataJSON) == 0 {
		return nil, fmt.Errorf("%w: client data JSON is required", ErrInvalidInput)
	}

	timeout := request.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > time.Duration(^uint32(0))*time.Millisecond {
		return nil, fmt.Errorf("%w: timeout is too large", ErrInvalidInput)
	}

	rpIDPtr, err := utf16Pointer(request.RPID)
	if err != nil {
		return nil, err
	}
	publicKeyPtr, err := utf16Pointer("public-key")
	if err != nil {
		return nil, err
	}
	sha256Ptr, err := utf16Pointer("SHA-256")
	if err != nil {
		return nil, err
	}

	credential := Credential{
		Version:        CredentialVersion,
		IDLength:       uint32(len(request.CredentialID)),
		ID:             bytePointer(request.CredentialID),
		CredentialType: unsafe.Pointer(publicKeyPtr),
	}
	credentials := Credentials{
		Count:       1,
		Credentials: structPointer(&credential),
	}
	clientData := ClientData{
		Version:       ClientDataVersion,
		JSONLength:    uint32(len(request.ClientDataJSON)),
		JSON:          bytePointer(request.ClientDataJSON),
		HashAlgorithm: unsafe.Pointer(sha256Ptr),
	}
	salt := HMACSecretSalt{
		FirstLength: uint32(len(request.Salt)),
		First:       bytePointer(request.Salt),
	}
	saltValues := HMACSecretSaltValues{
		GlobalSalt: structPointer(&salt),
	}
	options := GetAssertionOptionsV6{
		Version:                     GetAssertionOptionsVersionPRF,
		TimeoutMilliseconds:         uint32(timeout / time.Millisecond),
		CredentialList:              credentials,
		AuthenticatorAttachment:     AuthenticatorAttachmentCrossPlatform,
		UserVerificationRequirement: UserVerificationAny,
		Flags:                       AuthenticatorHMACSecretValuesFlag,
		HMACSecretSaltValues:        structPointer(&saltValues),
	}

	window, _, _ := getForegroundWindowProc.Call()
	var assertion *Assertion
	result, _, _ := a.getAssertion.Call(
		window,
		uintptr(unsafe.Pointer(rpIDPtr)),
		callPointer(&clientData),
		callPointer(&options),
		uintptr(unsafe.Pointer(&assertion)),
	)

	runtime.KeepAlive(request.CredentialID)
	runtime.KeepAlive(request.Salt)
	runtime.KeepAlive(request.ClientDataJSON)
	runtime.KeepAlive(rpIDPtr)
	runtime.KeepAlive(publicKeyPtr)
	runtime.KeepAlive(sha256Ptr)
	runtime.KeepAlive(credential)
	runtime.KeepAlive(credentials)
	runtime.KeepAlive(clientData)
	runtime.KeepAlive(salt)
	runtime.KeepAlive(saltValues)
	runtime.KeepAlive(options)

	hresult := HRESULT(result)
	if hresult.Failed() {
		return nil, a.callError("WebAuthNAuthenticatorGetAssertion", hresult)
	}
	if assertion == nil {
		return nil, fmt.Errorf("WebAuthNAuthenticatorGetAssertion: nil result")
	}
	defer a.freeAssertion.Call(uintptr(unsafe.Pointer(assertion)))

	if assertion.Version < 3 || assertion.HMACSecret == nil {
		return nil, ErrPRFDisabled
	}

	credentialID, err := copyResultBytes(
		assertion.Credential.ID,
		assertion.Credential.IDLength,
		"credential ID",
	)
	if err != nil {
		return nil, err
	}
	if len(credentialID) == 0 {
		credentialID = append([]byte(nil), request.CredentialID...)
	} else if !bytes.Equal(credentialID, request.CredentialID) {
		return nil, fmt.Errorf("WebAuthNAuthenticatorGetAssertion: returned credential ID does not match request")
	}
	authenticatorData, err := copyResultBytes(
		assertion.AuthenticatorData,
		assertion.AuthenticatorDataLength,
		"authenticator data",
	)
	if err != nil {
		return nil, err
	}

	secretSalt := (*HMACSecretSalt)(assertion.HMACSecret)
	if secretSalt.FirstLength != HMACSecretLength {
		return nil, fmt.Errorf(
			"WebAuthNAuthenticatorGetAssertion: HMAC secret is %d bytes, want %d",
			secretSalt.FirstLength,
			HMACSecretLength,
		)
	}
	secret, err := sealResultBytes(secretSalt.First, secretSalt.FirstLength, "HMAC secret")
	if err != nil {
		return nil, err
	}

	return &GetAssertionResult{
		CredentialID:      credentialID,
		AuthenticatorData: authenticatorData,
		HMACSecret:        secret,
	}, nil
}
