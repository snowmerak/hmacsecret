//go:build windows

package webauthn

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const defaultTimeout = 10 * time.Minute

var (
	user32DLL               = windows.NewLazySystemDLL("user32.dll")
	getForegroundWindowProc = user32DLL.NewProc("GetForegroundWindow")
)

type MakeCredentialRequest struct {
	RPID            string
	RPName          string
	UserID          []byte
	UserName        string
	UserDisplayName string
	ClientDataJSON  []byte
	Timeout         time.Duration
}

type MakeCredentialResult struct {
	CredentialID      []byte
	AuthenticatorData []byte
	PRFEnabled        bool
}

func (a *API) MakeCredential(request MakeCredentialRequest) (*MakeCredentialResult, error) {
	if a == nil || a.makeCredential == nil {
		return nil, ErrUnavailable
	}
	if version := a.Version(); version < APIVersionPRF {
		return nil, fmt.Errorf("%w: API version %d, PRF requires >= %d", ErrUnsupported, version, APIVersionPRF)
	}
	if request.RPID == "" {
		return nil, fmt.Errorf("%w: RP ID is required", ErrInvalidInput)
	}
	if len(request.UserID) == 0 || len(request.UserID) > 64 {
		return nil, fmt.Errorf("%w: user ID must contain 1..64 bytes", ErrInvalidInput)
	}
	if request.UserName == "" {
		return nil, fmt.Errorf("%w: user name is required", ErrInvalidInput)
	}
	if len(request.ClientDataJSON) == 0 {
		return nil, fmt.Errorf("%w: client data JSON is required", ErrInvalidInput)
	}

	rpName := request.RPName
	if rpName == "" {
		rpName = request.RPID
	}
	displayName := request.UserDisplayName
	if displayName == "" {
		displayName = request.UserName
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
	rpNamePtr, err := utf16Pointer(rpName)
	if err != nil {
		return nil, err
	}
	userNamePtr, err := utf16Pointer(request.UserName)
	if err != nil {
		return nil, err
	}
	displayNamePtr, err := utf16Pointer(displayName)
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
	hmacSecretPtr, err := utf16Pointer("hmac-secret")
	if err != nil {
		return nil, err
	}

	rp := RPEntityInformation{
		Version: RPEntityInformationVersion,
		ID:      unsafe.Pointer(rpIDPtr),
		Name:    unsafe.Pointer(rpNamePtr),
	}
	user := UserEntityInformation{
		Version:     UserEntityInformationVersion,
		IDLength:    uint32(len(request.UserID)),
		ID:          bytePointer(request.UserID),
		Name:        unsafe.Pointer(userNamePtr),
		DisplayName: unsafe.Pointer(displayNamePtr),
	}
	parameter := COSECredentialParameter{
		Version:        COSECredentialParameterVersion,
		CredentialType: unsafe.Pointer(publicKeyPtr),
		Algorithm:      COSEAlgorithmES256,
	}
	parameters := COSECredentialParameters{
		Count:      1,
		Parameters: structPointer(&parameter),
	}
	clientData := ClientData{
		Version:       ClientDataVersion,
		JSONLength:    uint32(len(request.ClientDataJSON)),
		JSON:          bytePointer(request.ClientDataJSON),
		HashAlgorithm: unsafe.Pointer(sha256Ptr),
	}
	extensionEnabled := int32(1)
	extension := Extension{
		Identifier: unsafe.Pointer(hmacSecretPtr),
		ValueSize:  uint32(unsafe.Sizeof(extensionEnabled)),
		Value:      structPointer(&extensionEnabled),
	}
	options := MakeCredentialOptionsV6{
		Version:                         MakeCredentialOptionsVersionPRF,
		TimeoutMilliseconds:             uint32(timeout / time.Millisecond),
		Extensions:                      Extensions{Count: 1, Extensions: structPointer(&extension)},
		AuthenticatorAttachment:         AuthenticatorAttachmentCrossPlatform,
		RequireResidentKey:              0,
		UserVerificationRequirement:     UserVerificationAny,
		AttestationConveyancePreference: AttestationConveyanceDirect,
		EnablePRF:                       1,
	}

	window, _, _ := getForegroundWindowProc.Call()
	var attestation *CredentialAttestation
	result, _, _ := a.makeCredential.Call(
		window,
		callPointer(&rp),
		callPointer(&user),
		callPointer(&parameters),
		callPointer(&clientData),
		callPointer(&options),
		uintptr(unsafe.Pointer(&attestation)),
	)

	runtime.KeepAlive(request.UserID)
	runtime.KeepAlive(request.ClientDataJSON)
	runtime.KeepAlive(rpIDPtr)
	runtime.KeepAlive(rpNamePtr)
	runtime.KeepAlive(userNamePtr)
	runtime.KeepAlive(displayNamePtr)
	runtime.KeepAlive(publicKeyPtr)
	runtime.KeepAlive(sha256Ptr)
	runtime.KeepAlive(hmacSecretPtr)
	runtime.KeepAlive(rp)
	runtime.KeepAlive(user)
	runtime.KeepAlive(parameter)
	runtime.KeepAlive(parameters)
	runtime.KeepAlive(clientData)
	runtime.KeepAlive(extensionEnabled)
	runtime.KeepAlive(extension)
	runtime.KeepAlive(options)

	hresult := HRESULT(result)
	if hresult.Failed() {
		return nil, a.callError("WebAuthNAuthenticatorMakeCredential", hresult)
	}
	if attestation == nil {
		return nil, fmt.Errorf("WebAuthNAuthenticatorMakeCredential: nil result")
	}
	defer a.freeCredentialAttestation.Call(uintptr(unsafe.Pointer(attestation)))

	credentialID, err := copyResultBytes(attestation.CredentialID, attestation.CredentialIDLength, "credential ID")
	if err != nil {
		return nil, err
	}
	if len(credentialID) == 0 {
		return nil, fmt.Errorf("WebAuthNAuthenticatorMakeCredential: empty credential ID")
	}
	authenticatorData, err := copyResultBytes(
		attestation.AuthenticatorData,
		attestation.AuthenticatorDataLength,
		"authenticator data",
	)
	if err != nil {
		return nil, err
	}

	prfEnabled := attestation.Version >= 5 && attestation.PRFEnabled != 0
	if !prfEnabled {
		prfEnabled = hmacSecretExtensionEnabled(attestation.Extensions)
	}
	if !prfEnabled {
		return nil, ErrPRFDisabled
	}
	return &MakeCredentialResult{
		CredentialID:      credentialID,
		AuthenticatorData: authenticatorData,
		PRFEnabled:        true,
	}, nil
}

func hmacSecretExtensionEnabled(extensions Extensions) bool {
	if extensions.Count == 0 || extensions.Extensions == nil || extensions.Count > 64 {
		return false
	}
	for _, extension := range unsafe.Slice((*Extension)(extensions.Extensions), extensions.Count) {
		if extension.Identifier == nil ||
			windows.UTF16PtrToString((*uint16)(extension.Identifier)) != "hmac-secret" {
			continue
		}
		if extension.ValueSize < uint32(unsafe.Sizeof(int32(0))) || extension.Value == nil {
			return false
		}
		return *(*int32)(extension.Value) != 0
	}
	return false
}
