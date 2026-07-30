//go:build windows

package webauthn

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

var ErrUnavailable = errors.New("Windows WebAuthn API is unavailable")

type HRESULT uint32

func (h HRESULT) Failed() bool {
	return int32(h) < 0
}

func (h HRESULT) Error() string {
	return fmt.Sprintf("HRESULT 0x%08x", uint32(h))
}

type API struct {
	dll                       *windows.LazyDLL
	getAPIVersion             *windows.LazyProc
	makeCredential            *windows.LazyProc
	getAssertion              *windows.LazyProc
	freeCredentialAttestation *windows.LazyProc
	freeAssertion             *windows.LazyProc
}

func Load() (*API, error) {
	dll := windows.NewLazySystemDLL("webauthn.dll")
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	api := &API{
		dll:                       dll,
		getAPIVersion:             dll.NewProc("WebAuthNGetApiVersionNumber"),
		makeCredential:            dll.NewProc("WebAuthNAuthenticatorMakeCredential"),
		getAssertion:              dll.NewProc("WebAuthNAuthenticatorGetAssertion"),
		freeCredentialAttestation: dll.NewProc("WebAuthNFreeCredentialAttestation"),
		freeAssertion:             dll.NewProc("WebAuthNFreeAssertion"),
	}

	for name, proc := range map[string]*windows.LazyProc{
		"WebAuthNGetApiVersionNumber":         api.getAPIVersion,
		"WebAuthNAuthenticatorMakeCredential": api.makeCredential,
		"WebAuthNAuthenticatorGetAssertion":   api.getAssertion,
		"WebAuthNFreeCredentialAttestation":   api.freeCredentialAttestation,
		"WebAuthNFreeAssertion":               api.freeAssertion,
	} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, name, err)
		}
	}

	if version := api.Version(); version < 1 {
		return nil, fmt.Errorf("%w: invalid API version %d", ErrUnavailable, version)
	}
	return api, nil
}

func (a *API) Version() uint32 {
	if a == nil || a.getAPIVersion == nil {
		return 0
	}
	version, _, _ := a.getAPIVersion.Call()
	return uint32(version)
}

func (a *API) ErrorName(result HRESULT) string {
	switch result {
	case S_OK:
		return "Success"
	case NTEInvalidParameter:
		return "NotSupportedError"
	case NTENotSupported:
		return "ConstraintError"
	case NTEDeviceNotFound, NTENotFound, NTEUserCancelled, HRESULTCancelled:
		return "NotAllowedError"
	default:
		return result.Error()
	}
}
