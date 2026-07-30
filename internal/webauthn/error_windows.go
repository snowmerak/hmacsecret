//go:build windows

package webauthn

import (
	"errors"
	"fmt"
)

var (
	ErrUnsupported  = errors.New("Windows WebAuthn operation is unsupported")
	ErrInvalidInput = errors.New("Windows WebAuthn input is invalid")
	ErrNotFound     = errors.New("Windows WebAuthn credential or device was not found")
	ErrUserCanceled = errors.New("Windows WebAuthn operation was canceled")
	ErrPRFDisabled  = errors.New("Windows WebAuthn PRF extension was not enabled")
)

type CallError struct {
	Operation string
	Result    HRESULT
	Name      string
}

func (e *CallError) Error() string {
	name := e.Name
	if name == "" {
		name = e.Result.Error()
	}
	return fmt.Sprintf("%s: %s (0x%08x)", e.Operation, name, uint32(e.Result))
}

func (e *CallError) Unwrap() error {
	switch e.Result {
	case NTENotSupported:
		return ErrUnsupported
	case NTEInvalidParameter:
		return ErrInvalidInput
	case NTEDeviceNotFound, NTENotFound:
		return ErrNotFound
	case NTEUserCancelled, HRESULTCancelled:
		return ErrUserCanceled
	default:
		return nil
	}
}

func (a *API) callError(operation string, result HRESULT) error {
	return &CallError{
		Operation: operation,
		Result:    result,
		Name:      a.ErrorName(result),
	}
}
