//go:build windows && !hmacsecret_libfido2

package hmacsecret

import (
	"errors"
	"fmt"
	"strings"

	winwebauthn "github.com/snowmerak/hmacsecret/internal/webauthn"
)

// CreateCredential registers a non-discoverable PRF-enabled credential.
func (d *Device) CreateCredential(opts CreateOptions) (*Credential, error) {
	if d == nil || d.api == nil {
		return nil, ErrInvalidArgument
	}

	rpID := strings.TrimSpace(opts.RPID)
	if rpID == "" {
		return nil, fmt.Errorf("%w: RPID is required", ErrInvalidArgument)
	}
	userName := strings.TrimSpace(opts.UserName)
	if userName == "" {
		userName = "hmac-secret"
	}
	displayName := strings.TrimSpace(opts.UserDisplayName)
	if displayName == "" {
		displayName = userName
	}
	rpName := strings.TrimSpace(opts.RPName)
	if rpName == "" {
		rpName = "hmacsecret"
	}

	userID := opts.UserID
	var err error
	if len(userID) == 0 {
		userID, err = randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("generate user id: %w", err)
		}
	}

	challenge, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	clientDataJSON := opts.ClientDataJSON
	if len(clientDataJSON) == 0 {
		clientDataJSON, err = MakeClientDataJSON("webauthn.create", challenge, rpID)
		if err != nil {
			return nil, err
		}
	}

	result, err := d.api.MakeCredential(winwebauthn.MakeCredentialRequest{
		RPID:            rpID,
		RPName:          rpName,
		UserID:          userID,
		UserName:        userName,
		UserDisplayName: displayName,
		ClientDataJSON:  clientDataJSON,
	})
	if err != nil {
		return nil, mapWindowsError("make hmac-secret credential", err)
	}
	return &Credential{
		ID:   append([]byte(nil), result.CredentialID...),
		RPID: rpID,
	}, nil
}

// Derive requests a PRF value for credential+salt.
func (d *Device) Derive(opts DeriveOptions) (*Secret, error) {
	if d == nil || d.api == nil {
		return nil, ErrInvalidArgument
	}

	rpID := strings.TrimSpace(opts.RPID)
	if rpID == "" {
		return nil, fmt.Errorf("%w: RPID is required", ErrInvalidArgument)
	}
	if len(opts.CredentialID) == 0 {
		return nil, fmt.Errorf("%w: CredentialID is required", ErrInvalidArgument)
	}
	if err := validateSalt(opts.Salt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	if opts.UserPresenceSet && !opts.UserPresence {
		return nil, fmt.Errorf("%w: Windows WebAuthn requires user presence", ErrInvalidArgument)
	}

	challenge, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("generate challenge: %w", err)
	}
	clientDataJSON := opts.ClientDataJSON
	if len(clientDataJSON) == 0 {
		clientDataJSON, err = MakeClientDataJSON("webauthn.get", challenge, rpID)
		if err != nil {
			return nil, err
		}
	}

	result, err := d.api.GetAssertion(winwebauthn.GetAssertionRequest{
		RPID:           rpID,
		CredentialID:   opts.CredentialID,
		Salt:           opts.Salt,
		ClientDataJSON: clientDataJSON,
	})
	if err != nil {
		return nil, mapWindowsError("hmac-secret assertion", err)
	}
	if len(result.HMACSecret) == 0 {
		return nil, ErrEmptyHMACSecret
	}
	return &Secret{
		CredentialID: append([]byte(nil), opts.CredentialID...),
		Salt:         append([]byte(nil), opts.Salt...),
		HMACSecret:   append([]byte(nil), result.HMACSecret...),
	}, nil
}

// CreateAndDerive creates a credential then immediately derives a secret.
func (d *Device) CreateAndDerive(create CreateOptions, salt []byte, pin string) (*Secret, error) {
	create.PIN = pin
	cred, err := d.CreateCredential(create)
	if err != nil {
		return nil, err
	}
	if len(salt) == 0 {
		salt, err = randomBytes(SaltSize)
		if err != nil {
			return nil, fmt.Errorf("generate salt: %w", err)
		}
	}
	return d.Derive(DeriveOptions{
		RPID:         create.RPID,
		CredentialID: cred.ID,
		Salt:         salt,
		PIN:          pin,
	})
}

func mapWindowsError(operation string, err error) error {
	switch {
	case errors.Is(err, winwebauthn.ErrInvalidInput):
		return fmt.Errorf("%w: %s: %v", ErrInvalidArgument, operation, err)
	case errors.Is(err, winwebauthn.ErrUnsupported), errors.Is(err, winwebauthn.ErrPRFDisabled):
		return fmt.Errorf("%w: %s: %v", ErrNotFIDO2, operation, err)
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}
