//go:build cgo && (darwin || linux || hmacsecret_libfido2)

// Package hmacsecret derives secrets with the FIDO2 hmac-secret extension.
//
// It creates non-discoverable credentials (RK=false) and derives a 32-byte
// secret from a credential + 32-byte salt. Results are deterministic for the
// same authenticator, credential, and salt.
//
// Windows (compatibility libfido2 WebAuthn PRF path):
//   - Build with the hmacsecret_libfido2 tag and the required native toolchain.
//   - ListDevices shows windows://hello broker, not individual USB product names.
//   - CreateCredential/Derive open that broker; Windows Security UI lets the user
//     pick the external security key (e.g. T120). CROSS_PLATFORM is applied inside
//     the patched libfido2 winhello backend.
//   - Pass empty PIN for the broker path; PIN/touch are handled by Security UI.
//   - ClientDataJSON is required and auto-generated when omitted.
//
// macOS and Linux: normal CGO builds link the system libfido2 without a custom
// build tag. HID devices are listed directly and PIN is console input.
package hmacsecret

import (
	"fmt"
	"strings"

	libfido2 "github.com/snowmerak/hmacsecret/third_party/go-libfido2"
)

// CreateCredential registers a non-discoverable credential with hmac-secret enabled.
func (d *Device) CreateCredential(opts CreateOptions) (*Credential, error) {
	if d == nil || d.device == nil {
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

	ok, err := d.IsFIDO2()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFIDO2
	}

	userID := opts.UserID
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

	attestation, err := d.device.MakeCredential(
		challenge,
		libfido2.RelyingParty{
			ID:   rpID,
			Name: rpName,
		},
		libfido2.User{
			ID:          userID,
			Name:        userName,
			DisplayName: displayName,
		},
		libfido2.ES256,
		opts.PIN,
		&libfido2.MakeCredentialOpts{
			Extensions:     []libfido2.Extension{libfido2.HMACSecretExtension},
			RK:             libfido2.False,
			ClientDataJSON: clientDataJSON,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("make hmac-secret credential: %w", err)
	}
	if len(attestation.CredentialID) == 0 {
		return nil, fmt.Errorf("make hmac-secret credential: empty credential id")
	}

	return &Credential{
		ID:     append([]byte(nil), attestation.CredentialID...),
		RPID:   rpID,
		PubKey: append([]byte(nil), attestation.PubKey...),
	}, nil
}

// Derive requests an hmac-secret value for credential+salt.
func (d *Device) Derive(opts DeriveOptions) (*Secret, error) {
	if d == nil || d.device == nil {
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

	ok, err := d.IsFIDO2()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFIDO2
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

	up := libfido2.True
	if opts.UserPresenceSet && !opts.UserPresence {
		up = libfido2.False
	} else if opts.UserPresenceSet && opts.UserPresence {
		up = libfido2.True
	}

	assertion, err := d.device.Assertion(
		rpID,
		challenge,
		[][]byte{opts.CredentialID},
		opts.PIN,
		&libfido2.AssertionOpts{
			Extensions:     []libfido2.Extension{libfido2.HMACSecretExtension},
			UP:             up,
			HMACSalt:       opts.Salt,
			ClientDataJSON: clientDataJSON,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("hmac-secret assertion: %w", err)
	}
	if len(assertion.HMACSecret) == 0 {
		return nil, ErrEmptyHMACSecret
	}

	return &Secret{
		CredentialID: append([]byte(nil), opts.CredentialID...),
		Salt:         append([]byte(nil), opts.Salt...),
		HMACSecret:   append([]byte(nil), assertion.HMACSecret...),
	}, nil
}

// CreateAndDerive creates a credential then immediately derives a secret.
// If salt is nil/empty, a random salt is generated.
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
