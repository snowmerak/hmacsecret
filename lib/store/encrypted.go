package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/awnumar/memguard"
)

// Errors used by encrypted stores.
var (
	ErrNotInitialized    = errors.New("store: encrypted store is not initialized")
	ErrLocked            = errors.New("store: encrypted store is locked")
	ErrIntegrity         = errors.New("store: encrypted data authentication failed")
	ErrConflict          = errors.New("store: revision conflict")
	ErrUnsupportedFormat = errors.New("store: unsupported encrypted format")
)

// KEKReference contains the public metadata needed to re-derive a KEK.
// The KEK itself is never stored.
type KEKReference struct {
	CredentialID []byte
	Salt         []byte
	RPID         string
}

// EncryptedBlob is a versioned authenticated ciphertext and its public nonce.
type EncryptedBlob struct {
	Version    uint16
	Algorithm  string
	Nonce      []byte
	Ciphertext []byte
}

// EncryptionHeader is the public bootstrap data for an encrypted store.
// WrappedDEK contains the random store DEK encrypted by the KEK.
type EncryptionHeader struct {
	Version    uint16
	Revision   uint64
	StoreID    []byte
	KEK        KEKReference
	WrappedDEK EncryptedBlob
}

// EncryptedStore extends Store with KEK lifecycle operations.
//
// Initialize and Unlock accept a sealed 32-byte KEK. Implementations must not
// retain the KEK after wrapping or unwrapping the store DEK.
type EncryptedStore interface {
	Store

	// Header returns the public KEK reference and wrapped store DEK.
	Header(ctx context.Context) (EncryptionHeader, error)
	// Initialize creates a new encrypted-store header and leaves the store unlocked.
	Initialize(ctx context.Context, ref KEKReference, kek *memguard.Enclave) error
	// Unlock unwraps the store DEK with kek.
	Unlock(ctx context.Context, kek *memguard.Enclave) error
	// Lock forgets the in-memory store DEK. It does not close the backend.
	Lock()
	// RotateKEK rewraps the existing store DEK without rewriting record ciphertext.
	RotateKEK(ctx context.Context, next KEKReference, nextKEK *memguard.Enclave) error
}

// EnvelopeBackend persists encrypted-store headers and record envelopes.
// It never receives plaintext credential records or key material.
type EnvelopeBackend interface {
	CreateHeader(ctx context.Context, header EncryptionHeader) error
	LoadHeader(ctx context.Context) (EncryptionHeader, error)
	CompareAndSwapHeader(ctx context.Context, expectedRevision uint64, next EncryptionHeader) error

	PutEnvelope(ctx context.Context, alias string, blob EncryptedBlob) error
	GetEnvelope(ctx context.Context, alias string) (EncryptedBlob, error)
	DeleteEnvelope(ctx context.Context, alias string) error
	HasEnvelope(ctx context.Context, alias string) (bool, error)
	ListEnvelopes(ctx context.Context) ([]string, error)

	Close() error
}

// ValidateKEKReference checks public metadata required to re-derive a KEK.
func ValidateKEKReference(ref KEKReference) error {
	if len(ref.CredentialID) == 0 {
		return fmt.Errorf("%w: empty KEK credential id", ErrInvalidRecord)
	}
	if len(ref.Salt) != SaltSize {
		return fmt.Errorf("%w: KEK salt must be %d bytes", ErrInvalidRecord, SaltSize)
	}
	if strings.TrimSpace(ref.RPID) == "" {
		return fmt.Errorf("%w: empty KEK rp id", ErrInvalidRecord)
	}
	return nil
}
