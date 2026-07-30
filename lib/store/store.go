// Package store defines the credential metadata storage contract.
// Implementations live under pkg/store/*.
package store

import (
	"context"
	"errors"
	"fmt"
)

// SaltSize matches FIDO2 hmac-secret salt length (lib/hmacsecret.SaltSize).
const SaltSize = 32

// Sentinel errors.
var (
	ErrNotFound      = errors.New("store: alias not found")
	ErrExists        = errors.New("store: alias already exists")
	ErrInvalidAlias  = errors.New("store: invalid alias")
	ErrInvalidRecord = errors.New("store: invalid record")
)

// Record is metadata required to re-derive an hmac-secret.
// Alias is the primary key. HMAC secret bytes are never stored.
type Record struct {
	Alias        string
	CredentialID []byte
	Salt         []byte
	RPID         string
}

// Store persists alias → credential metadata.
type Store interface {
	// Put inserts record. Returns ErrExists if alias is already present.
	Put(ctx context.Context, rec Record) error
	// Get returns the record for alias. Returns ErrNotFound if missing.
	Get(ctx context.Context, alias string) (Record, error)
	// Delete removes alias. Returns ErrNotFound if missing.
	Delete(ctx context.Context, alias string) error
	// Has reports whether alias exists.
	Has(ctx context.Context, alias string) (bool, error)
	// List returns all aliases in unspecified order.
	List(ctx context.Context) ([]string, error)
	// Close releases resources.
	Close() error
}

// ValidateAlias checks alias is non-empty.
func ValidateAlias(alias string) error {
	if alias == "" {
		return ErrInvalidAlias
	}
	return nil
}

// ValidateRecord checks required fields for Put/Get decoding.
func ValidateRecord(rec Record) error {
	if err := ValidateAlias(rec.Alias); err != nil {
		return err
	}
	if len(rec.CredentialID) == 0 {
		return fmt.Errorf("%w: empty credential id", ErrInvalidRecord)
	}
	if len(rec.Salt) != SaltSize {
		return fmt.Errorf("%w: salt must be %d bytes", ErrInvalidRecord, SaltSize)
	}
	if rec.RPID == "" {
		return fmt.Errorf("%w: empty rp id", ErrInvalidRecord)
	}
	return nil
}
