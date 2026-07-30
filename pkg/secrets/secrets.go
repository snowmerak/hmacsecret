// Package secrets provides a simple alias-based API over hmacsecret + store.
package secrets

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	"github.com/snowmerak/hmacsecret/lib/store"
)

// Errors.
var (
	ErrInvalidAlias = errors.New("secrets: invalid alias")
	ErrExists       = errors.New("secrets: alias already exists")
	ErrNotFound     = errors.New("secrets: alias not found")
	ErrNoDevice     = errors.New("secrets: no authenticator")
)

// Authenticator is the FIDO surface secrets needs.
// *hmacsecret.Device satisfies this interface.
type Authenticator interface {
	CreateCredential(opts hmacsecret.CreateOptions) (*hmacsecret.Credential, error)
	Derive(opts hmacsecret.DeriveOptions) (*hmacsecret.Secret, error)
}

// OpenFunc opens an authenticator for a create/derive call.
type OpenFunc func(ctx context.Context) (Authenticator, error)

// Options configures Secrets.
type Options struct {
	// Store is required.
	Store store.Store
	// Open opens the authenticator. Required for Create/Derive.
	Open OpenFunc
	// RPID binds new credentials. Required for Create.
	RPID string
	// RPName is optional RP display name.
	RPName string
	// UserName is optional credential user name.
	UserName string
	// PIN is passed to the authenticator. Empty on Windows WebAuthn broker.
	PIN string
}

// Secrets is the high-level alias API.
type Secrets struct {
	store    store.Store
	open     OpenFunc
	rpID     string
	rpName   string
	userName string
	pin      string

	// createMu serializes Create so concurrent callers cannot race
	// Has → FIDO enrollment → Put (avoids double Security UI / orphan races).
	createMu sync.Mutex
}

// New constructs Secrets.
func New(opts Options) (*Secrets, error) {
	if opts.Store == nil {
		return nil, errors.New("secrets: Store is required")
	}
	if opts.Open == nil {
		return nil, errors.New("secrets: Open is required")
	}
	rpID := strings.TrimSpace(opts.RPID)
	if rpID == "" {
		rpID = "hmac-secret.example"
	}
	rpName := strings.TrimSpace(opts.RPName)
	if rpName == "" {
		rpName = "hmacsecret"
	}
	userName := strings.TrimSpace(opts.UserName)
	if userName == "" {
		userName = "hmac-secret"
	}
	return &Secrets{
		store:    opts.Store,
		open:     opts.Open,
		rpID:     rpID,
		rpName:   rpName,
		userName: userName,
		pin:      opts.PIN,
	}, nil
}

// Create registers a new FIDO hmac-secret credential under alias and returns
// the derived secret bytes.
//
// Order: generate salt → CreateCredential → store.Put → Derive.
// If the first Derive fails, metadata is already stored so Derive(alias) can retry.
func (s *Secrets) Create(ctx context.Context, alias string) ([]byte, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return nil, ErrInvalidAlias
	}

	s.createMu.Lock()
	defer s.createMu.Unlock()

	exists, err := s.store.Has(ctx, alias)
	if err != nil {
		return nil, fmt.Errorf("secrets create has: %w", err)
	}
	if exists {
		return nil, ErrExists
	}

	salt := make([]byte, hmacsecret.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("secrets create salt: %w", err)
	}

	auth, err := s.open(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDevice, err)
	}

	cred, err := auth.CreateCredential(hmacsecret.CreateOptions{
		RPID:     s.rpID,
		RPName:   s.rpName,
		UserName: s.userName,
		PIN:      s.pin,
	})
	if err != nil {
		return nil, fmt.Errorf("secrets create fido: %w", err)
	}

	rec := store.Record{
		Alias:        alias,
		CredentialID: append([]byte(nil), cred.ID...),
		Salt:         append([]byte(nil), salt...),
		RPID:         s.rpID,
	}
	if err := s.store.Put(ctx, rec); err != nil {
		if errors.Is(err, store.ErrExists) {
			return nil, ErrExists
		}
		return nil, fmt.Errorf("secrets create store: %w", err)
	}

	sec, err := auth.Derive(hmacsecret.DeriveOptions{
		RPID:         rec.RPID,
		CredentialID: rec.CredentialID,
		Salt:         rec.Salt,
		PIN:          s.pin,
	})
	if err != nil {
		// Record is durable; caller can secrets.Derive(alias) to retry.
		return nil, fmt.Errorf("secrets create derive: %w", err)
	}
	return append([]byte(nil), sec.HMACSecret...), nil
}

// Derive re-derives the hmac-secret for an existing alias.
func (s *Secrets) Derive(ctx context.Context, alias string) ([]byte, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return nil, ErrInvalidAlias
	}

	rec, err := s.store.Get(ctx, alias)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("secrets derive store: %w", err)
	}

	auth, err := s.open(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDevice, err)
	}

	sec, err := auth.Derive(hmacsecret.DeriveOptions{
		RPID:         rec.RPID,
		CredentialID: rec.CredentialID,
		Salt:         rec.Salt,
		PIN:          s.pin,
	})
	if err != nil {
		return nil, fmt.Errorf("secrets derive fido: %w", err)
	}
	return append([]byte(nil), sec.HMACSecret...), nil
}

// Delete removes stored metadata for alias. Does not touch the authenticator.
func (s *Secrets) Delete(ctx context.Context, alias string) error {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return ErrInvalidAlias
	}
	if err := s.store.Delete(ctx, alias); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("secrets delete: %w", err)
	}
	return nil
}

// Has reports whether alias exists in the store.
func (s *Secrets) Has(ctx context.Context, alias string) (bool, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return false, ErrInvalidAlias
	}
	ok, err := s.store.Has(ctx, alias)
	if err != nil {
		return false, fmt.Errorf("secrets has: %w", err)
	}
	return ok, nil
}

// List returns stored aliases.
func (s *Secrets) List(ctx context.Context) ([]string, error) {
	aliases, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("secrets list: %w", err)
	}
	return aliases, nil
}

// DefaultOpen returns an OpenFunc that opens device index 0 with listOpts.
func DefaultOpen(deviceIndex int, listOpts hmacsecret.ListOptions) OpenFunc {
	return func(ctx context.Context) (Authenticator, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dev, err := hmacsecret.OpenIndex(deviceIndex, listOpts)
		if err != nil {
			return nil, err
		}
		return dev, nil
	}
}
