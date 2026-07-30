// Package secrets provides a simple alias-based API over hmacsecret + store.
//
// Public methods take only alias (the store primary key). Authenticator
// selection and PIN collection are injected via DeviceSelector and PINProvider.
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

// Operation identifies why an authenticator interaction is requested.
type Operation string

const (
	OpCreate Operation = "create"
	OpDerive Operation = "derive"
)

// DeviceSelector chooses one device from a freshly listed set.
// It returns a DeviceInfo (path); Secrets opens the device after selection.
type DeviceSelector interface {
	Select(ctx context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error)
}

// DeviceSelectorFunc adapts a function to DeviceSelector.
type DeviceSelectorFunc func(ctx context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error)

// Select implements DeviceSelector.
func (f DeviceSelectorFunc) Select(ctx context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
	return f(ctx, devices)
}

// PINProvider returns a PIN for the selected device and operation.
// Return "" when the platform collects PIN/UV itself (e.g. Windows WebAuthn).
type PINProvider interface {
	Provide(ctx context.Context, op Operation, device hmacsecret.DeviceInfo) (string, error)
}

// PINProviderFunc adapts a function to PINProvider.
type PINProviderFunc func(ctx context.Context, op Operation, device hmacsecret.DeviceInfo) (string, error)

// Provide implements PINProvider.
func (f PINProviderFunc) Provide(ctx context.Context, op Operation, device hmacsecret.DeviceInfo) (string, error) {
	return f(ctx, op, device)
}

// Authenticator is the FIDO surface secrets needs after a device is opened.
// *hmacsecret.Device satisfies this interface.
type Authenticator interface {
	CreateCredential(opts hmacsecret.CreateOptions) (*hmacsecret.Credential, error)
	Derive(opts hmacsecret.DeriveOptions) (*hmacsecret.Secret, error)
}

// Options configures Secrets.
type Options struct {
	// Store is required. alias is the primary key for credential_id + salt (+ rp_id).
	Store store.Store
	// Devices lists authenticators each call. Defaults to hmacsecret.ListDevices.
	Devices func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error)
	// Open opens a device path. Defaults to hmacsecret.Open.
	Open func(path string) (Authenticator, error)
	// Select chooses a device from the listed set. Required.
	Select DeviceSelector
	// PIN provides a PIN after device selection. Required.
	// Use NoPIN() when the OS UI handles UV (Windows WebAuthn).
	PIN PINProvider
	// ListOptions is passed to Devices on each call.
	ListOptions hmacsecret.ListOptions
	// RPID binds newly created credentials (stored per alias). Defaults to hmac-secret.example.
	RPID string
	// RPName is optional RP display name for create.
	RPName string
	// UserName is optional credential user name for create.
	UserName string
}

// Secrets is the high-level alias API.
// Callers pass alias every time; nothing about alias is fixed in Options.
type Secrets struct {
	store    store.Store
	devices  func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error)
	open     func(path string) (Authenticator, error)
	select_  DeviceSelector
	pin      PINProvider
	listOpts hmacsecret.ListOptions
	rpID     string
	rpName   string
	userName string

	// createMu serializes Create: Has → enroll → Put (no double UI / orphans).
	createMu sync.Mutex
}

// New constructs Secrets.
func New(opts Options) (*Secrets, error) {
	if opts.Store == nil {
		return nil, errors.New("secrets: Store is required")
	}
	if opts.Select == nil {
		return nil, errors.New("secrets: Select is required")
	}
	if opts.PIN == nil {
		return nil, errors.New("secrets: PIN is required")
	}

	devices := opts.Devices
	if devices == nil {
		devices = hmacsecret.ListDevices
	}
	open := opts.Open
	if open == nil {
		open = func(path string) (Authenticator, error) {
			return hmacsecret.Open(path)
		}
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
		devices:  devices,
		open:     open,
		select_:  opts.Select,
		pin:      opts.PIN,
		listOpts: opts.ListOptions,
		rpID:     rpID,
		rpName:   rpName,
		userName: userName,
	}, nil
}

// Create registers a new FIDO hmac-secret credential under alias and returns
// the derived secret bytes. alias is the store primary key for this credential.
//
// Order: generate salt → CreateCredential → store.Put → Derive.
// If the first Derive fails, metadata is stored so Derive(alias) can retry.
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

	salt := make([]byte, store.SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("secrets create salt: %w", err)
	}

	auth, info, pin, err := s.openSelected(ctx, OpCreate)
	if err != nil {
		return nil, err
	}
	_ = info

	cred, err := auth.CreateCredential(hmacsecret.CreateOptions{
		RPID:     s.rpID,
		RPName:   s.rpName,
		UserName: s.userName,
		PIN:      pin,
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
		PIN:          pin,
	})
	if err != nil {
		return nil, fmt.Errorf("secrets create derive: %w", err)
	}
	return append([]byte(nil), sec.HMACSecret...), nil
}

// Derive re-derives the hmac-secret for an existing alias.
// alias is looked up in the store (credential_id + salt + rp_id).
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

	auth, _, pin, err := s.openSelected(ctx, OpDerive)
	if err != nil {
		return nil, err
	}

	sec, err := auth.Derive(hmacsecret.DeriveOptions{
		RPID:         rec.RPID,
		CredentialID: rec.CredentialID,
		Salt:         rec.Salt,
		PIN:          pin,
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

func (s *Secrets) openSelected(ctx context.Context, op Operation) (Authenticator, hmacsecret.DeviceInfo, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, hmacsecret.DeviceInfo{}, "", err
	}
	devices, err := s.devices(s.listOpts)
	if err != nil {
		return nil, hmacsecret.DeviceInfo{}, "", fmt.Errorf("%w: %v", ErrNoDevice, err)
	}
	if len(devices) == 0 {
		return nil, hmacsecret.DeviceInfo{}, "", ErrNoDevice
	}

	info, err := s.select_.Select(ctx, devices)
	if err != nil {
		return nil, hmacsecret.DeviceInfo{}, "", fmt.Errorf("%w: %v", ErrNoDevice, err)
	}
	if strings.TrimSpace(info.Path) == "" {
		return nil, hmacsecret.DeviceInfo{}, "", fmt.Errorf("%w: empty device path", ErrNoDevice)
	}

	pin, err := s.pin.Provide(ctx, op, info)
	if err != nil {
		return nil, hmacsecret.DeviceInfo{}, "", fmt.Errorf("secrets pin: %w", err)
	}

	auth, err := s.open(info.Path)
	if err != nil {
		return nil, hmacsecret.DeviceInfo{}, "", fmt.Errorf("%w: %v", ErrNoDevice, err)
	}
	return auth, info, pin, nil
}

// FirstDevice selects devices[0]. Useful when only one authenticator is present
// or the list order is already preferred (e.g. Windows WebAuthn first).
func FirstDevice() DeviceSelector {
	return DeviceSelectorFunc(func(_ context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
		if len(devices) == 0 {
			return hmacsecret.DeviceInfo{}, ErrNoDevice
		}
		return devices[0], nil
	})
}

// DeviceByPath selects the device whose path matches (case-insensitive on Windows hello path).
func DeviceByPath(path string) DeviceSelector {
	want := strings.TrimSpace(path)
	return DeviceSelectorFunc(func(_ context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
		for _, d := range devices {
			if strings.EqualFold(d.Path, want) {
				return d, nil
			}
		}
		return hmacsecret.DeviceInfo{}, fmt.Errorf("%w: path %q not found", ErrNoDevice, want)
	})
}

// DeviceByIndex selects devices[index] from the current listing.
func DeviceByIndex(index int) DeviceSelector {
	return DeviceSelectorFunc(func(_ context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
		if index < 0 || index >= len(devices) {
			return hmacsecret.DeviceInfo{}, fmt.Errorf("%w: index %d out of range (count=%d)", ErrNoDevice, index, len(devices))
		}
		return devices[index], nil
	})
}

// NoPIN always returns an empty PIN (Windows WebAuthn / UV via OS UI).
func NoPIN() PINProvider {
	return PINProviderFunc(func(context.Context, Operation, hmacsecret.DeviceInfo) (string, error) {
		return "", nil
	})
}

// StaticPIN always returns pin.
func StaticPIN(pin string) PINProvider {
	return PINProviderFunc(func(context.Context, Operation, hmacsecret.DeviceInfo) (string, error) {
		return pin, nil
	})
}

// TerminalPIN asks for a console PIN when the device needs one; otherwise "".
func TerminalPIN() PINProvider {
	return PINProviderFunc(func(_ context.Context, _ Operation, device hmacsecret.DeviceInfo) (string, error) {
		if !hmacsecret.NeedsTerminalPIN(device.Path) {
			return "", nil
		}
		return hmacsecret.ReadTerminalPIN(nil)
	})
}
