package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	"github.com/snowmerak/hmacsecret/lib/store"
	"github.com/snowmerak/hmacsecret/pkg/secrets"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
)

type mockAuth struct {
	mu             sync.Mutex
	createCalls    atomic.Int32
	createCred     *hmacsecret.Credential
	deriveSecret   *hmacsecret.Secret
	createErr      error
	deriveErr      error
	lastDerive     hmacsecret.DeriveOptions
	lastCreatePIN  string
	lastDerivePIN  string
	createDelay    time.Duration
	failFirstDer   bool
	deriveFailOnce atomic.Bool
}

func (m *mockAuth) CreateCredential(opts hmacsecret.CreateOptions) (*hmacsecret.Credential, error) {
	m.createCalls.Add(1)
	if m.createDelay > 0 {
		time.Sleep(m.createDelay)
	}
	if m.createErr != nil {
		return nil, m.createErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastCreatePIN = opts.PIN
	cred := *m.createCred
	n := m.createCalls.Load()
	cred.ID = append(append([]byte(nil), m.createCred.ID...), byte(n))
	cred.RPID = opts.RPID
	return &cred, nil
}

func (m *mockAuth) Derive(opts hmacsecret.DeriveOptions) (*hmacsecret.Secret, error) {
	m.mu.Lock()
	m.lastDerive = opts
	m.lastDerivePIN = opts.PIN
	m.mu.Unlock()
	if m.failFirstDer && m.deriveFailOnce.CompareAndSwap(false, true) {
		return nil, errors.New("transient derive failure")
	}
	if m.deriveErr != nil {
		return nil, m.deriveErr
	}
	sec := *m.deriveSecret
	sec.CredentialID = append([]byte(nil), opts.CredentialID...)
	sec.Salt = append([]byte(nil), opts.Salt...)
	return &sec, nil
}

func newTestSecrets(t *testing.T, auth *mockAuth, pin secrets.PINProvider) *secrets.Secrets {
	t.Helper()
	st, err := pebble.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	devices := []hmacsecret.DeviceInfo{{Index: 0, Path: "test://dev", Product: "mock"}}
	svc, err := secrets.New(secrets.Options{
		Store: st,
		Devices: func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error) {
			return devices, nil
		},
		Open: func(string) (secrets.Authenticator, error) {
			return auth, nil
		},
		Select: secrets.FirstDevice(),
		PIN:    pin,
		RPID:   "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestCreateDeriveDelete(t *testing.T) {
	ctx := context.Background()
	auth := &mockAuth{
		createCred:   &hmacsecret.Credential{ID: []byte{1, 2, 3, 4}, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{HMACSecret: bytes.Repeat([]byte{0x22}, 32)},
	}
	svc := newTestSecrets(t, auth, secrets.StaticPIN("1234"))

	got, err := svc.Create(ctx, "db")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatalf("create secret mismatch")
	}
	if auth.lastCreatePIN != "1234" || auth.lastDerivePIN != "1234" {
		t.Fatalf("pin not from provider: create=%q derive=%q", auth.lastCreatePIN, auth.lastDerivePIN)
	}
	if _, err := svc.Create(ctx, "db"); !errors.Is(err, secrets.ErrExists) {
		t.Fatalf("dup create = %v", err)
	}

	// Different provider pin on a new service would be app wiring; same svc uses same provider.
	got, err = svc.Derive(ctx, "db")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x22}, 32)) {
		t.Fatalf("derive secret mismatch")
	}
	if len(auth.lastDerive.Salt) != store.SaltSize || auth.lastDerive.RPID != "example.com" {
		t.Fatalf("derive opts = %+v", auth.lastDerive)
	}

	if err := svc.Delete(ctx, "db"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Derive(ctx, "db"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("derive after delete = %v", err)
	}
}

func TestCreateStoresBeforeDeriveFailure(t *testing.T) {
	ctx := context.Background()
	auth := &mockAuth{
		createCred:   &hmacsecret.Credential{ID: []byte{9}, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{HMACSecret: bytes.Repeat([]byte{0x33}, 32)},
		failFirstDer: true,
	}
	svc := newTestSecrets(t, auth, secrets.NoPIN())

	if _, err := svc.Create(ctx, "retry-me"); err == nil {
		t.Fatal("expected create derive failure")
	}
	ok, err := svc.Has(ctx, "retry-me")
	if err != nil || !ok {
		t.Fatalf("has after failed create derive: ok=%v err=%v", ok, err)
	}
	got, err := svc.Derive(ctx, "retry-me")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x33}, 32)) {
		t.Fatalf("retry secret mismatch")
	}
}

func TestDeviceSelectorReceivesListing(t *testing.T) {
	ctx := context.Background()
	st, err := pebble.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auth := &mockAuth{
		createCred:   &hmacsecret.Credential{ID: []byte{1}, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{HMACSecret: bytes.Repeat([]byte{0x22}, 32)},
	}
	var seen []hmacsecret.DeviceInfo
	svc, err := secrets.New(secrets.Options{
		Store: st,
		Devices: func(hmacsecret.ListOptions) ([]hmacsecret.DeviceInfo, error) {
			return []hmacsecret.DeviceInfo{
				{Index: 0, Path: "a", Product: "A"},
				{Index: 1, Path: "b", Product: "B"},
			}, nil
		},
		Open: func(path string) (secrets.Authenticator, error) {
			if path != "b" {
				t.Fatalf("opened %q want b", path)
			}
			return auth, nil
		},
		Select: secrets.DeviceSelectorFunc(func(_ context.Context, devices []hmacsecret.DeviceInfo) (hmacsecret.DeviceInfo, error) {
			seen = append([]hmacsecret.DeviceInfo(nil), devices...)
			return devices[1], nil
		}),
		PIN:  secrets.NoPIN(),
		RPID: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[1].Path != "b" {
		t.Fatalf("seen = %+v", seen)
	}
}

func TestConcurrentCreateSameAlias(t *testing.T) {
	ctx := context.Background()
	auth := &mockAuth{
		createCred:   &hmacsecret.Credential{ID: []byte{1}, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{HMACSecret: bytes.Repeat([]byte{0x22}, 32)},
		createDelay:  20 * time.Millisecond,
	}
	svc := newTestSecrets(t, auth, secrets.NoPIN())

	const n = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		success  int
		exists   int
		otherErr int
	)
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, err := svc.Create(ctx, "same")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				success++
			case errors.Is(err, secrets.ErrExists):
				exists++
			default:
				otherErr++
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()

	if success != 1 {
		t.Fatalf("success=%d want 1 (exists=%d other=%d creates=%d)", success, exists, otherErr, auth.createCalls.Load())
	}
	if auth.createCalls.Load() != 1 {
		t.Fatalf("createCalls=%d want 1", auth.createCalls.Load())
	}
}
