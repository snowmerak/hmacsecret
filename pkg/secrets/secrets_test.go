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
	"github.com/snowmerak/hmacsecret/pkg/secrets"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
)

type mockAuth struct {
	mu            sync.Mutex
	createCalls   atomic.Int32
	deriveCalls   atomic.Int32
	createCred    *hmacsecret.Credential
	deriveSecret  *hmacsecret.Secret
	createErr     error
	deriveErr     error
	lastDerive    hmacsecret.DeriveOptions
	createDelay   time.Duration
	failFirstDer  bool
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
	cred := *m.createCred
	n := m.createCalls.Load()
	cred.ID = append(append([]byte(nil), m.createCred.ID...), byte(n))
	cred.RPID = opts.RPID
	return &cred, nil
}

func (m *mockAuth) Derive(opts hmacsecret.DeriveOptions) (*hmacsecret.Secret, error) {
	m.deriveCalls.Add(1)
	m.mu.Lock()
	m.lastDerive = opts
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

func TestCreateDeriveDelete(t *testing.T) {
	ctx := context.Background()
	st, err := pebble.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	credID := []byte{1, 2, 3, 4}
	secret := bytes.Repeat([]byte{0x22}, 32)

	auth := &mockAuth{
		createCred: &hmacsecret.Credential{ID: credID, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{
			HMACSecret: secret,
		},
	}

	svc, err := secrets.New(secrets.Options{
		Store: st,
		Open:  func(context.Context) (secrets.Authenticator, error) { return auth, nil },
		RPID:  "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := svc.Create(ctx, "db")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("create secret mismatch")
	}
	if _, err := svc.Create(ctx, "db"); !errors.Is(err, secrets.ErrExists) {
		t.Fatalf("dup create = %v", err)
	}

	got, err = svc.Derive(ctx, "db")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("derive secret mismatch")
	}
	if len(auth.lastDerive.CredentialID) == 0 || len(auth.lastDerive.Salt) != hmacsecret.SaltSize {
		t.Fatalf("derive opts = %+v", auth.lastDerive)
	}
	if auth.lastDerive.RPID != "example.com" {
		t.Fatalf("rp = %q", auth.lastDerive.RPID)
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
	st, err := pebble.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auth := &mockAuth{
		createCred:   &hmacsecret.Credential{ID: []byte{9}, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{HMACSecret: bytes.Repeat([]byte{0x33}, 32)},
		failFirstDer: true,
	}
	svc, err := secrets.New(secrets.Options{
		Store: st,
		Open:  func(context.Context) (secrets.Authenticator, error) { return auth, nil },
		RPID:  "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Create(ctx, "retry-me"); err == nil {
		t.Fatal("expected create derive failure")
	}
	ok, err := svc.Has(ctx, "retry-me")
	if err != nil || !ok {
		t.Fatalf("has after failed create derive: ok=%v err=%v", ok, err)
	}
	// Retry via Derive should succeed with stored metadata.
	got, err := svc.Derive(ctx, "retry-me")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x33}, 32)) {
		t.Fatalf("retry secret mismatch")
	}
}

func TestConcurrentCreateSameAlias(t *testing.T) {
	ctx := context.Background()
	st, err := pebble.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	auth := &mockAuth{
		createCred: &hmacsecret.Credential{ID: []byte{1}, RPID: "example.com"},
		deriveSecret: &hmacsecret.Secret{
			HMACSecret: bytes.Repeat([]byte{0x22}, 32),
		},
		createDelay: 20 * time.Millisecond,
	}
	svc, err := secrets.New(secrets.Options{
		Store: st,
		Open:  func(context.Context) (secrets.Authenticator, error) { return auth, nil },
		RPID:  "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}

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
