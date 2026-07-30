package encrypted_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/awnumar/memguard"

	libstore "github.com/snowmerak/hmacsecret/lib/store"
	"github.com/snowmerak/hmacsecret/pkg/store/encrypted"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
	"github.com/snowmerak/hmacsecret/pkg/store/sqlite"
)

func TestEncryptedStoreWithRandomKEK(t *testing.T) {
	t.Run("pebble", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "db")
		testEncryptedStore(t, func() (libstore.EnvelopeBackend, error) {
			return pebble.Open(path)
		})
	})

	t.Run("sqlite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "db.sqlite")
		testEncryptedStore(t, func() (libstore.EnvelopeBackend, error) {
			return sqlite.Open(path)
		})
	})
}

func testEncryptedStore(
	t *testing.T,
	openBackend func() (libstore.EnvelopeBackend, error),
) {
	t.Helper()
	ctx := context.Background()

	oldKEK := memguard.NewEnclaveRandom(32)
	newKEK := memguard.NewEnclaveRandom(32)
	wrongKEK := memguard.NewEnclaveRandom(32)
	oldRef := randomKEKReference(t, "old.example")
	newRef := randomKEKReference(t, "new.example")

	backend, err := openBackend()
	if err != nil {
		t.Fatal(err)
	}
	encryptedStore, err := encrypted.New(backend)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := encryptedStore.Header(ctx); !errors.Is(err, libstore.ErrNotInitialized) {
		t.Fatalf("Header before Initialize = %v, want ErrNotInitialized", err)
	}
	if err := encryptedStore.Initialize(ctx, oldRef, oldKEK); err != nil {
		t.Fatal(err)
	}
	if err := encryptedStore.Initialize(ctx, oldRef, oldKEK); !errors.Is(err, libstore.ErrExists) {
		t.Fatalf("second Initialize = %v, want ErrExists", err)
	}

	header, err := encryptedStore.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if header.Revision != 1 || !equalKEKReference(header.KEK, oldRef) {
		t.Fatalf("initial header = %+v", header)
	}
	if len(header.WrappedDEK.Ciphertext) == 0 {
		t.Fatal("wrapped DEK is empty")
	}

	first := randomRecord(t, "alpha", "alpha.example")
	second := randomRecord(t, "beta", "beta.example")
	if err := encryptedStore.Put(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := encryptedStore.Put(ctx, second); err != nil {
		t.Fatal(err)
	}
	if err := encryptedStore.Put(ctx, first); !errors.Is(err, libstore.ErrExists) {
		t.Fatalf("duplicate Put = %v, want ErrExists", err)
	}

	firstBlob, err := backend.GetEnvelope(ctx, first.Alias)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(firstBlob.Ciphertext, first.CredentialID) ||
		bytes.Contains(firstBlob.Ciphertext, first.Salt) ||
		bytes.Contains(firstBlob.Ciphertext, []byte(first.RPID)) {
		t.Fatal("encrypted envelope contains plaintext record data")
	}

	got, err := encryptedStore.Get(ctx, first.Alias)
	if err != nil {
		t.Fatal(err)
	}
	if !equalRecord(got, first) {
		t.Fatalf("Get = %+v, want %+v", got, first)
	}

	// The alias is authenticated as AAD, so moving a valid envelope to another
	// alias must fail authentication.
	if err := backend.PutEnvelope(ctx, "swapped", firstBlob); err != nil {
		t.Fatal(err)
	}
	if _, err := encryptedStore.Get(ctx, "swapped"); !errors.Is(err, libstore.ErrIntegrity) {
		t.Fatalf("Get swapped envelope = %v, want ErrIntegrity", err)
	}
	if err := encryptedStore.Delete(ctx, "swapped"); err != nil {
		t.Fatal(err)
	}

	encryptedStore.Lock()
	if _, err := encryptedStore.Get(ctx, first.Alias); !errors.Is(err, libstore.ErrLocked) {
		t.Fatalf("Get while locked = %v, want ErrLocked", err)
	}
	if err := encryptedStore.Delete(ctx, first.Alias); !errors.Is(err, libstore.ErrLocked) {
		t.Fatalf("Delete while locked = %v, want ErrLocked", err)
	}
	if err := encryptedStore.RotateKEK(ctx, newRef, newKEK); !errors.Is(err, libstore.ErrLocked) {
		t.Fatalf("RotateKEK while locked = %v, want ErrLocked", err)
	}
	if ok, err := encryptedStore.Has(ctx, first.Alias); err != nil || !ok {
		t.Fatalf("Has while locked = %v, %v", ok, err)
	}
	if aliases, err := encryptedStore.List(ctx); err != nil || !reflect.DeepEqual(aliases, []string{"alpha", "beta"}) {
		t.Fatalf("List while locked = %v, %v", aliases, err)
	}

	if err := encryptedStore.Unlock(ctx, wrongKEK); !errors.Is(err, libstore.ErrIntegrity) {
		t.Fatalf("Unlock with wrong KEK = %v, want ErrIntegrity", err)
	}
	if err := encryptedStore.Unlock(ctx, oldKEK); err != nil {
		t.Fatal(err)
	}

	secondBlobBefore, err := backend.GetEnvelope(ctx, second.Alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := encryptedStore.RotateKEK(ctx, newRef, newKEK); err != nil {
		t.Fatal(err)
	}
	rotatedHeader, err := encryptedStore.Header(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedHeader.Revision != 2 || !equalKEKReference(rotatedHeader.KEK, newRef) {
		t.Fatalf("rotated header = %+v", rotatedHeader)
	}
	secondBlobAfter, err := backend.GetEnvelope(ctx, second.Alias)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(secondBlobAfter, secondBlobBefore) {
		t.Fatal("KEK rotation rewrote record ciphertext")
	}

	encryptedStore.Lock()
	if err := encryptedStore.Unlock(ctx, oldKEK); !errors.Is(err, libstore.ErrIntegrity) {
		t.Fatalf("Unlock with old KEK after rotation = %v, want ErrIntegrity", err)
	}
	if err := encryptedStore.Unlock(ctx, newKEK); err != nil {
		t.Fatal(err)
	}
	got, err = encryptedStore.Get(ctx, second.Alias)
	if err != nil {
		t.Fatal(err)
	}
	if !equalRecord(got, second) {
		t.Fatalf("Get after rotation = %+v, want %+v", got, second)
	}

	if err := encryptedStore.Delete(ctx, first.Alias); err != nil {
		t.Fatal(err)
	}
	if _, err := encryptedStore.Get(ctx, first.Alias); !errors.Is(err, libstore.ErrNotFound) {
		t.Fatalf("Get deleted alias = %v, want ErrNotFound", err)
	}
	if err := encryptedStore.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen the physical backend to verify that only the new KEK can recover
	// the persisted store DEK and records.
	reopenedBackend, err := openBackend()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := encrypted.New(reopenedBackend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Unlock(ctx, newKEK); err != nil {
		t.Fatal(err)
	}
	got, err = reopened.Get(ctx, second.Alias)
	if err != nil {
		t.Fatal(err)
	}
	if !equalRecord(got, second) {
		t.Fatalf("Get after reopen = %+v, want %+v", got, second)
	}
}

func randomKEKReference(t *testing.T, rpID string) libstore.KEKReference {
	t.Helper()
	return libstore.KEKReference{
		CredentialID: randomBytes(t, 64),
		Salt:         randomBytes(t, libstore.SaltSize),
		RPID:         rpID,
	}
}

func randomRecord(t *testing.T, alias, rpID string) libstore.Record {
	t.Helper()
	return libstore.Record{
		Alias:        alias,
		CredentialID: randomBytes(t, 64),
		Salt:         randomBytes(t, libstore.SaltSize),
		RPID:         rpID,
	}
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return value
}

func equalKEKReference(a, b libstore.KEKReference) bool {
	return bytes.Equal(a.CredentialID, b.CredentialID) &&
		bytes.Equal(a.Salt, b.Salt) &&
		a.RPID == b.RPID
}

func equalRecord(a, b libstore.Record) bool {
	return a.Alias == b.Alias &&
		bytes.Equal(a.CredentialID, b.CredentialID) &&
		bytes.Equal(a.Salt, b.Salt) &&
		a.RPID == b.RPID
}
