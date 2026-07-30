package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snowmerak/hmacsecret/lib/store"
	"github.com/snowmerak/hmacsecret/pkg/store/sqlite"
)

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := sqlite.Open(filepath.Join(t.TempDir(), "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	rec := store.Record{
		Alias:        "app-key",
		CredentialID: []byte{9, 8, 7},
		Salt:         make([]byte, 32),
		RPID:         "example.com",
	}
	rec.Salt[0] = 0xcd

	if err := st.Put(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := st.Put(ctx, rec); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second put = %v, want ErrExists", err)
	}

	got, err := st.Get(ctx, "app-key")
	if err != nil {
		t.Fatal(err)
	}
	if got.RPID != rec.RPID || string(got.CredentialID) != string(rec.CredentialID) {
		t.Fatalf("got %+v", got)
	}

	if err := st.Delete(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if err := st.Delete(ctx, "app-key"); err != nil {
		t.Fatal(err)
	}
}
