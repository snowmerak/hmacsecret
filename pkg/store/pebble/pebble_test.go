package pebble_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snowmerak/hmacsecret/lib/store"
	"github.com/snowmerak/hmacsecret/pkg/store/pebble"
)

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := pebble.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	rec := store.Record{
		Alias:        "app-key",
		CredentialID: []byte{1, 2, 3},
		Salt:         make([]byte, 32),
		RPID:         "example.com",
	}
	rec.Salt[0] = 0xab

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
	if got.RPID != rec.RPID || string(got.CredentialID) != string(rec.CredentialID) || string(got.Salt) != string(rec.Salt) {
		t.Fatalf("got %+v", got)
	}

	ok, err := st.Has(ctx, "app-key")
	if err != nil || !ok {
		t.Fatalf("has = %v, %v", ok, err)
	}

	aliases, err := st.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(aliases) != 1 || aliases[0] != "app-key" {
		t.Fatalf("list = %v", aliases)
	}

	if err := st.Delete(ctx, "app-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(ctx, "app-key"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("get after delete = %v", err)
	}
}
