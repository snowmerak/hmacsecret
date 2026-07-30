// Package pebble implements lib/store.Store with CockroachDB Pebble v2.
package pebble

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/cockroachdb/pebble/v2"

	"github.com/snowmerak/hmacsecret/lib/store"
)

// Store is a Pebble-backed store.Store.
type Store struct {
	db *pebble.DB
	// mu protects check-then-act sequences (Put exists+set, Delete exists+del).
	mu sync.Mutex
}

type storedRecord struct {
	CredentialID []byte `json:"credential_id"`
	Salt         []byte `json:"salt"`
	RPID         string `json:"rp_id"`
}

// Open opens or creates a Pebble database at path.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("pebble store: empty path")
	}
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("pebble open: %w", err)
	}
	return &Store{db: db}, nil
}

// Put implements store.Store.
func (s *Store) Put(ctx context.Context, rec store.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rec.Alias = strings.TrimSpace(rec.Alias)
	rec.RPID = strings.TrimSpace(rec.RPID)
	if err := store.ValidateRecord(rec); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := []byte(rec.Alias)
	_, closer, err := s.db.Get(key)
	if err == nil {
		_ = closer.Close()
		return store.ErrExists
	}
	if err != pebble.ErrNotFound {
		return fmt.Errorf("pebble get: %w", err)
	}

	body, err := json.Marshal(storedRecord{
		CredentialID: rec.CredentialID,
		Salt:         rec.Salt,
		RPID:         rec.RPID,
	})
	if err != nil {
		return fmt.Errorf("pebble marshal: %w", err)
	}
	if err := s.db.Set(key, body, pebble.Sync); err != nil {
		return fmt.Errorf("pebble set: %w", err)
	}
	return nil
}

// Get implements store.Store.
func (s *Store) Get(ctx context.Context, alias string) (store.Record, error) {
	if err := ctx.Err(); err != nil {
		return store.Record{}, err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return store.Record{}, err
	}

	val, closer, err := s.db.Get([]byte(alias))
	if err == pebble.ErrNotFound {
		return store.Record{}, store.ErrNotFound
	}
	if err != nil {
		return store.Record{}, fmt.Errorf("pebble get: %w", err)
	}
	defer closer.Close()

	var body storedRecord
	if err := json.Unmarshal(val, &body); err != nil {
		return store.Record{}, fmt.Errorf("pebble unmarshal: %w", err)
	}
	rec := store.Record{
		Alias:        alias,
		CredentialID: append([]byte(nil), body.CredentialID...),
		Salt:         append([]byte(nil), body.Salt...),
		RPID:         body.RPID,
	}
	if err := store.ValidateRecord(rec); err != nil {
		return store.Record{}, err
	}
	return rec, nil
}

// Delete implements store.Store.
func (s *Store) Delete(ctx context.Context, alias string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := []byte(alias)
	_, closer, err := s.db.Get(key)
	if err == pebble.ErrNotFound {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("pebble get: %w", err)
	}
	_ = closer.Close()

	if err := s.db.Delete(key, pebble.Sync); err != nil {
		return fmt.Errorf("pebble delete: %w", err)
	}
	return nil
}

// Has implements store.Store.
func (s *Store) Has(ctx context.Context, alias string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return false, err
	}
	_, closer, err := s.db.Get([]byte(alias))
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pebble get: %w", err)
	}
	_ = closer.Close()
	return true, nil
}

// List implements store.Store.
func (s *Store) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	iter, err := s.db.NewIter(nil)
	if err != nil {
		return nil, fmt.Errorf("pebble iter: %w", err)
	}
	defer iter.Close()

	var out []string
	for iter.First(); iter.Valid(); iter.Next() {
		out = append(out, string(iter.Key()))
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("pebble iter: %w", err)
	}
	return out, nil
}

// Close implements store.Store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}
