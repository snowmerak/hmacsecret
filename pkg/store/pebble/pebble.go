// Package pebble implements lib/store.Store with CockroachDB Pebble v2.
package pebble

import (
	"bytes"
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

var _ store.EnvelopeBackend = (*Store)(nil)

type storedRecord struct {
	CredentialID []byte `json:"credential_id"`
	Salt         []byte `json:"salt"`
	RPID         string `json:"rp_id"`
}

var (
	encryptionHeaderKey = []byte{0, 'h', 'm', 'a', 'c', 's', 'e', 'c', 'r', 'e', 't', '/', 'h', 'e', 'a', 'd', 'e', 'r'}
	envelopePrefix      = []byte{0, 'h', 'm', 'a', 'c', 's', 'e', 'c', 'r', 'e', 't', '/', 'r', 'e', 'c', 'o', 'r', 'd', '/'}
)

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

// CreateHeader atomically creates an encrypted-store header.
func (s *Store) CreateHeader(ctx context.Context, header store.EncryptionHeader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("pebble marshal encryption header: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	_, closer, err := s.db.Get(encryptionHeaderKey)
	if err == nil {
		_ = closer.Close()
		return store.ErrExists
	}
	if err != pebble.ErrNotFound {
		return fmt.Errorf("pebble get encryption header: %w", err)
	}
	if err := s.db.Set(encryptionHeaderKey, body, pebble.Sync); err != nil {
		return fmt.Errorf("pebble set encryption header: %w", err)
	}
	return nil
}

// LoadHeader loads the encrypted-store header.
func (s *Store) LoadHeader(ctx context.Context) (store.EncryptionHeader, error) {
	if err := ctx.Err(); err != nil {
		return store.EncryptionHeader{}, err
	}
	body, closer, err := s.db.Get(encryptionHeaderKey)
	if err == pebble.ErrNotFound {
		return store.EncryptionHeader{}, store.ErrNotInitialized
	}
	if err != nil {
		return store.EncryptionHeader{}, fmt.Errorf("pebble get encryption header: %w", err)
	}
	defer closer.Close()

	var header store.EncryptionHeader
	if err := json.Unmarshal(body, &header); err != nil {
		return store.EncryptionHeader{}, fmt.Errorf("pebble unmarshal encryption header: %w", err)
	}
	return header, nil
}

// CompareAndSwapHeader replaces the header when its revision matches.
func (s *Store) CompareAndSwapHeader(
	ctx context.Context,
	expectedRevision uint64,
	next store.EncryptionHeader,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("pebble marshal encryption header: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	currentBody, closer, err := s.db.Get(encryptionHeaderKey)
	if err == pebble.ErrNotFound {
		return store.ErrNotInitialized
	}
	if err != nil {
		return fmt.Errorf("pebble get encryption header: %w", err)
	}
	var current store.EncryptionHeader
	unmarshalErr := json.Unmarshal(currentBody, &current)
	_ = closer.Close()
	if unmarshalErr != nil {
		return fmt.Errorf("pebble unmarshal encryption header: %w", unmarshalErr)
	}
	if current.Revision != expectedRevision {
		return store.ErrConflict
	}
	if err := s.db.Set(encryptionHeaderKey, body, pebble.Sync); err != nil {
		return fmt.Errorf("pebble set encryption header: %w", err)
	}
	return nil
}

// PutEnvelope inserts an encrypted record envelope.
func (s *Store) PutEnvelope(ctx context.Context, alias string, blob store.EncryptedBlob) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("pebble marshal envelope: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := envelopeKey(alias)
	_, closer, err := s.db.Get(key)
	if err == nil {
		_ = closer.Close()
		return store.ErrExists
	}
	if err != pebble.ErrNotFound {
		return fmt.Errorf("pebble get envelope: %w", err)
	}
	if err := s.db.Set(key, body, pebble.Sync); err != nil {
		return fmt.Errorf("pebble set envelope: %w", err)
	}
	return nil
}

// GetEnvelope loads an encrypted record envelope.
func (s *Store) GetEnvelope(ctx context.Context, alias string) (store.EncryptedBlob, error) {
	if err := ctx.Err(); err != nil {
		return store.EncryptedBlob{}, err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return store.EncryptedBlob{}, err
	}
	body, closer, err := s.db.Get(envelopeKey(alias))
	if err == pebble.ErrNotFound {
		return store.EncryptedBlob{}, store.ErrNotFound
	}
	if err != nil {
		return store.EncryptedBlob{}, fmt.Errorf("pebble get envelope: %w", err)
	}
	defer closer.Close()

	var blob store.EncryptedBlob
	if err := json.Unmarshal(body, &blob); err != nil {
		return store.EncryptedBlob{}, fmt.Errorf("pebble unmarshal envelope: %w", err)
	}
	return blob, nil
}

// DeleteEnvelope removes an encrypted record envelope.
func (s *Store) DeleteEnvelope(ctx context.Context, alias string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := envelopeKey(alias)
	_, closer, err := s.db.Get(key)
	if err == pebble.ErrNotFound {
		return store.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("pebble get envelope: %w", err)
	}
	_ = closer.Close()
	if err := s.db.Delete(key, pebble.Sync); err != nil {
		return fmt.Errorf("pebble delete envelope: %w", err)
	}
	return nil
}

// HasEnvelope reports whether an encrypted record envelope exists.
func (s *Store) HasEnvelope(ctx context.Context, alias string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return false, err
	}
	_, closer, err := s.db.Get(envelopeKey(alias))
	if err == pebble.ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("pebble get envelope: %w", err)
	}
	_ = closer.Close()
	return true, nil
}

// ListEnvelopes lists aliases with encrypted record envelopes.
func (s *Store) ListEnvelopes(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	upperBound := prefixUpperBound(envelopePrefix)
	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: envelopePrefix,
		UpperBound: upperBound,
	})
	if err != nil {
		return nil, fmt.Errorf("pebble envelope iter: %w", err)
	}
	defer iter.Close()

	var aliases []string
	for iter.First(); iter.Valid(); iter.Next() {
		key := iter.Key()
		if !bytes.HasPrefix(key, envelopePrefix) {
			break
		}
		aliases = append(aliases, string(key[len(envelopePrefix):]))
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("pebble envelope iter: %w", err)
	}
	return aliases, nil
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

func envelopeKey(alias string) []byte {
	key := make([]byte, 0, len(envelopePrefix)+len(alias))
	key = append(key, envelopePrefix...)
	return append(key, alias...)
}

func prefixUpperBound(prefix []byte) []byte {
	upper := append([]byte(nil), prefix...)
	for i := len(upper) - 1; i >= 0; i-- {
		if upper[i] != 0xff {
			upper[i]++
			return upper[:i+1]
		}
	}
	return nil
}
