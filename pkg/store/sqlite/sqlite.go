// Package sqlite implements lib/store.Store with database/sql + modernc.org/sqlite.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/snowmerak/hmacsecret/lib/store"
)

// Store is a SQLite-backed store.Store.
type Store struct {
	db *sql.DB
}

var _ store.EnvelopeBackend = (*Store)(nil)

// Open opens or creates a SQLite database at path.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("sqlite store: empty path")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate(ctx context.Context) error {
	const q = `
CREATE TABLE IF NOT EXISTS credentials (
	alias TEXT PRIMARY KEY NOT NULL,
	credential_id BLOB NOT NULL,
	salt BLOB NOT NULL,
	rp_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS encryption_header (
	singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
	revision INTEGER NOT NULL,
	body BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_credentials (
	alias TEXT PRIMARY KEY NOT NULL,
	version INTEGER NOT NULL,
	algorithm TEXT NOT NULL,
	nonce BLOB NOT NULL,
	ciphertext BLOB NOT NULL
);`
	if _, err := s.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("sqlite migrate: %w", err)
	}
	return nil
}

// Put implements store.Store.
func (s *Store) Put(ctx context.Context, rec store.Record) error {
	rec.Alias = strings.TrimSpace(rec.Alias)
	rec.RPID = strings.TrimSpace(rec.RPID)
	if err := store.ValidateRecord(rec); err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, `
INSERT INTO credentials (alias, credential_id, salt, rp_id)
VALUES (?, ?, ?, ?)`,
		rec.Alias, rec.CredentialID, rec.Salt, rec.RPID,
	)
	if err != nil {
		// modernc sqlite unique violation
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return store.ErrExists
		}
		return fmt.Errorf("sqlite insert: %w", err)
	}
	_, _ = res.RowsAffected()
	return nil
}

// Get implements store.Store.
func (s *Store) Get(ctx context.Context, alias string) (store.Record, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return store.Record{}, err
	}

	var rec store.Record
	rec.Alias = alias
	err := s.db.QueryRowContext(ctx, `
SELECT credential_id, salt, rp_id FROM credentials WHERE alias = ?`, alias,
	).Scan(&rec.CredentialID, &rec.Salt, &rec.RPID)
	if err == sql.ErrNoRows {
		return store.Record{}, store.ErrNotFound
	}
	if err != nil {
		return store.Record{}, fmt.Errorf("sqlite get: %w", err)
	}
	if err := store.ValidateRecord(rec); err != nil {
		return store.Record{}, err
	}
	return rec, nil
}

// Delete implements store.Store.
func (s *Store) Delete(ctx context.Context, alias string) error {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE alias = ?`, alias)
	if err != nil {
		return fmt.Errorf("sqlite delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite rows affected: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// Has implements store.Store.
func (s *Store) Has(ctx context.Context, alias string) (bool, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM credentials WHERE alias = ?`, alias).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sqlite has: %w", err)
	}
	return n > 0, nil
}

// List implements store.Store.
func (s *Store) List(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT alias FROM credentials ORDER BY alias`)
	if err != nil {
		return nil, fmt.Errorf("sqlite list: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			return nil, fmt.Errorf("sqlite list scan: %w", err)
		}
		out = append(out, alias)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite list: %w", err)
	}
	return out, nil
}

// CreateHeader atomically creates an encrypted-store header.
func (s *Store) CreateHeader(ctx context.Context, header store.EncryptionHeader) error {
	body, err := json.Marshal(header)
	if err != nil {
		return fmt.Errorf("sqlite marshal encryption header: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO encryption_header (singleton, revision, body)
VALUES (1, ?, ?)`, header.Revision, body)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return store.ErrExists
		}
		return fmt.Errorf("sqlite insert encryption header: %w", err)
	}
	return nil
}

// LoadHeader loads the encrypted-store header.
func (s *Store) LoadHeader(ctx context.Context) (store.EncryptionHeader, error) {
	var revision uint64
	var body []byte
	err := s.db.QueryRowContext(ctx, `
SELECT revision, body FROM encryption_header WHERE singleton = 1`).Scan(&revision, &body)
	if err == sql.ErrNoRows {
		return store.EncryptionHeader{}, store.ErrNotInitialized
	}
	if err != nil {
		return store.EncryptionHeader{}, fmt.Errorf("sqlite get encryption header: %w", err)
	}
	var header store.EncryptionHeader
	if err := json.Unmarshal(body, &header); err != nil {
		return store.EncryptionHeader{}, fmt.Errorf("sqlite unmarshal encryption header: %w", err)
	}
	if header.Revision != revision {
		return store.EncryptionHeader{}, fmt.Errorf(
			"%w: header revision column=%d body=%d",
			store.ErrInvalidRecord,
			revision,
			header.Revision,
		)
	}
	return header, nil
}

// CompareAndSwapHeader replaces the header when its revision matches.
func (s *Store) CompareAndSwapHeader(
	ctx context.Context,
	expectedRevision uint64,
	next store.EncryptionHeader,
) error {
	body, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("sqlite marshal encryption header: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE encryption_header
SET revision = ?, body = ?
WHERE singleton = 1 AND revision = ?`,
		next.Revision,
		body,
		expectedRevision,
	)
	if err != nil {
		return fmt.Errorf("sqlite update encryption header: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite encryption header rows affected: %w", err)
	}
	if n != 0 {
		return nil
	}
	var exists int
	err = s.db.QueryRowContext(ctx, `
SELECT COUNT(1) FROM encryption_header WHERE singleton = 1`).Scan(&exists)
	if err != nil {
		return fmt.Errorf("sqlite check encryption header: %w", err)
	}
	if exists == 0 {
		return store.ErrNotInitialized
	}
	return store.ErrConflict
}

// PutEnvelope inserts an encrypted record envelope.
func (s *Store) PutEnvelope(ctx context.Context, alias string, blob store.EncryptedBlob) error {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO encrypted_credentials (alias, version, algorithm, nonce, ciphertext)
VALUES (?, ?, ?, ?, ?)`,
		alias,
		blob.Version,
		blob.Algorithm,
		blob.Nonce,
		blob.Ciphertext,
	)
	if err != nil {
		if isSQLiteUniqueError(err) {
			return store.ErrExists
		}
		return fmt.Errorf("sqlite insert envelope: %w", err)
	}
	return nil
}

// GetEnvelope loads an encrypted record envelope.
func (s *Store) GetEnvelope(ctx context.Context, alias string) (store.EncryptedBlob, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return store.EncryptedBlob{}, err
	}
	var blob store.EncryptedBlob
	err := s.db.QueryRowContext(ctx, `
SELECT version, algorithm, nonce, ciphertext
FROM encrypted_credentials
WHERE alias = ?`, alias,
	).Scan(&blob.Version, &blob.Algorithm, &blob.Nonce, &blob.Ciphertext)
	if err == sql.ErrNoRows {
		return store.EncryptedBlob{}, store.ErrNotFound
	}
	if err != nil {
		return store.EncryptedBlob{}, fmt.Errorf("sqlite get envelope: %w", err)
	}
	return blob, nil
}

// DeleteEnvelope removes an encrypted record envelope.
func (s *Store) DeleteEnvelope(ctx context.Context, alias string) error {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
DELETE FROM encrypted_credentials WHERE alias = ?`, alias)
	if err != nil {
		return fmt.Errorf("sqlite delete envelope: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("sqlite envelope rows affected: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// HasEnvelope reports whether an encrypted record envelope exists.
func (s *Store) HasEnvelope(ctx context.Context, alias string) (bool, error) {
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return false, err
	}
	var n int
	err := s.db.QueryRowContext(ctx, `
SELECT COUNT(1) FROM encrypted_credentials WHERE alias = ?`, alias).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("sqlite has envelope: %w", err)
	}
	return n > 0, nil
}

// ListEnvelopes lists aliases with encrypted record envelopes.
func (s *Store) ListEnvelopes(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT alias FROM encrypted_credentials ORDER BY alias`)
	if err != nil {
		return nil, fmt.Errorf("sqlite list envelopes: %w", err)
	}
	defer rows.Close()

	var aliases []string
	for rows.Next() {
		var alias string
		if err := rows.Scan(&alias); err != nil {
			return nil, fmt.Errorf("sqlite list envelopes scan: %w", err)
		}
		aliases = append(aliases, alias)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite list envelopes: %w", err)
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

func isSQLiteUniqueError(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique") || strings.Contains(message, "primary key")
}
