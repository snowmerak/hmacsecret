// Package sqlite implements lib/store.Store with database/sql + modernc.org/sqlite.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/snowmerak/hmacsecret/lib/store"
)

// Store is a SQLite-backed store.Store.
type Store struct {
	db *sql.DB
}

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

// Close implements store.Store.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}
