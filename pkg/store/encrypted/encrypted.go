// Package encrypted implements an authenticated encrypted store over a
// store.EnvelopeBackend.
package encrypted

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/snowmerak/hmacsecret/lib/store"
)

const (
	// FormatVersion is the encrypted header and record format implemented here.
	FormatVersion uint16 = 1
	// AlgorithmXChaCha20Poly1305 identifies the AEAD used for wrapping and records.
	AlgorithmXChaCha20Poly1305 = "xchacha20poly1305-v1"

	storeIDSize     = 16
	maxPayloadField = 1 << 20
	maxCiphertext   = 4 << 20
)

var (
	headerAADPrefix = []byte("hmacsecret/encrypted-store/dek/v1")
	recordAADPrefix = []byte("hmacsecret/encrypted-store/record/v1")
)

// Store implements store.EncryptedStore.
//
// The backend contains only public bootstrap metadata and authenticated
// ciphertext. Ownership of backend is transferred to Store and Close closes it.
type Store struct {
	backend store.EnvelopeBackend

	mu     sync.RWMutex
	header store.EncryptionHeader
	dek    *memguard.Enclave
}

var _ store.EncryptedStore = (*Store)(nil)

// New constructs a locked encrypted store.
func New(backend store.EnvelopeBackend) (*Store, error) {
	if backend == nil {
		return nil, errors.New("encrypted store: backend is required")
	}
	return &Store{backend: backend}, nil
}

// Header returns a copy of the public encryption header.
func (s *Store) Header(ctx context.Context) (store.EncryptionHeader, error) {
	header, err := s.backend.LoadHeader(ctx)
	if err != nil {
		return store.EncryptionHeader{}, err
	}
	if err := validateHeader(header); err != nil {
		return store.EncryptionHeader{}, err
	}
	return cloneHeader(header), nil
}

// Initialize creates the header, generates a random store DEK, wraps it with
// kek, and leaves the store unlocked.
func (s *Store) Initialize(ctx context.Context, ref store.KEKReference, kek *memguard.Enclave) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ref = cloneKEKReference(ref)
	ref.RPID = strings.TrimSpace(ref.RPID)
	if err := store.ValidateKEKReference(ref); err != nil {
		return err
	}
	if err := validateKeyEnclave(kek, "KEK"); err != nil {
		return err
	}
	if _, err := s.backend.LoadHeader(ctx); err == nil {
		return store.ErrExists
	} else if !errors.Is(err, store.ErrNotInitialized) {
		return err
	}
	aliases, err := s.backend.ListEnvelopes(ctx)
	if err != nil {
		return err
	}
	if len(aliases) != 0 {
		return fmt.Errorf("%w: encrypted records exist without a header", store.ErrConflict)
	}

	storeID := make([]byte, storeIDSize)
	if _, err := rand.Read(storeID); err != nil {
		return fmt.Errorf("encrypted store: generate store id: %w", err)
	}

	dek, err := randomEnclave(chacha20poly1305.KeySize)
	if err != nil {
		return fmt.Errorf("encrypted store: generate DEK: %w", err)
	}
	header := store.EncryptionHeader{
		Version:  FormatVersion,
		Revision: 1,
		StoreID:  storeID,
		KEK:      ref,
	}
	header.WrappedDEK, err = wrapEnclave(kek, dek, headerAAD(header))
	if err != nil {
		return fmt.Errorf("encrypted store: wrap DEK: %w", err)
	}

	if err := s.backend.CreateHeader(ctx, header); err != nil {
		return fmt.Errorf("encrypted store: create header: %w", err)
	}

	s.mu.Lock()
	s.header = cloneHeader(header)
	s.dek = dek
	s.mu.Unlock()
	return nil
}

// Unlock unwraps and retains only the sealed store DEK. The supplied KEK is
// opened for the duration of the unwrap operation and is not retained.
func (s *Store) Unlock(ctx context.Context, kek *memguard.Enclave) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateKeyEnclave(kek, "KEK"); err != nil {
		return err
	}

	header, err := s.backend.LoadHeader(ctx)
	if err != nil {
		return err
	}
	if err := validateHeader(header); err != nil {
		return err
	}
	dek, err := unwrapEnclave(kek, header.WrappedDEK, headerAAD(header))
	if err != nil {
		return fmt.Errorf("encrypted store: unwrap DEK: %w", err)
	}

	s.mu.Lock()
	s.header = cloneHeader(header)
	s.dek = dek
	s.mu.Unlock()
	return nil
}

// Lock forgets the sealed store DEK.
func (s *Store) Lock() {
	s.mu.Lock()
	s.header = store.EncryptionHeader{}
	s.dek = nil
	s.mu.Unlock()
}

// RotateKEK rewraps the existing store DEK under nextKEK.
func (s *Store) RotateKEK(ctx context.Context, next store.KEKReference, nextKEK *memguard.Enclave) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	next = cloneKEKReference(next)
	next.RPID = strings.TrimSpace(next.RPID)
	if err := store.ValidateKEKReference(next); err != nil {
		return err
	}
	if err := validateKeyEnclave(nextKEK, "KEK"); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dek == nil {
		return store.ErrLocked
	}

	current, err := s.backend.LoadHeader(ctx)
	if err != nil {
		return err
	}
	if err := validateHeader(current); err != nil {
		return err
	}
	if current.Revision != s.header.Revision {
		return store.ErrConflict
	}

	rotated := cloneHeader(current)
	rotated.Revision++
	rotated.KEK = next
	rotated.WrappedDEK, err = wrapEnclave(nextKEK, s.dek, headerAAD(rotated))
	if err != nil {
		return fmt.Errorf("encrypted store: rewrap DEK: %w", err)
	}
	if err := s.backend.CompareAndSwapHeader(ctx, current.Revision, rotated); err != nil {
		return fmt.Errorf("encrypted store: rotate header: %w", err)
	}
	s.header = cloneHeader(rotated)
	return nil
}

// Put encrypts and inserts rec.
func (s *Store) Put(ctx context.Context, rec store.Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rec.Alias = strings.TrimSpace(rec.Alias)
	rec.RPID = strings.TrimSpace(rec.RPID)
	if err := store.ValidateRecord(rec); err != nil {
		return err
	}
	header, dek, err := s.snapshot()
	if err != nil {
		return err
	}

	plaintext, err := encodeRecord(rec)
	if err != nil {
		return err
	}
	defer memguard.WipeBytes(plaintext)

	blob, err := seal(dek, plaintext, recordAAD(header, rec.Alias))
	if err != nil {
		return fmt.Errorf("encrypted store: encrypt record: %w", err)
	}
	if err := s.backend.PutEnvelope(ctx, rec.Alias, blob); err != nil {
		return err
	}
	return nil
}

// Get loads and decrypts the record for alias.
func (s *Store) Get(ctx context.Context, alias string) (store.Record, error) {
	if err := ctx.Err(); err != nil {
		return store.Record{}, err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return store.Record{}, err
	}
	header, dek, err := s.snapshot()
	if err != nil {
		return store.Record{}, err
	}

	blob, err := s.backend.GetEnvelope(ctx, alias)
	if err != nil {
		return store.Record{}, err
	}
	plaintext, err := openLocked(dek, blob, recordAAD(header, alias))
	if err != nil {
		return store.Record{}, fmt.Errorf("encrypted store: decrypt record: %w", err)
	}
	defer plaintext.Destroy()

	rec, err := decodeRecord(alias, plaintext.Bytes())
	if err != nil {
		return store.Record{}, err
	}
	if err := store.ValidateRecord(rec); err != nil {
		return store.Record{}, err
	}
	return rec, nil
}

// Delete removes an encrypted record. The store must be unlocked.
func (s *Store) Delete(ctx context.Context, alias string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return err
	}
	if _, _, err := s.snapshot(); err != nil {
		return err
	}
	return s.backend.DeleteEnvelope(ctx, alias)
}

// Has reports whether an alias exists. Aliases are public, so this works while locked.
func (s *Store) Has(ctx context.Context, alias string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	alias = strings.TrimSpace(alias)
	if err := store.ValidateAlias(alias); err != nil {
		return false, err
	}
	return s.backend.HasEnvelope(ctx, alias)
}

// List returns public aliases and works while locked.
func (s *Store) List(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.backend.ListEnvelopes(ctx)
}

// Close locks the store and closes its backend.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.Lock()
	if s.backend == nil {
		return nil
	}
	err := s.backend.Close()
	s.backend = nil
	return err
}

func (s *Store) snapshot() (store.EncryptionHeader, *memguard.Enclave, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dek == nil {
		return store.EncryptionHeader{}, nil, store.ErrLocked
	}
	return cloneHeader(s.header), s.dek, nil
}

func randomEnclave(size int) (*memguard.Enclave, error) {
	plaintext := memguard.NewBuffer(size)
	if plaintext.Size() != size {
		plaintext.Destroy()
		return nil, fmt.Errorf("allocate locked buffer")
	}
	if _, err := io.ReadFull(rand.Reader, plaintext.Bytes()); err != nil {
		plaintext.Destroy()
		return nil, err
	}
	return plaintext.Seal(), nil
}

func wrapEnclave(kek, plaintext *memguard.Enclave, aad []byte) (store.EncryptedBlob, error) {
	if err := validateKeyEnclave(plaintext, "DEK"); err != nil {
		return store.EncryptedBlob{}, err
	}
	buf, err := plaintext.Open()
	if err != nil {
		return store.EncryptedBlob{}, err
	}
	defer buf.Destroy()
	return seal(kek, buf.Bytes(), aad)
}

func unwrapEnclave(kek *memguard.Enclave, blob store.EncryptedBlob, aad []byte) (*memguard.Enclave, error) {
	plaintext, err := openLocked(kek, blob, aad)
	if err != nil {
		return nil, err
	}
	if plaintext.Size() != chacha20poly1305.KeySize {
		plaintext.Destroy()
		return nil, fmt.Errorf("%w: unwrapped DEK has invalid size", store.ErrIntegrity)
	}
	return plaintext.Seal(), nil
}

func seal(key *memguard.Enclave, plaintext, aad []byte) (store.EncryptedBlob, error) {
	if err := validateKeyEnclave(key, "key"); err != nil {
		return store.EncryptedBlob{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return store.EncryptedBlob{}, err
	}

	var ciphertext []byte
	err := withAEAD(key, func(aead cipher.AEAD) error {
		ciphertext = aead.Seal(nil, nonce, plaintext, aad)
		return nil
	})
	if err != nil {
		return store.EncryptedBlob{}, err
	}
	return store.EncryptedBlob{
		Version:    FormatVersion,
		Algorithm:  AlgorithmXChaCha20Poly1305,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func openLocked(key *memguard.Enclave, blob store.EncryptedBlob, aad []byte) (*memguard.LockedBuffer, error) {
	if err := validateKeyEnclave(key, "key"); err != nil {
		return nil, err
	}
	if err := validateBlob(blob); err != nil {
		return nil, err
	}

	size := len(blob.Ciphertext) - chacha20poly1305.Overhead
	plaintext := memguard.NewBuffer(size)
	if plaintext.Size() != size {
		plaintext.Destroy()
		return nil, fmt.Errorf("allocate locked plaintext buffer")
	}

	err := withAEAD(key, func(aead cipher.AEAD) error {
		opened, err := aead.Open(plaintext.Bytes()[:0], blob.Nonce, blob.Ciphertext, aad)
		if err != nil {
			return store.ErrIntegrity
		}
		if len(opened) != size || (size > 0 && &opened[0] != &plaintext.Bytes()[0]) {
			memguard.WipeBytes(opened)
			return fmt.Errorf("%w: plaintext escaped locked buffer", store.ErrIntegrity)
		}
		return nil
	})
	if err != nil {
		plaintext.Destroy()
		return nil, err
	}
	plaintext.Freeze()
	return plaintext, nil
}

func withAEAD(key *memguard.Enclave, fn func(cipher.AEAD) error) error {
	buf, err := key.Open()
	if err != nil {
		return err
	}
	defer buf.Destroy()
	aead, err := chacha20poly1305.NewX(buf.Bytes())
	if err != nil {
		return err
	}
	return fn(aead)
}

func validateKeyEnclave(key *memguard.Enclave, name string) error {
	if key == nil || key.Size() != chacha20poly1305.KeySize {
		return fmt.Errorf("encrypted store: %s must be a sealed %d-byte key", name, chacha20poly1305.KeySize)
	}
	return nil
}

func validateHeader(header store.EncryptionHeader) error {
	if header.Version != FormatVersion {
		return fmt.Errorf("%w: header version %d", store.ErrUnsupportedFormat, header.Version)
	}
	if header.Revision == 0 {
		return fmt.Errorf("%w: zero header revision", store.ErrInvalidRecord)
	}
	if len(header.StoreID) != storeIDSize {
		return fmt.Errorf("%w: store id must be %d bytes", store.ErrInvalidRecord, storeIDSize)
	}
	if err := store.ValidateKEKReference(header.KEK); err != nil {
		return err
	}
	return validateBlob(header.WrappedDEK)
}

func validateBlob(blob store.EncryptedBlob) error {
	if blob.Version != FormatVersion || blob.Algorithm != AlgorithmXChaCha20Poly1305 {
		return fmt.Errorf(
			"%w: envelope version=%d algorithm=%q",
			store.ErrUnsupportedFormat,
			blob.Version,
			blob.Algorithm,
		)
	}
	if len(blob.Nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("%w: invalid nonce size", store.ErrInvalidRecord)
	}
	if len(blob.Ciphertext) < chacha20poly1305.Overhead {
		return fmt.Errorf("%w: ciphertext is too short", store.ErrInvalidRecord)
	}
	if len(blob.Ciphertext) > maxCiphertext {
		return fmt.Errorf("%w: ciphertext is too large", store.ErrInvalidRecord)
	}
	return nil
}

func headerAAD(header store.EncryptionHeader) []byte {
	out := appendLengthPrefixed(nil, headerAADPrefix)
	out = appendUint16(out, header.Version)
	out = appendUint64(out, header.Revision)
	out = appendLengthPrefixed(out, header.StoreID)
	out = appendLengthPrefixed(out, header.KEK.CredentialID)
	out = appendLengthPrefixed(out, header.KEK.Salt)
	out = appendLengthPrefixed(out, []byte(header.KEK.RPID))
	return out
}

func recordAAD(header store.EncryptionHeader, alias string) []byte {
	out := appendLengthPrefixed(nil, recordAADPrefix)
	out = appendUint16(out, FormatVersion)
	out = appendLengthPrefixed(out, header.StoreID)
	out = appendLengthPrefixed(out, []byte(alias))
	return out
}

func encodeRecord(rec store.Record) ([]byte, error) {
	if len(rec.CredentialID) > maxPayloadField || len(rec.RPID) > maxPayloadField {
		return nil, fmt.Errorf("%w: record field is too large", store.ErrInvalidRecord)
	}
	out := appendUint16(nil, FormatVersion)
	out = appendLengthPrefixed(out, rec.CredentialID)
	out = appendLengthPrefixed(out, rec.Salt)
	out = appendLengthPrefixed(out, []byte(rec.RPID))
	return out, nil
}

func decodeRecord(alias string, data []byte) (store.Record, error) {
	reader := payloadReader{data: data}
	version, err := reader.uint16()
	if err != nil {
		return store.Record{}, err
	}
	if version != FormatVersion {
		return store.Record{}, fmt.Errorf("%w: record version %d", store.ErrUnsupportedFormat, version)
	}
	credentialID, err := reader.bytes()
	if err != nil {
		return store.Record{}, err
	}
	salt, err := reader.bytes()
	if err != nil {
		return store.Record{}, err
	}
	rpID, err := reader.bytes()
	if err != nil {
		return store.Record{}, err
	}
	if len(reader.data) != 0 {
		return store.Record{}, fmt.Errorf("%w: trailing record data", store.ErrInvalidRecord)
	}
	return store.Record{
		Alias:        alias,
		CredentialID: credentialID,
		Salt:         salt,
		RPID:         string(rpID),
	}, nil
}

type payloadReader struct {
	data []byte
}

func (r *payloadReader) uint16() (uint16, error) {
	if len(r.data) < 2 {
		return 0, fmt.Errorf("%w: truncated record", store.ErrInvalidRecord)
	}
	value := binary.BigEndian.Uint16(r.data[:2])
	r.data = r.data[2:]
	return value, nil
}

func (r *payloadReader) bytes() ([]byte, error) {
	if len(r.data) < 4 {
		return nil, fmt.Errorf("%w: truncated record", store.ErrInvalidRecord)
	}
	size := binary.BigEndian.Uint32(r.data[:4])
	r.data = r.data[4:]
	if size > maxPayloadField || uint64(size) > uint64(len(r.data)) {
		return nil, fmt.Errorf("%w: invalid record field size", store.ErrInvalidRecord)
	}
	value := append([]byte(nil), r.data[:size]...)
	r.data = r.data[size:]
	return value, nil
}

func appendUint16(dst []byte, value uint16) []byte {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], value)
	return append(dst, buf[:]...)
}

func appendUint64(dst []byte, value uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], value)
	return append(dst, buf[:]...)
}

func appendLengthPrefixed(dst, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}

func cloneKEKReference(ref store.KEKReference) store.KEKReference {
	return store.KEKReference{
		CredentialID: append([]byte(nil), ref.CredentialID...),
		Salt:         append([]byte(nil), ref.Salt...),
		RPID:         ref.RPID,
	}
}

func cloneBlob(blob store.EncryptedBlob) store.EncryptedBlob {
	return store.EncryptedBlob{
		Version:    blob.Version,
		Algorithm:  blob.Algorithm,
		Nonce:      append([]byte(nil), blob.Nonce...),
		Ciphertext: append([]byte(nil), blob.Ciphertext...),
	}
}

func cloneHeader(header store.EncryptionHeader) store.EncryptionHeader {
	return store.EncryptionHeader{
		Version:    header.Version,
		Revision:   header.Revision,
		StoreID:    append([]byte(nil), header.StoreID...),
		KEK:        cloneKEKReference(header.KEK),
		WrappedDEK: cloneBlob(header.WrappedDEK),
	}
}
