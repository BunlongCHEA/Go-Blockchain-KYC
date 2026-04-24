// Package crypto — envelope encryption and KEK rotation.
//
// Terminology:
//   Root KEK   — 32-byte AES key sourced from env KYC_ROOT_KEK (base64).
//                Used ONLY to wrap/unwrap the active KEK loaded from DB.
//                Rotation of Root KEK is an out-of-band ops task (touch env,
//                re-wrap all KEK rows in one transaction).
//   KEK        — Key Encryption Key. Stored wrapped-by-root in kek_keys.
//                One is_active at a time; retired ones stay for unwrap.
//   DEK        — Data Encryption Key. Random per KYC record. Encrypts the
//                PII ciphertext stored in kyc_records. Wrapped by KEK and
//                stored in kyc_records.wrapped_dek alongside encryption_key_id
//                (the KEK id used to wrap).
//
// Rotation flow (KEK, 1–2 years cadence):
//   1. GenerateKEK()          — creates new KEK, wraps with root, inserts is_active=false
//   2. ActivateKEK(newID)     — atomically flips is_active; old becomes retired
//   3. RewrapAllDEKs()        — background job: for each kyc_records row,
//                                unwrap DEK with old KEK, re-wrap with new KEK,
//                                update encryption_key_id + wrapped_dek.
//   4. RetireKEK(oldID)       — once RewrapAllDEKs completes, old KEK can be
//                                deleted. Historical verification does not need it
//                                because DEKs have been re-wrapped to new KEK.

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// KEKStore abstracts the persistence of KEKs. Implemented by storage package.
type KEKStore interface {
	SaveKEK(kekID string, wrappedKey string, isActive bool, createdBy string) error
	GetKEK(kekID string) (wrappedKey string, isActive bool, err error)
	GetActiveKEK() (kekID string, wrappedKey string, err error)
	ActivateKEK(kekID string, userID string) error // atomically deactivates others
	RetireKEK(kekID string) error
	ListKEKs() ([]KEKRecord, error)
}

type KEKRecord struct {
	KEKID     string
	IsActive  bool
	CreatedAt int64
	RetiredAt int64 // 0 if not retired
}

// EnvelopeEncryptor provides AES-256-GCM envelope encryption on top of a
// rotatable KEK backed by KEKStore.
type EnvelopeEncryptor struct {
	rootKEK []byte // 32 bytes, from env, wraps KEKs only
	store   KEKStore

	// cached unwrapped KEK material; invalidated on rotation
	mu       sync.RWMutex
	kekCache map[string][]byte // kek_id -> plaintext 32-byte KEK
	activeID string
}

// NewEnvelopeEncryptor constructs the encryptor.
// rootKEKB64 must be 32 bytes base64-encoded. Returns error if missing/wrong size.
func NewEnvelopeEncryptor(rootKEKB64 string, store KEKStore) (*EnvelopeEncryptor, error) {
	if rootKEKB64 == "" {
		return nil, errors.New("KYC_ROOT_KEK is required")
	}
	root, err := base64.StdEncoding.DecodeString(rootKEKB64)
	if err != nil {
		return nil, fmt.Errorf("KYC_ROOT_KEK invalid base64: %w", err)
	}
	if len(root) != 32 {
		return nil, fmt.Errorf("KYC_ROOT_KEK must decode to 32 bytes (got %d)", len(root))
	}
	return &EnvelopeEncryptor{
		rootKEK:  root,
		store:    store,
		kekCache: make(map[string][]byte),
	}, nil
}

// Bootstrap ensures at least one active KEK exists. Called on startup.
// If none exists, generates one. Safe to call every boot.
func (e *EnvelopeEncryptor) Bootstrap(createdBy string) error {
	kekID, _, err := e.store.GetActiveKEK()
	if err == nil && kekID != "" {
		return nil // already bootstrapped
	}
	_, err = e.GenerateKEK(createdBy, true)
	return err
}

// GenerateKEK creates a new 32-byte KEK, wraps it with root, persists it.
// Set activate=true to immediately activate (first-time bootstrap).
// For rotation, pass activate=false, then call ActivateKEK after re-wrapping.
func (e *EnvelopeEncryptor) GenerateKEK(createdBy string, activate bool) (string, error) {
	plain := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, plain); err != nil {
		return "", err
	}
	kekID := fmt.Sprintf("KEK_%d", time.Now().UnixNano())

	wrapped, err := aesGCMEncrypt(e.rootKEK, plain)
	if err != nil {
		return "", err
	}
	if err := e.store.SaveKEK(kekID, wrapped, activate, createdBy); err != nil {
		return "", err
	}

	e.mu.Lock()
	e.kekCache[kekID] = plain
	if activate {
		e.activeID = kekID
	}
	e.mu.Unlock()
	return kekID, nil
}

// ActivateKEK flips is_active to the given KEK and retires others.
// Only call after you've finished RewrapAllDEKs for the new KEK, OR if
// you're fine letting the background worker catch up (rows with old KEK
// will unwrap with the retired KEK until re-wrapped).
func (e *EnvelopeEncryptor) ActivateKEK(kekID, userID string) error {
	if err := e.store.ActivateKEK(kekID, userID); err != nil {
		return err
	}
	e.mu.Lock()
	e.activeID = kekID
	e.mu.Unlock()
	return nil
}

// ActiveKEKID returns the current active KEK id (cached).
func (e *EnvelopeEncryptor) ActiveKEKID() (string, error) {
	e.mu.RLock()
	id := e.activeID
	e.mu.RUnlock()
	if id != "" {
		return id, nil
	}
	id, _, err := e.store.GetActiveKEK()
	if err != nil {
		return "", err
	}
	e.mu.Lock()
	e.activeID = id
	e.mu.Unlock()
	return id, nil
}

// unwrapKEK returns the plaintext KEK bytes, using cache where possible.
func (e *EnvelopeEncryptor) unwrapKEK(kekID string) ([]byte, error) {
	e.mu.RLock()
	if cached, ok := e.kekCache[kekID]; ok {
		e.mu.RUnlock()
		return cached, nil
	}
	e.mu.RUnlock()

	wrapped, _, err := e.store.GetKEK(kekID)
	if err != nil {
		return nil, err
	}
	plain, err := aesGCMDecrypt(e.rootKEK, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unwrap KEK %s failed: %w", kekID, err)
	}

	e.mu.Lock()
	e.kekCache[kekID] = plain
	e.mu.Unlock()
	return plain, nil
}

// EncryptField generates a DEK, encrypts the plaintext with it, wraps the
// DEK with the active KEK, returns (ciphertext, wrappedDEK, kekID).
//
// The caller stores all three:
//
//	kyc_records.<field>_encrypted   = ciphertext
//	kyc_records.wrapped_dek         = wrappedDEK  (one DEK per row, shared across fields)
//	kyc_records.encryption_key_id   = kekID
//
// For multi-field rows (id, email, phone), call this ONCE to get a shared DEK,
// then use EncryptWithDEK for each field to avoid one DEK per field.
func (e *EnvelopeEncryptor) EncryptField(plaintext []byte) (ciphertext, wrappedDEK, kekID string, err error) {
	dek := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, dek); err != nil {
		return
	}
	kekID, err = e.ActiveKEKID()
	if err != nil {
		return
	}
	kek, err := e.unwrapKEK(kekID)
	if err != nil {
		return
	}
	wrappedDEK, err = aesGCMEncrypt(kek, dek)
	if err != nil {
		return
	}
	ct, err := aesGCMEncrypt(dek, plaintext)
	if err != nil {
		return
	}
	ciphertext = ct
	return
}

// NewDEK returns a fresh DEK + its wrapped form + active KEK id.
// Use this when you have multiple fields on one row so they share a DEK.
func (e *EnvelopeEncryptor) NewDEK() (dek []byte, wrappedDEK, kekID string, err error) {
	dek = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, dek); err != nil {
		return
	}
	kekID, err = e.ActiveKEKID()
	if err != nil {
		return
	}
	kek, err := e.unwrapKEK(kekID)
	if err != nil {
		return
	}
	wrappedDEK, err = aesGCMEncrypt(kek, dek)
	return
}

// EncryptWithDEK encrypts plaintext using a provided DEK.
func (e *EnvelopeEncryptor) EncryptWithDEK(dek, plaintext []byte) (string, error) {
	return aesGCMEncrypt(dek, plaintext)
}

// DecryptField unwraps the DEK using the named KEK, then decrypts the ciphertext.
// Works for both active and retired KEKs (retired KEKs must still exist in store
// until their DEKs are re-wrapped).
func (e *EnvelopeEncryptor) DecryptField(ciphertext, wrappedDEK, kekID string) ([]byte, error) {
	kek, err := e.unwrapKEK(kekID)
	if err != nil {
		return nil, err
	}
	dek, err := aesGCMDecrypt(kek, wrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap DEK failed: %w", err)
	}
	return aesGCMDecryptBytes(dek, ciphertext)
}

// RewrapDEK takes a wrapped DEK under oldKEK and rewraps it under the active KEK.
// Returns (newWrappedDEK, newKEKID). The ciphertext of the PII itself doesn't change.
func (e *EnvelopeEncryptor) RewrapDEK(oldWrappedDEK, oldKEKID string) (string, string, error) {
	oldKEK, err := e.unwrapKEK(oldKEKID)
	if err != nil {
		return "", "", err
	}
	dek, err := aesGCMDecrypt(oldKEK, oldWrappedDEK)
	if err != nil {
		return "", "", fmt.Errorf("unwrap with old KEK: %w", err)
	}
	newKEKID, err := e.ActiveKEKID()
	if err != nil {
		return "", "", err
	}
	newKEK, err := e.unwrapKEK(newKEKID)
	if err != nil {
		return "", "", err
	}
	newWrapped, err := aesGCMEncrypt(newKEK, dek)
	if err != nil {
		return "", "", err
	}
	return newWrapped, newKEKID, nil
}

// ─── AES-GCM helpers ──────────────────────────────────────────────────────────

func aesGCMEncrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func aesGCMDecrypt(key []byte, ctB64 string) ([]byte, error) {
	return aesGCMDecryptBytes(key, ctB64)
}

func aesGCMDecryptBytes(key []byte, ctB64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(ctB64)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, body := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}
