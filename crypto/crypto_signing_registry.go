// Package crypto — system signing key registry with rotation support.
//
// Design:
//  - One is_active signing key at a time (used for NEW certs).
//  - Retired keys kept forever (or until all certs they signed have expired)
//    so certs remain verifiable. External requesters verify using the
//    issuer_public_key embedded in the cert itself — they don't need to
//    know about rotation. This registry is for OUR verify endpoint to
//    answer "was this pubkey legitimately ours when signed?".
//
// Every new cert stamps issuer_key_id. VerifyCertificate looks up the key
// by id first; if NULL (legacy cert from before rotation was deployed),
// falls back to trusting the embedded issuer_public_key as before.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SigningKeyStore persists system signing keys.
type SigningKeyStore interface {
	SaveSystemKey(rec *SystemKeyRecord) error
	GetSystemKey(keyID string) (*SystemKeyRecord, error)
	GetActiveSystemKey() (*SystemKeyRecord, error)
	ActivateSystemKey(keyID, userID string) error
	RetireSystemKey(keyID string) error
	ListSystemKeys() ([]*SystemKeyRecord, error)
}

type SystemKeyRecord struct {
	KeyID               string
	KeyType             string // "RSA" or "ECDSA"
	KeySize             int
	PublicKeyPEM        string
	PrivateKeyEncrypted string // wrapped by KEK
	WrappingKEKID       string
	IsActive            bool
	ValidFrom           int64
	ValidUntil          int64
	RetiredAt           int64
	CreatedBy           string
	CreatedAt           int64
}

// SigningKeyManager is a rotation-aware replacement for the old KeyManager.
// It keeps the same signing/verify API so handlers don't need to know
// whether they're signing with key v1 or v2.
type SigningKeyManager struct {
	store    SigningKeyStore
	envelope *EnvelopeEncryptor // to wrap/unwrap private keys at rest

	mu        sync.RWMutex
	active    *SystemKeyRecord       // cached active key (pubkey only for signing)
	privCache map[string]interface{} // keyID -> *rsa.PrivateKey or *ecdsa.PrivateKey
	pubCache  map[string]interface{} // keyID -> *rsa.PublicKey or *ecdsa.PublicKey
}

func NewSigningKeyManager(store SigningKeyStore, env *EnvelopeEncryptor) *SigningKeyManager {
	return &SigningKeyManager{
		store:     store,
		envelope:  env,
		privCache: make(map[string]interface{}),
		pubCache:  make(map[string]interface{}),
	}
}

// Bootstrap ensures an active signing key exists. Returns the active key id.
// If no key exists, generates the first one with the given algorithm+size.
func (m *SigningKeyManager) Bootstrap(algorithm string, keySize int, createdBy string) (string, error) {
	active, err := m.store.GetActiveSystemKey()
	if err == nil && active != nil {
		m.mu.Lock()
		m.active = active
		m.mu.Unlock()
		return active.KeyID, nil
	}
	return m.Rotate(algorithm, keySize, createdBy, true)
}

// Rotate generates a new signing key. If activate=true, immediately makes it
// active (retiring any previous active key). Otherwise, leaves it inactive —
// useful for staged rotation where you want to pre-provision the new key.
//
// For system signing keys, activate=true is the normal flow: new certs start
// using the new key right away, old certs stay valid because they carry their
// own issuer pubkey + reference issuer_key_id.
func (m *SigningKeyManager) Rotate(algorithm string, keySize int, createdBy string, activate bool) (string, error) {
	keyID := fmt.Sprintf("SYSKEY_%d", time.Now().UnixNano())

	pubPEM, privPEM, err := generateSigningKeyPair(algorithm, keySize)
	if err != nil {
		return "", err
	}

	// Wrap the private key PEM with the active KEK (envelope encryption).
	// Uses the same AES primitives as PII encryption so rotating the KEK
	// also protects signing keys.
	wrapped, wrappedDEK, kekID, err := m.envelope.EncryptField([]byte(privPEM))
	if err != nil {
		return "", fmt.Errorf("wrap private key: %w", err)
	}
	// Pack ciphertext||wrappedDEK as a single string — we don't need a
	// separate column because signing keys are rare (1/year).
	packed := wrapped + "::" + wrappedDEK

	now := time.Now().Unix()
	validUntil := time.Now().AddDate(2, 0, 0).Unix() // 2 year hard ceiling; rotate at 1y

	rec := &SystemKeyRecord{
		KeyID:               keyID,
		KeyType:             algorithm,
		KeySize:             keySize,
		PublicKeyPEM:        pubPEM,
		PrivateKeyEncrypted: packed,
		WrappingKEKID:       kekID,
		IsActive:            activate,
		ValidFrom:           now,
		ValidUntil:          validUntil,
		CreatedBy:           createdBy,
		CreatedAt:           now,
	}

	if err := m.store.SaveSystemKey(rec); err != nil {
		return "", err
	}

	if activate {
		if err := m.store.ActivateSystemKey(keyID, createdBy); err != nil {
			return "", err
		}
		m.mu.Lock()
		m.active = rec
		m.mu.Unlock()
	}
	return keyID, nil
}

// ActiveKeyID returns the id of the currently active signing key.
func (m *SigningKeyManager) ActiveKeyID() (string, error) {
	m.mu.RLock()
	if m.active != nil {
		id := m.active.KeyID
		m.mu.RUnlock()
		return id, nil
	}
	m.mu.RUnlock()
	active, err := m.store.GetActiveSystemKey()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.active = active
	m.mu.Unlock()
	return active.KeyID, nil
}

// ActivePublicKeyPEM returns the PEM of the current signing key (for embedding in new certs).
func (m *SigningKeyManager) ActivePublicKeyPEM() (string, error) {
	m.mu.RLock()
	if m.active != nil {
		pem := m.active.PublicKeyPEM
		m.mu.RUnlock()
		return pem, nil
	}
	m.mu.RUnlock()
	_, err := m.ActiveKeyID()
	if err != nil {
		return "", err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.PublicKeyPEM, nil
}

// ActiveKeyType returns "RSA" or "ECDSA".
func (m *SigningKeyManager) ActiveKeyType() (string, error) {
	m.mu.RLock()
	if m.active != nil {
		t := m.active.KeyType
		m.mu.RUnlock()
		return t, nil
	}
	m.mu.RUnlock()
	active, err := m.store.GetActiveSystemKey()
	if err != nil {
		return "", err
	}
	return active.KeyType, nil
}

// loadPrivate unwraps and parses the private key for the given key id.
func (m *SigningKeyManager) loadPrivate(keyID string) (interface{}, string, error) {
	m.mu.RLock()
	if cached, ok := m.privCache[keyID]; ok {
		m.mu.RUnlock()
		rec, err := m.store.GetSystemKey(keyID)
		if err != nil {
			return nil, "", err
		}
		return cached, rec.KeyType, nil
	}
	m.mu.RUnlock()

	rec, err := m.store.GetSystemKey(keyID)
	if err != nil {
		return nil, "", err
	}

	// Unpack ciphertext||wrappedDEK
	sep := -1
	for i := 0; i+1 < len(rec.PrivateKeyEncrypted); i++ {
		if rec.PrivateKeyEncrypted[i] == ':' && rec.PrivateKeyEncrypted[i+1] == ':' {
			sep = i
			break
		}
	}
	if sep < 0 {
		return nil, "", errors.New("malformed wrapped private key")
	}
	ct := rec.PrivateKeyEncrypted[:sep]
	wrappedDEK := rec.PrivateKeyEncrypted[sep+2:]

	privPEM, err := m.envelope.DecryptField(ct, wrappedDEK, rec.WrappingKEKID)
	if err != nil {
		return nil, "", fmt.Errorf("unwrap private key: %w", err)
	}

	priv, err := parsePrivateKeyPEM(string(privPEM))
	if err != nil {
		return nil, "", err
	}

	m.mu.Lock()
	m.privCache[keyID] = priv
	m.mu.Unlock()
	return priv, rec.KeyType, nil
}

// LookupPublicKey returns the public key for a historical signing key id.
// Used by VerifyCertificate to support certs signed before rotation.
func (m *SigningKeyManager) LookupPublicKey(keyID string) (string, error) {
	m.mu.RLock()
	if _, ok := m.pubCache[keyID]; ok {
		m.mu.RUnlock()
	} else {
		m.mu.RUnlock()
	}
	rec, err := m.store.GetSystemKey(keyID)
	if err != nil {
		return "", err
	}
	return rec.PublicKeyPEM, nil
}

// ActivePrivate returns the currently active private key + type for signing.
func (m *SigningKeyManager) ActivePrivate() (interface{}, string, string, error) {
	id, err := m.ActiveKeyID()
	if err != nil {
		return nil, "", "", err
	}
	priv, keyType, err := m.loadPrivate(id)
	if err != nil {
		return nil, "", "", err
	}
	return priv, keyType, id, nil
}

// ─── PEM helpers ──────────────────────────────────────────────────────────────

func generateSigningKeyPair(algorithm string, keySize int) (pubPEM, privPEM string, err error) {
	switch algorithm {
	case "RSA":
		priv, e := rsa.GenerateKey(rand.Reader, keySize)
		if e != nil {
			return "", "", e
		}
		privBytes := x509.MarshalPKCS1PrivateKey(priv)
		privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}))
		pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes}))
		return
	case "ECDSA":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}
		priv, e := ecdsa.GenerateKey(curve, rand.Reader)
		if e != nil {
			return "", "", e
		}
		privBytes, e := x509.MarshalECPrivateKey(priv)
		if e != nil {
			return "", "", e
		}
		privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}))
		pubBytes, e := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if e != nil {
			return "", "", e
		}
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
		return
	default:
		return "", "", fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

func parsePrivateKeyPEM(pemStr string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type: %s", block.Type)
	}
}
