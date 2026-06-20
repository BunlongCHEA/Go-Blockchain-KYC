package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// ─── Types now live in crypto (same pattern as KEKRecord / SystemKeyRecord) ──
// This avoids the import cycle: crypto must NOT import storage or models,
// since storage imports crypto (for these types) and models is imported by
// crypto's own callers elsewhere in the dependency graph.

type MQKeyRecord struct {
	KeyVersion           string
	EncryptedKey         string // wrapped by KEK — never logged or exposed via API
	WrappingKEKID        string
	IsActive             bool
	RotationPolicyMonths int // 6 or 12
	ValidFrom            int64
	ValidUntil           int64
	RetiredAt            int64
	CreatedBy            string
	CreatedAt            int64
}

// MQKeySafeView is what the admin UI/API is allowed to see — NEVER the raw key.
type MQKeySafeView struct {
	KeyVersion           string `json:"key_version"`
	Fingerprint          string `json:"fingerprint"`
	IsActive             bool   `json:"is_active"`
	RotationPolicyMonths int    `json:"rotation_policy_months"`
	ValidFrom            int64  `json:"valid_from"`
	ValidUntil           int64  `json:"valid_until"`
	RetiredAt            int64  `json:"retired_at,omitempty"`
	DaysUntilRotation    int    `json:"days_until_rotation"`
	CreatedBy            string `json:"created_by"`
	CreatedAt            int64  `json:"created_at"`
}

// MQKeyStore is the minimal persistence contract MQKeyManager needs.
// crypto does NOT import storage — storage.PostgresStorage satisfies this
// interface implicitly (Go structural typing), exactly like it already does
// for the EnvelopeEncryptor's KEK persistence calls.
type MQKeyStore interface {
	SaveMQKey(rec *MQKeyRecord) error
	GetMQKey(version string) (*MQKeyRecord, error)
	GetActiveMQKey() (*MQKeyRecord, error)
	ActivateMQKey(version string) error
	ListMQKeys() ([]*MQKeyRecord, error)
}

// MQKeyManager owns AES-256-GCM key generation, KEK-wrapping, rotation,
// and in-memory caching of the active key for the hot publish path.
type MQKeyManager struct {
	store    MQKeyStore
	envelope *EnvelopeEncryptor

	mu        sync.RWMutex
	activeVer string
	activeKey []byte
	keyCache  map[string][]byte
}

func NewMQKeyManager(store MQKeyStore, envelope *EnvelopeEncryptor) *MQKeyManager {
	return &MQKeyManager{
		store:    store,
		envelope: envelope,
		keyCache: make(map[string][]byte),
	}
}

func (m *MQKeyManager) Bootstrap(defaultPolicyMonths int, createdBy string) (string, error) {
	rec, err := m.store.GetActiveMQKey()
	if err != nil {
		return "", fmt.Errorf("load active mq key: %w", err)
	}
	if rec != nil {
		plain, err := m.unwrapKey(rec.EncryptedKey, rec.WrappingKEKID)
		if err != nil {
			return "", fmt.Errorf("unwrap active mq key: %w", err)
		}
		m.mu.Lock()
		m.activeVer = rec.KeyVersion
		m.activeKey = plain
		m.keyCache[rec.KeyVersion] = plain
		m.mu.Unlock()
		log.Printf("[MQKeyManager] loaded active key %s (policy=%dmo)", rec.KeyVersion, rec.RotationPolicyMonths)
		return rec.KeyVersion, nil
	}
	return m.Rotate(defaultPolicyMonths, createdBy)
}

func (m *MQKeyManager) Rotate(policyMonths int, createdBy string) (string, error) {
	if policyMonths != 6 && policyMonths != 12 {
		return "", fmt.Errorf("rotation_policy_months must be 6 or 12, got %d", policyMonths)
	}

	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		return "", fmt.Errorf("generate mq key: %w", err)
	}

	wrapped, kekID, err := m.wrapKey(plain)
	if err != nil {
		return "", fmt.Errorf("wrap mq key: %w", err)
	}

	version := m.nextVersion()
	now := time.Now()

	rec := &MQKeyRecord{
		KeyVersion:           version,
		EncryptedKey:         wrapped,
		WrappingKEKID:        kekID,
		IsActive:             true,
		RotationPolicyMonths: policyMonths,
		ValidFrom:            now.Unix(),
		ValidUntil:           now.AddDate(0, policyMonths, 0).Unix(),
		CreatedBy:            createdBy,
		CreatedAt:            now.Unix(),
	}

	if err := m.store.SaveMQKey(rec); err != nil {
		return "", fmt.Errorf("save mq key: %w", err)
	}
	if err := m.store.ActivateMQKey(version); err != nil {
		return "", fmt.Errorf("activate mq key: %w", err)
	}

	m.mu.Lock()
	m.activeVer = version
	m.activeKey = plain
	m.keyCache[version] = plain
	m.mu.Unlock()

	log.Printf("[MQKeyManager] rotated → %s (policy=%dmo, valid_until=%s)",
		version, policyMonths, time.Unix(rec.ValidUntil, 0).Format("2006-01-02"))
	return version, nil
}

func (m *MQKeyManager) GetActive() (version string, key []byte, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.activeKey == nil {
		return "", nil, fmt.Errorf("mq key manager not bootstrapped")
	}
	return m.activeVer, m.activeKey, nil
}

func (m *MQKeyManager) GetByVersion(version string) ([]byte, error) {
	m.mu.RLock()
	if k, ok := m.keyCache[version]; ok {
		m.mu.RUnlock()
		return k, nil
	}
	m.mu.RUnlock()

	rec, err := m.store.GetMQKey(version)
	if err != nil {
		return nil, err
	}
	plain, err := m.unwrapKey(rec.EncryptedKey, rec.WrappingKEKID)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.keyCache[version] = plain
	m.mu.Unlock()
	return plain, nil
}

func (m *MQKeyManager) SafeList() ([]MQKeySafeView, error) {
	recs, err := m.store.ListMQKeys()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	out := make([]MQKeySafeView, 0, len(recs))
	for _, r := range recs {
		fp := ""
		if plain, err := m.GetByVersion(r.KeyVersion); err == nil {
			fp = fingerprint(plain)
		}
		daysLeft := int((r.ValidUntil - now) / 86400)
		if daysLeft < 0 {
			daysLeft = 0
		}
		out = append(out, MQKeySafeView{
			KeyVersion:           r.KeyVersion,
			Fingerprint:          fp,
			IsActive:             r.IsActive,
			RotationPolicyMonths: r.RotationPolicyMonths,
			ValidFrom:            r.ValidFrom,
			ValidUntil:           r.ValidUntil,
			RetiredAt:            r.RetiredAt,
			DaysUntilRotation:    daysLeft,
			CreatedBy:            r.CreatedBy,
			CreatedAt:            r.CreatedAt,
		})
	}
	return out, nil
}

func fingerprint(key []byte) string {
	h := sha256.Sum256(key)
	return "sha256:" + hex.EncodeToString(h[:8])
}

func (m *MQKeyManager) nextVersion() string {
	recs, _ := m.store.ListMQKeys()
	return fmt.Sprintf("v%d", len(recs)+1)
}

func (m *MQKeyManager) wrapKey(plain []byte) (wrapped string, kekID string, err error) {
	return m.envelope.WrapRawKey(plain)
}
func (m *MQKeyManager) unwrapKey(wrapped, kekID string) ([]byte, error) {
	return m.envelope.UnwrapRawKey(wrapped, kekID)
}
