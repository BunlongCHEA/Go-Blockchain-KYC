package models

// MQKeyRecord represents one AES-256-GCM key version for MQ payload encryption.
// PlaintextKey is populated only transiently in memory after unwrap — never persisted.
type MQKeyRecord struct {
	KeyVersion           string `json:"key_version"`
	EncryptedKey         string `json:"-"` // wrapped by KEK — never serialize to API
	WrappingKEKID        string `json:"-"`
	IsActive             bool   `json:"is_active"`
	RotationPolicyMonths int    `json:"rotation_policy_months"` // 6 or 12
	ValidFrom            int64  `json:"valid_from"`
	ValidUntil           int64  `json:"valid_until"`
	RetiredAt            int64  `json:"retired_at,omitempty"`
	CreatedBy            string `json:"created_by"`
	CreatedAt            int64  `json:"created_at"`
}

// MQKeySafeView is what the admin UI/API is allowed to see — NEVER the raw key.
type MQKeySafeView struct {
	KeyVersion           string `json:"key_version"`
	Fingerprint          string `json:"fingerprint"` // SHA-256(key)[:8] hex — identifies key without exposing it
	IsActive             bool   `json:"is_active"`
	RotationPolicyMonths int    `json:"rotation_policy_months"`
	ValidFrom            int64  `json:"valid_from"`
	ValidUntil           int64  `json:"valid_until"`
	RetiredAt            int64  `json:"retired_at,omitempty"`
	DaysUntilRotation    int    `json:"days_until_rotation"`
	CreatedBy            string `json:"created_by"`
	CreatedAt            int64  `json:"created_at"`
}
