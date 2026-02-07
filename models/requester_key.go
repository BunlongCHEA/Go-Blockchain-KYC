package models

// RequesterKeyInfo represents stored requester key information
type RequesterKeyInfo struct {
	ID           string `json:"id"`
	KeyName      string `json:"key_name"`
	KeyType      string `json:"key_type"`
	KeySize      int    `json:"key_size"`
	PublicKeyPEM string `json:"public_key_pem"`
	Fingerprint  string `json:"fingerprint"`
	Organization string `json:"organization"`
	Email        string `json:"email"`
	Description  string `json:"description"`
	IsActive     bool   `json:"is_active"`
	CreatedAt    int64  `json:"created_at"`
	ExpiresAt    int64  `json:"expires_at"`
	CreatedBy    string `json:"created_by"`
	LastUsedAt   *int64 `json:"last_used_at,omitempty"`
	RevokedAt    *int64 `json:"revoked_at,omitempty"`
	RevokedBy    string `json:"revoked_by,omitempty"`
}
