package models

import (
	"time"
)

// Bank represents a registered bank
type Bank struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Code         string    `json:"code"`
	Country      string    `json:"country"`
	LicenseNo    string    `json:"license_no"`
	PublicKey    string    `json:"public_key"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Address      Address   `json:"address"`
	ContactEmail string    `json:"contact_email"`
	ContactPhone string    `json:"contact_phone"`
}

// NewBank creates a new bank
func NewBank(id, name, code, country, licenseNo, publicKey string) *Bank {
	return &Bank{
		ID:        id,
		Name:      name,
		Code:      code,
		Country:   country,
		LicenseNo: licenseNo,
		PublicKey: publicKey,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Deactivate deactivates the bank
func (b *Bank) Deactivate() {
	b.IsActive = false
	b.UpdatedAt = time.Now()
}

// Activate activates the bank
func (b *Bank) Activate() {
	b.IsActive = true
	b.UpdatedAt = time.Now()
}
