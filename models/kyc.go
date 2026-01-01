package models

import (
	"encoding/json"
	"time"

	"Go-Blockchain-KYC/crypto"
)

// KYCStatus represents the verification status
type KYCStatus string

const (
	StatusPending   KYCStatus = "PENDING"
	StatusVerified  KYCStatus = "VERIFIED"
	StatusRejected  KYCStatus = "REJECTED"
	StatusSuspended KYCStatus = "SUSPENDED"
	StatusExpired   KYCStatus = "EXPIRED"
)

// Address represents customer's address
type Address struct {
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

// KYCData represents customer identity data
type KYCData struct {
	CustomerID       string    `json:"customer_id"`
	FirstName        string    `json:"first_name"`
	LastName         string    `json:"last_name"`
	DateOfBirth      string    `json:"date_of_birth"`
	Nationality      string    `json:"nationality"`
	IDType           string    `json:"id_type"`
	IDNumber         string    `json:"id_number"` // Encrypted
	IDExpiryDate     string    `json:"id_expiry_date"`
	Address          Address   `json:"address"`
	Email            string    `json:"email"` // Encrypted
	Phone            string    `json:"phone"` // Encrypted
	Status           KYCStatus `json:"status"`
	VerifiedBy       string    `json:"verified_by"`
	VerificationDate int64     `json:"verification_date"`
	CreatedAt        int64     `json:"created_at"`
	UpdatedAt        int64     `json:"updated_at"`
	DocumentHash     string    `json:"document_hash"`
	RiskLevel        string    `json:"risk_level"`
	BankID           string    `json:"bank_id"`

	// Encrypted sensitive fields
	EncryptedData *EncryptedKYCData `json:"encrypted_data,omitempty"`
}

// EncryptedKYCData holds encrypted sensitive fields
type EncryptedKYCData struct {
	IDNumber string `json:"id_number"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	SSN      string `json:"ssn,omitempty"`
	KeyID    string `json:"key_id"`
}

// NewKYCData creates a new KYC data record
func NewKYCData(customerID, firstName, lastName, dob, nationality, idType, idNumber, idExpiry string,
	address Address, email, phone, bankID string) *KYCData {
	return &KYCData{
		CustomerID:   customerID,
		FirstName:    firstName,
		LastName:     lastName,
		DateOfBirth:  dob,
		Nationality:  nationality,
		IDType:       idType,
		IDNumber:     idNumber,
		IDExpiryDate: idExpiry,
		Address:      address,
		Email:        email,
		Phone:        phone,
		Status:       StatusPending,
		BankID:       bankID,
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
		RiskLevel:    "medium",
	}
}

// EncryptSensitiveData encrypts sensitive fields
func (k *KYCData) EncryptSensitiveData(encryptor *crypto.Encryptor, keyID string) error {
	encryptedID, err := encryptor.EncryptString(k.IDNumber)
	if err != nil {
		return err
	}

	encryptedEmail, err := encryptor.EncryptString(k.Email)
	if err != nil {
		return err
	}

	encryptedPhone, err := encryptor.EncryptString(k.Phone)
	if err != nil {
		return err
	}

	k.EncryptedData = &EncryptedKYCData{
		IDNumber: encryptedID,
		Email:    encryptedEmail,
		Phone:    encryptedPhone,
		KeyID:    keyID,
	}

	// Clear plaintext sensitive data
	k.IDNumber = "[ENCRYPTED]"
	k.Email = "[ENCRYPTED]"
	k.Phone = "[ENCRYPTED]"

	return nil
}

// DecryptSensitiveData decrypts sensitive fields
func (k *KYCData) DecryptSensitiveData(encryptor *crypto.Encryptor) error {
	if k.EncryptedData == nil {
		return nil
	}

	idNumber, err := encryptor.DecryptString(k.EncryptedData.IDNumber)
	if err != nil {
		return err
	}

	email, err := encryptor.DecryptString(k.EncryptedData.Email)
	if err != nil {
		return err
	}

	phone, err := encryptor.DecryptString(k.EncryptedData.Phone)
	if err != nil {
		return err
	}

	k.IDNumber = idNumber
	k.Email = email
	k.Phone = phone

	return nil
}

// Verify marks the KYC as verified
func (k *KYCData) Verify(bankID string) {
	k.Status = StatusVerified
	k.VerifiedBy = bankID
	k.VerificationDate = time.Now().Unix()
	k.UpdatedAt = time.Now().Unix()
}

// Reject marks the KYC as rejected
func (k *KYCData) Reject() {
	k.Status = StatusRejected
	k.UpdatedAt = time.Now().Unix()
}

// Suspend marks the KYC as suspended
func (k *KYCData) Suspend() {
	k.Status = StatusSuspended
	k.UpdatedAt = time.Now().Unix()
}

// ToJSON converts KYC data to JSON
func (k *KYCData) ToJSON() ([]byte, error) {
	return json.Marshal(k)
}

// KYCDataFromJSON creates KYC data from JSON
func KYCDataFromJSON(data []byte) (*KYCData, error) {
	var kyc KYCData
	err := json.Unmarshal(data, &kyc)
	return &kyc, err
}
