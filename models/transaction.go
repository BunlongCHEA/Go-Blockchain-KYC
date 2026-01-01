package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"Go-Blockchain-KYC/crypto"
)

// TransactionType represents the type of KYC transaction
type TransactionType string

const (
	TxCreate  TransactionType = "CREATE"
	TxUpdate  TransactionType = "UPDATE"
	TxVerify  TransactionType = "VERIFY"
	TxReject  TransactionType = "REJECT"
	TxDelete  TransactionType = "DELETE"
	TxSuspend TransactionType = "SUSPEND"
)

// Transaction represents a KYC transaction on the blockchain
type Transaction struct {
	ID          string                 `json:"id"`
	Type        TransactionType        `json:"type"`
	CustomerID  string                 `json:"customer_id"`
	KYCData     *KYCData               `json:"kyc_data,omitempty"`
	BankID      string                 `json:"bank_id"`
	UserID      string                 `json:"user_id"`
	Timestamp   int64                  `json:"timestamp"`
	Signature   string                 `json:"signature"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// NewTransaction creates a new KYC transaction
func NewTransaction(txType TransactionType, customerID string, kycData *KYCData,
	bankID, userID, description string) *Transaction {
	tx := &Transaction{
		Type:        txType,
		CustomerID:  customerID,
		KYCData:     kycData,
		BankID:      bankID,
		UserID:      userID,
		Timestamp:   time.Now().Unix(),
		Description: description,
		Metadata:    make(map[string]interface{}),
	}
	tx.ID = tx.GenerateID()
	return tx
}

// GenerateID generates a unique transaction ID
func (t *Transaction) GenerateID() string {
	data, _ := json.Marshal(struct {
		Type       TransactionType
		CustomerID string
		BankID     string
		Timestamp  int64
	}{
		Type:       t.Type,
		CustomerID: t.CustomerID,
		BankID:     t.BankID,
		Timestamp:  t.Timestamp,
	})

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])[:16]
}

// Sign signs the transaction with a key pair
func (t *Transaction) Sign(signer *crypto.Signer) error {
	data, err := t.GetSigningData()
	if err != nil {
		return err
	}

	signature, err := signer.Sign(data)
	if err != nil {
		return err
	}

	t.Signature = signature
	return nil
}

// Verify verifies the transaction signature
func (t *Transaction) Verify(signer *crypto.Signer) (bool, error) {
	data, err := t.GetSigningData()
	if err != nil {
		return false, err
	}

	return signer.Verify(data, t.Signature)
}

// GetSigningData returns the data to be signed
func (t *Transaction) GetSigningData() ([]byte, error) {
	return json.Marshal(struct {
		ID          string
		Type        TransactionType
		CustomerID  string
		BankID      string
		Timestamp   int64
		Description string
	}{
		ID:          t.ID,
		Type:        t.Type,
		CustomerID:  t.CustomerID,
		BankID:      t.BankID,
		Timestamp:   t.Timestamp,
		Description: t.Description,
	})
}

// ToJSON converts transaction to JSON
func (t *Transaction) ToJSON() ([]byte, error) {
	return json.Marshal(t)
}

// CreateKYCTransaction creates a new KYC record transaction
func CreateKYCTransaction(kycData *KYCData, bankID, userID string) *Transaction {
	return NewTransaction(TxCreate, kycData.CustomerID, kycData, bankID, userID, "KYC record created")
}

// UpdateKYCTransaction creates an update KYC transaction
func UpdateKYCTransaction(kycData *KYCData, bankID, userID, description string) *Transaction {
	return NewTransaction(TxUpdate, kycData.CustomerID, kycData, bankID, userID, description)
}

// VerifyKYCTransaction creates a verification transaction
func VerifyKYCTransaction(customerID, bankID, userID string) *Transaction {
	return NewTransaction(TxVerify, customerID, nil, bankID, userID, "KYC verified by bank")
}

// RejectKYCTransaction creates a rejection transaction
func RejectKYCTransaction(customerID, bankID, userID, reason string) *Transaction {
	return NewTransaction(TxReject, customerID, nil, bankID, userID, reason)
}

// DeleteKYCTransaction creates a deletion transaction
func DeleteKYCTransaction(customerID, bankID, userID, reason string) *Transaction {
	return NewTransaction(TxDelete, customerID, nil, bankID, userID, reason)
}

// SuspendKYCTransaction creates a suspension transaction
func SuspendKYCTransaction(customerID, bankID, userID, reason string) *Transaction {
	return NewTransaction(TxSuspend, customerID, nil, bankID, userID, reason)
}
