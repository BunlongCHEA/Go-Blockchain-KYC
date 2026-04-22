package storage

import (
	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/models"
	"time"
)

// Storage defines the interface for blockchain storage
type Storage interface {
	// Database operations
	Close() error
	Ping() error
	Migrate() error

	// Block operations
	SaveBlock(block *models.Block) error
	GetBlock(hash string) (*models.Block, error)
	GetBlockByIndex(index int64) (*models.Block, error)
	GetLatestBlock() (*models.Block, error)
	GetAllBlocks() ([]*models.Block, error)

	// Transaction operations
	SaveTransaction(tx *models.Transaction) error
	GetTransaction(id string) (*models.Transaction, error)
	GetTransactionsByCustomer(customerID string) ([]*models.Transaction, error)
	GetPendingTransactions() ([]*models.Transaction, error)
	DeletePendingTransaction(id string) error

	// KYC operations
	SaveKYC(kyc *models.KYCData) error
	GetKYC(customerID string) (*models.KYCData, error)
	GetAllKYC() ([]*models.KYCData, error)
	GetKYCByStatus(status models.KYCStatus) ([]*models.KYCData, error)
	GetKYCByBank(bankID string) ([]*models.KYCData, error)
	DeleteKYC(customerID string) error

	// Bank operations
	SaveBank(bank *models.Bank) error
	GetBank(bankID string) (*models.Bank, error)
	GetAllBanks() ([]*models.Bank, error)
	DeleteBank(bankID string) error

	// Audit Log operations
	SaveAuditLog(log *models.AuditLog) error
	GetAuditLogs(userID, action string, startTime, endTime time.Time, limit int) ([]*models.AuditLog, error)

	// User operations
	BlockUser(userID, reason string) error
	UnblockUser(userID string) error
	SaveUser(user *auth.User) error
	GetUserByUsername(username string) (*auth.User, error)
	GetAllUsers() ([]*auth.User, error)

	// Recovery operations
	LoadRecoveryData() (*models.RecoveryData, error)
	LoadAllBlocks() ([]*models.Block, error)
	LoadPendingTransactions() ([]*models.Transaction, error)
	LoadAllKYCRecords() ([]*models.KYCData, error)
	LoadAllBanks() ([]*models.Bank, error)
	LoadTransactionsByBlockHash(blockHash string) ([]*models.Transaction, error)

	// Renewal Alert operations
	SaveRenewalAlert(alert *models.RenewalAlert) error
	GetRenewalAlerts(requesterID string) ([]*models.RenewalAlert, error)
	GetPendingRenewalAlerts(before int64) ([]*models.RenewalAlert, error)
	// UpdateRenewalAlertStatus(alertID string, status models.RenewalAlertStatus) error
	// UpdateRenewalAlertConfig(certificateID, webhookURL, emailRecipient string) error
	UpdateRenewalAlertFullConfig(
		certificateID string,
		webhookURL string,
		emailRecipient string,
		isActive bool,
		delivery string,
		sendInterval string,
	) error
	UpdateRenewalAlertIsActive(alertID string, isActive bool) error
	MarkRenewalAlertSent(alertID string, status string) error // SENT or FAILED
	DeactivateRenewalAlerts(customerID string) error          // Called after a new cert is saved — deactivates pending renewal alerts
	// SendRenewalAlertNow(alertID string) error
	// GetRenewalAlertsByRequester(requesterID string) ([]*models.RenewalAlert, error)

	// Requester Key operations
	SaveRequesterKey(key *models.RequesterKeyInfo) error
	GetRequesterKeyByID(keyID string) (*models.RequesterKeyInfo, error)
	GetRequesterKeyByName(keyName string) (*models.RequesterKeyInfo, error)
	GetAllRequesterKeys() ([]*models.RequesterKeyInfo, error)
	RevokeRequesterKey(keyID string) error
	UpdateRequesterKeyLastUsed(keyID string) error

	// Certificate operations
	SaveCertificate(cert *models.VerificationCertificate) error
	GetCertificate(certificateID string) (*models.VerificationCertificate, error)
	// includeHistory=false → only is_active=true rows (UI default view)
	// includeHistory=true  → all rows (audit / history view)
	ListCertificates(requesterID string, limit int, includeHistory bool) ([]*models.VerificationCertificate, error)
	// Called after a new cert is saved — deactivates older certs for same customer+requester
	DeactivateOldCertificates(customerID, requesterID, newCertificateID string) error

	// Returns all active certificates for a specific customer.
	GetCertificatesByCustomer(customerID string) ([]*models.VerificationCertificate, error)
}
