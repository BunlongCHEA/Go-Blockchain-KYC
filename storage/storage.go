package storage

import (
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

	// Recovery operations
	LoadRecoveryData() (*models.RecoveryData, error)
	LoadAllBlocks() ([]*models.Block, error)
	LoadPendingTransactions() ([]*models.Transaction, error)
	LoadAllKYCRecords() ([]*models.KYCData, error)
	LoadAllBanks() ([]*models.Bank, error)
	LoadTransactionsByBlockHash(blockHash string) ([]*models.Transaction, error)

	// Renewal Alert operations
	SaveRenewalAlert(alert *models.RenewalAlert) error
	GetPendingRenewalAlerts() ([]*models.RenewalAlert, error)
	UpdateRenewalAlertStatus(alertID string, status models.RenewalAlertStatus) error
	UpdateRenewalAlertConfig(certificateID, webhookURL, emailRecipient string) error
	GetRenewalAlertsByRequester(requesterID string) ([]*models.RenewalAlert, error)

	// Requester Key operations
	SaveRequesterKey(key *models.RequesterKeyInfo) error
	GetRequesterKeyByID(keyID string) (*models.RequesterKeyInfo, error)
	GetRequesterKeyByName(keyName string) (*models.RequesterKeyInfo, error)
	GetAllRequesterKeys() ([]*models.RequesterKeyInfo, error)
	RevokeRequesterKey(keyID string) error
	UpdateRequesterKeyLastUsed(keyID string) error
}
