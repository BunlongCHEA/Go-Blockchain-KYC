package storage

import (
	"Go-Blockchain-KYC/models"
)

// Storage defines the interface for blockchain storage
type Storage interface {
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

	// Utility operations
	Close() error
	Ping() error
	Migrate() error
}
