package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"Go-Blockchain-KYC/crypto"
)

// Blockchain represents the KYC blockchain
type Blockchain struct {
	Blocks        []*Block
	PendingTxs    []*Transaction
	KYCRecords    map[string]*KYCData
	Banks         map[string]*Bank
	Difficulty    int
	MaxTxPerBlock int
	mutex         sync.RWMutex
	encryptor     *crypto.Encryptor
	nodeID        string
}

// NewBlockchain creates a new blockchain with genesis block
func NewBlockchain(difficulty, maxTxPerBlock int, encryptor *crypto.Encryptor, nodeID string) *Blockchain {
	bc := &Blockchain{
		Blocks:        []*Block{NewGenesisBlock(difficulty)},
		PendingTxs:    []*Transaction{},
		KYCRecords:    make(map[string]*KYCData),
		Banks:         make(map[string]*Bank),
		Difficulty:    difficulty,
		MaxTxPerBlock: maxTxPerBlock,
		encryptor:     encryptor,
		nodeID:        nodeID,
	}
	return bc
}

// RegisterBank registers a new authorized bank
func (bc *Blockchain) RegisterBank(bank *Bank) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	if _, exists := bc.Banks[bank.ID]; exists {
		return errors.New("bank already registered")
	}

	bc.Banks[bank.ID] = bank
	return nil
}

// GetBank retrieves a bank by ID
func (bc *Blockchain) GetBank(bankID string) (*Bank, error) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	bank, exists := bc.Banks[bankID]
	if !exists {
		return nil, errors.New("bank not found")
	}
	return bank, nil
}

// IsAuthorizedBank checks if a bank is authorized
func (bc *Blockchain) IsAuthorizedBank(bankID string) bool {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	bank, exists := bc.Banks[bankID]
	return exists && bank.IsActive
}

// AddTransaction adds a transaction to pending transactions
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// Validate bank authorization
	bank, exists := bc.Banks[tx.BankID]
	if !exists || !bank.IsActive {
		return errors.New("unauthorized or inactive bank")
	}

	bc.PendingTxs = append(bc.PendingTxs, tx)

	// Auto-mine if we have enough transactions
	if len(bc.PendingTxs) >= bc.MaxTxPerBlock {
		bc.mineBlockUnsafe()
	}

	return nil
}

// MineBlock mines a new block with pending transactions
func (bc *Blockchain) MineBlock() *Block {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()
	return bc.mineBlockUnsafe()
}

func (bc *Blockchain) mineBlockUnsafe() *Block {
	if len(bc.PendingTxs) == 0 {
		return nil
	}

	lastBlock := bc.Blocks[len(bc.Blocks)-1]
	newBlock := NewBlock(bc.PendingTxs, lastBlock.Hash, lastBlock.Index+1, bc.Difficulty, bc.nodeID)
	bc.Blocks = append(bc.Blocks, newBlock)

	// Process transactions and update KYC records
	for _, tx := range bc.PendingTxs {
		bc.processTransaction(tx)
	}

	bc.PendingTxs = []*Transaction{}
	return newBlock
}

func (bc *Blockchain) processTransaction(tx *Transaction) {
	switch tx.Type {
	case TxCreate:
		if tx.KYCData != nil {
			bc.KYCRecords[tx.CustomerID] = tx.KYCData
		}
	case TxUpdate:
		if tx.KYCData != nil {
			bc.KYCRecords[tx.CustomerID] = tx.KYCData
		}
	case TxVerify:
		if kyc, exists := bc.KYCRecords[tx.CustomerID]; exists {
			kyc.Verify(tx.BankID)
		}
	case TxReject:
		if kyc, exists := bc.KYCRecords[tx.CustomerID]; exists {
			kyc.Reject()
		}
	case TxSuspend:
		if kyc, exists := bc.KYCRecords[tx.CustomerID]; exists {
			kyc.Suspend()
		}
	case TxDelete:
		delete(bc.KYCRecords, tx.CustomerID)
	}
}

// CreateKYC creates a new KYC record - ONLY saves to memory/database, NOT to pending transactions
func (bc *Blockchain) CreateKYC(kycData *KYCData, bankID, userID string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// bc.mutex.RLock()
	_, exists := bc.KYCRecords[kycData.CustomerID]
	// bc.mutex.RUnlock()

	if exists {
		return errors.New("KYC record already exists for this customer")
	}

	// Encrypt sensitive data
	if bc.encryptor != nil {
		if err := kycData.EncryptSensitiveData(bc.encryptor, "primary"); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Only save to KYCRecords (memory/database), NOT to pending transactions
	// Transaction will be created only when KYC is VERIFIED
	bc.KYCRecords[kycData.CustomerID] = kycData
	return nil

	// tx := CreateKYCTransaction(kycData, bankID, userID)
	// return bc.AddTransaction(tx)
}

// ReadKYC retrieves a KYC record by customer ID
func (bc *Blockchain) ReadKYC(customerID string, decrypt bool) (*KYCData, error) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	kyc, exists := bc.KYCRecords[customerID]
	if !exists {
		return nil, errors.New("KYC record not found")
	}

	// Create a copy to avoid modifying the stored data
	kycCopy := *kyc

	// Decrypt if requested and encryptor is available
	if decrypt && bc.encryptor != nil && kycCopy.EncryptedData != nil {
		if err := kycCopy.DecryptSensitiveData(bc.encryptor); err != nil {
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	}

	return &kycCopy, nil
}

// UpdateKYC updates an existing KYC record - Updates KYC in memory/database only (no transaction)
func (bc *Blockchain) UpdateKYC(kycData *KYCData, bankID, userID, description string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// bc.mutex.RLock()
	// _, exists := bc.KYCRecords[kycData.CustomerID]
	// bc.mutex.RUnlock()

	existing, exists := bc.KYCRecords[kycData.CustomerID]
	if !exists {
		return errors.New("KYC record not found")
	}

	// Cannot update if already verified (already on blockchain)
	if existing.Status == StatusVerified {
		return errors.New("cannot update verified KYC - already on blockchain")
	}

	// Encrypt sensitive data
	if bc.encryptor != nil {
		if err := kycData.EncryptSensitiveData(bc.encryptor, "primary"); err != nil {
			return fmt.Errorf("encryption failed: %w", err)
		}
	}

	// Update in memory only
	bc.KYCRecords[kycData.CustomerID] = kycData
	return nil

	// tx := UpdateKYCTransaction(kycData, bankID, userID, description)
	// return bc.AddTransaction(tx)
}

// DeleteKYC marks a KYC record for deletion - Only allowed for non-verified KYC
func (bc *Blockchain) DeleteKYC(customerID, bankID, userID, reason string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// bc.mutex.RLock()
	// _, exists := bc.KYCRecords[customerID]
	// bc.mutex.RUnlock()

	kyc, exists := bc.KYCRecords[customerID]
	if !exists {
		return errors.New("KYC record not found")
	}

	// Cannot delete if already verified (on blockchain)
	if kyc.Status == StatusVerified {
		return errors.New("cannot delete verified KYC - already on blockchain")
	}

	// Delete from memory only
	delete(bc.KYCRecords, customerID)
	return nil

	// tx := DeleteKYCTransaction(customerID, bankID, userID, reason)
	// return bc.AddTransaction(tx)
}

// VerifyKYC verifies a customer's KYC - ONLY this creates a transaction for blockchain
func (bc *Blockchain) VerifyKYC(customerID, bankID, userID string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// bc.mutex.RLock()
	// _, exists := bc.KYCRecords[customerID]
	// bc.mutex.RUnlock()

	kyc, exists := bc.KYCRecords[customerID]
	if !exists {
		return errors.New("KYC record not found")
	}

	// Check current status
	if kyc.Status == StatusVerified {
		return errors.New("KYC already verified")
	}

	if kyc.Status == StatusRejected {
		return errors.New("cannot verify rejected KYC")
	}

	if kyc.Status == StatusExpired {
		return errors.New("cannot verify expired KYC")
	}

	// Update status to VERIFIED
	kyc.Verify(bankID)

	// NOW create transaction for blockchain (only for VERIFIED status)
	tx := CreateKYCTransaction(kyc, bankID, userID)

	// Validate bank authorization
	bank, bankExists := bc.Banks[bankID]
	if !bankExists || !bank.IsActive {
		return errors.New("unauthorized or inactive bank")
	}

	// Add to pending transactions (will go to blockchain when mined)
	bc.PendingTxs = append(bc.PendingTxs, tx)

	return nil

	// tx := VerifyKYCTransaction(customerID, bankID, userID)
	// return bc.AddTransaction(tx)
}

// RejectKYC rejects a customer's KYC - Only updates status, NO blockchain transaction
func (bc *Blockchain) RejectKYC(customerID, bankID, userID, reason string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// bc.mutex.RLock()
	// _, exists := bc.KYCRecords[customerID]
	// bc.mutex.RUnlock()

	kyc, exists := bc.KYCRecords[customerID]
	if !exists {
		return errors.New("KYC record not found")
	}

	if kyc.Status == StatusVerified {
		return errors.New("cannot reject verified KYC - already on blockchain")
	}

	// Update status only - NO transaction created
	kyc.Status = StatusRejected
	kyc.UpdatedAt = time.Now().Unix()

	return nil

	// tx := RejectKYCTransaction(customerID, bankID, userID, reason)
	// return bc.AddTransaction(tx)
}

// SuspendKYC suspends a customer's KYC - Only updates status, NO blockchain transaction
func (bc *Blockchain) SuspendKYC(customerID, bankID, userID, reason string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	// bc.mutex.RLock()
	// _, exists := bc.KYCRecords[customerID]
	// bc.mutex.RUnlock()

	kyc, exists := bc.KYCRecords[customerID]
	if !exists {
		return errors.New("KYC record not found")
	}

	if kyc.Status == StatusVerified {
		return errors.New("cannot suspend verified KYC - already on blockchain")
	}

	// Update status only - NO transaction created
	kyc.Status = StatusSuspended
	kyc.UpdatedAt = time.Now().Unix()

	return nil

	// tx := SuspendKYCTransaction(customerID, bankID, userID, reason)
	// return bc.AddTransaction(tx)
}

// ExpireKYC - Only updates status, NO blockchain transaction
func (bc *Blockchain) ExpireKYC(customerID string) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	kyc, exists := bc.KYCRecords[customerID]
	if !exists {
		return errors.New("KYC record not found")
	}

	if kyc.Status == StatusVerified {
		return errors.New("cannot expire verified KYC - already on blockchain")
	}

	// Update status only - NO transaction created
	kyc.Status = StatusExpired
	kyc.UpdatedAt = time.Now().Unix()

	return nil
}

// GetAllKYCRecords returns all KYC records
func (bc *Blockchain) GetAllKYCRecords() map[string]*KYCData {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	records := make(map[string]*KYCData)
	for k, v := range bc.KYCRecords {
		records[k] = v
	}
	return records
}

// GetKYCByStatus returns KYC records filtered by status
func (bc *Blockchain) GetKYCByStatus(status KYCStatus) []*KYCData {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	var records []*KYCData
	for _, kyc := range bc.KYCRecords {
		if kyc.Status == status {
			records = append(records, kyc)
		}
	}
	return records
}

// GetKYCByBank returns KYC records for a specific bank
func (bc *Blockchain) GetKYCByBank(bankID string) []*KYCData {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	var records []*KYCData
	for _, kyc := range bc.KYCRecords {
		if kyc.BankID == bankID {
			records = append(records, kyc)
		}
	}
	return records
}

// IsChainValid validates the blockchain integrity
func (bc *Blockchain) IsChainValid() bool {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	for i := 1; i < len(bc.Blocks); i++ {
		currentBlock := bc.Blocks[i]
		prevBlock := bc.Blocks[i-1]

		// Validate current block
		if !currentBlock.Validate() {
			return false
		}

		// Check chain linkage
		if currentBlock.PrevHash != prevBlock.Hash {
			return false
		}
	}
	return true
}

// GetCustomerHistory returns all transactions for a customer
func (bc *Blockchain) GetCustomerHistory(customerID string) []*Transaction {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	var history []*Transaction
	for _, block := range bc.Blocks {
		for _, tx := range block.Transactions {
			if tx.CustomerID == customerID {
				history = append(history, tx)
			}
		}
	}
	return history
}

// GetBlockByIndex returns a block by its index
func (bc *Blockchain) GetBlockByIndex(index int64) (*Block, error) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	if index < 0 || index >= int64(len(bc.Blocks)) {
		return nil, errors.New("block not found")
	}
	return bc.Blocks[index], nil
}

// GetBlockByHash returns a block by its hash
func (bc *Blockchain) GetBlockByHash(hash string) (*Block, error) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	for _, block := range bc.Blocks {
		if block.Hash == hash {
			return block, nil
		}
	}
	return nil, errors.New("block not found")
}

// GetLatestBlock returns the latest block
func (bc *Blockchain) GetLatestBlock() *Block {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	return bc.Blocks[len(bc.Blocks)-1]
}

// GetPendingTransactions returns pending transactions
func (bc *Blockchain) GetPendingTransactions() []*Transaction {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	txs := make([]*Transaction, len(bc.PendingTxs))
	copy(txs, bc.PendingTxs)
	return txs
}

// GetChainLength returns the number of blocks
func (bc *Blockchain) GetChainLength() int {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()
	return len(bc.Blocks)
}

// ToJSON exports blockchain to JSON
func (bc *Blockchain) ToJSON() (string, error) {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	data, err := json.MarshalIndent(bc.Blocks, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetStats returns blockchain statistics
func (bc *Blockchain) GetStats() map[string]interface{} {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	totalTxs := 0
	for _, block := range bc.Blocks {
		totalTxs += len(block.Transactions)
	}

	return map[string]interface{}{
		"total_blocks":       len(bc.Blocks),
		"total_transactions": totalTxs,
		"pending_txs":        len(bc.PendingTxs),
		"total_kyc_records":  len(bc.KYCRecords),
		"registered_banks":   len(bc.Banks),
		"difficulty":         bc.Difficulty,
		"latest_block_hash":  bc.Blocks[len(bc.Blocks)-1].Hash,
	}
}
