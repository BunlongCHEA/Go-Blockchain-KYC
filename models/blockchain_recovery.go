package models

import (
	"log"
	"sort"
)

// RecoverFromStorage restores blockchain state from database
func (bc *Blockchain) RecoverFromStorage(data *RecoveryData) error {
	bc.mutex.Lock()
	defer bc.mutex.Unlock()

	log.Println("   Starting blockchain recovery from storage...")

	// Recover banks first (needed for KYC records)
	if len(data.Banks) > 0 {
		for _, bank := range data.Banks {
			bc.Banks[bank.ID] = bank
		}
		log.Printf("   ✓ Recovered %d banks", len(data.Banks))
	}

	// Recover blocks
	if len(data.Blocks) > 0 {
		// Sort blocks by index to ensure correct order
		sort.Slice(data.Blocks, func(i, j int) bool {
			return data.Blocks[i].Index < data.Blocks[j].Index
		})

		// Replace chain with recovered blocks (use Blocks, not Chain)
		bc.Blocks = make([]*Block, 0, len(data.Blocks))
		for _, block := range data.Blocks {
			bc.Blocks = append(bc.Blocks, block)
		}
		log.Printf("   ✓ Recovered %d blocks", len(data.Blocks))
	}

	// Recover KYC records
	if len(data.KYCRecords) > 0 {
		for _, kyc := range data.KYCRecords {
			bc.KYCRecords[kyc.CustomerID] = kyc
		}
		log.Printf("   ✓ Recovered %d KYC records", len(data.KYCRecords))
	}

	// Recover pending transactions
	if len(data.Transactions) > 0 {
		for _, tx := range data.Transactions {
			bc.PendingTxs = append(bc.PendingTxs, tx)
		}
		log.Printf("   ✓ Recovered %d pending transactions", len(data.Transactions))
	}

	// Validate recovered chain
	if len(bc.Blocks) > 0 {
		if bc.isChainValidInternal() {
			log.Println("   ✓ Recovered blockchain is valid")
		} else {
			log.Println("   ⚠ Warning: Recovered blockchain validation failed")
		}
	}

	log.Println("   Blockchain recovery complete")
	return nil
}

// isChainValidInternal validates chain without locking (internal use)
func (bc *Blockchain) isChainValidInternal() bool {
	for i := 1; i < len(bc.Blocks); i++ {
		currentBlock := bc.Blocks[i]
		prevBlock := bc.Blocks[i-1]

		// Check if previous hash matches
		if currentBlock.PrevHash != prevBlock.Hash {
			return false
		}

		// Verify block hash
		if currentBlock.Hash != currentBlock.CalculateHash() {
			return false
		}
	}
	return true
}

// GetRecoveryStats returns stats about recovered/current blockchain state
func (bc *Blockchain) GetRecoveryStats() map[string]interface{} {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_blocks":      len(bc.Blocks),
		"total_banks":       len(bc.Banks),
		"total_kyc_records": len(bc.KYCRecords),
		"pending_txs":       len(bc.PendingTxs),
		"chain_valid":       bc.isChainValidInternal(),
	}

	// Add latest block info if exists
	if len(bc.Blocks) > 0 {
		latestBlock := bc.Blocks[len(bc.Blocks)-1]
		stats["latest_block_index"] = latestBlock.Index
		stats["latest_block_hash"] = latestBlock.Hash
		stats["latest_block_timestamp"] = latestBlock.Timestamp
	}

	return stats
}

// HasData checks if blockchain has any data (used to determine if recovery is needed)
func (bc *Blockchain) HasData() bool {
	bc.mutex.RLock()
	defer bc.mutex.RUnlock()

	// More than just genesis block means we have data
	return len(bc.Blocks) > 1 || len(bc.Banks) > 0 || len(bc.KYCRecords) > 0
}
