package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Block represents a block in the blockchain
type Block struct {
	Index        int64          `json:"index"`
	Timestamp    int64          `json:"timestamp"`
	Transactions []*Transaction `json:"transactions"`
	PrevHash     string         `json:"prev_hash"`
	Hash         string         `json:"hash"`
	Nonce        int            `json:"nonce"`
	MerkleRoot   string         `json:"merkle_root"`
	Difficulty   int            `json:"difficulty"`
	Miner        string         `json:"miner"`
}

// NewBlock creates a new block with the given transactions
func NewBlock(transactions []*Transaction, prevHash string, index int64, difficulty int, miner string) *Block {
	block := &Block{
		Index:        index,
		Timestamp:    time.Now().Unix(),
		Transactions: transactions,
		PrevHash:     prevHash,
		Nonce:        0,
		Difficulty:   difficulty,
		Miner:        miner,
	}
	block.MerkleRoot = block.CalculateMerkleRoot()
	block.Hash = block.CalculateHash()
	block.MineBlock()
	return block
}

// CalculateHash calculates the hash of the block
func (b *Block) CalculateHash() string {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)

	data := struct {
		Index      int64
		Timestamp  int64
		MerkleRoot string
		PrevHash   string
		Nonce      int
		Difficulty int
	}{
		Index:      b.Index,
		Timestamp:  b.Timestamp,
		MerkleRoot: b.MerkleRoot,
		PrevHash:   b.PrevHash,
		Nonce:      b.Nonce,
		Difficulty: b.Difficulty,
	}

	err := encoder.Encode(data)
	if err != nil {
		return ""
	}

	hash := sha256.Sum256(buffer.Bytes())
	return hex.EncodeToString(hash[:])
}

// CalculateMerkleRoot calculates the Merkle root of transactions
func (b *Block) CalculateMerkleRoot() string {
	if len(b.Transactions) == 0 {
		return ""
	}

	var hashes []string
	for _, tx := range b.Transactions {
		txData, _ := tx.ToJSON()
		hash := sha256.Sum256(txData)
		hashes = append(hashes, hex.EncodeToString(hash[:]))
	}

	for len(hashes) > 1 {
		var newHashes []string
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				combined := hashes[i] + hashes[i+1]
				hash := sha256.Sum256([]byte(combined))
				newHashes = append(newHashes, hex.EncodeToString(hash[:]))
			} else {
				newHashes = append(newHashes, hashes[i])
			}
		}
		hashes = newHashes
	}

	return hashes[0]
}

// MineBlock performs proof-of-work mining
func (b *Block) MineBlock() {
	target := strings.Repeat("0", b.Difficulty)

	for !strings.HasPrefix(b.Hash, target) {
		b.Nonce++
		b.Hash = b.CalculateHash()
	}
}

// Validate validates the block
func (b *Block) Validate() bool {
	// Check hash is valid
	if b.Hash != b.CalculateHash() {
		return false
	}

	// Check proof of work
	target := strings.Repeat("0", b.Difficulty)
	if !strings.HasPrefix(b.Hash, target) {
		return false
	}

	// Check merkle root
	if b.MerkleRoot != b.CalculateMerkleRoot() {
		return false
	}

	return true
}

// ToJSON converts block to JSON
func (b *Block) ToJSON() ([]byte, error) {
	return json.MarshalIndent(b, "", "  ")
}

// NewGenesisBlock creates the first block in the blockchain
func NewGenesisBlock(difficulty int) *Block {
	genesis := &Block{
		Index:        0,
		Timestamp:    time.Now().Unix(),
		Transactions: []*Transaction{},
		PrevHash:     "0",
		Nonce:        0,
		Difficulty:   difficulty,
		Miner:        "genesis",
	}
	genesis.MerkleRoot = ""
	genesis.Hash = genesis.CalculateHash()
	genesis.MineBlock()
	return genesis
}
