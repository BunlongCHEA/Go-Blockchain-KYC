package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"Go-Blockchain-KYC/models"

	_ "github.com/lib/pq"
)

// Global placeholder for encrypted strings
var encryptedStringPlaceholder = "[ENCRYPTED]"

// PostgresStorage implements Storage interface for PostgreSQL
type PostgresStorage struct {
	db *sql.DB
}

// ==================== Database Operations =================

// EnsureDatabase creates the database if it doesn't exist
func EnsureDatabase(host string, port int, user, password, dbname, sslmode string) error {
	// Connect to default 'postgres' database first
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s",
		host, port, user, password, sslmode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("failed to connect to postgres: %w", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping postgres: %w", err)
	}

	// Check if database exists
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)"
	err = db.QueryRow(query, dbname).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check database existence: %w", err)
	}

	// Create database if not exists
	if !exists {
		// Note: Database names cannot be parameterized, so we use fmt.Sprintf
		// Ensure dbname is validated before this point to prevent SQL injection
		_, err = db.Exec(fmt.Sprintf("CREATE DATABASE %s", dbname))
		if err != nil {
			return fmt.Errorf("failed to create database: %w", err)
		}
		log.Printf("Database '%s' created successfully", dbname)
	}

	return nil
}

// NewPostgresStorage creates a new PostgreSQL storage instance
func NewPostgresStorage(host string, port int, user, password, dbname, sslmode string) (*PostgresStorage, error) {
	connStr := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &PostgresStorage{db: db}, nil
}

// Migrate runs database migrations
func (p *PostgresStorage) Migrate() error {
	for _, migration := range Migrations {
		_, err := p.db.Exec(migration)
		if err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
	}
	return nil
}

// Close closes the database connection
func (p *PostgresStorage) Close() error {
	return p.db.Close()
}

// Ping checks database connectivity
func (p *PostgresStorage) Ping() error {
	return p.db.Ping()
}

// ==================== Block Operations ====================

// SaveBlock saves a block to the database
func (p *PostgresStorage) SaveBlock(block *models.Block) error {
	query := `
		INSERT INTO blocks (block_index, timestamp, prev_hash, hash, nonce, merkle_root, difficulty, miner)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (hash) DO NOTHING
	`

	_, err := p.db.Exec(query,
		block.Index,
		block.Timestamp,
		block.PrevHash,
		block.Hash,
		block.Nonce,
		block.MerkleRoot,
		block.Difficulty,
		block.Miner,
	)

	if err != nil {
		return fmt.Errorf("failed to save block: %w", err)
	}

	// Save transactions
	for _, tx := range block.Transactions {
		if err := p.saveTransactionWithBlock(tx, block.Hash); err != nil {
			return err
		}
	}

	return nil
}

// GetBlock retrieves a block by hash
func (p *PostgresStorage) GetBlock(hash string) (*models.Block, error) {
	query := `
		SELECT block_index, timestamp, prev_hash, hash, nonce, merkle_root, difficulty, miner
		FROM blocks WHERE hash = $1
	`

	block := &models.Block{}
	err := p.db.QueryRow(query, hash).Scan(
		&block.Index,
		&block.Timestamp,
		&block.PrevHash,
		&block.Hash,
		&block.Nonce,
		&block.MerkleRoot,
		&block.Difficulty,
		&block.Miner,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("block not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	// Get transactions for this block
	txs, err := p.getTransactionsByBlock(hash)
	if err != nil {
		return nil, err
	}
	block.Transactions = txs

	return block, nil
}

// GetBlockByIndex retrieves a block by index
func (p *PostgresStorage) GetBlockByIndex(index int64) (*models.Block, error) {
	query := `
		SELECT block_index, timestamp, prev_hash, hash, nonce, merkle_root, difficulty, miner
		FROM blocks WHERE block_index = $1
	`

	block := &models.Block{}
	err := p.db.QueryRow(query, index).Scan(
		&block.Index,
		&block.Timestamp,
		&block.PrevHash,
		&block.Hash,
		&block.Nonce,
		&block.MerkleRoot,
		&block.Difficulty,
		&block.Miner,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("block not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	// Get transactions
	txs, err := p.getTransactionsByBlock(block.Hash)
	if err != nil {
		return nil, err
	}
	block.Transactions = txs

	return block, nil
}

// GetLatestBlock retrieves the latest block
func (p *PostgresStorage) GetLatestBlock() (*models.Block, error) {
	query := `
		SELECT block_index, timestamp, prev_hash, hash, nonce, merkle_root, difficulty, miner
		FROM blocks ORDER BY block_index DESC LIMIT 1
	`

	block := &models.Block{}
	err := p.db.QueryRow(query).Scan(
		&block.Index,
		&block.Timestamp,
		&block.PrevHash,
		&block.Hash,
		&block.Nonce,
		&block.MerkleRoot,
		&block.Difficulty,
		&block.Miner,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no blocks found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block: %w", err)
	}

	txs, err := p.getTransactionsByBlock(block.Hash)
	if err != nil {
		return nil, err
	}
	block.Transactions = txs

	return block, nil
}

// GetAllBlocks retrieves all blocks
func (p *PostgresStorage) GetAllBlocks() ([]*models.Block, error) {
	query := `
		SELECT block_index, timestamp, prev_hash, hash, nonce, merkle_root, difficulty, miner
		FROM blocks ORDER BY block_index ASC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get blocks: %w", err)
	}
	defer rows.Close()

	var blocks []*models.Block
	for rows.Next() {
		block := &models.Block{}
		err := rows.Scan(
			&block.Index,
			&block.Timestamp,
			&block.PrevHash,
			&block.Hash,
			&block.Nonce,
			&block.MerkleRoot,
			&block.Difficulty,
			&block.Miner,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan block: %w", err)
		}

		txs, err := p.getTransactionsByBlock(block.Hash)
		if err != nil {
			return nil, err
		}
		block.Transactions = txs

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// ==================== Transaction Operations ====================

// SaveTransaction saves a pending transaction
func (p *PostgresStorage) SaveTransaction(tx *models.Transaction) error {
	return p.saveTransactionWithBlock(tx, "")
}

func (p *PostgresStorage) saveTransactionWithBlock(tx *models.Transaction, blockHash string) error {
	metadata, _ := json.Marshal(tx.Metadata)

	query := `
		INSERT INTO transactions (id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata, block_hash, is_pending)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, ''), $11)
		ON CONFLICT (id) DO UPDATE SET block_hash = EXCLUDED.block_hash, is_pending = EXCLUDED.is_pending
	`

	isPending := blockHash == ""
	_, err := p.db.Exec(query,
		tx.ID,
		tx.Type,
		tx.CustomerID,
		tx.BankID,
		tx.UserID,
		tx.Timestamp,
		tx.Signature,
		tx.Description,
		metadata,
		blockHash,
		isPending,
	)

	if err != nil {
		return fmt.Errorf("failed to save transaction: %w", err)
	}

	return nil
}

// GetTransaction retrieves a transaction by ID
func (p *PostgresStorage) GetTransaction(id string) (*models.Transaction, error) {
	query := `
		SELECT id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata
		FROM transactions WHERE id = $1
	`

	tx := &models.Transaction{}
	var metadata []byte

	err := p.db.QueryRow(query, id).Scan(
		&tx.ID,
		&tx.Type,
		&tx.CustomerID,
		&tx.BankID,
		&tx.UserID,
		&tx.Timestamp,
		&tx.Signature,
		&tx.Description,
		&metadata,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("transaction not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	if metadata != nil {
		json.Unmarshal(metadata, &tx.Metadata)
	}

	return tx, nil
}

// GetTransactionsByCustomer retrieves transactions for a customer
func (p *PostgresStorage) GetTransactionsByCustomer(customerID string) ([]*models.Transaction, error) {
	query := `
		SELECT id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata
		FROM transactions WHERE customer_id = $1 ORDER BY timestamp DESC
	`

	rows, err := p.db.Query(query, customerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions: %w", err)
	}
	defer rows.Close()

	return p.scanTransactions(rows)
}

// getTransactionsByBlock retrieves transactions for a block
func (p *PostgresStorage) getTransactionsByBlock(blockHash string) ([]*models.Transaction, error) {
	query := `
		SELECT id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata
		FROM transactions WHERE block_hash = $1 ORDER BY timestamp ASC
	`

	rows, err := p.db.Query(query, blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get transactions: %w", err)
	}
	defer rows.Close()

	return p.scanTransactions(rows)
}

// GetPendingTransactions retrieves all pending transactions
func (p *PostgresStorage) GetPendingTransactions() ([]*models.Transaction, error) {
	query := `
		SELECT id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata
		FROM transactions WHERE is_pending = TRUE ORDER BY timestamp ASC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending transactions: %w", err)
	}
	defer rows.Close()

	return p.scanTransactions(rows)
}

// DeletePendingTransaction deletes a pending transaction
func (p *PostgresStorage) DeletePendingTransaction(id string) error {
	query := `DELETE FROM transactions WHERE id = $1 AND is_pending = TRUE`
	_, err := p.db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete transaction: %w", err)
	}
	return nil
}

func (p *PostgresStorage) scanTransactions(rows *sql.Rows) ([]*models.Transaction, error) {
	var transactions []*models.Transaction

	for rows.Next() {
		tx := &models.Transaction{}
		var metadata []byte

		err := rows.Scan(
			&tx.ID,
			&tx.Type,
			&tx.CustomerID,
			&tx.BankID,
			&tx.UserID,
			&tx.Timestamp,
			&tx.Signature,
			&tx.Description,
			&metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}

		if metadata != nil {
			json.Unmarshal(metadata, &tx.Metadata)
		}

		transactions = append(transactions, tx)
	}

	return transactions, nil
}

// ==================== KYC Operations ====================

// SaveKYC saves a KYC record
func (p *PostgresStorage) SaveKYC(kyc *models.KYCData) error {
	query := `
		INSERT INTO kyc_records (
			customer_id, first_name, last_name, date_of_birth, nationality,
			id_type, id_number_encrypted, id_expiry_date,
			address_street, address_city, address_state, address_postal_code, address_country,
			email_encrypted, phone_encrypted, status, verified_by, verification_date,
			document_hash, risk_level, bank_id, encryption_key_id, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
		ON CONFLICT (customer_id) DO UPDATE SET
			first_name = EXCLUDED.first_name,
			last_name = EXCLUDED.last_name,
			date_of_birth = EXCLUDED.date_of_birth,
			nationality = EXCLUDED.nationality,
			id_type = EXCLUDED.id_type,
			id_number_encrypted = EXCLUDED.id_number_encrypted,
			id_expiry_date = EXCLUDED.id_expiry_date,
			address_street = EXCLUDED.address_street,
			address_city = EXCLUDED.address_city,
			address_state = EXCLUDED.address_state,
			address_postal_code = EXCLUDED.address_postal_code,
			address_country = EXCLUDED.address_country,
			email_encrypted = EXCLUDED.email_encrypted,
			phone_encrypted = EXCLUDED.phone_encrypted,
			status = EXCLUDED.status,
			verified_by = EXCLUDED.verified_by,
			verification_date = EXCLUDED.verification_date,
			document_hash = EXCLUDED.document_hash,
			risk_level = EXCLUDED.risk_level,
			updated_at = EXCLUDED.updated_at
	`

	var idNumber, email, phone, keyID string
	if kyc.EncryptedData != nil {
		idNumber = kyc.EncryptedData.IDNumber
		email = kyc.EncryptedData.Email
		phone = kyc.EncryptedData.Phone
		keyID = kyc.EncryptedData.KeyID
	} else {
		idNumber = kyc.IDNumber
		email = kyc.Email
		phone = kyc.Phone
	}

	_, err := p.db.Exec(query,
		kyc.CustomerID,
		kyc.FirstName,
		kyc.LastName,
		kyc.DateOfBirth,
		kyc.Nationality,
		kyc.IDType,
		idNumber,
		kyc.IDExpiryDate,
		kyc.Address.Street,
		kyc.Address.City,
		kyc.Address.State,
		kyc.Address.PostalCode,
		kyc.Address.Country,
		email,
		phone,
		kyc.Status,
		kyc.VerifiedBy,
		kyc.VerificationDate,
		kyc.DocumentHash,
		kyc.RiskLevel,
		kyc.BankID,
		keyID,
		kyc.CreatedAt,
		kyc.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save KYC:  %w", err)
	}

	return nil
}

// GetKYC retrieves a KYC record by customer ID
func (p *PostgresStorage) GetKYC(customerID string) (*models.KYCData, error) {
	query := `
		SELECT customer_id, first_name, last_name, date_of_birth, nationality,
			id_type, id_number_encrypted, id_expiry_date,
			address_street, address_city, address_state, address_postal_code, address_country,
			email_encrypted, phone_encrypted, status, verified_by, verification_date,
			document_hash, risk_level, bank_id, encryption_key_id, created_at, updated_at
		FROM kyc_records WHERE customer_id = $1
	`

	kyc := &models.KYCData{}
	var idNumber, email, phone string
	var keyID sql.NullString
	var verifiedBy sql.NullString
	var verificationDate sql.NullInt64

	err := p.db.QueryRow(query, customerID).Scan(
		&kyc.CustomerID,
		&kyc.FirstName,
		&kyc.LastName,
		&kyc.DateOfBirth,
		&kyc.Nationality,
		&kyc.IDType,
		&idNumber,
		&kyc.IDExpiryDate,
		&kyc.Address.Street,
		&kyc.Address.City,
		&kyc.Address.State,
		&kyc.Address.PostalCode,
		&kyc.Address.Country,
		&email,
		&phone,
		&kyc.Status,
		&verifiedBy,
		&verificationDate,
		&kyc.DocumentHash,
		&kyc.RiskLevel,
		&kyc.BankID,
		&keyID,
		&kyc.CreatedAt,
		&kyc.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("KYC record not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC: %w", err)
	}

	if verifiedBy.Valid {
		kyc.VerifiedBy = verifiedBy.String
	}
	if verificationDate.Valid {
		kyc.VerificationDate = verificationDate.Int64
	}

	// Set encrypted data
	if keyID.Valid && keyID.String != "" {
		kyc.EncryptedData = &models.EncryptedKYCData{
			IDNumber: idNumber,
			Email:    email,
			Phone:    phone,
			KeyID:    keyID.String,
		}
		kyc.IDNumber = encryptedStringPlaceholder
		kyc.Email = encryptedStringPlaceholder
		kyc.Phone = encryptedStringPlaceholder
	} else {
		kyc.IDNumber = idNumber
		kyc.Email = email
		kyc.Phone = phone
	}

	return kyc, nil
}

// GetAllKYC retrieves all KYC records
func (p *PostgresStorage) GetAllKYC() ([]*models.KYCData, error) {
	query := `
		SELECT customer_id, first_name, last_name, date_of_birth, nationality,
			id_type, id_number_encrypted, id_expiry_date,
			address_street, address_city, address_state, address_postal_code, address_country,
			email_encrypted, phone_encrypted, status, verified_by, verification_date,
			document_hash, risk_level, bank_id, encryption_key_id, created_at, updated_at
		FROM kyc_records ORDER BY created_at DESC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC records: %w", err)
	}
	defer rows.Close()

	return p.scanKYCRecords(rows)
}

// GetKYCByStatus retrieves KYC records by status
func (p *PostgresStorage) GetKYCByStatus(status models.KYCStatus) ([]*models.KYCData, error) {
	query := `
		SELECT customer_id, first_name, last_name, date_of_birth, nationality,
			id_type, id_number_encrypted, id_expiry_date,
			address_street, address_city, address_state, address_postal_code, address_country,
			email_encrypted, phone_encrypted, status, verified_by, verification_date,
			document_hash, risk_level, bank_id, encryption_key_id, created_at, updated_at
		FROM kyc_records WHERE status = $1 ORDER BY created_at DESC
	`

	rows, err := p.db.Query(query, status)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC records:  %w", err)
	}
	defer rows.Close()

	return p.scanKYCRecords(rows)
}

// GetKYCByBank retrieves KYC records for a bank
func (p *PostgresStorage) GetKYCByBank(bankID string) ([]*models.KYCData, error) {
	query := `
		SELECT customer_id, first_name, last_name, date_of_birth, nationality,
			id_type, id_number_encrypted, id_expiry_date,
			address_street, address_city, address_state, address_postal_code, address_country,
			email_encrypted, phone_encrypted, status, verified_by, verification_date,
			document_hash, risk_level, bank_id, encryption_key_id, created_at, updated_at
		FROM kyc_records WHERE bank_id = $1 ORDER BY created_at DESC
	`

	rows, err := p.db.Query(query, bankID)
	if err != nil {
		return nil, fmt.Errorf("failed to get KYC records: %w", err)
	}
	defer rows.Close()

	return p.scanKYCRecords(rows)
}

// DeleteKYC deletes a KYC record
func (p *PostgresStorage) DeleteKYC(customerID string) error {
	query := `DELETE FROM kyc_records WHERE customer_id = $1`
	_, err := p.db.Exec(query, customerID)
	if err != nil {
		return fmt.Errorf("failed to delete KYC:  %w", err)
	}
	return nil
}

func (p *PostgresStorage) scanKYCRecords(rows *sql.Rows) ([]*models.KYCData, error) {
	var records []*models.KYCData

	for rows.Next() {
		kyc := &models.KYCData{}
		var idNumber, email, phone string
		var keyID sql.NullString
		var verifiedBy sql.NullString
		var verificationDate sql.NullInt64

		err := rows.Scan(
			&kyc.CustomerID,
			&kyc.FirstName,
			&kyc.LastName,
			&kyc.DateOfBirth,
			&kyc.Nationality,
			&kyc.IDType,
			&idNumber,
			&kyc.IDExpiryDate,
			&kyc.Address.Street,
			&kyc.Address.City,
			&kyc.Address.State,
			&kyc.Address.PostalCode,
			&kyc.Address.Country,
			&email,
			&phone,
			&kyc.Status,
			&verifiedBy,
			&verificationDate,
			&kyc.DocumentHash,
			&kyc.RiskLevel,
			&kyc.BankID,
			&keyID,
			&kyc.CreatedAt,
			&kyc.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan KYC:  %w", err)
		}

		if verifiedBy.Valid {
			kyc.VerifiedBy = verifiedBy.String
		}
		if verificationDate.Valid {
			kyc.VerificationDate = verificationDate.Int64
		}

		if keyID.Valid && keyID.String != "" {
			kyc.EncryptedData = &models.EncryptedKYCData{
				IDNumber: idNumber,
				Email:    email,
				Phone:    phone,
				KeyID:    keyID.String,
			}
			kyc.IDNumber = encryptedStringPlaceholder
			kyc.Email = encryptedStringPlaceholder
			kyc.Phone = encryptedStringPlaceholder
		} else {
			kyc.IDNumber = idNumber
			kyc.Email = email
			kyc.Phone = phone
		}

		records = append(records, kyc)
	}

	return records, nil
}

// ==================== Bank Operations ====================

// SaveBank saves a bank record
func (p *PostgresStorage) SaveBank(bank *models.Bank) error {
	query := `
		INSERT INTO banks (id, name, code, country, license_no, public_key, is_active,
			address_street, address_city, address_state, address_postal_code, address_country,
			contact_email, contact_phone)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			code = EXCLUDED.code,
			country = EXCLUDED.country,
			license_no = EXCLUDED.license_no,
			public_key = EXCLUDED.public_key,
			is_active = EXCLUDED.is_active,
			address_street = EXCLUDED.address_street,
			address_city = EXCLUDED.address_city,
			address_state = EXCLUDED.address_state,
			address_postal_code = EXCLUDED.address_postal_code,
			address_country = EXCLUDED.address_country,
			contact_email = EXCLUDED.contact_email,
			contact_phone = EXCLUDED.contact_phone,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := p.db.Exec(query,
		bank.ID,
		bank.Name,
		bank.Code,
		bank.Country,
		bank.LicenseNo,
		bank.PublicKey,
		bank.IsActive,
		bank.Address.Street,
		bank.Address.City,
		bank.Address.State,
		bank.Address.PostalCode,
		bank.Address.Country,
		bank.ContactEmail,
		bank.ContactPhone,
	)

	if err != nil {
		return fmt.Errorf("failed to save bank: %w", err)
	}

	return nil
}

// GetBank retrieves a bank by ID
func (p *PostgresStorage) GetBank(bankID string) (*models.Bank, error) {
	query := `
		SELECT id, name, code, country, license_no, public_key, is_active,
			address_street, address_city, address_state, address_postal_code, address_country,
			contact_email, contact_phone, created_at, updated_at
		FROM banks WHERE id = $1
	`

	bank := &models.Bank{}
	err := p.db.QueryRow(query, bankID).Scan(
		&bank.ID,
		&bank.Name,
		&bank.Code,
		&bank.Country,
		&bank.LicenseNo,
		&bank.PublicKey,
		&bank.IsActive,
		&bank.Address.Street,
		&bank.Address.City,
		&bank.Address.State,
		&bank.Address.PostalCode,
		&bank.Address.Country,
		&bank.ContactEmail,
		&bank.ContactPhone,
		&bank.CreatedAt,
		&bank.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("bank not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get bank:  %w", err)
	}

	return bank, nil
}

// GetAllBanks retrieves all banks
func (p *PostgresStorage) GetAllBanks() ([]*models.Bank, error) {
	query := `
		SELECT id, name, code, country, license_no, public_key, is_active,
			address_street, address_city, address_state, address_postal_code, address_country,
			contact_email, contact_phone, created_at, updated_at
		FROM banks ORDER BY name ASC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get banks: %w", err)
	}
	defer rows.Close()

	var banks []*models.Bank
	for rows.Next() {
		bank := &models.Bank{}
		err := rows.Scan(
			&bank.ID,
			&bank.Name,
			&bank.Code,
			&bank.Country,
			&bank.LicenseNo,
			&bank.PublicKey,
			&bank.IsActive,
			&bank.Address.Street,
			&bank.Address.City,
			&bank.Address.State,
			&bank.Address.PostalCode,
			&bank.Address.Country,
			&bank.ContactEmail,
			&bank.ContactPhone,
			&bank.CreatedAt,
			&bank.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bank: %w", err)
		}
		banks = append(banks, bank)
	}

	return banks, nil
}

// DeleteBank deletes a bank
func (p *PostgresStorage) DeleteBank(bankID string) error {
	query := `DELETE FROM banks WHERE id = $1`
	_, err := p.db.Exec(query, bankID)
	if err != nil {
		return fmt.Errorf("failed to delete bank: %w", err)
	}
	return nil
}

// ==================== Audit Log Operations ====================

// SaveAuditLog saves an audit log entry
func (p *PostgresStorage) SaveAuditLog(auditLog *models.AuditLog) error {
	details, _ := json.Marshal(auditLog.Details)

	query := `
		INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := p.db.Exec(query,
		auditLog.UserID,
		auditLog.Action,
		auditLog.ResourceType,
		auditLog.ResourceID,
		details,
		auditLog.IPAddress,
		auditLog.UserAgent,
		auditLog.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to save audit log:  %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit logs with filters
func (p *PostgresStorage) GetAuditLogs(userID, action string, startTime, endTime time.Time, limit int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at
		FROM audit_log
		WHERE ($1 = '' OR user_id = $1)
		AND ($2 = '' OR action = $2)
		AND created_at >= $3
		AND created_at <= $4
		ORDER BY created_at DESC
		LIMIT $5
	`

	rows, err := p.db.Query(query, userID, action, startTime, endTime, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*models.AuditLog
	for rows.Next() {
		auditLog := &models.AuditLog{}
		var details []byte

		err := rows.Scan(
			&auditLog.ID,
			&auditLog.UserID,
			&auditLog.Action,
			&auditLog.ResourceType,
			&auditLog.ResourceID,
			&details,
			&auditLog.IPAddress,
			&auditLog.UserAgent,
			&auditLog.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if details != nil {
			json.Unmarshal(details, &auditLog.Details)
		}

		logs = append(logs, auditLog)
	}

	return logs, nil
}

// GetAuditLogsByUser retrieves audit logs for a specific user
func (p *PostgresStorage) GetAuditLogsByUser(userID string, limit int) ([]*models.AuditLog, error) {
	return p.GetAuditLogs(userID, "", time.Now().AddDate(0, 0, -30), time.Now(), limit)
}

// BlockUser blocks a user account
func (p *PostgresStorage) BlockUser(userID, reason string) error {
	query := `UPDATE users SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := p.db.Exec(query, userID)

	if err == nil {
		// Log the block action
		p.SaveAuditLog(&models.AuditLog{
			UserID:       "SYSTEM",
			Action:       "USER_BLOCKED",
			ResourceType: "USER",
			ResourceID:   userID,
			Details:      map[string]interface{}{"reason": reason},
			CreatedAt:    time.Now(),
		})
	}

	return err
}

// UnblockUser unblocks a user account
func (p *PostgresStorage) UnblockUser(userID string) error {
	query := `UPDATE users SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP WHERE id = $1`
	_, err := p.db.Exec(query, userID)

	if err == nil {
		p.SaveAuditLog(&models.AuditLog{
			UserID:       "SYSTEM",
			Action:       "USER_UNBLOCKED",
			ResourceType: "USER",
			ResourceID:   userID,
			Details:      map[string]interface{}{},
			CreatedAt:    time.Now(),
		})
	}

	return err
}

// ==================== Recovery Operations ====================

// LoadRecoveryData loads all data needed for blockchain recovery
func (p *PostgresStorage) LoadRecoveryData() (*models.RecoveryData, error) {
	data := &models.RecoveryData{}
	var err error

	// Load blocks
	data.Blocks, err = p.LoadAllBlocks()
	if err != nil {
		return nil, fmt.Errorf("failed to load blocks: %w", err)
	}

	// Load pending transactions
	data.Transactions, err = p.LoadPendingTransactions()
	if err != nil {
		return nil, fmt.Errorf("failed to load pending transactions: %w", err)
	}

	// Load KYC records
	data.KYCRecords, err = p.LoadAllKYCRecords()
	if err != nil {
		return nil, fmt.Errorf("failed to load KYC records: %w", err)
	}

	// Load banks
	data.Banks, err = p.LoadAllBanks()
	if err != nil {
		return nil, fmt.Errorf("failed to load banks: %w", err)
	}

	return data, nil
}

// LoadAllBlocks loads all blocks from database
func (p *PostgresStorage) LoadAllBlocks() ([]*models.Block, error) {
	query := `
		SELECT block_index, timestamp, prev_hash, hash, nonce, merkle_root, difficulty, miner
		FROM blocks
		ORDER BY block_index ASC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocks: %w", err)
	}
	defer rows.Close()

	blocks := make([]*models.Block, 0)
	for rows.Next() {
		block := &models.Block{}
		var merkleRoot sql.NullString
		var miner sql.NullString

		err := rows.Scan(
			&block.Index,
			&block.Timestamp,
			&block.PrevHash,
			&block.Hash,
			&block.Nonce,
			&merkleRoot,
			&block.Difficulty,
			&miner,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan block: %w", err)
		}

		if merkleRoot.Valid {
			block.MerkleRoot = merkleRoot.String
		}
		if miner.Valid {
			block.Miner = miner.String
		}

		// Load transactions for this block
		txs, err := p.LoadTransactionsByBlockHash(block.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to load transactions for block %s: %w", block.Hash, err)
		}
		block.Transactions = txs

		blocks = append(blocks, block)
	}

	return blocks, nil
}

// LoadTransactionsByBlockHash loads transactions for a specific block
func (p *PostgresStorage) LoadTransactionsByBlockHash(blockHash string) ([]*models.Transaction, error) {
	query := `
		SELECT id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata, is_pending
		FROM transactions
		WHERE block_hash = $1
		ORDER BY timestamp ASC
	`

	rows, err := p.db.Query(query, blockHash)
	if err != nil {
		return nil, fmt.Errorf("failed to query transactions: %w", err)
	}
	defer rows.Close()

	return p.scanTransactionsWithPending(rows)
}

// LoadPendingTransactions loads all pending transactions
func (p *PostgresStorage) LoadPendingTransactions() ([]*models.Transaction, error) {
	query := `
		SELECT id, type, customer_id, bank_id, user_id, timestamp, signature, description, metadata, is_pending
		FROM transactions
		WHERE is_pending = TRUE
		ORDER BY timestamp ASC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending transactions: %w", err)
	}
	defer rows.Close()

	return p.scanTransactionsWithPending(rows)
}

// scanTransactionsWithPending scans transaction rows including is_pending field
func (p *PostgresStorage) scanTransactionsWithPending(rows *sql.Rows) ([]*models.Transaction, error) {
	txs := make([]*models.Transaction, 0)

	for rows.Next() {
		tx := &models.Transaction{}
		var signature, description sql.NullString
		var metadata []byte
		var isPending bool

		err := rows.Scan(
			&tx.ID,
			&tx.Type,
			&tx.CustomerID,
			&tx.BankID,
			&tx.UserID,
			&tx.Timestamp,
			&signature,
			&description,
			&metadata,
			&isPending,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan transaction: %w", err)
		}

		if signature.Valid {
			tx.Signature = signature.String
		}
		if description.Valid {
			tx.Description = description.String
		}
		if metadata != nil {
			json.Unmarshal(metadata, &tx.Metadata)
		}

		txs = append(txs, tx)
	}

	return txs, nil
}

// LoadAllKYCRecords loads all KYC records from database
func (p *PostgresStorage) LoadAllKYCRecords() ([]*models.KYCData, error) {
	query := `
		SELECT customer_id, first_name, last_name, date_of_birth, nationality,
			   id_type, id_number_encrypted, id_expiry_date,
			   address_street, address_city, address_state, address_postal_code, address_country,
			   email_encrypted, phone_encrypted, status, verified_by, verification_date,
			   document_hash, risk_level, bank_id, encryption_key_id, created_at, updated_at
		FROM kyc_records
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query KYC records: %w", err)
	}
	defer rows.Close()

	records := make([]*models.KYCData, 0)
	for rows.Next() {
		kyc := &models.KYCData{
			Address: models.Address{},
		}
		var idNumber, email, phone string
		var keyID sql.NullString
		var verifiedBy sql.NullString
		var verificationDate sql.NullInt64

		err := rows.Scan(
			&kyc.CustomerID,
			&kyc.FirstName,
			&kyc.LastName,
			&kyc.DateOfBirth,
			&kyc.Nationality,
			&kyc.IDType,
			&idNumber,
			&kyc.IDExpiryDate,
			&kyc.Address.Street,
			&kyc.Address.City,
			&kyc.Address.State,
			&kyc.Address.PostalCode,
			&kyc.Address.Country,
			&email,
			&phone,
			&kyc.Status,
			&verifiedBy,
			&verificationDate,
			&kyc.DocumentHash,
			&kyc.RiskLevel,
			&kyc.BankID,
			&keyID,
			&kyc.CreatedAt,
			&kyc.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan KYC record: %w", err)
		}

		if verifiedBy.Valid {
			kyc.VerifiedBy = verifiedBy.String
		}
		if verificationDate.Valid {
			kyc.VerificationDate = verificationDate.Int64
		}

		// Handle encrypted data
		if keyID.Valid && keyID.String != "" {
			kyc.EncryptedData = &models.EncryptedKYCData{
				IDNumber: idNumber,
				Email:    email,
				Phone:    phone,
				KeyID:    keyID.String,
			}
			kyc.EncryptionKeyID = keyID.String
		} else {
			kyc.IDNumber = idNumber
			kyc.Email = email
			kyc.Phone = phone
		}

		records = append(records, kyc)
	}

	return records, nil
}

// LoadAllBanks loads all banks from database
func (p *PostgresStorage) LoadAllBanks() ([]*models.Bank, error) {
	query := `
		SELECT id, name, code, country, license_no, public_key, is_active,
			   address_street, address_city, address_state, address_postal_code, address_country,
			   contact_email, contact_phone, created_at, updated_at
		FROM banks
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query banks: %w", err)
	}
	defer rows.Close()

	banks := make([]*models.Bank, 0)
	for rows.Next() {
		bank := &models.Bank{
			Address: models.Address{},
		}
		var licenseNo, publicKey sql.NullString
		var contactEmail, contactPhone sql.NullString

		err := rows.Scan(
			&bank.ID,
			&bank.Name,
			&bank.Code,
			&bank.Country,
			&licenseNo,
			&publicKey,
			&bank.IsActive,
			&bank.Address.Street,
			&bank.Address.City,
			&bank.Address.State,
			&bank.Address.PostalCode,
			&bank.Address.Country,
			&contactEmail,
			&contactPhone,
			&bank.CreatedAt,
			&bank.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan bank:  %w", err)
		}

		if licenseNo.Valid {
			bank.LicenseNo = licenseNo.String
		}
		if publicKey.Valid {
			bank.PublicKey = publicKey.String
		}
		if contactEmail.Valid {
			bank.ContactEmail = contactEmail.String
		}
		if contactPhone.Valid {
			bank.ContactPhone = contactPhone.String
		}

		banks = append(banks, bank)
	}

	return banks, nil
}

// ==================== Renewal Alert Operations ====================

// SaveRenewalAlert saves a renewal alert
func (p *PostgresStorage) SaveRenewalAlert(alert *models.RenewalAlert) error {
	query := `
		INSERT INTO renewal_alerts (id, certificate_id, customer_id, requester_id, alert_type, 
			alert_date, cert_expires_at, status, webhook_url, email_recipient, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, sent_at = EXCLUDED.sent_at
	`

	_, err := p.db.Exec(query,
		alert.ID,
		alert.CertificateID,
		alert.CustomerID,
		alert.RequesterID,
		alert.AlertType,
		alert.AlertDate,
		alert.CertExpiresAt,
		alert.Status,
		alert.WebhookURL,
		alert.EmailRecipient,
		alert.CreatedAt,
	)

	return err
}

// GetPendingRenewalAlerts gets alerts that need to be sent
func (p *PostgresStorage) GetPendingRenewalAlerts() ([]*models.RenewalAlert, error) {
	now := time.Now().Unix()

	query := `
		SELECT id, certificate_id, customer_id, requester_id, alert_type, 
			alert_date, cert_expires_at, status, webhook_url, email_recipient, created_at
		FROM renewal_alerts
		WHERE status = 'PENDING' AND alert_date <= $1
		ORDER BY alert_date ASC
	`

	rows, err := p.db.Query(query, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.RenewalAlert
	for rows.Next() {
		alert := &models.RenewalAlert{}
		var webhookURL, emailRecipient sql.NullString

		err := rows.Scan(
			&alert.ID,
			&alert.CertificateID,
			&alert.CustomerID,
			&alert.RequesterID,
			&alert.AlertType,
			&alert.AlertDate,
			&alert.CertExpiresAt,
			&alert.Status,
			&webhookURL,
			&emailRecipient,
			&alert.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if webhookURL.Valid {
			alert.WebhookURL = webhookURL.String
		}
		if emailRecipient.Valid {
			alert.EmailRecipient = emailRecipient.String
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// UpdateRenewalAlertStatus updates alert status
func (p *PostgresStorage) UpdateRenewalAlertStatus(alertID string, status models.RenewalAlertStatus) error {
	now := time.Now().Unix()

	query := `UPDATE renewal_alerts SET status = $1, sent_at = $2 WHERE id = $3`
	_, err := p.db.Exec(query, status, now, alertID)

	return err
}

// UpdateRenewalAlertConfig updates webhook/email for certificate alerts
func (p *PostgresStorage) UpdateRenewalAlertConfig(certificateID, webhookURL, emailRecipient string) error {
	query := `
		UPDATE renewal_alerts 
		SET webhook_url = $1, email_recipient = $2 
		WHERE certificate_id = $3 AND status = 'PENDING'
	`

	_, err := p.db.Exec(query, webhookURL, emailRecipient, certificateID)
	return err
}

// GetRenewalAlertsByRequester gets alerts for a specific requester
func (p *PostgresStorage) GetRenewalAlertsByRequester(requesterID string) ([]*models.RenewalAlert, error) {
	query := `
		SELECT id, certificate_id, customer_id, requester_id, alert_type, 
			alert_date, cert_expires_at, status, webhook_url, email_recipient, sent_at, created_at
		FROM renewal_alerts
		WHERE requester_id = $1
		ORDER BY alert_date DESC
	`

	rows, err := p.db.Query(query, requesterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []*models.RenewalAlert
	for rows.Next() {
		alert := &models.RenewalAlert{}
		var webhookURL, emailRecipient sql.NullString
		var sentAt sql.NullInt64

		err := rows.Scan(
			&alert.ID,
			&alert.CertificateID,
			&alert.CustomerID,
			&alert.RequesterID,
			&alert.AlertType,
			&alert.AlertDate,
			&alert.CertExpiresAt,
			&alert.Status,
			&webhookURL,
			&emailRecipient,
			&sentAt,
			&alert.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if webhookURL.Valid {
			alert.WebhookURL = webhookURL.String
		}
		if emailRecipient.Valid {
			alert.EmailRecipient = emailRecipient.String
		}
		if sentAt.Valid {
			alert.SentAt = &sentAt.Int64
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// ==================== Requester Key Operations ====================

// SaveRequesterKey saves a requester key info
func (p *PostgresStorage) SaveRequesterKey(key *models.RequesterKeyInfo) error {
	query := `
		INSERT INTO requester_keys (
			id, key_name, key_type, key_size, public_key_pem, fingerprint,
			organization, email, description, is_active, created_at, expires_at, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := p.db.Exec(query,
		key.ID,
		key.KeyName,
		key.KeyType,
		key.KeySize,
		key.PublicKeyPEM,
		key.Fingerprint,
		key.Organization,
		key.Email,
		key.Description,
		key.IsActive,
		key.CreatedAt,
		key.ExpiresAt,
		key.CreatedBy,
	)

	return err
}

// GetRequesterKeyByID retrieves a requester key by ID
func (p *PostgresStorage) GetRequesterKeyByID(keyID string) (*models.RequesterKeyInfo, error) {
	query := `
		SELECT id, key_name, key_type, key_size, public_key_pem, fingerprint,
			organization, email, description, is_active, created_at, expires_at, 
			created_by, last_used_at
		FROM requester_keys WHERE id = $1
	`

	key := &models.RequesterKeyInfo{}
	var lastUsedAt sql.NullInt64
	var description sql.NullString

	err := p.db.QueryRow(query, keyID).Scan(
		&key.ID,
		&key.KeyName,
		&key.KeyType,
		&key.KeySize,
		&key.PublicKeyPEM,
		&key.Fingerprint,
		&key.Organization,
		&key.Email,
		&description,
		&key.IsActive,
		&key.CreatedAt,
		&key.ExpiresAt,
		&key.CreatedBy,
		&lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key not found")
	}
	if err != nil {
		return nil, err
	}

	if description.Valid {
		key.Description = description.String
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Int64
	}

	return key, nil
}

// GetRequesterKeyByName retrieves a requester key by name
func (p *PostgresStorage) GetRequesterKeyByName(keyName string) (*models.RequesterKeyInfo, error) {
	query := `
		SELECT id, key_name, key_type, key_size, public_key_pem, fingerprint,
			organization, email, description, is_active, created_at, expires_at, 
			created_by, last_used_at
		FROM requester_keys WHERE key_name = $1
	`

	key := &models.RequesterKeyInfo{}
	var lastUsedAt sql.NullInt64
	var description sql.NullString

	err := p.db.QueryRow(query, keyName).Scan(
		&key.ID,
		&key.KeyName,
		&key.KeyType,
		&key.KeySize,
		&key.PublicKeyPEM,
		&key.Fingerprint,
		&key.Organization,
		&key.Email,
		&description,
		&key.IsActive,
		&key.CreatedAt,
		&key.ExpiresAt,
		&key.CreatedBy,
		&lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key not found")
	}
	if err != nil {
		return nil, err
	}

	if description.Valid {
		key.Description = description.String
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Int64
	}

	return key, nil
}

// GetRequesterKeyByFingerprint retrieves a requester key by fingerprint
func (p *PostgresStorage) GetRequesterKeyByFingerprint(fingerprint string) (*models.RequesterKeyInfo, error) {
	query := `
		SELECT id, key_name, key_type, key_size, public_key_pem, fingerprint,
			organization, email, description, is_active, created_at, expires_at, 
			created_by, last_used_at
		FROM requester_keys WHERE fingerprint = $1 AND is_active = TRUE
	`

	key := &models.RequesterKeyInfo{}
	var lastUsedAt sql.NullInt64
	var description sql.NullString

	err := p.db.QueryRow(query, fingerprint).Scan(
		&key.ID,
		&key.KeyName,
		&key.KeyType,
		&key.KeySize,
		&key.PublicKeyPEM,
		&key.Fingerprint,
		&key.Organization,
		&key.Email,
		&description,
		&key.IsActive,
		&key.CreatedAt,
		&key.ExpiresAt,
		&key.CreatedBy,
		&lastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key not found")
	}
	if err != nil {
		return nil, err
	}

	if description.Valid {
		key.Description = description.String
	}
	if lastUsedAt.Valid {
		key.LastUsedAt = &lastUsedAt.Int64
	}

	return key, nil
}

// GetAllRequesterKeys retrieves all requester keys
func (p *PostgresStorage) GetAllRequesterKeys() ([]*models.RequesterKeyInfo, error) {
	query := `
		SELECT id, key_name, key_type, key_size, public_key_pem, fingerprint,
			organization, email, description, is_active, created_at, expires_at, 
			created_by, last_used_at
		FROM requester_keys
		ORDER BY created_at DESC
	`

	rows, err := p.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*models.RequesterKeyInfo
	for rows.Next() {
		key := &models.RequesterKeyInfo{}
		var lastUsedAt sql.NullInt64
		var description sql.NullString

		err := rows.Scan(
			&key.ID,
			&key.KeyName,
			&key.KeyType,
			&key.KeySize,
			&key.PublicKeyPEM,
			&key.Fingerprint,
			&key.Organization,
			&key.Email,
			&description,
			&key.IsActive,
			&key.CreatedAt,
			&key.ExpiresAt,
			&key.CreatedBy,
			&lastUsedAt,
		)
		if err != nil {
			return nil, err
		}

		if description.Valid {
			key.Description = description.String
		}
		if lastUsedAt.Valid {
			key.LastUsedAt = &lastUsedAt.Int64
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// RevokeRequesterKey revokes a requester key
func (p *PostgresStorage) RevokeRequesterKey(keyID string) error {
	query := `UPDATE requester_keys SET is_active = FALSE, revoked_at = $1 WHERE id = $2`
	_, err := p.db.Exec(query, time.Now().Unix(), keyID)
	return err
}

// UpdateRequesterKeyLastUsed updates the last used timestamp
func (p *PostgresStorage) UpdateRequesterKeyLastUsed(keyID string) error {
	query := `UPDATE requester_keys SET last_used_at = $1 WHERE id = $2`
	_, err := p.db.Exec(query, time.Now().Unix(), keyID)
	return err
}
