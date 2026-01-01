package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"Go-Blockchain-KYC/models"

	_ "github.com/lib/pq"
)

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
		kyc.IDNumber = "[ENCRYPTED]"
		kyc.Email = "[ENCRYPTED]"
		kyc.Phone = "[ENCRYPTED]"
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
			kyc.IDNumber = "[ENCRYPTED]"
			kyc.Email = "[ENCRYPTED]"
			kyc.Phone = "[ENCRYPTED]"
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

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           int64                  `json:"id"`
	UserID       string                 `json:"user_id"`
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Details      map[string]interface{} `json:"details"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	CreatedAt    string                 `json:"created_at"`
}

// SaveAuditLog saves an audit log entry
func (p *PostgresStorage) SaveAuditLog(log *AuditLog) error {
	details, _ := json.Marshal(log.Details)

	query := `
		INSERT INTO audit_log (user_id, action, resource_type, resource_id, details, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := p.db.Exec(query,
		log.UserID,
		log.Action,
		log.ResourceType,
		log.ResourceID,
		details,
		log.IPAddress,
		log.UserAgent,
	)

	if err != nil {
		return fmt.Errorf("failed to save audit log: %w", err)
	}

	return nil
}

// GetAuditLogs retrieves audit logs with pagination
func (p *PostgresStorage) GetAuditLogs(limit, offset int) ([]*AuditLog, error) {
	query := `
		SELECT id, user_id, action, resource_type, resource_id, details, ip_address, user_agent, created_at
		FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2
	`

	rows, err := p.db.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		log := &AuditLog{}
		var details []byte

		err := rows.Scan(
			&log.ID,
			&log.UserID,
			&log.Action,
			&log.ResourceType,
			&log.ResourceID,
			&details,
			&log.IPAddress,
			&log.UserAgent,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if details != nil {
			json.Unmarshal(details, &log.Details)
		}

		logs = append(logs, log)
	}

	return logs, nil
}
