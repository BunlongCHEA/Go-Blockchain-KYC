package storage

// Migrations contains all database migrations
var Migrations = []string{
	// Create blocks table
	`CREATE TABLE IF NOT EXISTS blocks (
		id SERIAL PRIMARY KEY,
		block_index BIGINT UNIQUE NOT NULL,
		timestamp BIGINT NOT NULL,
		prev_hash VARCHAR(64) NOT NULL,
		hash VARCHAR(64) UNIQUE NOT NULL,
		nonce INTEGER NOT NULL,
		merkle_root VARCHAR(64),
		difficulty INTEGER NOT NULL,
		miner VARCHAR(100),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`,

	// Create transactions table
	`CREATE TABLE IF NOT EXISTS transactions (
		id VARCHAR(32) PRIMARY KEY,
		type VARCHAR(20) NOT NULL,
		customer_id VARCHAR(50) NOT NULL,
		bank_id VARCHAR(50) NOT NULL,
		user_id VARCHAR(50) NOT NULL,
		timestamp BIGINT NOT NULL,
		signature TEXT,
		description TEXT,
		metadata JSONB,
		block_hash VARCHAR(64),
		is_pending BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (block_hash) REFERENCES blocks(hash) ON DELETE SET NULL
	)`,

	// Create kyc_records table
	`CREATE TABLE IF NOT EXISTS kyc_records (
		customer_id VARCHAR(50) PRIMARY KEY,
		first_name VARCHAR(100) NOT NULL,
		last_name VARCHAR(100) NOT NULL,
		date_of_birth VARCHAR(20) NOT NULL,
		nationality VARCHAR(100),
		id_type VARCHAR(50) NOT NULL,
		id_number_encrypted TEXT NOT NULL,
		id_expiry_date VARCHAR(20),
		address_street VARCHAR(255),
		address_city VARCHAR(100),
		address_state VARCHAR(100),
		address_postal_code VARCHAR(20),
		address_country VARCHAR(100),
		email_encrypted TEXT NOT NULL,
		phone_encrypted TEXT NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
		verified_by VARCHAR(50),
		verification_date BIGINT,
		document_hash VARCHAR(64),
		risk_level VARCHAR(20) DEFAULT 'medium',
		bank_id VARCHAR(50) NOT NULL,
		encryption_key_id VARCHAR(50),
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL
	)`,

	// Create banks table
	`CREATE TABLE IF NOT EXISTS banks (
		id VARCHAR(50) PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		code VARCHAR(20) UNIQUE NOT NULL,
		country VARCHAR(100) NOT NULL,
		license_no VARCHAR(100),
		public_key TEXT,
		is_active BOOLEAN DEFAULT TRUE,
		address_street VARCHAR(255),
		address_city VARCHAR(100),
		address_state VARCHAR(100),
		address_postal_code VARCHAR(20),
		address_country VARCHAR(100),
		contact_email VARCHAR(255),
		contact_phone VARCHAR(50),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`,

	// Create users table
	`CREATE TABLE IF NOT EXISTS users (
		id VARCHAR(50) PRIMARY KEY,
		username VARCHAR(100) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		password_salt VARCHAR(50) NOT NULL,
		role VARCHAR(50) NOT NULL,
		bank_id VARCHAR(50),
		is_active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_login TIMESTAMP,
		FOREIGN KEY (bank_id) REFERENCES banks(id) ON DELETE SET NULL
	)`,

	// Create audit_log table
	`CREATE TABLE IF NOT EXISTS audit_log (
		id SERIAL PRIMARY KEY,
		user_id VARCHAR(50) NOT NULL,
		action VARCHAR(100) NOT NULL,
		resource_type VARCHAR(50) NOT NULL,
		resource_id VARCHAR(100),
		details JSONB,
		ip_address VARCHAR(45),
		user_agent TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`,

	// Create renewal_alerts table
	`CREATE TABLE IF NOT EXISTS renewal_alerts (
		id VARCHAR(50) PRIMARY KEY,
		certificate_id VARCHAR(50) NOT NULL,
		customer_id VARCHAR(50) NOT NULL,
		requester_id VARCHAR(100) NOT NULL,
		alert_type VARCHAR(20) NOT NULL,
		alert_date BIGINT NOT NULL,
		cert_expires_at BIGINT NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
		webhook_url TEXT,
		email_recipient VARCHAR(255),
		sent_at BIGINT,
		created_at BIGINT NOT NULL
	)`,

	// Create requester_keys table
	`CREATE TABLE IF NOT EXISTS requester_keys (
		id VARCHAR(50) PRIMARY KEY,
		key_name VARCHAR(100) UNIQUE NOT NULL,
		key_type VARCHAR(10) NOT NULL,
		key_size INT NOT NULL,
		public_key_pem TEXT NOT NULL,
		fingerprint VARCHAR(100) NOT NULL,
		organization VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL,
		description TEXT,
		is_active BOOLEAN DEFAULT TRUE,
		created_at BIGINT NOT NULL,
		expires_at BIGINT NOT NULL,
		created_by VARCHAR(50) NOT NULL,
		last_used_at BIGINT,
		revoked_at BIGINT,
		revoked_by VARCHAR(50)
	)`,

	// Create indexes
	`CREATE INDEX IF NOT EXISTS idx_transactions_customer_id ON transactions(customer_id)`,
	`CREATE INDEX IF NOT EXISTS idx_transactions_bank_id ON transactions(bank_id)`,
	`CREATE INDEX IF NOT EXISTS idx_transactions_is_pending ON transactions(is_pending)`,
	`CREATE INDEX IF NOT EXISTS idx_kyc_records_status ON kyc_records(status)`,
	`CREATE INDEX IF NOT EXISTS idx_kyc_records_bank_id ON kyc_records(bank_id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)`,
	`CREATE INDEX IF NOT EXISTS idx_renewal_alerts_status ON renewal_alerts(status)`,
	`CREATE INDEX IF NOT EXISTS idx_renewal_alerts_alert_date ON renewal_alerts(alert_date)`,
	`CREATE INDEX IF NOT EXISTS idx_renewal_alerts_requester ON renewal_alerts(requester_id)`,
	`CREATE INDEX IF NOT EXISTS idx_requester_keys_name ON requester_keys(key_name)`,
	`CREATE INDEX IF NOT EXISTS idx_requester_keys_fingerprint ON requester_keys(fingerprint)`,
	`CREATE INDEX IF NOT EXISTS idx_requester_keys_active ON requester_keys(is_active)`,
}
