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
		id_image_path TEXT,
		selfie_image_path TEXT,
		last_scan_at TIMESTAMPTZ,
		scan_score NUMERIC(5,2),
		scan_status VARCHAR(20),
		ocr_result JSONB,
		last_review_date BIGINT DEFAULT 0,
		next_review_date BIGINT DEFAULT 0,
		review_count INT DEFAULT 0,
		review_notes TEXT,
		wrapped_dek TEXT,
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
		is_deleted BOOLEAN DEFAULT FALSE,
		password_change_required BOOLEAN DEFAULT FALSE,
		login_count INT DEFAULT 0,
		last_login TIMESTAMP,
		password_changed_at TIMESTAMP,
		customer_id VARCHAR(50) DEFAULT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
		is_active BOOLEAN NOT NULL DEFAULT TRUE,
		delivery VARCHAR(10) NOT NULL DEFAULT 'none',
		send_interval VARCHAR(10) NOT NULL DEFAULT 'immediate',
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

	// Certificate storage table
	`CREATE TABLE IF NOT EXISTS certificates (
		certificate_id        VARCHAR(50)  PRIMARY KEY,
		customer_id           VARCHAR(50)  NOT NULL,
		customer_name         VARCHAR(255),
		requester_id          VARCHAR(100) NOT NULL,
		requester_public_key  TEXT,
		issuer_id             VARCHAR(100),
		issuer_public_key     TEXT,
		status                VARCHAR(20)  NOT NULL DEFAULT 'VERIFIED',
		verified_by           VARCHAR(100),
		verification_date     BIGINT,
		key_type              VARCHAR(10),
		signature             TEXT,
		kyc_summary           JSONB,
		issued_at             BIGINT       NOT NULL,
		expires_at            BIGINT       NOT NULL,
		is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
		issuer_key_id		  VARCHAR(64),
		created_at            TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (customer_id) REFERENCES kyc_records(customer_id) ON DELETE CASCADE
		-- One active certificate per customer per requester.
		-- Re-issuing replaces instead of accumulating duplicates.
		-- UNIQUE (customer_id, requester_id)
	)`,

	// Password rotation policy
	`CREATE TABLE IF NOT EXISTS password_policy (
		id                   INT         PRIMARY KEY DEFAULT 1,
		interval_months      INT         NOT NULL DEFAULT 3,
		updated_by           VARCHAR(50),
		updated_at           TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT single_row CHECK (id = 1)
	)`,

	// System singleton flags (emergency lock, etc.)
	`CREATE TABLE IF NOT EXISTS system_flags (
		flag_key    VARCHAR(64) PRIMARY KEY,
		flag_value  TEXT        NOT NULL,
		updated_by  VARCHAR(50),
		updated_at  TIMESTAMP   DEFAULT CURRENT_TIMESTAMP
	)`,

	// System signing key registry
	// Holds current + all retired signing keys so historical certs stay
	// verifiable after rotation. Private key is stored AES-encrypted with
	// the KEK (see kek_keys below) — never in plaintext on disk.
	`CREATE TABLE IF NOT EXISTS system_keys (
		key_id                    VARCHAR(64) PRIMARY KEY,
		key_type                  VARCHAR(10) NOT NULL,
		key_size                  INT         NOT NULL,
		public_key_pem            TEXT        NOT NULL,
		private_key_encrypted     TEXT        NOT NULL,
		wrapping_kek_id           VARCHAR(64) NOT NULL,
		is_active                 BOOLEAN     NOT NULL DEFAULT FALSE,
		valid_from                BIGINT      NOT NULL,
		valid_until               BIGINT,
		retired_at                BIGINT,
		created_by                VARCHAR(50),
		created_at                BIGINT      NOT NULL
	)`,

	// KEK registry (for AES envelope encryption)
	// Stores KEK material wrapped by a bootstrap key sourced from env var
	// KYC_ROOT_KEK (32 bytes base64). Rotate KEKs by generating a new one,
	// re-wrapping every DEK, then retiring the old KEK.
	`CREATE TABLE IF NOT EXISTS kek_keys (
		kek_id              VARCHAR(64) PRIMARY KEY,
		wrapped_key         TEXT        NOT NULL,
		is_active           BOOLEAN     NOT NULL DEFAULT FALSE,
		created_at          BIGINT      NOT NULL,
		retired_at          BIGINT,
		created_by          VARCHAR(50)
	)`,

	// Seed default (3 months) — only if no row exists yet.
	`INSERT INTO password_policy (id, interval_months)
	 VALUES (1, 3)
	 ON CONFLICT (id) DO NOTHING`,

	// Track when each user last changed their password. Treat NULL as "use created_at"
	// for existing rows so the policy kicks in on their next login.
	`ALTER TABLE users
	 ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP`,

	`UPDATE users
	 SET    password_changed_at = created_at
	 WHERE  password_changed_at IS NULL`,

	`ALTER TABLE kyc_records
	 ADD COLUMN IF NOT EXISTS wrapped_dek TEXT`,

	`ALTER TABLE certificates
	 ADD COLUMN IF NOT EXISTS issuer_key_id VARCHAR(64)`,

	// Create indexes
	`CREATE INDEX IF NOT EXISTS idx_users_customer_id ON users(customer_id)`,

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
	`CREATE INDEX IF NOT EXISTS idx_renewal_alerts_is_active ON renewal_alerts(is_active)`,

	`CREATE INDEX IF NOT EXISTS idx_requester_keys_name ON requester_keys(key_name)`,
	`CREATE INDEX IF NOT EXISTS idx_requester_keys_fingerprint ON requester_keys(fingerprint)`,
	`CREATE INDEX IF NOT EXISTS idx_requester_keys_active ON requester_keys(is_active)`,

	`CREATE INDEX IF NOT EXISTS idx_certificates_customer   ON certificates(customer_id)`,
	`CREATE INDEX IF NOT EXISTS idx_certificates_requester  ON certificates(requester_id)`,
	`CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON certificates(expires_at)`,
	`CREATE INDEX IF NOT EXISTS idx_certificates_is_active   ON certificates(is_active)`,
	`CREATE INDEX IF NOT EXISTS idx_certificates_issuer_key ON certificates(issuer_key_id)`,

	// Only one key may be active at a time.
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_system_keys_active_unique ON system_keys (is_active) WHERE is_active = TRUE`,

	`CREATE UNIQUE INDEX IF NOT EXISTS idx_kek_keys_active_unique ON kek_keys (is_active) WHERE is_active = TRUE`,
}
