package main

import (
	"fmt"
	"log"
	"time"

	"Go-Blockchain-KYC/api"
	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/config"
	"Go-Blockchain-KYC/consensus"
	"Go-Blockchain-KYC/crypto"
	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/storage"
)

func main() {
	fmt.Println("==============================================")
	fmt.Println("   KYC Blockchain System - Production Ready   ")
	fmt.Println("==============================================")
	fmt.Println()

	// Load configuration
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.Printf("Using default configuration: %v", err)
		cfg = config.DefaultConfig()
	}

	// Initialize components in order
	log.Println("1. Initializing Cryptographic Components...")
	keyManager, encryptor, err := initializeCrypto(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize crypto:  %v", err)
	}
	log.Println("   ✓ Key Manager initialized")
	log.Println("   ✓ Encryptor initialized (AES-256-GCM)")

	// Initialize authentication service
	log.Println("\n2. Initializing Authentication Service...")
	authService := auth.NewAuthService(
		cfg.JWT.SecretKey,
		cfg.JWT.TokenExpiry,
		cfg.JWT.RefreshExpiry,
	)
	log.Println("   ✓ JWT Service initialized")
	log.Println("   ✓ RBAC initialized")

	// Initialize database storage
	log.Println("\n3. Initializing Database Storage...")
	store, err := initializeStorage(cfg)
	if err != nil {
		log.Printf("   ⚠ Database not available, using in-memory storage: %v", err)
		store = nil
	} else {
		log.Println("   ✓ PostgreSQL connection established")
		log.Println("   ✓ Database migrations completed")
	}

	// Initialize blockchain
	log.Println("\n4. Initializing Blockchain...")
	blockchain := models.NewBlockchain(
		cfg.Blockchain.Difficulty,
		cfg.Blockchain.MaxTxPerBlock,
		encryptor,
		cfg.Consensus.NodeID,
	)
	log.Printf("   ✓ Blockchain initialized (Difficulty: %d)", cfg.Blockchain.Difficulty)
	log.Println("   ✓ Genesis block created")

	// Initialize consensus mechanism
	log.Println("\n5. Initializing Consensus Mechanism...")
	consensusEngine := initializeConsensus(cfg)
	if err := consensusEngine.Start(); err != nil {
		log.Printf("   ⚠ Consensus not started:  %v", err)
	} else {
		log.Printf("   ✓ %s consensus initialized", cfg.Consensus.Type)
	}

	// Setup demo data
	log.Println("\n6. Setting Up Demo Data...")
	setupDemoData(blockchain, authService, keyManager)

	// Start API server
	log.Println("\n7. Starting REST API Server...")
	server := api.NewServer(cfg, blockchain, authService, store)

	fmt.Println()
	fmt.Println("==============================================")
	fmt.Printf("   Server running on http://%s:%d\n", cfg.Server.Host, cfg.Server.Port)
	fmt.Println("==============================================")
	fmt.Println()
	fmt.Println("API Endpoints:")
	fmt.Println("  POST   /api/v1/auth/register     - Register user")
	fmt.Println("  POST   /api/v1/auth/login        - Login")
	fmt.Println("  POST   /api/v1/auth/refresh      - Refresh token")
	fmt.Println("  GET    /api/v1/auth/profile      - Get profile")
	fmt.Println()
	fmt.Println("  POST   /api/v1/kyc               - Create KYC")
	fmt.Println("  GET    /api/v1/kyc               - Get KYC")
	fmt.Println("  PUT    /api/v1/kyc               - Update KYC")
	fmt.Println("  DELETE /api/v1/kyc               - Delete KYC")
	fmt.Println("  GET    /api/v1/kyc/list          - List KYC records")
	fmt.Println("  POST   /api/v1/kyc/verify        - Verify KYC")
	fmt.Println("  POST   /api/v1/kyc/reject        - Reject KYC")
	fmt.Println()
	fmt.Println("  POST   /api/v1/banks             - Register bank")
	fmt.Println("  GET    /api/v1/banks             - Get bank")
	fmt.Println("  GET    /api/v1/banks/list        - List banks")
	fmt.Println()
	fmt.Println("  GET    /api/v1/blockchain/stats  - Blockchain stats")
	fmt.Println("  GET    /api/v1/blockchain/blocks - Get blocks")
	fmt.Println("  POST   /api/v1/blockchain/mine   - Mine block")
	fmt.Println()
	fmt.Println("  GET    /health                   - Health check")
	fmt.Println()

	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

// initializeCrypto initializes cryptographic components
func initializeCrypto(cfg *config.Config) (*crypto.KeyManager, *crypto.Encryptor, error) {
	// Create key manager
	keyManager := crypto.NewKeyManager(
		cfg.Crypto.KeyStorePath,
		cfg.Crypto.Algorithm,
		cfg.Crypto.KeySize,
	)

	// Try to load existing keys or generate new ones
	keyPair, err := keyManager.LoadKeyPair("system")
	if err != nil {
		log.Println("   Generating new system key pair...")
		keyPair, err = keyManager.GenerateKeyPair()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
		if err := keyManager.SaveKeyPair(keyPair, "system"); err != nil {
			log.Printf("   Warning: Could not save key pair: %v", err)
		}
	}

	// Create encryptor for data encryption
	encryptionKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	encryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	_ = keyPair // Use for transaction signing

	return keyManager, encryptor, nil
}

// initializeStorage initializes database storage
func initializeStorage(cfg *config.Config) (storage.Storage, error) {
	// Ensure database exists before connecting
	err := storage.EnsureDatabase(
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.SSLMode,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to ensure database:  %w", err)
	}

	// Now connect to the database
	store, err := storage.NewPostgresStorage(
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.DBName,
		cfg.Database.SSLMode,
	)
	if err != nil {
		return nil, err
	}

	// Run migrations
	if err := store.Migrate(); err != nil {
		store.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return store, nil
}

// initializeConsensus initializes the consensus mechanism
func initializeConsensus(cfg *config.Config) consensus.Consensus {
	nodes := make([]consensus.Node, len(cfg.Consensus.Nodes))
	for i, nodeID := range cfg.Consensus.Nodes {
		nodes[i] = consensus.Node{
			ID:       nodeID,
			Address:  fmt.Sprintf("localhost:%d", 9000+i),
			IsActive: true,
		}
	}

	consensusConfig := consensus.ConsensusConfig{
		Type:    consensus.ConsensusType(cfg.Consensus.Type),
		NodeID:  cfg.Consensus.NodeID,
		Nodes:   nodes,
		Timeout: int64(cfg.Consensus.ElectionTimeout / time.Millisecond),
	}

	return consensus.NewConsensus(consensusConfig)
}

// setupDemoData creates demo banks and users
func setupDemoData(blockchain *models.Blockchain, authService *auth.AuthService, keyManager *crypto.KeyManager) {
	// Register demo banks
	bank1 := models.NewBank("BANK00000001", "First National Bank", "FNB", "USA", "LIC-001", "")
	bank1.Address = models.Address{
		Street:     "123 Financial District",
		City:       "New York",
		State:      "NY",
		PostalCode: "10001",
		Country:    "USA",
	}
	bank1.ContactEmail = "contact@fnb.com"
	blockchain.RegisterBank(bank1)

	bank2 := models.NewBank("BANK00000002", "Global Trust Bank", "GTB", "USA", "LIC-002", "")
	bank2.Address = models.Address{
		Street:     "456 Banking Avenue",
		City:       "Los Angeles",
		State:      "CA",
		PostalCode: "90001",
		Country:    "USA",
	}
	bank2.ContactEmail = "contact@gtb.com"
	blockchain.RegisterBank(bank2)

	log.Println("   ✓ Demo banks registered")

	// Register demo users
	adminUser := &auth.RegisterRequest{
		Username: "admin",
		Email:    "admin@kyc-blockchain.com",
		Password: "admin123",
		Role:     auth.RoleAdmin,
	}
	authService.Register(adminUser)

	bankAdmin := &auth.RegisterRequest{
		Username: "bank_admin",
		Email:    "admin@fnb.com",
		Password: "bank123",
		Role:     auth.RoleBankAdmin,
		BankID:   "BANK00000001",
	}
	authService.Register(bankAdmin)

	bankOfficer := &auth.RegisterRequest{
		Username: "bank_officer",
		Email:    "officer@fnb.com",
		Password: "officer123",
		Role:     auth.RoleBankOfficer,
		BankID:   "BANK00000001",
	}
	authService.Register(bankOfficer)

	auditor := &auth.RegisterRequest{
		Username: "auditor",
		Email:    "auditor@kyc-blockchain.com",
		Password: "auditor123",
		Role:     auth.RoleAuditor,
	}
	authService.Register(auditor)

	log.Println("   ✓ Demo users created")
	log.Println()
	log.Println("   Demo Credentials:")
	log.Println("   -----------------")
	log.Println("   Admin:        admin / admin123")
	log.Println("   Bank Admin:   bank_admin / bank123")
	log.Println("   Bank Officer: bank_officer / officer123")
	log.Println("   Auditor:      auditor / auditor123")
}
