package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Go-Blockchain-KYC/api"
	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/config"
	"Go-Blockchain-KYC/consensus"
	"Go-Blockchain-KYC/crypto"
	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/monitoring"
	"Go-Blockchain-KYC/storage"
	"Go-Blockchain-KYC/verification"
)

func main() {
	fmt.Println("==============================================")
	fmt.Println("   KYC Blockchain System - Production Ready   ")
	fmt.Println("==============================================")
	fmt.Println()

	// Load configuration
	cfg, err := config.LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
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

	// 5.  Recover blockchain from database (if available)
	log.Println("\n5. Checking for existing data to recover...")
	if store != nil {
		err = recoverBlockchainFromStorage(blockchain, store)
		if err != nil {
			log.Printf("   ⚠ Recovery warning: %v", err)
		}
	} else {
		log.Println("   No database available, starting fresh blockchain")
	}

	// Initialize consensus mechanism
	log.Println("\n6. Initializing Consensus Mechanism...")
	consensusEngine := initializeConsensus(cfg)
	if err := consensusEngine.Start(); err != nil {
		log.Printf("   ⚠ Consensus not started:  %v", err)
	} else {
		log.Printf("   ✓ %s consensus initialized", cfg.Consensus.Type)
	}

	// Initialize verification service
	log.Println("\n7. Initializing Identity Verification Service...")
	verificationService := initializeVerification(cfg)
	log.Println("   ✓ Verification service initialized")

	// Initialize monitoring service
	log.Println("\n8. Initializing Monitoring Service...")
	monitoringConfig := monitoring.DefaultMonitoringConfig()
	monitoringService := monitoring.NewMonitoringService(store, monitoringConfig)
	monitoringService.Start()

	// Setup demo data
	log.Println("\n9. Setting Up Demo Data...")
	// setupDemoData(blockchain, authService, keyManager)

	// if !blockchain.HasData() {
	// 	setupDemoDataBank(blockchain, store)
	// } else {
	// 	log.Println("   ✓ Skipping demo banking data setup - existing data recovered")
	// }

	setupDemoData(blockchain, authService, keyManager, store)
	// if !blockchain.HasData() {
	// 	setupDemoData(blockchain, authService, keyManager, store)
	// } else {
	// 	log.Println("   ✓ Skipping demo data setup - existing data recovered")
	// }

	// Start API server
	log.Println("\n7. Starting REST API Server...")
	server := api.NewServer(cfg, blockchain, authService, store, verificationService, monitoringService, keyManager)

	// Handle graceful shutdown
	go handleGracefulShutdown(monitoringService, store, consensusEngine)

	printAPIEndpoints(cfg)

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

	// // Create encryptor for data encryption
	// encryptionKey, err := crypto.GenerateKey()
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("failed to generate encryption key: %w", err)
	// }

	// Use fixed key from config instead of generating new one
	var encryptionKey []byte
	if cfg.Crypto.EncryptionKey != "" {
		// Use key from config (must be 32 bytes for AES-256)
		encryptionKey = []byte(cfg.Crypto.EncryptionKey)
		if len(encryptionKey) != 32 {
			return nil, nil, fmt.Errorf("encryption_key must be exactly 32 bytes, got %d", len(encryptionKey))
		}
		log.Println("   ✓ Using encryption key from config")
	} else {
		// Generate new key (only for first run, will break on restart!)
		encryptionKey, err = crypto.GenerateKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		log.Println("   ⚠ Generated new encryption key (data won't persist across restarts)")
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

func initializeVerification(cfg *config.Config) *verification.VerificationService {
	verificationConfig := verification.VerificationConfig{
		AutoApprove: true,
		MinScore:    80.0,
	}

	service := verification.NewVerificationService(verificationConfig)

	// Check which provider to use
	switch cfg.Verification.Provider {
	case "didit":
		// Use Didit as primary provider
		if cfg.Verification.DiditClientID != "" {
			diditProvider := verification.NewDiditProvider(verification.DiditConfig{
				ClientID:     cfg.Verification.DiditClientID,
				ClientSecret: cfg.Verification.DiditSecret,
			})
			service.AddProvider(diditProvider)
			service.SetPrimaryProvider(diditProvider)
			log.Println("   ✓ Didit provider configured")
		}
	case "mock":
		// Use mock provider for development/testing
		provider := verification.NewMockProvider(verification.MockConfig{
			SimulateDelay: true,
			RandomResults: false,
		})
		service.AddProvider(provider)
		log.Println("   ✓ Mock provider configured (development mode)")
	case "onfido":
		// Add Onfido provider (if API key configured)
		if cfg.Verification.OnfidoAPIKey != "" {
			onfidoProvider := verification.NewOnfidoProvider(verification.OnfidoConfig{
				APIKey: cfg.Verification.OnfidoAPIKey,
			})
			service.AddProvider(onfidoProvider)
			log.Println("   ✓ Onfido provider configured (fallback)")
		}
	case "trulioo":
		// Add Trulioo provider (if API key configured)
		if cfg.Verification.TruliooAPIKey != "" {
			truliooProvider := verification.NewTruliooProvider(verification.TruliooConfig{
				APIKey: cfg.Verification.TruliooAPIKey,
			})
			service.AddProvider(truliooProvider)
			log.Println("   ✓ Trulioo provider configured (fallback)")
		}
	default:
		// Default to mock for development
		provider := verification.NewMockProvider(verification.MockConfig{
			SimulateDelay: true,
			RandomResults: false,
		})
		service.AddProvider(provider)
		log.Println("   ✓ Mock provider configured (default)")
	}

	return service
}

// recoverBlockchainFromStorage recovers blockchain state from database
func recoverBlockchainFromStorage(blockchain *models.Blockchain, store storage.Storage) error {
	// Load recovery data from database
	data, err := store.LoadRecoveryData()
	if err != nil {
		return err
	}

	// Check if there's data to recover
	if len(data.Blocks) == 0 && len(data.Banks) == 0 && len(data.KYCRecords) == 0 {
		log.Println("   No existing data found, starting fresh blockchain")
		return nil
	}

	log.Println("   Found existing data in database:")
	log.Printf("   - Blocks: %d", len(data.Blocks))
	log.Printf("   - Banks: %d", len(data.Banks))
	log.Printf("   - KYC Records: %d", len(data.KYCRecords))
	log.Printf("   - Pending Transactions: %d", len(data.Transactions))

	// Recover blockchain state
	err = blockchain.RecoverFromStorage(data)
	if err != nil {
		return err
	}

	// Log recovery stats
	stats := blockchain.GetRecoveryStats()
	log.Println("\n   Recovery Summary:")
	log.Printf("   - Total Blocks: %d", stats["total_blocks"])
	log.Printf("   - Total Banks: %d", stats["total_banks"])
	log.Printf("   - Total KYC Records:  %d", stats["total_kyc_records"])
	log.Printf("   - Pending Transactions: %d", stats["pending_txs"])
	log.Printf("   - Chain Valid: %v", stats["chain_valid"])

	if latestHash, ok := stats["latest_block_hash"]; ok {
		log.Printf("   - Latest Block Hash: %s", latestHash)
	}

	return nil
}

// // setupDemoData creates demo banks
// func setupDemoDataBank(blockchain *models.Blockchain, store storage.Storage) {
// 	// Register demo banks
// 	bank1 := models.NewBank("BANK00000001", "First National Bank", "FNB", "USA", "LIC-001", "")
// 	bank1.Address = models.Address{
// 		Street:     "123 Financial District",
// 		City:       "New York",
// 		State:      "NY",
// 		PostalCode: "10001",
// 		Country:    "USA",
// 	}
// 	bank1.ContactEmail = "contact@fnb.com"
// 	blockchain.RegisterBank(bank1)

// 	// Save to database if available
// 	if store != nil {
// 		store.SaveBank(bank1)
// 	}

// 	bank2 := models.NewBank("BANK00000002", "Global Trust Bank", "GTB", "USA", "LIC-002", "")
// 	bank2.Address = models.Address{
// 		Street:     "456 Banking Avenue",
// 		City:       "Los Angeles",
// 		State:      "CA",
// 		PostalCode: "90001",
// 		Country:    "USA",
// 	}
// 	bank2.ContactEmail = "contact@gtb.com"
// 	blockchain.RegisterBank(bank2)

// 	// Save to database if available
// 	if store != nil {
// 		store.SaveBank(bank2)
// 	}

// 	log.Println("   ✓ Demo banks registered")
// }

// setupDemoData creates demo banks and users
func setupDemoData(blockchain *models.Blockchain, authService *auth.AuthService, keyManager *crypto.KeyManager, store storage.Storage) {
	// func setupDemoData(authService *auth.AuthService, keyManager *crypto.KeyManager) {

	// Only register banks if no data exists
	if !blockchain.HasData() {
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

		// Save to database if available
		if store != nil {
			store.SaveBank(bank1)
		}

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

		// Save to database if available
		if store != nil {
			store.SaveBank(bank2)
		}

		log.Println("   ✓ Demo banks registered")
	} else {
		log.Println("   ✓ Skipping bank registration - existing data recovered")
	}

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

// handleGracefulShutdown handles graceful shutdown on SIGINT/SIGTERM
func handleGracefulShutdown(monitoringService *monitoring.MonitoringService, store storage.Storage, consensusEngine consensus.Consensus) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n\n==============================================")
	fmt.Println("   Shutting down gracefully...")
	fmt.Println("==============================================")

	// Stop monitoring service
	if monitoringService != nil {
		log.Println("   Stopping monitoring service...")
		monitoringService.Stop()
	}

	// Stop consensus engine
	if consensusEngine != nil {
		log.Println("   Stopping consensus engine...")
		consensusEngine.Stop()
	}

	// Close database connection
	if store != nil {
		log.Println("   Closing database connection...")
		store.Close()
	}

	log.Println("   ✓ Shutdown complete")
	fmt.Println("   Goodbye!")
	os.Exit(0)
}

// printAPIEndpoints prints available API endpoints
func printAPIEndpoints(cfg *config.Config) {
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
	fmt.Println("  POST   /api/v1/kyc/auto-verify   - Auto Verify KYC")
	fmt.Println("  POST   /api/v1/kyc/reject        - Reject KYC")
	fmt.Println()
	fmt.Println("  POST   /api/v1/banks             - Register bank")
	fmt.Println("  GET    /api/v1/banks             - Get bank")
	fmt.Println("  GET    /api/v1/banks/list        - List banks")
	fmt.Println()
	fmt.Println("  GET    /api/v1/blockchain/stats  - Blockchain stats")
	fmt.Println("  GET    /api/v1/blockchain/blocks - Get blocks")
	fmt.Println("  POST   /api/v1/blockchain/mine   - Mine block")
	fmt.Println("  GET    /api/v1/blockchain/pending - Get pending transactions")
	fmt.Println("  GET    /api/v1/blockchain/validate - Validate chain")
	fmt.Println()
	fmt.Println("  GET    /api/v1/audit/logs        - Get audit logs")
	fmt.Println("  GET    /api/v1/security/alerts   - Get security alerts")
	fmt.Println("  POST   /api/v1/security/alerts/review - Review alert")
	fmt.Println()
	fmt.Println("  POST   /api/v1/certificate/issue   - Issue verification certificate")
	fmt.Println("  POST   /api/v1/certificate/verify  - Verify certificate (Public)")
	fmt.Println()
	fmt.Println("  GET    /api/v1/alerts/renewal      - Get renewal alerts")
	fmt.Println("  POST   /api/v1/alerts/renewal/configure - Configure renewal alerts")
	fmt.Println()

	fmt.Println("  POST   /api/v1/keys/generate     - Generate key pair for external service")
	fmt.Println("  GET    /api/v1/keys              - List all requester keys (Admin)")
	fmt.Println("  GET    /api/v1/keys/info         - Get key info by ID or name")
	fmt.Println("  POST   /api/v1/keys/revoke       - Revoke a requester key (Admin)")
	fmt.Println()
	fmt.Println("  GET    /health                   - Health check")
	fmt.Println()
}
