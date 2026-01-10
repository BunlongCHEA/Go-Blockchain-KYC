package config

import (
	"encoding/json"
	"os"
	"time"
)

// Config holds all application configuration
type Config struct {
	Server       ServerConfig       `json:"server"`
	Database     DatabaseConfig     `json:"database"`
	JWT          JWTConfig          `json:"jwt"`
	Crypto       CryptoConfig       `json:"crypto"`
	Consensus    ConsensusConfig    `json:"consensus"`
	Blockchain   BlockchainConfig   `json:"blockchain"`
	Verification VerificationConfig `json:"verification"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host         string        `json:"host"`
	Port         int           `json:"port"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	TLSCertFile  string        `json:"tls_cert_file"`
	TLSKeyFile   string        `json:"tls_key_file"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver          string `json:"driver"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	User            string `json:"user"`
	Password        string `json:"password"`
	DBName          string `json:"db_name"`
	SSLMode         string `json:"ssl_mode"`
	MaxOpenConns    int    `json:"max_open_conns"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey     string        `json:"secret_key"`
	TokenExpiry   time.Duration `json:"token_expiry"`
	RefreshExpiry time.Duration `json:"refresh_expiry"`
	Issuer        string        `json:"issuer"`
}

// CryptoConfig holds cryptographic configuration
type CryptoConfig struct {
	Algorithm    string `json:"algorithm"` // RSA or ECDSA
	KeySize      int    `json:"key_size"`  // 2048 for RSA, 256 for ECDSA
	AESKeySize   int    `json:"aes_key_size"`
	KeyStorePath string `json:"key_store_path"`
}

// ConsensusConfig holds consensus configuration
type ConsensusConfig struct {
	Type              string        `json:"type"` // pbft or raft
	NodeID            string        `json:"node_id"`
	Nodes             []string      `json:"nodes"`
	ElectionTimeout   time.Duration `json:"election_timeout"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
}

// BlockchainConfig holds blockchain configuration
type BlockchainConfig struct {
	Difficulty    int `json:"difficulty"`
	MaxTxPerBlock int `json:"max_tx_per_block"`
	BlockInterval int `json:"block_interval"`
}

type VerificationConfig struct {
	Enabled       bool    `json:"enabled"`
	AutoApprove   bool    `json:"auto_approve"`
	MinScore      float64 `json:"min_score"`
	Provider      string  `json:"provider"` // "didit", "onfido", "trulioo"
	DiditClientID string  `json:"didit_client_id"`
	DiditSecret   string  `json:"didit_client_secret"`
	OnfidoAPIKey  string  `json:"onfido_api_key"`
	TruliooAPIKey string  `json:"trulioo_api_key"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
		},
		Database: DatabaseConfig{
			Driver:          "postgres",
			Host:            "localhost",
			Port:            5432,
			User:            "kyc_user",
			Password:        "kyc_password",
			DBName:          "kyc_blockchain",
			SSLMode:         "disable",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 300,
		},
		JWT: JWTConfig{
			SecretKey:     "your-super-secret-key-change-in-production",
			TokenExpiry:   24 * time.Hour,
			RefreshExpiry: 7 * 24 * time.Hour,
			Issuer:        "kyc-blockchain",
		},
		Crypto: CryptoConfig{
			Algorithm:    "ECDSA",
			KeySize:      256,
			AESKeySize:   32,
			KeyStorePath: "./keys",
		},
		Consensus: ConsensusConfig{
			Type:              "pbft",
			NodeID:            "node1",
			Nodes:             []string{"node1", "node2", "node3", "node4"},
			ElectionTimeout:   150 * time.Millisecond,
			HeartbeatInterval: 50 * time.Millisecond,
		},
		Blockchain: BlockchainConfig{
			Difficulty:    2,
			MaxTxPerBlock: 100,
			BlockInterval: 10,
		},
	}
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil // Use defaults if file doesn't exist
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config *Config, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

// GetDSN returns database connection string
func (d *DatabaseConfig) GetDSN() string {
	return "host=" + d.Host +
		" port=" + string(rune(d.Port)) +
		" user=" + d.User +
		" password=" + d.Password +
		" dbname=" + d.DBName +
		" sslmode=" + d.SSLMode
}
