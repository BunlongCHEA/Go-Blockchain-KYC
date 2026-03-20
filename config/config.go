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
	Monitoring   MonitoringConfig   `json:"monitoring"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ReadTimeout  int    `json:"read_timeout"`  // seconds
	WriteTimeout int    `json:"write_timeout"` // seconds
	IdleTimeout  int    `json:"idle_timeout"`  // seconds
	TLSCertFile  string `json:"tls_cert_file"`
	TLSKeyFile   string `json:"tls_key_file"`
}

// Helper methods to get durations
func (s *ServerConfig) GetReadTimeout() time.Duration {
	if s.ReadTimeout <= 0 {
		return 30 * time.Second
	}
	return time.Duration(s.ReadTimeout) * time.Second
}

func (s *ServerConfig) GetWriteTimeout() time.Duration {
	if s.WriteTimeout <= 0 {
		return 120 * time.Second
	}
	return time.Duration(s.WriteTimeout) * time.Second
}

func (s *ServerConfig) GetIdleTimeout() time.Duration {
	if s.IdleTimeout <= 0 {
		return 120 * time.Second
	}
	return time.Duration(s.IdleTimeout) * time.Second
}

// Add these helper methods (already in the config.go above)
func (c *ConsensusConfig) GetElectionTimeout() time.Duration {
	if c.ElectionTimeout <= 0 {
		return 1000 * time.Millisecond
	}
	return time.Duration(c.ElectionTimeout) * time.Millisecond
}

func (c *ConsensusConfig) GetHeartbeatInterval() time.Duration {
	if c.HeartbeatInterval <= 0 {
		return 150 * time.Millisecond
	}
	return time.Duration(c.HeartbeatInterval) * time.Millisecond
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Driver          string `json:"driver"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	User            string `json:"user"`
	Password        string `json:"password"`
	DBName          string `json:"dbname"`  // Changed to match ConfigMap
	SSLMode         string `json:"sslmode"` // Changed to match ConfigMap
	MaxOpenConns    int    `json:"max_open_conns"`
	MaxIdleConns    int    `json:"max_idle_conns"`
	ConnMaxLifetime int    `json:"conn_max_lifetime"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	SecretKey     string `json:"secret_key"`
	TokenExpiry   int    `json:"token_expiry"`   // seconds
	RefreshExpiry int    `json:"refresh_expiry"` // seconds
	Issuer        string `json:"issuer"`
}

func (j *JWTConfig) GetTokenExpiry() time.Duration {
	if j.TokenExpiry <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(j.TokenExpiry) * time.Second
}

func (j *JWTConfig) GetRefreshExpiry() time.Duration {
	if j.RefreshExpiry <= 0 {
		return 7 * 24 * time.Hour
	}
	return time.Duration(j.RefreshExpiry) * time.Second
}

// CryptoConfig holds cryptographic configuration
type CryptoConfig struct {
	Algorithm     string `json:"algorithm"`
	KeySize       int    `json:"key_size"`
	AESKeySize    int    `json:"aes_key_size"`
	KeyStorePath  string `json:"key_store_path"`
	EncryptionKey string `json:"encryption_key"`
}

// ConsensusConfig holds consensus configuration
type ConsensusConfig struct {
	Type              string   `json:"type"`
	Namespace         string   `json:"namespace"`
	NodeID            string   `json:"node_id"`
	Nodes             []string `json:"nodes"`
	DiscoveryMethod   string   `json:"discovery_method"`
	HeadlessService   string   `json:"headless_service"`
	ElectionTimeout   int      `json:"election_timeout"`   // milliseconds
	HeartbeatInterval int      `json:"heartbeat_interval"` // milliseconds
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
	Provider      string  `json:"provider"`
	DiditClientID string  `json:"didit_client_id"`
	DiditSecret   string  `json:"didit_client_secret"`
	OnfidoAPIKey  string  `json:"onfido_api_key"`
	TruliooAPIKey string  `json:"trulioo_api_key"`
}

// MonitoringConfig holds Prometheus metrics configuration
type MonitoringConfig struct {
	Enabled     bool   `json:"enabled"`
	MetricsPort int    `json:"metrics_port"`
	LogLevel    string `json:"log_level"`
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30,
			WriteTimeout: 30,
			IdleTimeout:  120,
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
			TokenExpiry:   3600,
			RefreshExpiry: 86400,
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
			ElectionTimeout:   1000,
			HeartbeatInterval: 150,
		},
		Blockchain: BlockchainConfig{
			Difficulty:    2,
			MaxTxPerBlock: 100,
			BlockInterval: 10,
		},
		Monitoring: MonitoringConfig{
			Enabled:     true,
			MetricsPort: 9090,
			LogLevel:    "info",
		},
	}
}

// LoadConfig loads configuration from file
func LoadConfig(path string) (*Config, error) {
	config := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	if podName := os.Getenv("POD_NAME"); podName != "" {
		config.Consensus.NodeID = podName
	}
	if podNamespace := os.Getenv("POD_NAMESPACE"); podNamespace != "" {
		config.Consensus.Namespace = podNamespace
	}

	return config, nil
}
