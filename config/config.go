package config

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	Server        ServerConfig        `json:"server"`
	Database      DatabaseConfig      `json:"database"`
	JWT           JWTConfig           `json:"jwt"`
	Crypto        CryptoConfig        `json:"crypto"`
	Consensus     ConsensusConfig     `json:"consensus"`
	Blockchain    BlockchainConfig    `json:"blockchain"`
	Verification  VerificationConfig  `json:"verification"`
	Monitoring    MonitoringConfig    `json:"monitoring"`
	PythonService PythonServiceConfig `json:"python_service"`
	// CBSIntegration CBSIntegrationConfig `json:"cbs_integration"`
	RabbitMQ RabbitMQConfig `json:"rabbitmq"`
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
	RootKEK       string `json:"root_kek,omitempty"`
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

// ── PythonServiceConfig holds Python KYC AI service configuration

type PythonServiceConfig struct {
	URL              string `json:"url"`               // base URL, e.g. http://localhost:5001
	TimeoutJSON      int    `json:"timeout_json"`      // seconds - for JSON body requests (face compare, scan)
	TimeoutMultipart int    `json:"timeout_multipart"` // seconds - for multipart file upload requests
}

// GetTimeoutJSON returns the timeout for JSON requests as time.Duration
func (p *PythonServiceConfig) GetTimeoutJSON() time.Duration {
	if p.TimeoutJSON <= 0 {
		return 300 * time.Second
	}
	return time.Duration(p.TimeoutJSON) * time.Second
}

// GetTimeoutMultipart returns the timeout for multipart requests as time.Duration
func (p *PythonServiceConfig) GetTimeoutMultipart() time.Duration {
	if p.TimeoutMultipart <= 0 {
		return 600 * time.Second
	}
	return time.Duration(p.TimeoutMultipart) * time.Second
}

// GetURL returns the Python service URL, with env var override
func (p *PythonServiceConfig) GetURL() string {
	if envURL := os.Getenv("PYTHON_KYC_SERVICE_URL"); envURL != "" {
		return envURL
	}
	if p.URL != "" {
		return p.URL
	}
	return "http://localhost:5001"
}

// ── GetRootKEK returns the 32-byte AES root key (base64) used to wrap DB-stored KEKs
// To generate a new one:
//
//	openssl rand -base64 32
//	# or: head -c 32 /dev/urandom | base64
func (c *CryptoConfig) GetRootKEK() string {
	if v := os.Getenv("KYC_ROOT_KEK"); v != "" {
		return v
	}
	return c.RootKEK
}

// ── Returns the configured into default values if not set in the config file

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8080,
			ReadTimeout:  30,
			WriteTimeout: 300,
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
		PythonService: PythonServiceConfig{
			URL:              "http://localhost:5001",
			TimeoutJSON:      300, // 5 minutes - face comparison on CPU
			TimeoutMultipart: 600, // 10 minutes - full pipeline with file uploads
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

// // ── CBSIntegrationConfig holds NextJS gateway connection settings.

// // nextjs_webhook_url  — safe to commit, not a secret.
// // integration_key     — loaded from env NEXTJS_INTEGRATION_KEY only, never config file.
// type CBSIntegrationConfig struct {
// 	// NextJS webhook relay URL (update config.json when NextJS domain changes)
// 	NextJSWebhookURL string `json:"nextjs_webhook_url"`
// }

// // GetNextJSWebhookURL returns the NextJS webhook URL.
// // Env var NEXTJS_KYC_WEBHOOK_URL overrides config.json (useful for local dev).
// func (c *CBSIntegrationConfig) GetNextJSWebhookURL() string {
// 	if v := os.Getenv("NEXTJS_KYC_WEBHOOK_URL"); v != "" {
// 		return v
// 	}
// 	return c.NextJSWebhookURL
// }

// // GetIntegrationKey returns the raw NextJS integration API key.
// // Sourced from env NEXTJS_INTEGRATION_KEY only — never stored in config file.
// func (c *CBSIntegrationConfig) GetIntegrationKey() string {
// 	return os.Getenv("NEXTJS_INTEGRATION_KEY")
// }

// ─── RabbitMQ
// URL and exchange come from config.json.
// AES/HMAC keys come from env vars ONLY — never stored in config file.

type RabbitMQConfig struct {
	URL      string `json:"url"`      // amqps://user:pass@host:5671/vhost
	Exchange string `json:"exchange"` // kyc.events
}

// GetAMQPURL returns the broker URL or empty string if not configured.
func (c *RabbitMQConfig) GetAMQPURL() string {
	if url := os.Getenv("KYC_MQ_URL"); url != "" {
		return url
	}
	return c.URL
}

// // GetAESKey decodes KYC_MQ_AES_KEY from env (base64, must be 32 bytes).
// // Returns nil when the env var is absent — caller must handle gracefully.
// func (c *RabbitMQConfig) GetAESKey() []byte {
// 	return decodeMQKey("KYC_MQ_AES_KEY")
// }

// // GetHMACKey decodes KYC_MQ_HMAC_KEY from env (base64, must be 32 bytes).
// func (c *RabbitMQConfig) GetHMACKey() []byte {
// 	return decodeMQKey("KYC_MQ_HMAC_KEY")
// }

// GetExchange returns the exchange name with a safe default.
func (c *RabbitMQConfig) GetExchange() string {
	if c.Exchange != "" {
		return c.Exchange
	}
	return "kyc.events"
}

// decodeMQKey is a shared helper — decodes a base64 env var and validates length.
func decodeMQKey(envVar string) []byte {
	raw := os.Getenv(envVar)
	if raw == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		log.Printf("[config] WARNING: %s is not valid base64: %v", envVar, err)
		return nil
	}
	if len(b) != 32 {
		log.Printf("[config] WARNING: %s must decode to exactly 32 bytes, got %d", envVar, len(b))
		return nil
	}
	return b
}

func (c *RabbitMQConfig) GetDefaultRotationMonths() int {
	v := os.Getenv("KYC_MQ_ROTATION_MONTHS")
	if v == "6" || v == "12" {
		n, _ := strconv.Atoi(v)
		return n
	}
	return 6
}
