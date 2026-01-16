package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyType represents the type of cryptographic key
type KeyType string

const (
	KeyTypeRSA   KeyType = "RSA"
	KeyTypeECDSA KeyType = "ECDSA"
)

// KeyPair holds a public-private key pair
type KeyPair struct {
	Type          KeyType
	PrivateKey    interface{}
	PublicKey     interface{}
	PublicKeyPEM  string // PEM encoded public key for sharing
	PrivateKeyPEM string // PEM encoded private key
}

// KeyManager handles key generation and storage
type KeyManager struct {
	keyStorePath  string
	algorithm     KeyType
	keySize       int
	systemKeyPair *KeyPair // Cached system key pair
}

// NewKeyManager creates a new key manager
func NewKeyManager(storePath string, algorithm string, keySize int) *KeyManager {
	keyType := KeyTypeECDSA
	if algorithm == "RSA" {
		keyType = KeyTypeRSA
	}

	// Create key store directory if it doesn't exist
	os.MkdirAll(storePath, 0700)

	return &KeyManager{
		keyStorePath: storePath,
		algorithm:    keyType,
		keySize:      keySize,
	}
}

// GenerateKeyPair generates a new key pair based on configured algorithm
func (km *KeyManager) GenerateKeyPair() (*KeyPair, error) {
	var keyPair *KeyPair
	var err error

	switch km.algorithm {
	case KeyTypeRSA:
		keyPair, err = km.generateRSAKeyPair()
	case KeyTypeECDSA:
		keyPair, err = km.generateECDSAKeyPair()
	default:
		return nil, errors.New("unsupported algorithm")
	}

	if err != nil {
		return nil, err
	}

	// Generate PEM strings
	if err := km.generatePEMStrings(keyPair); err != nil {
		return nil, err
	}

	return keyPair, nil
}

// generateRSAKeyPair generates an RSA key pair
func (km *KeyManager) generateRSAKeyPair() (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, km.keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &KeyPair{
		Type:       KeyTypeRSA,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// generateECDSAKeyPair generates an ECDSA key pair
func (km *KeyManager) generateECDSAKeyPair() (*KeyPair, error) {
	var curve elliptic.Curve
	switch km.keySize {
	case 224:
		curve = elliptic.P224()
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		curve = elliptic.P256()
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	return &KeyPair{
		Type:       KeyTypeECDSA,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// generatePEMStrings generates PEM encoded strings for the key pair
func (km *KeyManager) generatePEMStrings(keyPair *KeyPair) error {
	// Generate public key PEM
	pubPEM, err := km.PublicKeyToPEM(keyPair)
	if err != nil {
		return err
	}
	keyPair.PublicKeyPEM = pubPEM

	// Generate private key PEM
	privPEM, err := km.PrivateKeyToPEM(keyPair)
	if err != nil {
		return err
	}
	keyPair.PrivateKeyPEM = privPEM

	return nil
}

// PublicKeyToPEM converts public key to PEM string
func (km *KeyManager) PublicKeyToPEM(keyPair *KeyPair) (string, error) {
	var pubBytes []byte
	var pemType string

	switch keyPair.Type {
	case KeyTypeRSA:
		pubBytes = x509.MarshalPKCS1PublicKey(keyPair.PublicKey.(*rsa.PublicKey))
		pemType = "RSA PUBLIC KEY"
	case KeyTypeECDSA:
		var err error
		pubBytes, err = x509.MarshalPKIXPublicKey(keyPair.PublicKey.(*ecdsa.PublicKey))
		if err != nil {
			return "", fmt.Errorf("failed to marshal ECDSA public key: %w", err)
		}
		pemType = "PUBLIC KEY"
	default:
		return "", errors.New("unsupported key type")
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: pubBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// PrivateKeyToPEM converts private key to PEM string
func (km *KeyManager) PrivateKeyToPEM(keyPair *KeyPair) (string, error) {
	var pemBlock *pem.Block

	switch keyPair.Type {
	case KeyTypeRSA:
		privBytes := x509.MarshalPKCS1PrivateKey(keyPair.PrivateKey.(*rsa.PrivateKey))
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		}
	case KeyTypeECDSA:
		privBytes, err := x509.MarshalECPrivateKey(keyPair.PrivateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return "", fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		}
	default:
		return "", errors.New("unsupported key type")
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// SaveKeyPair saves a key pair to files
func (km *KeyManager) SaveKeyPair(keyPair *KeyPair, name string) error {
	privPath := filepath.Join(km.keyStorePath, name+"_private.pem")
	pubPath := filepath.Join(km.keyStorePath, name+"_public.pem")

	// Save private key
	if err := km.savePrivateKey(keyPair, privPath); err != nil {
		return err
	}

	// Save public key
	return km.savePublicKey(keyPair, pubPath)
}

// savePrivateKey saves the private key to a PEM file
func (km *KeyManager) savePrivateKey(keyPair *KeyPair, path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer file.Close()

	var pemBlock *pem.Block

	switch keyPair.Type {
	case KeyTypeRSA:
		privBytes := x509.MarshalPKCS1PrivateKey(keyPair.PrivateKey.(*rsa.PrivateKey))
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privBytes,
		}
	case KeyTypeECDSA:
		privBytes, err := x509.MarshalECPrivateKey(keyPair.PrivateKey.(*ecdsa.PrivateKey))
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA private key:  %w", err)
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privBytes,
		}
	}

	return pem.Encode(file, pemBlock)
}

// savePublicKey saves the public key to a PEM file
func (km *KeyManager) savePublicKey(keyPair *KeyPair, path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	var pubBytes []byte
	var pemType string

	switch keyPair.Type {
	case KeyTypeRSA:
		pubBytes = x509.MarshalPKCS1PublicKey(keyPair.PublicKey.(*rsa.PublicKey))
		pemType = "RSA PUBLIC KEY"
	case KeyTypeECDSA:
		var err error
		pubBytes, err = x509.MarshalPKIXPublicKey(keyPair.PublicKey.(*ecdsa.PublicKey))
		if err != nil {
			return fmt.Errorf("failed to marshal ECDSA public key: %w", err)
		}
		pemType = "PUBLIC KEY"
	}

	pemBlock := &pem.Block{
		Type:  pemType,
		Bytes: pubBytes,
	}

	return pem.Encode(file, pemBlock)
}

// LoadKeyPair loads a key pair from files
func (km *KeyManager) LoadKeyPair(name string) (*KeyPair, error) {
	privPath := filepath.Join(km.keyStorePath, name+"_private.pem")
	pubPath := filepath.Join(km.keyStorePath, name+"_public.pem")

	privateKey, keyType, err := km.loadPrivateKey(privPath)
	if err != nil {
		return nil, err
	}

	publicKey, err := km.loadPublicKey(pubPath, keyType)
	if err != nil {
		return nil, err
	}

	keyPair := &KeyPair{
		Type:       keyType,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}

	// Generate PEM strings
	if err := km.generatePEMStrings(keyPair); err != nil {
		return nil, err
	}

	// Cache as system key pair
	km.systemKeyPair = keyPair

	return keyPair, nil
}

// loadPrivateKey loads a private key from a PEM file
func (km *KeyManager) loadPrivateKey(path string) (interface{}, KeyType, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, "", errors.New("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse RSA private key:  %w", err)
		}
		return key, KeyTypeRSA, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
		return key, KeyTypeECDSA, nil
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// loadPublicKey loads a public key from a PEM file
func (km *KeyManager) loadPublicKey(path string, keyType KeyType) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	switch keyType {
	case KeyTypeRSA:
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		return key, nil
	case KeyTypeECDSA:
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA public key:  %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// GetPublicKeyBytes returns the public key as bytes for storage/transmission
func (km *KeyManager) GetPublicKeyBytes(keyPair *KeyPair) ([]byte, error) {
	switch keyPair.Type {
	case KeyTypeRSA:
		return x509.MarshalPKCS1PublicKey(keyPair.PublicKey.(*rsa.PublicKey)), nil
	case KeyTypeECDSA:
		return x509.MarshalPKIXPublicKey(keyPair.PublicKey.(*ecdsa.PublicKey))
	default:
		return nil, errors.New("unsupported key type")
	}
}

// ==================== Certificate Support Methods ====================

// GetSystemKeyPair returns the cached system key pair
func (km *KeyManager) GetSystemKeyPair() *KeyPair {
	return km.systemKeyPair
}

// SetSystemKeyPair sets the system key pair (call after LoadKeyPair or GenerateKeyPair)
func (km *KeyManager) SetSystemKeyPair(keyPair *KeyPair) {
	km.systemKeyPair = keyPair
}

// GetPublicKeyPEM returns the system public key in PEM format
func (km *KeyManager) GetPublicKeyPEM() (string, error) {
	if km.systemKeyPair == nil {
		return "", errors.New("no system key pair loaded")
	}
	return km.systemKeyPair.PublicKeyPEM, nil
}

// GetPrivateKey returns the RSA private key (for RSA keys only)
func (km *KeyManager) GetPrivateKey() (*rsa.PrivateKey, error) {
	if km.systemKeyPair == nil {
		return nil, errors.New("no system key pair loaded")
	}

	if km.systemKeyPair.Type != KeyTypeRSA {
		return nil, errors.New("system key is not RSA type")
	}

	privateKey, ok := km.systemKeyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to cast private key to RSA")
	}

	return privateKey, nil
}

// GetECDSAPrivateKey returns the ECDSA private key (for ECDSA keys only)
func (km *KeyManager) GetECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	if km.systemKeyPair == nil {
		return nil, errors.New("no system key pair loaded")
	}

	if km.systemKeyPair.Type != KeyTypeECDSA {
		return nil, errors.New("system key is not ECDSA type")
	}

	privateKey, ok := km.systemKeyPair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("failed to cast private key to ECDSA")
	}

	return privateKey, nil
}

// GetKeyType returns the type of system key
func (km *KeyManager) GetKeyType() KeyType {
	if km.systemKeyPair == nil {
		return ""
	}
	return km.systemKeyPair.Type
}

// ==================== Signing Methods ====================

// SignData signs data with the system private key (supports RSA and ECDSA)
func (km *KeyManager) SignData(data []byte) (string, error) {
	if km.systemKeyPair == nil {
		return "", errors.New("no system key pair loaded")
	}

	// Hash the data
	hash := sha256.Sum256(data)

	var signature []byte
	var err error

	switch km.systemKeyPair.Type {
	case KeyTypeRSA:
		privateKey := km.systemKeyPair.PrivateKey.(*rsa.PrivateKey)
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	case KeyTypeECDSA:
		privateKey := km.systemKeyPair.PrivateKey.(*ecdsa.PrivateKey)
		signature, err = ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	default:
		return "", errors.New("unsupported key type for signing")
	}

	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifySignature verifies a signature with the system public key
func (km *KeyManager) VerifySignature(data []byte, signatureB64 string) error {
	if km.systemKeyPair == nil {
		return errors.New("no system key pair loaded")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Hash the data
	hash := sha256.Sum256(data)

	switch km.systemKeyPair.Type {
	case KeyTypeRSA:
		publicKey := km.systemKeyPair.PublicKey.(*rsa.PublicKey)
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	case KeyTypeECDSA:
		publicKey := km.systemKeyPair.PublicKey.(*ecdsa.PublicKey)
		if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	default:
		return errors.New("unsupported key type for verification")
	}
}

// VerifySignatureWithKey verifies signature with a provided public key PEM
func (km *KeyManager) VerifySignatureWithKey(data []byte, signatureB64 string, publicKeyPEM string) error {
	// Parse PEM
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("failed to decode public key PEM")
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	hash := sha256.Sum256(data)

	// Try RSA first
	if block.Type == "RSA PUBLIC KEY" {
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
	}

	// Try ECDSA/generic public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil
	default:
		return errors.New("unsupported public key type")
	}
}
