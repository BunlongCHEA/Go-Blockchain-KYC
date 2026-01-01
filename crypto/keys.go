package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	Type       KeyType
	PrivateKey interface{}
	PublicKey  interface{}
}

// KeyManager handles key generation and storage
type KeyManager struct {
	keyStorePath string
	algorithm    KeyType
	keySize      int
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
	switch km.algorithm {
	case KeyTypeRSA:
		return km.generateRSAKeyPair()
	case KeyTypeECDSA:
		return km.generateECDSAKeyPair()
	default:
		return nil, errors.New("unsupported algorithm")
	}
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

	return &KeyPair{
		Type:       keyType,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
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
