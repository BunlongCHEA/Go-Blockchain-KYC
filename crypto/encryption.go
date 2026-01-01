package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Encryptor handles AES-256 encryption/decryption
type Encryptor struct {
	key []byte
}

// NewEncryptor creates a new encryptor with the given key
func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	return &Encryptor{
		key: key,
	}, nil
}

// NewEncryptorFromPassword creates an encryptor from a password using PBKDF2
func NewEncryptorFromPassword(password, salt string, iterations int) (*Encryptor, error) {
	key := pbkdf2.Key([]byte(password), []byte(salt), iterations, 32, sha256.New)
	return NewEncryptor(key)
}

// GenerateKey generates a random 256-bit key
func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// GenerateSalt generates a random salt
func GenerateSalt(length int) (string, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	if err != nil {
		return "", fmt.Errorf("failed to generate salt:  %w", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func (e *Encryptor) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher:  %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM:  %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (e *Encryptor) Decrypt(ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string
func (e *Encryptor) EncryptString(plaintext string) (string, error) {
	return e.Encrypt([]byte(plaintext))
}

// DecryptString decrypts to a string
func (e *Encryptor) DecryptString(ciphertext string) (string, error) {
	plaintext, err := e.Decrypt(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// EncryptedField represents an encrypted field with metadata
type EncryptedField struct {
	Ciphertext string `json:"ciphertext"`
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
}

// EncryptField creates an encrypted field with metadata
func (e *Encryptor) EncryptField(plaintext []byte, keyID string) (*EncryptedField, error) {
	ciphertext, err := e.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	return &EncryptedField{
		Ciphertext: ciphertext,
		KeyID:      keyID,
		Algorithm:  "AES-256-GCM",
	}, nil
}

// DecryptField decrypts an encrypted field
func (e *Encryptor) DecryptField(field *EncryptedField) ([]byte, error) {
	return e.Decrypt(field.Ciphertext)
}

// HashPassword hashes a password using PBKDF2
func HashPassword(password, salt string) string {
	hash := pbkdf2.Key([]byte(password), []byte(salt), 100000, 32, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, salt, hash string) bool {
	return HashPassword(password, salt) == hash
}
