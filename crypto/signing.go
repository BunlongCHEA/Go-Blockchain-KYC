package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// Signer handles digital signature operations
type Signer struct {
	keyPair *KeyPair
}

// NewSigner creates a new signer with the given key pair
func NewSigner(keyPair *KeyPair) *Signer {
	return &Signer{
		keyPair: keyPair,
	}
}

// Sign signs data and returns the signature as base64
func (s *Signer) Sign(data []byte) (string, error) {
	hash := sha256.Sum256(data)

	switch s.keyPair.Type {
	case KeyTypeRSA:
		return s.signRSA(hash[:])
	case KeyTypeECDSA:
		return s.signECDSA(hash[:])
	default:
		return "", errors.New("unsupported key type")
	}
}

// signRSA signs data using RSA-PSS
func (s *Signer) signRSA(hash []byte) (string, error) {
	privateKey, ok := s.keyPair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", errors.New("invalid RSA private key")
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", fmt.Errorf("RSA signing failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

// signECDSA signs data using ECDSA
func (s *Signer) signECDSA(hash []byte) (string, error) {
	privateKey, ok := s.keyPair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", errors.New("invalid ECDSA private key")
	}

	r, ss, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return "", fmt.Errorf("ECDSA signing failed: %w", err)
	}

	// Combine r and s into a single signature
	signature := append(r.Bytes(), ss.Bytes()...)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Verify verifies a signature against data
func (s *Signer) Verify(data []byte, signatureB64 string) (bool, error) {
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	hash := sha256.Sum256(data)

	switch s.keyPair.Type {
	case KeyTypeRSA:
		return s.verifyRSA(hash[:], signature)
	case KeyTypeECDSA:
		return s.verifyECDSA(hash[:], signature)
	default:
		return false, errors.New("unsupported key type")
	}
}

// verifyRSA verifies an RSA-PSS signature
func (s *Signer) verifyRSA(hash, signature []byte) (bool, error) {
	publicKey, ok := s.keyPair.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("invalid RSA public key")
	}

	err := rsa.VerifyPSS(publicKey, crypto.SHA256, hash, signature, nil)
	if err != nil {
		return false, nil // Signature doesn't match
	}

	return true, nil
}

// verifyECDSA verifies an ECDSA signature
func (s *Signer) verifyECDSA(hash, signature []byte) (bool, error) {
	publicKey, ok := s.keyPair.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, errors.New("invalid ECDSA public key")
	}

	// Split signature into r and s
	keySize := publicKey.Params().BitSize / 8
	if len(signature) != 2*keySize {
		// Handle variable length signatures
		keySize = len(signature) / 2
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	ss := new(big.Int).SetBytes(signature[keySize:])

	valid := ecdsa.Verify(publicKey, hash, r, ss)
	return valid, nil
}

// VerifyWithPublicKey verifies a signature using a provided public key
func VerifyWithPublicKey(data []byte, signatureB64 string, publicKey interface{}, keyType KeyType) (bool, error) {
	tempKeyPair := &KeyPair{
		Type:      keyType,
		PublicKey: publicKey,
	}

	signer := NewSigner(tempKeyPair)
	return signer.Verify(data, signatureB64)
}

// SignatureInfo contains signature metadata
type SignatureInfo struct {
	Algorithm   string `json:"algorithm"`
	Signature   string `json:"signature"`
	SignedAt    int64  `json:"signed_at"`
	SignerID    string `json:"signer_id"`
	PublicKeyID string `json:"public_key_id"`
}

// CreateSignatureInfo creates signature info with metadata
func (s *Signer) CreateSignatureInfo(data []byte, signerID string) (*SignatureInfo, error) {
	signature, err := s.Sign(data)
	if err != nil {
		return nil, err
	}

	return &SignatureInfo{
		Algorithm: string(s.keyPair.Type),
		Signature: signature,
		SignerID:  signerID,
	}, nil
}
