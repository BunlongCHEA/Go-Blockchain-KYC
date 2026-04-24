package models

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	kycCrypto "Go-Blockchain-KYC/crypto"
)

// VerificationCertificate represents a signed KYC verification proof
type VerificationCertificate struct {
	// Certificate Data
	CertificateID    string `json:"certificate_id"`
	CustomerID       string `json:"customer_id"`
	Status           string `json:"status"`
	VerifiedBy       string `json:"verified_by"`
	VerificationDate int64  `json:"verification_date"`
	ExpiresAt        int64  `json:"expires_at"`

	// Requester Info (external service)
	RequesterID     string `json:"requester_id"`
	RequesterPubKey string `json:"requester_public_key,omitempty"`

	// KYC Summary (non-sensitive)
	KYCSummary KYCSummary `json:"kyc_summary"`

	// Issuer Info
	IssuerID     string `json:"issuer_id"`
	IssuerPubKey string `json:"issuer_public_key"`
	IssuerKeyID  string `json:"issuer_key_id,omitempty"` // key ID for signature verification (if using KeyManager)

	KeyType string `json:"key_type"` // "RSA" or "ECDSA"

	// Signature
	Signature string `json:"signature"`
	SignedAt  int64  `json:"signed_at"`

	IsActive bool `json:"is_active"` // for soft deletion and history tracking
}

// KYCSummary contains non-sensitive KYC info for certificate
type KYCSummary struct {
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	Nationality string `json:"nationality"`
	IDType      string `json:"id_type"`
	RiskLevel   string `json:"risk_level"`
	BankID      string `json:"bank_id"`
}

// CertificatePayload is the data to be signed
type CertificatePayload struct {
	CertificateID    string     `json:"certificate_id"`
	CustomerID       string     `json:"customer_id"`
	Status           string     `json:"status"`
	VerifiedBy       string     `json:"verified_by"`
	VerificationDate int64      `json:"verification_date"`
	ExpiresAt        int64      `json:"expires_at"`
	RequesterID      string     `json:"requester_id"`
	RequesterPubKey  string     `json:"requester_public_key"`
	KYCSummary       KYCSummary `json:"kyc_summary"`
	IssuerID         string     `json:"issuer_id"`
	IssuerKeyID      string     `json:"issuer_key_id,omitempty"` // omitempty keeps legacy payloads identical
	SignedAt         int64      `json:"signed_at"`
}

// NewVerificationCertificate creates a new certificate
func NewVerificationCertificate(
	kyc *KYCData,
	requesterID string,
	requesterPubKey string,
	issuerID string,
	validityDays int,
) *VerificationCertificate {
	now := time.Now()

	return &VerificationCertificate{
		CertificateID:    generateCertificateID(),
		CustomerID:       kyc.CustomerID,
		Status:           string(kyc.Status),
		VerifiedBy:       kyc.VerifiedBy,
		VerificationDate: kyc.VerificationDate,
		ExpiresAt:        now.AddDate(0, 0, validityDays).Unix(),
		RequesterID:      requesterID,
		RequesterPubKey:  requesterPubKey,
		KYCSummary: KYCSummary{
			FirstName:   kyc.FirstName,
			LastName:    kyc.LastName,
			Nationality: kyc.Nationality,
			IDType:      kyc.IDType,
			RiskLevel:   kyc.RiskLevel,
			BankID:      kyc.BankID,
		},
		IssuerID: issuerID,
		SignedAt: now.Unix(),
	}
}

// GetPayload returns the payload to be signed
func (vc *VerificationCertificate) GetPayload() CertificatePayload {
	return CertificatePayload{
		CertificateID:    vc.CertificateID,
		CustomerID:       vc.CustomerID,
		Status:           vc.Status,
		VerifiedBy:       vc.VerifiedBy,
		VerificationDate: vc.VerificationDate,
		ExpiresAt:        vc.ExpiresAt,
		RequesterID:      vc.RequesterID,
		RequesterPubKey:  vc.RequesterPubKey,
		KYCSummary:       vc.KYCSummary,
		IssuerID:         vc.IssuerID,
		IssuerKeyID:      vc.IssuerKeyID,
		SignedAt:         vc.SignedAt,
	}
}

// GetPayloadBytes returns serialized payload bytes
func (vc *VerificationCertificate) GetPayloadBytes() ([]byte, error) {
	return json.Marshal(vc.GetPayload())
}

// SignWithKeyManager signs the certificate using KeyManager (supports RSA and ECDSA)
func (vc *VerificationCertificate) SignWithKeyManager(km *kycCrypto.KeyManager) error {
	keyPair := km.GetSystemKeyPair()
	if keyPair == nil {
		return fmt.Errorf("no system key pair available")
	}

	// Set issuer public key
	pubKeyPEM, err := km.GetPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to get public key PEM: %w", err)
	}
	vc.IssuerPubKey = pubKeyPEM
	vc.KeyType = string(keyPair.Type)

	// Get payload bytes
	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	// Sign using KeyManager
	signature, err := km.SignData(payloadBytes)
	if err != nil {
		return fmt.Errorf("failed to sign:  %w", err)
	}

	vc.Signature = signature
	return nil
}

// Sign signs the certificate with RSA private key (legacy support)
func (vc *VerificationCertificate) Sign(privateKey *rsa.PrivateKey, issuerPubKeyPEM string) error {
	vc.IssuerPubKey = issuerPubKeyPEM
	vc.KeyType = "RSA"

	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(payloadBytes)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return err
	}

	vc.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// SignECDSA signs the certificate with ECDSA private key
func (vc *VerificationCertificate) SignECDSA(privateKey *ecdsa.PrivateKey, issuerPubKeyPEM string) error {
	vc.IssuerPubKey = issuerPubKeyPEM
	vc.KeyType = "ECDSA"

	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(payloadBytes)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return err
	}

	vc.Signature = base64.StdEncoding.EncodeToString(signature)
	return nil
}

// VerifyWithKeyManager verifies the certificate using KeyManager
func (vc *VerificationCertificate) VerifyWithKeyManager(km *kycCrypto.KeyManager) error {
	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	return km.VerifySignatureWithKey(payloadBytes, vc.Signature, vc.IssuerPubKey)
}

// Verify verifies the certificate signature with RSA public key (legacy)
func (vc *VerificationCertificate) Verify(publicKey *rsa.PublicKey) error {
	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(payloadBytes)
	signature, err := base64.StdEncoding.DecodeString(vc.Signature)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature)
}

// VerifyECDSA verifies the certificate signature with ECDSA public key
func (vc *VerificationCertificate) VerifyECDSA(publicKey *ecdsa.PublicKey) error {
	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return err
	}

	hash := sha256.Sum256(payloadBytes)
	signature, err := base64.StdEncoding.DecodeString(vc.Signature)
	if err != nil {
		return err
	}

	if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
		return fmt.Errorf("ECDSA signature verification failed")
	}
	return nil
}

// IsExpired checks if certificate is expired
func (vc *VerificationCertificate) IsExpired() bool {
	return time.Now().Unix() > vc.ExpiresAt
}

// IsValid checks if certificate is valid (verified status and not expired)
func (vc *VerificationCertificate) IsValid() bool {
	return vc.Status == string(StatusVerified) && !vc.IsExpired()
}

func generateCertificateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "CERT" + base64.URLEncoding.EncodeToString(b)[:20]
}

// IssuedAt returns the Unix timestamp when the certificate was issued (== SignedAt)
func (vc *VerificationCertificate) IssuedAt() int64 {
	return vc.SignedAt
}

// CustomerName returns a display name from KYCSummary
func (vc *VerificationCertificate) CustomerName() string {
	return vc.KYCSummary.FirstName + " " + vc.KYCSummary.LastName
}

// SignWithSigningManager signs the certificate using the currently active key
// in the signing key registry. Stamps IssuerKeyID + IssuerPubKey + KeyType.
// This is the rotation-aware replacement for SignWithKeyManager.
func (vc *VerificationCertificate) SignWithSigningManager(m *kycCrypto.SigningKeyManager) error {
	priv, keyType, keyID, err := m.ActivePrivate()
	if err != nil {
		return err
	}
	pubPEM, err := m.ActivePublicKeyPEM()
	if err != nil {
		return err
	}

	// Stamp issuer metadata BEFORE computing payload bytes — the signature
	// binds the cert to a specific key version.
	vc.IssuerPubKey = pubPEM
	vc.KeyType = keyType
	vc.IssuerKeyID = keyID
	vc.SignedAt = time.Now().Unix()

	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return err
	}

	// Sign with the active private key
	hash := sha256.Sum256(payloadBytes)
	var sig []byte
	switch pk := priv.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, hash[:])
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, pk, hash[:])
	default:
		err = errors.New("unsupported private key type")
	}
	if err != nil {
		return err
	}
	vc.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// VerifyWithSigningManager is the rotation-aware verifier
// External requesters (banks, fintechs) that verify OFFLINE using the
// public key embedded in the cert still work in both paths — they don't
// need to know about the registry. The registry is OUR extra check when
// WE do the verify.
func (vc *VerificationCertificate) VerifyWithSigningManager(m *kycCrypto.SigningKeyManager) error {
	payloadBytes, err := vc.GetPayloadBytes()
	if err != nil {
		return fmt.Errorf("payload serialize: %w", err)
	}

	// Determine which public key PEM to trust.
	trustedPubPEM := vc.IssuerPubKey // fallback for legacy certs

	if vc.IssuerKeyID != "" {
		registryPEM, lookupErr := m.LookupPublicKey(vc.IssuerKeyID)
		if lookupErr != nil {
			// IssuerKeyID was stamped but we don't have it in our registry.
			// Either data was tampered with or this cert came from a different
			// system. Reject.
			return fmt.Errorf("unknown issuer_key_id %q — certificate not from this system", vc.IssuerKeyID)
		}
		// Consistency check — embedded pubkey should match what's in our registry
		// for that key_id. If not, the cert was tampered with (attacker swapped
		// pubkey hoping we'd trust the embedded value).
		if vc.IssuerPubKey != "" && vc.IssuerPubKey != registryPEM {
			return errors.New("certificate issuer_public_key does not match registry — possible tampering")
		}
		trustedPubPEM = registryPEM
	}

	if trustedPubPEM == "" {
		return errors.New("certificate has no issuer public key and no issuer_key_id")
	}

	// Verify using the manager's generic verify-with-PEM helper.
	// (This internally parses the PEM and picks RSA vs ECDSA.)
	return m.VerifyWithPEM(payloadBytes, vc.Signature, trustedPubPEM)
}
