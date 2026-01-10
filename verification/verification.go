package verification

import (
	"Go-Blockchain-KYC/models"
)

// VerificationResult represents the result from identity verification API
type VerificationResult struct {
	Status          models.KYCStatus       `json:"status"`
	Verified        bool                   `json:"verified"`
	Score           float64                `json:"score"` // Confidence score 0-100
	Reason          string                 `json:"reason"`
	Details         map[string]interface{} `json:"details"`
	ProviderRef     string                 `json:"provider_ref"` // Reference ID from provider
	DocumentValid   bool                   `json:"document_valid"`
	FaceMatch       bool                   `json:"face_match"`
	AddressVerified bool                   `json:"address_verified"`
	AMLCheck        bool                   `json:"aml_check"` // Anti-Money Laundering
	PEPCheck        bool                   `json:"pep_check"` // Politically Exposed Person
	RiskLevel       string                 `json:"risk_level"`
}

// VerificationProvider defines interface for identity verification providers
type VerificationProvider interface {
	// VerifyIdentity verifies customer identity against government database
	VerifyIdentity(kyc *models.KYCData) (*VerificationResult, error)

	// VerifyDocument verifies ID document authenticity
	VerifyDocument(documentType, documentNumber, country string) (*VerificationResult, error)

	// CheckAML performs Anti-Money Laundering check
	CheckAML(firstName, lastName, dateOfBirth, country string) (*VerificationResult, error)

	// GetVerificationStatus gets status of ongoing verification
	GetVerificationStatus(referenceID string) (*VerificationResult, error)

	// GetProviderName returns the provider name
	GetProviderName() string
}

// DetermineKYCStatus determines KYC status based on verification result
func DetermineKYCStatus(result *VerificationResult) models.KYCStatus {
	// Auto-approve if score >= 80 and all checks pass
	if result.Score >= 80 &&
		result.DocumentValid &&
		result.AMLCheck &&
		!result.PEPCheck {
		return models.StatusVerified
	}

	// Auto-reject if score < 30 or document invalid
	if result.Score < 30 || !result.DocumentValid {
		return models.StatusRejected
	}

	// Suspend if PEP or AML issues
	if result.PEPCheck || !result.AMLCheck {
		return models.StatusSuspended
	}

	// Manual review needed
	return models.StatusPending
}
