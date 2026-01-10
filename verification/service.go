package verification

import (
	"fmt"
	"log"

	"Go-Blockchain-KYC/models"
)

// VerificationService handles identity verification
type VerificationService struct {
	providers       []VerificationProvider
	primaryProvider VerificationProvider
	autoApprove     bool
	minScore        float64
}

// VerificationConfig holds verification service configuration
type VerificationConfig struct {
	AutoApprove bool
	MinScore    float64
}

// NewVerificationService creates a new verification service
func NewVerificationService(config VerificationConfig) *VerificationService {
	return &VerificationService{
		providers:   []VerificationProvider{},
		autoApprove: config.AutoApprove,
		minScore:    config.MinScore,
	}
}

// AddProvider adds a verification provider
func (v *VerificationService) AddProvider(provider VerificationProvider) {
	v.providers = append(v.providers, provider)
	if v.primaryProvider == nil {
		v.primaryProvider = provider
	}
}

// SetPrimaryProvider sets the primary verification provider
func (v *VerificationService) SetPrimaryProvider(provider VerificationProvider) {
	v.primaryProvider = provider
}

// VerifyKYC verifies KYC data and returns result with auto-determined status
func (v *VerificationService) VerifyKYC(kyc *models.KYCData) (*VerificationResult, error) {
	if v.primaryProvider == nil {
		return nil, fmt.Errorf("no verification provider configured")
	}

	log.Printf("Starting verification for customer %s using %s",
		kyc.CustomerID, v.primaryProvider.GetProviderName())

	// Call primary provider
	result, err := v.primaryProvider.VerifyIdentity(kyc)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	// Auto-determine status if enabled
	if v.autoApprove {
		result.Status = DetermineKYCStatus(result)
	}

	log.Printf("Verification result for %s: Status=%s, Score=%.2f",
		kyc.CustomerID, result.Status, result.Score)

	return result, nil
}

// VerifyWithAllProviders verifies with all providers and combines results
func (v *VerificationService) VerifyWithAllProviders(kyc *models.KYCData) (*VerificationResult, error) {
	if len(v.providers) == 0 {
		return nil, fmt.Errorf("no verification providers configured")
	}

	combinedResult := &VerificationResult{
		Score:   0,
		Details: make(map[string]interface{}),
	}

	totalScore := 0.0
	providerResults := make(map[string]*VerificationResult)

	for _, provider := range v.providers {
		result, err := provider.VerifyIdentity(kyc)
		if err != nil {
			log.Printf("Provider %s failed:  %v", provider.GetProviderName(), err)
			continue
		}

		providerResults[provider.GetProviderName()] = result
		totalScore += result.Score

		// Combine boolean checks (all must pass)
		combinedResult.DocumentValid = combinedResult.DocumentValid || result.DocumentValid
		combinedResult.FaceMatch = combinedResult.FaceMatch || result.FaceMatch
		combinedResult.AMLCheck = combinedResult.AMLCheck && result.AMLCheck
		combinedResult.PEPCheck = combinedResult.PEPCheck || result.PEPCheck
	}

	// Calculate average score
	if len(providerResults) > 0 {
		combinedResult.Score = totalScore / float64(len(providerResults))
	}

	combinedResult.Details["provider_results"] = providerResults
	combinedResult.Status = DetermineKYCStatus(combinedResult)

	return combinedResult, nil
}
