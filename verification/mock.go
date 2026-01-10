package verification

import (
	"math/rand"
	"strings"
	"time"

	"Go-Blockchain-KYC/models"
)

// MockProvider implements VerificationProvider for testing
type MockProvider struct {
	simulateDelay bool
	defaultStatus models.KYCStatus
	randomResults bool
	rng           *rand.Rand
}

// MockConfig holds mock provider configuration
type MockConfig struct {
	SimulateDelay bool
	DefaultStatus models.KYCStatus
	RandomResults bool
}

// NewMockProvider creates a new mock provider
func NewMockProvider(config MockConfig) *MockProvider {
	return &MockProvider{
		simulateDelay: config.SimulateDelay,
		defaultStatus: config.DefaultStatus,
		randomResults: config.RandomResults,
		rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// GetProviderName returns provider name
func (m *MockProvider) GetProviderName() string {
	return "Mock"
}

// VerifyIdentity simulates identity verification
func (m *MockProvider) VerifyIdentity(kyc *models.KYCData) (*VerificationResult, error) {
	// Simulate API delay
	if m.simulateDelay {
		time.Sleep(time.Duration(500+m.rng.Intn(1500)) * time.Millisecond)
	}

	result := &VerificationResult{
		ProviderRef: "MOCK_" + m.generateMockID(),
		Details:     make(map[string]interface{}),
	}

	if m.randomResults {
		return m.generateRandomResult(result), nil
	}

	// Determine status based on KYC data
	status := m.determineStatus(kyc)
	result.Status = status

	// Set result fields based on status
	switch status {
	case models.StatusVerified:
		result.Verified = true
		result.Score = 95.0
		result.DocumentValid = true
		result.FaceMatch = true
		result.AMLCheck = true
		result.PEPCheck = false
		result.AddressVerified = true
		result.RiskLevel = "low"
		result.Reason = "Identity verified successfully"

	case models.StatusRejected:
		result.Verified = false
		result.Score = 25.0
		result.DocumentValid = false
		result.FaceMatch = false
		result.AMLCheck = true
		result.PEPCheck = false
		result.AddressVerified = false
		result.RiskLevel = "high"
		result.Reason = "Document verification failed"

	case models.StatusSuspended:
		result.Verified = false
		result.Score = 50.0
		result.DocumentValid = true
		result.FaceMatch = true
		result.AMLCheck = false
		result.PEPCheck = true
		result.AddressVerified = true
		result.RiskLevel = "high"
		result.Reason = "AML/PEP check failed - manual review required"

	case models.StatusPending:
		result.Verified = false
		result.Score = 60.0
		result.DocumentValid = true
		result.FaceMatch = false
		result.AMLCheck = true
		result.PEPCheck = false
		result.AddressVerified = true
		result.RiskLevel = "medium"
		result.Reason = "Manual review required"
	}

	return result, nil
}

// determineStatus determines status based on KYC data
func (m *MockProvider) determineStatus(kyc *models.KYCData) models.KYCStatus {
	// Use default if set
	if m.defaultStatus != "" {
		return m.defaultStatus
	}

	firstName := strings.ToLower(strings.TrimSpace(kyc.FirstName))
	lastName := strings.ToLower(strings.TrimSpace(kyc.LastName))

	// Check for "reject" keyword
	if strings.Contains(firstName, "reject") || strings.Contains(lastName, "reject") {
		return models.StatusRejected
	}

	// Check for "suspend" keyword
	if strings.Contains(firstName, "suspend") || strings.Contains(lastName, "suspend") {
		return models.StatusSuspended
	}

	// Check for "pending" keyword
	if strings.Contains(firstName, "pending") || strings.Contains(lastName, "pending") {
		return models.StatusPending
	}

	// Default: verified
	return models.StatusVerified
}

// generateRandomResult generates random verification result
func (m *MockProvider) generateRandomResult(result *VerificationResult) *VerificationResult {
	outcomes := []models.KYCStatus{
		models.StatusVerified,
		models.StatusVerified,
		models.StatusVerified,
		models.StatusPending,
		models.StatusRejected,
	}

	result.Status = outcomes[m.rng.Intn(len(outcomes))]

	switch result.Status {
	case models.StatusVerified:
		result.Verified = true
		result.Score = float64(80 + m.rng.Intn(20))
		result.DocumentValid = true
		result.FaceMatch = true
		result.AMLCheck = true
		result.PEPCheck = false
		result.RiskLevel = "low"
		result.Reason = "Identity verified successfully"
	case models.StatusRejected:
		result.Verified = false
		result.Score = float64(20 + m.rng.Intn(30))
		result.DocumentValid = false
		result.FaceMatch = false
		result.RiskLevel = "high"
		result.Reason = "Document verification failed"
	case models.StatusPending:
		result.Verified = false
		result.Score = float64(50 + m.rng.Intn(20))
		result.RiskLevel = "medium"
		result.Reason = "Manual review required"
	}

	return result
}

// generateMockID generates a random mock ID
func (m *MockProvider) generateMockID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, 12)
	for i := range result {
		result[i] = chars[m.rng.Intn(len(chars))]
	}
	return string(result)
}

// VerifyDocument simulates document verification
func (m *MockProvider) VerifyDocument(documentType, documentNumber, country string) (*VerificationResult, error) {
	if m.simulateDelay {
		time.Sleep(300 * time.Millisecond)
	}

	return &VerificationResult{
		Status:        models.StatusVerified,
		DocumentValid: true,
		Score:         95,
		Reason:        "Document verified (mock)",
		ProviderRef:   "MOCK_DOC_" + m.generateMockID(),
	}, nil
}

// CheckAML simulates AML check
func (m *MockProvider) CheckAML(firstName, lastName, dateOfBirth, country string) (*VerificationResult, error) {
	if m.simulateDelay {
		time.Sleep(200 * time.Millisecond)
	}

	firstNameLower := strings.ToLower(firstName)
	lastNameLower := strings.ToLower(lastName)

	isPEP := strings.Contains(firstNameLower, "politician") ||
		strings.Contains(lastNameLower, "politician")

	return &VerificationResult{
		Status:      models.StatusVerified,
		AMLCheck:    true,
		PEPCheck:    isPEP,
		Score:       90,
		Reason:      "AML check passed (mock)",
		ProviderRef: "MOCK_AML_" + m.generateMockID(),
	}, nil
}

// GetVerificationStatus gets verification status
func (m *MockProvider) GetVerificationStatus(referenceID string) (*VerificationResult, error) {
	return &VerificationResult{
		Status:      models.StatusVerified,
		ProviderRef: referenceID,
		Reason:      "Verification complete (mock)",
	}, nil
}
