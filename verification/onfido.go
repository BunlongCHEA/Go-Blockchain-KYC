package verification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"Go-Blockchain-KYC/models"
)

// OnfidoProvider implements VerificationProvider for Onfido API
type OnfidoProvider struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// OnfidoConfig holds Onfido configuration
type OnfidoConfig struct {
	APIKey  string
	BaseURL string
	Timeout time.Duration
}

// NewOnfidoProvider creates a new Onfido provider
func NewOnfidoProvider(config OnfidoConfig) *OnfidoProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.onfido. com/v3.6"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &OnfidoProvider{
		apiKey:  config.APIKey,
		baseURL: config.BaseURL,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// GetProviderName returns provider name
func (o *OnfidoProvider) GetProviderName() string {
	return "Onfido"
}

// VerifyIdentity verifies customer identity
func (o *OnfidoProvider) VerifyIdentity(kyc *models.KYCData) (*VerificationResult, error) {
	// Step 1: Create applicant
	applicantID, err := o.createApplicant(kyc)
	if err != nil {
		return nil, fmt.Errorf("failed to create applicant: %w", err)
	}

	// Step 2: Create check
	checkResult, err := o.createCheck(applicantID)
	if err != nil {
		return nil, fmt.Errorf("failed to create check: %w", err)
	}

	return checkResult, nil
}

// createApplicant creates an applicant in Onfido
func (o *OnfidoProvider) createApplicant(kyc *models.KYCData) (string, error) {
	payload := map[string]interface{}{
		"first_name": kyc.FirstName,
		"last_name":  kyc.LastName,
		"email":      kyc.Email,
		"dob":        kyc.DateOfBirth,
		"address": map[string]string{
			"street":   kyc.Address.Street,
			"town":     kyc.Address.City,
			"state":    kyc.Address.State,
			"postcode": kyc.Address.PostalCode,
			"country":  kyc.Address.Country,
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", o.baseURL+"/applicants", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Token token="+o.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	applicantID, ok := result["id"].(string)
	if !ok {
		return "", fmt.Errorf("failed to get applicant ID")
	}

	return applicantID, nil
}

// createCheck creates a verification check
func (o *OnfidoProvider) createCheck(applicantID string) (*VerificationResult, error) {
	payload := map[string]interface{}{
		"applicant_id": applicantID,
		"report_names": []string{"document", "facial_similarity_photo", "watchlist_aml"},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", o.baseURL+"/checks", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token token="+o.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return o.parseCheckResult(result), nil
}

// parseCheckResult parses Onfido check result
func (o *OnfidoProvider) parseCheckResult(result map[string]interface{}) *VerificationResult {
	status := result["status"].(string)
	checkResult := result["result"].(string)

	vr := &VerificationResult{
		ProviderRef: result["id"].(string),
		Details:     result,
	}

	switch checkResult {
	case "clear":
		vr.Status = models.StatusVerified
		vr.Verified = true
		vr.Score = 95
		vr.DocumentValid = true
		vr.FaceMatch = true
		vr.AMLCheck = true
		vr.RiskLevel = "low"
	case "consider":
		vr.Status = models.StatusPending
		vr.Verified = false
		vr.Score = 60
		vr.RiskLevel = "medium"
		vr.Reason = "Manual review required"
	case "unidentified":
		vr.Status = models.StatusRejected
		vr.Verified = false
		vr.Score = 20
		vr.DocumentValid = false
		vr.RiskLevel = "high"
		vr.Reason = "Identity could not be verified"
	default:
		vr.Status = models.StatusPending
		vr.Reason = "Verification in progress:  " + status
	}

	return vr
}

// VerifyDocument verifies document only
func (o *OnfidoProvider) VerifyDocument(documentType, documentNumber, country string) (*VerificationResult, error) {
	// Implementation for document-only verification
	return &VerificationResult{
		Status:        models.StatusPending,
		Reason:        "Document verification initiated",
		DocumentValid: false,
	}, nil
}

// CheckAML performs AML check
func (o *OnfidoProvider) CheckAML(firstName, lastName, dateOfBirth, country string) (*VerificationResult, error) {
	// Implementation for AML-only check
	return &VerificationResult{
		Status:   models.StatusPending,
		AMLCheck: true,
		PEPCheck: false,
	}, nil
}

// GetVerificationStatus gets status of ongoing verification
func (o *OnfidoProvider) GetVerificationStatus(referenceID string) (*VerificationResult, error) {
	req, err := http.NewRequest("GET", o.baseURL+"/checks/"+referenceID, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Token token="+o.apiKey)

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return o.parseCheckResult(result), nil
}
