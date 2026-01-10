package verification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"Go-Blockchain-KYC/models"
)

// DiditProvider implements VerificationProvider for Didit API
type DiditProvider struct {
	clientID     string
	clientSecret string
	baseURL      string
	accessToken  string
	tokenExpiry  time.Time
	httpClient   *http.Client
}

// DiditConfig holds Didit configuration
type DiditConfig struct {
	ClientID     string
	ClientSecret string
	BaseURL      string
	Timeout      time.Duration
}

// NewDiditProvider creates a new Didit provider
func NewDiditProvider(config DiditConfig) *DiditProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://apx.didit.me"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &DiditProvider{
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		baseURL:      config.BaseURL,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// GetProviderName returns provider name
func (d *DiditProvider) GetProviderName() string {
	return "Didit"
}

// authenticate gets access token from Didit
func (d *DiditProvider) authenticate() error {
	// Check if token is still valid
	if d.accessToken != "" && time.Now().Before(d.tokenExpiry) {
		return nil
	}

	payload := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     d.clientID,
		"client_secret": d.clientSecret,
		"scope":         "openid",
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", d.baseURL+"/auth/v2/token", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("auth failed with status:  %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	d.accessToken = result.AccessToken
	d.tokenExpiry = time.Now().Add(time.Duration(result.ExpiresIn-60) * time.Second)

	return nil
}

// VerifyIdentity verifies customer identity using Didit
func (d *DiditProvider) VerifyIdentity(kyc *models.KYCData) (*VerificationResult, error) {
	// Authenticate first
	if err := d.authenticate(); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Step 1: Create verification session
	sessionID, err := d.createSession(kyc)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Step 2: Submit documents for verification
	err = d.submitDocuments(sessionID, kyc)
	if err != nil {
		return nil, fmt.Errorf("failed to submit documents: %w", err)
	}

	// Step 3: Get verification result
	result, err := d.getVerificationResult(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get result: %w", err)
	}

	return result, nil
}

// createSession creates a verification session
func (d *DiditProvider) createSession(kyc *models.KYCData) (string, error) {
	payload := map[string]interface{}{
		"vendor_data": kyc.CustomerID,
		"callback":    "", // Optional webhook URL
		"features":    []string{"ocr", "face", "document", "aml"},
		"document_types": []string{
			d.mapDocumentType(kyc.IDType),
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", d.baseURL+"/v1/session/", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.accessToken)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		SessionID string `json:"session_id"`
		URL       string `json:"url"`
		Status    string `json:"status"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.SessionID, nil
}

// submitDocuments submits KYC data for verification
func (d *DiditProvider) submitDocuments(sessionID string, kyc *models.KYCData) error {
	payload := map[string]interface{}{
		"session_id": sessionID,
		"person": map[string]interface{}{
			"first_name":    kyc.FirstName,
			"last_name":     kyc.LastName,
			"date_of_birth": kyc.DateOfBirth,
			"nationality":   kyc.Nationality,
			"email":         kyc.Email,
			"phone":         kyc.Phone,
		},
		"document": map[string]interface{}{
			"type":        d.mapDocumentType(kyc.IDType),
			"number":      kyc.IDNumber,
			"expiry_date": kyc.IDExpiryDate,
			"country":     kyc.Address.Country,
		},
		"address": map[string]interface{}{
			"street":      kyc.Address.Street,
			"city":        kyc.Address.City,
			"state":       kyc.Address.State,
			"postal_code": kyc.Address.PostalCode,
			"country":     kyc.Address.Country,
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("PUT", d.baseURL+"/v1/session/"+sessionID+"/kyc", bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.accessToken)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("submit failed with status: %d", resp.StatusCode)
	}

	return nil
}

// getVerificationResult retrieves verification result
func (d *DiditProvider) getVerificationResult(sessionID string) (*VerificationResult, error) {
	req, err := http.NewRequest("GET", d.baseURL+"/v1/session/"+sessionID+"/decision/", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+d.accessToken)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result DiditDecisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return d.parseDecision(&result), nil
}

// DiditDecisionResponse represents Didit API decision response
type DiditDecisionResponse struct {
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
	Decision  string `json:"decision"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	// Verification details
	Document struct {
		Status   string  `json:"status"`
		Decision string  `json:"decision"`
		Score    float64 `json:"score"`
		Details  struct {
			Type       string `json:"type"`
			Number     string `json:"number"`
			ExpiryDate string `json:"expiry_date"`
			Country    string `json:"country"`
			Valid      bool   `json:"valid"`
			Expired    bool   `json:"expired"`
		} `json:"details"`
	} `json:"document"`

	Face struct {
		Status   string  `json:"status"`
		Decision string  `json:"decision"`
		Score    float64 `json:"score"`
		Match    bool    `json:"match"`
	} `json:"face"`

	AML struct {
		Status   string `json:"status"`
		Decision string `json:"decision"`
		Hits     []struct {
			Name       string   `json:"name"`
			Type       string   `json:"type"`
			Sources    []string `json:"sources"`
			MatchScore float64  `json:"match_score"`
		} `json:"hits"`
		PEP       bool `json:"pep"`
		Sanctions bool `json:"sanctions"`
		Watchlist bool `json:"watchlist"`
	} `json:"aml"`

	OCR struct {
		Status   string `json:"status"`
		Decision string `json:"decision"`
		Data     struct {
			FirstName   string `json:"first_name"`
			LastName    string `json:"last_name"`
			DateOfBirth string `json:"date_of_birth"`
			Nationality string `json:"nationality"`
			DocumentNo  string `json:"document_number"`
		} `json:"data"`
	} `json:"ocr"`

	RiskScore float64  `json:"risk_score"`
	RiskLevel string   `json:"risk_level"`
	Reasons   []string `json:"reasons"`
}

// parseDecision parses Didit decision response
func (d *DiditProvider) parseDecision(resp *DiditDecisionResponse) *VerificationResult {
	vr := &VerificationResult{
		ProviderRef: resp.SessionID,
		Score:       resp.RiskScore,
		RiskLevel:   resp.RiskLevel,
		Details: map[string]interface{}{
			"session_id": resp.SessionID,
			"document":   resp.Document,
			"face":       resp.Face,
			"aml":        resp.AML,
			"ocr":        resp.OCR,
			"decision":   resp.Decision,
			"reasons":    resp.Reasons,
		},
	}

	// Document validation
	vr.DocumentValid = resp.Document.Decision == "approved" &&
		resp.Document.Details.Valid &&
		!resp.Document.Details.Expired

	// Face match
	vr.FaceMatch = resp.Face.Match && resp.Face.Decision == "approved"

	// AML checks
	vr.AMLCheck = resp.AML.Decision == "approved" && !resp.AML.Sanctions
	vr.PEPCheck = resp.AML.PEP

	// Address verification (based on OCR match)
	vr.AddressVerified = resp.OCR.Decision == "approved"

	// Determine status based on decision
	switch resp.Decision {
	case "approved", "Approved":
		vr.Status = models.StatusVerified
		vr.Verified = true
		vr.Reason = "Identity verified successfully"

	case "declined", "Declined":
		vr.Status = models.StatusRejected
		vr.Verified = false
		if len(resp.Reasons) > 0 {
			vr.Reason = resp.Reasons[0]
		} else {
			vr.Reason = "Identity verification failed"
		}

	case "review", "Review":
		// Check specific issues
		if resp.AML.PEP || resp.AML.Sanctions || resp.AML.Watchlist {
			vr.Status = models.StatusSuspended
			vr.Reason = "AML/PEP check requires manual review"
		} else {
			vr.Status = models.StatusPending
			vr.Reason = "Manual review required"
		}

	default:
		vr.Status = models.StatusPending
		vr.Reason = "Verification in progress:  " + resp.Status
	}

	// Override status based on specific checks
	if resp.AML.Sanctions {
		vr.Status = models.StatusSuspended
		vr.Reason = "Sanctions list match detected"
	}

	if resp.Document.Details.Expired {
		vr.Status = models.StatusRejected
		vr.Reason = "Document has expired"
	}

	// Calculate confidence score if not provided
	if vr.Score == 0 {
		vr.Score = d.calculateScore(resp)
	}

	return vr
}

// calculateScore calculates a confidence score
func (d *DiditProvider) calculateScore(resp *DiditDecisionResponse) float64 {
	score := 0.0
	maxScore := 100.0

	// Document score (40 points)
	if resp.Document.Decision == "approved" {
		score += 40 * (resp.Document.Score / 100)
	}

	// Face match score (25 points)
	if resp.Face.Match {
		score += 25 * (resp.Face.Score / 100)
	}

	// AML clear (20 points)
	if resp.AML.Decision == "approved" && !resp.AML.PEP && !resp.AML.Sanctions {
		score += 20
	}

	// OCR match (15 points)
	if resp.OCR.Decision == "approved" {
		score += 15
	}

	return (score / maxScore) * 100
}

// mapDocumentType maps KYC ID type to Didit document type
func (d *DiditProvider) mapDocumentType(idType string) string {
	documentTypes := map[string]string{
		"passport":         "passport",
		"national_id":      "national_identity_card",
		"driver_license":   "driving_license",
		"residence_permit": "residence_permit",
	}

	if dt, ok := documentTypes[idType]; ok {
		return dt
	}
	return "national_identity_card"
}

// VerifyDocument verifies document only
func (d *DiditProvider) VerifyDocument(documentType, documentNumber, country string) (*VerificationResult, error) {
	if err := d.authenticate(); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"document_type":   d.mapDocumentType(documentType),
		"document_number": documentNumber,
		"country":         country,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", d.baseURL+"/v1/document/verify", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.accessToken)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Valid   bool   `json:"valid"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}

	json.NewDecoder(resp.Body).Decode(&result)

	return &VerificationResult{
		DocumentValid: result.Valid,
		Status:        models.StatusPending,
		Reason:        result.Message,
	}, nil
}

// CheckAML performs AML check only
func (d *DiditProvider) CheckAML(firstName, lastName, dateOfBirth, country string) (*VerificationResult, error) {
	if err := d.authenticate(); err != nil {
		return nil, err
	}

	payload := map[string]interface{}{
		"first_name":    firstName,
		"last_name":     lastName,
		"date_of_birth": dateOfBirth,
		"country":       country,
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", d.baseURL+"/v1/aml/check", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.accessToken)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Clear     bool   `json:"clear"`
		PEP       bool   `json:"pep"`
		Sanctions bool   `json:"sanctions"`
		Watchlist bool   `json:"watchlist"`
		Message   string `json:"message"`
	}

	json.NewDecoder(resp.Body).Decode(&result)

	vr := &VerificationResult{
		AMLCheck: result.Clear,
		PEPCheck: result.PEP,
		Reason:   result.Message,
	}

	if result.Sanctions || result.Watchlist {
		vr.Status = models.StatusSuspended
	} else if result.Clear {
		vr.Status = models.StatusVerified
	} else {
		vr.Status = models.StatusPending
	}

	return vr, nil
}

// GetVerificationStatus gets status of ongoing verification
func (d *DiditProvider) GetVerificationStatus(referenceID string) (*VerificationResult, error) {
	if err := d.authenticate(); err != nil {
		return nil, err
	}

	return d.getVerificationResult(referenceID)
}
