package verification

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"Go-Blockchain-KYC/models"
)

// TruliooProvider implements VerificationProvider for Trulioo GlobalGateway API
type TruliooProvider struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// TruliooConfig holds Trulioo configuration
type TruliooConfig struct {
	APIKey  string
	BaseURL string
	Timeout time.Duration
}

// NewTruliooProvider creates a new Trulioo provider
func NewTruliooProvider(config TruliooConfig) *TruliooProvider {
	if config.BaseURL == "" {
		config.BaseURL = "https://gateway.trulioo. com"
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	return &TruliooProvider{
		apiKey:  config.APIKey,
		baseURL: config.BaseURL,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// GetProviderName returns provider name
func (t *TruliooProvider) GetProviderName() string {
	return "Trulioo"
}

// VerifyIdentity verifies customer identity against government database
func (t *TruliooProvider) VerifyIdentity(kyc *models.KYCData) (*VerificationResult, error) {
	payload := map[string]interface{}{
		"AcceptTruliooTermsAndConditions": true,
		"ConfigurationName":               "Identity Verification",
		"CountryCode":                     t.getCountryCode(kyc.Address.Country),
		"DataFields": map[string]interface{}{
			"PersonInfo": map[string]string{
				"FirstGivenName": kyc.FirstName,
				"FirstSurName":   kyc.LastName,
				"DayOfBirth":     kyc.DateOfBirth[8:10],
				"MonthOfBirth":   kyc.DateOfBirth[5:7],
				"YearOfBirth":    kyc.DateOfBirth[0:4],
			},
			"Location": map[string]string{
				"StreetName":    kyc.Address.Street,
				"City":          kyc.Address.City,
				"StateProvince": kyc.Address.State,
				"PostalCode":    kyc.Address.PostalCode,
			},
			"Communication": map[string]string{
				"EmailAddress": kyc.Email,
				"Telephone":    kyc.Phone,
			},
			"NationalIds": []map[string]string{
				{
					"Number": kyc.IDNumber,
					"Type":   kyc.IDType,
				},
			},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", t.baseURL+"/verifications/v1/verify", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-trulioo-api-key", t.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return t.parseResult(result), nil
}

// parseResult parses Trulioo verification result
func (t *TruliooProvider) parseResult(result map[string]interface{}) *VerificationResult {
	vr := &VerificationResult{
		Details: result,
	}

	// Get TransactionID as reference
	if txID, ok := result["TransactionID"].(string); ok {
		vr.ProviderRef = txID
	}

	// Parse Record
	record, ok := result["Record"].(map[string]interface{})
	if !ok {
		vr.Status = models.StatusPending
		vr.Reason = "Verification in progress"
		return vr
	}

	// Get RecordStatus
	recordStatus, _ := record["RecordStatus"].(string)

	// Get individual match results
	datasourceResults, _ := record["DatasourceResults"].([]interface{})

	matchScore := 0.0
	totalChecks := 0
	passedChecks := 0

	for _, ds := range datasourceResults {
		dsMap := ds.(map[string]interface{})
		if results, ok := dsMap["Results"].([]interface{}); ok {
			for _, r := range results {
				rMap := r.(map[string]interface{})
				totalChecks++
				if matchResult, ok := rMap["MatchResult"].(string); ok && matchResult == "match" {
					passedChecks++
				}
			}
		}
	}

	if totalChecks > 0 {
		matchScore = float64(passedChecks) / float64(totalChecks) * 100
	}

	vr.Score = matchScore

	// Determine status based on RecordStatus and score
	switch recordStatus {
	case "match":
		if matchScore >= 80 {
			vr.Status = models.StatusVerified
			vr.Verified = true
			vr.DocumentValid = true
			vr.RiskLevel = "low"
		} else {
			vr.Status = models.StatusPending
			vr.Reason = "Partial match - manual review required"
			vr.RiskLevel = "medium"
		}
	case "nomatch":
		vr.Status = models.StatusRejected
		vr.Verified = false
		vr.DocumentValid = false
		vr.RiskLevel = "high"
		vr.Reason = "Identity verification failed - no match found"
	case "watchlist_hit":
		vr.Status = models.StatusSuspended
		vr.PEPCheck = true
		vr.RiskLevel = "high"
		vr.Reason = "Watchlist hit detected"
	default:
		vr.Status = models.StatusPending
		vr.Reason = "Verification status:  " + recordStatus
	}

	return vr
}

// getCountryCode converts country name to ISO code
func (t *TruliooProvider) getCountryCode(country string) string {
	countryCodes := map[string]string{
		"Cambodia":      "KH",
		"USA":           "US",
		"United States": "US",
		"Thailand":      "TH",
		"Vietnam":       "VN",
		"Singapore":     "SG",
		"Malaysia":      "MY",
	}

	if code, ok := countryCodes[country]; ok {
		return code
	}
	return country
}

// VerifyDocument verifies document
func (t *TruliooProvider) VerifyDocument(documentType, documentNumber, country string) (*VerificationResult, error) {
	return &VerificationResult{
		Status: models.StatusPending,
		Reason: "Document verification not implemented",
	}, nil
}

// CheckAML performs AML check
func (t *TruliooProvider) CheckAML(firstName, lastName, dateOfBirth, country string) (*VerificationResult, error) {
	return &VerificationResult{
		Status:   models.StatusPending,
		AMLCheck: true,
	}, nil
}

// GetVerificationStatus gets verification status
func (t *TruliooProvider) GetVerificationStatus(referenceID string) (*VerificationResult, error) {
	req, err := http.NewRequest("GET", t.baseURL+"/verifications/v1/transactionrecord/"+referenceID, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("x-trulioo-api-key", t.apiKey)

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return t.parseResult(result), nil
}
