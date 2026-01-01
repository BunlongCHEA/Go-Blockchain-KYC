package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

// GenerateCustomerID generates a unique customer ID
func GenerateCustomerID(firstName, lastName, dob string) string {
	data := fmt.Sprintf("%s%s%s%d", firstName, lastName, dob, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return "CUS" + hex.EncodeToString(hash[:])[:12]
}

// GenerateBankID generates a unique bank ID
func GenerateBankID(bankName string) string {
	data := fmt.Sprintf("%s%d", bankName, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return "BANK" + hex.EncodeToString(hash[:])[:8]
}

// HashDocument hashes document content for verification
func HashDocument(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}

// ValidatePhone validates phone number format
func ValidatePhone(phone string) bool {
	pattern := `^\+?[1-9]\d{1,14}$`
	matched, _ := regexp.MatchString(pattern, phone)
	return matched
}

// ValidateDateFormat validates date format (YYYY-MM-DD)
func ValidateDateFormat(date string) bool {
	pattern := `^\d{4}-\d{2}-\d{2}$`
	matched, _ := regexp.MatchString(pattern, date)
	return matched
}

// ValidateIDType checks if ID type is valid
func ValidateIDType(idType string) bool {
	validTypes := map[string]bool{
		"passport":       true,
		"national_id":    true,
		"driver_license": true,
	}
	return validTypes[idType]
}

// FormatTimestamp formats Unix timestamp to readable date
func FormatTimestamp(timestamp int64) string {
	t := time.Unix(timestamp, 0)
	return t.Format("2006-01-02 15:04:05")
}

// CalculateRiskLevel calculates risk level based on various factors
func CalculateRiskLevel(nationality string, highRiskCountries []string) string {
	riskScore := 0

	for _, country := range highRiskCountries {
		if nationality == country {
			riskScore += 3
			break
		}
	}

	switch {
	case riskScore >= 3:
		return "high"
	case riskScore >= 1:
		return "medium"
	default:
		return "low"
	}
}

// StringInSlice checks if a string exists in a slice
func StringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// MinInt returns the minimum of two integers
func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MaxInt returns the maximum of two integers
func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
