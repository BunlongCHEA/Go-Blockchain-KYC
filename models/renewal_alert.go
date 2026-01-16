package models

import (
	"fmt"
	"time"
)

// RenewalAlertStatus represents alert status
type RenewalAlertStatus string

const (
	AlertStatusPending   RenewalAlertStatus = "PENDING"
	AlertStatusSent      RenewalAlertStatus = "SENT"
	AlertStatusRenewed   RenewalAlertStatus = "RENEWED"
	AlertStatusExpired   RenewalAlertStatus = "EXPIRED"
	AlertStatusDismissed RenewalAlertStatus = "DISMISSED"
)

// RenewalAlert represents a certificate renewal reminder
type RenewalAlert struct {
	ID             string             `json:"id"`
	CertificateID  string             `json:"certificate_id"`
	CustomerID     string             `json:"customer_id"`
	RequesterID    string             `json:"requester_id"`
	AlertType      string             `json:"alert_type"` // "30_DAY", "7_DAY", "1_DAY", "EXPIRED"
	AlertDate      int64              `json:"alert_date"`
	CertExpiresAt  int64              `json:"cert_expires_at"`
	Status         RenewalAlertStatus `json:"status"`
	WebhookURL     string             `json:"webhook_url,omitempty"`
	EmailRecipient string             `json:"email_recipient,omitempty"`
	SentAt         *int64             `json:"sent_at,omitempty"`
	CreatedAt      int64              `json:"created_at"`
}

// NewRenewalAlert creates a new renewal alert
func NewRenewalAlert(certID, customerID, requesterID, alertType string, alertDate, expiresAt int64) *RenewalAlert {
	return &RenewalAlert{
		ID:            generateAlertID(),
		CertificateID: certID,
		CustomerID:    customerID,
		RequesterID:   requesterID,
		AlertType:     alertType,
		AlertDate:     alertDate,
		CertExpiresAt: expiresAt,
		Status:        AlertStatusPending,
		CreatedAt:     time.Now().Unix(),
	}
}

func generateAlertID() string {
	return fmt.Sprintf("ALRT_%d", time.Now().UnixNano())
}
