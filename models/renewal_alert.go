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
	SentAt         int64              `json:"sent_at"`

	IsActive     bool   `json:"is_active"`
	Delivery     string `json:"delivery"`      // email | webhook | both | none
	SendInterval string `json:"send_interval"` // immediate | daily | weekly

	CreatedAt int64 `json:"created_at"`
}

// NewRenewalAlert creates a new renewal alert
func NewRenewalAlert(certID, customerID, requesterID, alertType string, alertDate, certExpiresAt int64) *RenewalAlert {
	return &RenewalAlert{
		ID:            generateAlertID(), // keep existing ID generation
		CertificateID: certID,
		CustomerID:    customerID,
		RequesterID:   requesterID,
		AlertType:     alertType,
		AlertDate:     alertDate,
		CertExpiresAt: certExpiresAt,
		CreatedAt:     time.Now().Unix(),

		IsActive:     true,
		Status:       "PENDING",
		Delivery:     "none",
		SendInterval: "immediate",
		// webhook_url and email_recipient stay empty — configured later by user
	}
}

func generateAlertID() string {
	return fmt.Sprintf("ALRT_%d", time.Now().UnixNano())
}
