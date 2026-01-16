package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/storage"
)

// AlertService handles renewal alert notifications
type AlertService struct {
	storage     storage.Storage
	stopChannel chan struct{}
	httpClient  *http.Client
}

// NewAlertService creates a new alert service
func NewAlertService(store storage.Storage) *AlertService {
	return &AlertService{
		storage:     store,
		stopChannel: make(chan struct{}),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Start starts the alert service (runs every hour)
func (s *AlertService) Start() {
	go s.processAlertsLoop()
	log.Println("   ✓ Alert service started")
}

// Stop stops the alert service
func (s *AlertService) Stop() {
	close(s.stopChannel)
	log.Println("   Alert service stopped")
}

func (s *AlertService) processAlertsLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	// Process immediately on start
	s.processAlerts()

	for {
		select {
		case <-ticker.C:
			s.processAlerts()
		case <-s.stopChannel:
			return
		}
	}
}

func (s *AlertService) processAlerts() {
	if s.storage == nil {
		return
	}

	alerts, err := s.storage.GetPendingRenewalAlerts()
	if err != nil {
		log.Printf("Failed to get pending alerts: %v", err)
		return
	}

	for _, alert := range alerts {
		s.sendAlert(alert)
	}
}

func (s *AlertService) sendAlert(alert *models.RenewalAlert) {
	daysUntilExpiry := int((alert.CertExpiresAt - time.Now().Unix()) / 86400)

	notification := map[string]interface{}{
		"type":              "CERTIFICATE_RENEWAL_REMINDER",
		"alert_id":          alert.ID,
		"certificate_id":    alert.CertificateID,
		"customer_id":       alert.CustomerID,
		"alert_type":        alert.AlertType,
		"days_until_expiry": daysUntilExpiry,
		"expires_at":        alert.CertExpiresAt,
		"expires_at_human":  time.Unix(alert.CertExpiresAt, 0).Format("2006-01-02 15:04:05"),
		"action_required":   "Please renew certificate by calling POST /api/v1/certificate/issue",
		"timestamp":         time.Now().Unix(),
	}

	// Send via webhook if configured
	if alert.WebhookURL != "" {
		if err := s.sendWebhook(alert.WebhookURL, notification); err != nil {
			log.Printf("Failed to send webhook for alert %s: %v", alert.ID, err)
			return
		}
	}

	// Send via email if configured
	if alert.EmailRecipient != "" {
		s.sendEmail(alert.EmailRecipient, notification)
	}

	// Update alert status
	s.storage.UpdateRenewalAlertStatus(alert.ID, models.AlertStatusSent)

	log.Printf("Renewal alert sent:  %s for certificate %s (%d days until expiry)",
		alert.AlertType, alert.CertificateID, daysUntilExpiry)
}

func (s *AlertService) sendWebhook(url string, data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Source", "KYC-BLOCKCHAIN-SYSTEM")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func (s *AlertService) sendEmail(recipient string, data map[string]interface{}) {
	// Email implementation - integrate with your email service
	// Example: SendGrid, AWS SES, etc.
	log.Printf("Email alert would be sent to %s:  %v", recipient, data)
}
