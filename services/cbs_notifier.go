package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"Go-Blockchain-KYC/config"
	"Go-Blockchain-KYC/models"
)

// // CBSWebhookPayload is the request body sent to the Core Banking System
// // when a customer KYC status changes to EXPIRED or SUSPENDED.
// type CBSWebhookPayload struct {
// 	CustomerID string `json:"customer_id"` // Go_KYC customer_id == CBS customer_code
// 	KycStatus  string `json:"kyc_status"`
// 	Timestamp  int64  `json:"timestamp"`
// }

// CBSNotifier sends KYC status-change webhooks to CBS via the NextJS gateway.
// URL   → config.json  cbs_integration.nextjs_webhook_url  (not a secret, safe to commit)
// Key   → env only     NEXTJS_INTEGRATION_KEY               (secret, never in config file)
type CBSNotifier struct {
	cfg        *config.CBSIntegrationConfig
	httpClient *http.Client
}

// NewCBSNotifier creates a notifier wired to the CBS integration config.
// Pass cfg = &appConfig.CBSIntegration from main.go.
func NewCBSNotifier(cfg *config.CBSIntegrationConfig) *CBSNotifier {
	return &CBSNotifier{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// NotifyStatusChange fires when KYC status → SUSPENDED or EXPIRED.
// Best-effort: errors are returned but callers should log and continue.
func (n *CBSNotifier) NotifyStatusChange(customerID string, status models.KYCStatus) error {
	if status != models.StatusSuspended && status != models.StatusExpired {
		return nil // nothing to do for other statuses
	}

	webhookURL := n.cfg.GetNextJSWebhookURL()
	rawKey := n.cfg.GetIntegrationKey()

	if webhookURL == "" {
		log.Printf("[CBSNotifier] NEXTJS_KYC_WEBHOOK_URL not configured — skipping notify")
		return nil
	}
	if rawKey == "" {
		return fmt.Errorf("CBSNotifier: NEXTJS_INTEGRATION_KEY env var is not set")
	}

	payload, err := json.Marshal(map[string]interface{}{
		"customer_id": customerID,
		"kyc_status":  string(status),
		"timestamp":   time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("CBSNotifier: marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("CBSNotifier: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+rawKey) // NextJS validates this

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("CBSNotifier: send to NextJS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("CBSNotifier: NextJS responded %d for customer %s", resp.StatusCode, customerID)
	}

	log.Printf("[CBSNotifier] Notified NextJS → CBS: customer=%s status=%s", customerID, status)
	return nil
}
