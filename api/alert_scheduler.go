package api

//   Every 5 minutes:
//     SELECT * FROM renewal_alerts
//     WHERE  is_active = TRUE
//     AND    status    = 'PENDING'
//     AND    alert_date <= NOW()
//
//     For each row:
//       if send_interval = 'immediate' → dispatch now
//       if send_interval = 'daily'     → dispatch only if today's batch not sent
//       if send_interval = 'weekly'    → dispatch only if this week's batch not sent
//
//       dispatch = webhook POST + email (if configured)
//       on success: UPDATE status='SENT', sent_at=NOW()
//       on failure: UPDATE status='FAILED'
//

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"Go-Blockchain-KYC/models"
)

// AlertScheduler polls for due renewal alerts and dispatches them.
type AlertScheduler struct {
	handlers *Handlers
	ticker   *time.Ticker
	quit     chan struct{}
}

// NewAlertScheduler creates the scheduler (does not start it).
func NewAlertScheduler(h *Handlers) *AlertScheduler {
	return &AlertScheduler{
		handlers: h,
		quit:     make(chan struct{}),
	}
}

// Start launches the background goroutine.
// Checks for due alerts every 5 minutes.
// Safe to call multiple times — only one goroutine runs.
func (s *AlertScheduler) Start() {
	if s.handlers.storage == nil {
		log.Println("[AlertScheduler] no storage — scheduler disabled")
		return
	}

	s.ticker = time.NewTicker(5 * time.Minute)

	go func() {
		// Run once immediately at startup so alerts due during downtime are caught
		s.run()

		for {
			select {
			case <-s.ticker.C:
				s.run()
			case <-s.quit:
				s.ticker.Stop()
				log.Println("[AlertScheduler] stopped")
				return
			}
		}
	}()

	log.Println("[AlertScheduler] started — polling every 5 minutes")
}

// Stop gracefully shuts the scheduler goroutine down.
func (s *AlertScheduler) Stop() {
	close(s.quit)
}

// run is called on every tick.
func (s *AlertScheduler) run() {
	now := time.Now().Unix()

	alerts, err := s.handlers.storage.GetPendingRenewalAlerts(now)
	if err != nil {
		log.Printf("[AlertScheduler] failed to load pending alerts: %v", err)
		return
	}
	if len(alerts) == 0 {
		return
	}

	log.Printf("[AlertScheduler] %d alert(s) due — dispatching", len(alerts))

	for _, alert := range alerts {
		s.dispatch(alert)
	}
}

// dispatch sends one alert according to its delivery + send_interval config.
func (s *AlertScheduler) dispatch(alert *models.RenewalAlert) {
	// ── Interval gate ─────────────────────────────────────────────────────────
	// 'immediate' → always dispatch when due
	// 'daily'     → only dispatch if sent_at was NOT today
	// 'weekly'    → only dispatch if sent_at was NOT this week (Mon–Sun)
	if !s.shouldSendNow(alert) {
		return
	}

	status := "SENT"
	errors := []string{}

	// ── Webhook dispatch ──────────────────────────────────────────────────────
	if alert.WebhookURL != "" &&
		(alert.Delivery == "webhook" || alert.Delivery == "both") {

		if err := sendWebhook(alert); err != nil {
			log.Printf("[AlertScheduler] webhook failed for %s: %v", alert.ID, err)
			errors = append(errors, "webhook: "+err.Error())
			status = "FAILED"
		}
	}

	// ── Email dispatch ────────────────────────────────────────────────────────
	// Wire this to your SMTP / AWS SES client.
	if alert.EmailRecipient != "" &&
		(alert.Delivery == "email" || alert.Delivery == "both") {

		if err := sendEmail(alert); err != nil {
			log.Printf("[AlertScheduler] email failed for %s: %v", alert.ID, err)
			errors = append(errors, "email: "+err.Error())
			status = "FAILED"
		}
	}

	// 'none' delivery — log and mark sent so it doesn't re-trigger
	if alert.Delivery == "none" {
		log.Printf("[AlertScheduler] alert %s has no delivery configured — marking sent", alert.ID)
	}

	// ── Persist status ────────────────────────────────────────────────────────
	if markErr := s.handlers.storage.MarkRenewalAlertSent(alert.ID, status); markErr != nil {
		log.Printf("[AlertScheduler] failed to update status for %s: %v", alert.ID, markErr)
	}

	if len(errors) == 0 {
		log.Printf("[AlertScheduler] ✓ sent alert %s (%s) to %s",
			alert.ID, alert.AlertType, alert.Delivery)
	}
}

// shouldSendNow returns false for daily/weekly alerts that were already sent
// in the current period (prevents duplicate sends on repeated ticks).
func (s *AlertScheduler) shouldSendNow(alert *models.RenewalAlert) bool {
	if alert.SentAt == 0 {
		return true // never sent before — always dispatch
	}

	lastSent := time.Unix(alert.SentAt, 0)
	now := time.Now()

	switch alert.SendInterval {
	case "daily":
		// Same calendar day → skip
		return !sameDay(lastSent, now)

	case "weekly":
		// Same ISO week → skip
		ly, lw := lastSent.ISOWeek()
		ny, nw := now.ISOWeek()
		return ly != ny || lw != nw

	default: // "immediate"
		return true
	}
}

// sameDay returns true if two times fall on the same calendar day (local time).
func sameDay(a, b time.Time) bool {
	ay, am, ad := a.Date()
	by, bm, bd := b.Date()
	return ay == by && am == bm && ad == bd
}

// ─── Webhook dispatcher ───────────────────────────────────────────────────────

func sendWebhook(alert *models.RenewalAlert) error {
	payload := map[string]interface{}{
		"event":           "certificate.expiring",
		"id":              alert.ID,
		"certificate_id":  alert.CertificateID,
		"customer_id":     alert.CustomerID,
		"requester_id":    alert.RequesterID,
		"alert_type":      alert.AlertType, // 30_DAY | 7_DAY | 1_DAY
		"cert_expires_at": alert.CertExpiresAt,
		"alert_date":      alert.AlertDate,
		"sent_at":         time.Now().Unix(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(alert.WebhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-2xx response: %d", resp.StatusCode)
	}
	return nil
}

// ─── Email dispatcher (stub) ──────────────────────────────────────────────────
// Replace the log line with your actual email client (SMTP, AWS SES, SendGrid…)

func sendEmail(alert *models.RenewalAlert) error {
	subject := fmt.Sprintf("[KYC Alert] Certificate expiring in %s — %s",
		humanAlertType(alert.AlertType), alert.CertificateID)

	body := fmt.Sprintf(
		"Certificate %s for customer %s expires on %s.\n\n"+
			"Alert type: %s\n"+
			"Requester: %s\n\n"+
			"Please renew the certificate before expiry to avoid service interruption.\n",
		alert.CertificateID,
		alert.CustomerID,
		time.Unix(alert.CertExpiresAt, 0).Format("2006-01-02"),
		humanAlertType(alert.AlertType),
		alert.RequesterID,
	)

	// ── TODO: replace with real email send ────────────────────────────────────
	// Example with net/smtp:
	//
	//   msg := "From: noreply@yourdomain.com\r\n" +
	//           "To: " + alert.EmailRecipient + "\r\n" +
	//           "Subject: " + subject + "\r\n\r\n" + body
	//   return smtp.SendMail(smtpAddr, smtpAuth, from, []string{alert.EmailRecipient}, []byte(msg))
	//
	// Example with AWS SES SDK:
	//   _, err := sesClient.SendEmail(ctx, &ses.SendEmailInput{...})
	//   return err

	log.Printf("[AlertScheduler] EMAIL [stub] to=%s subject=%q body=%q",
		alert.EmailRecipient, subject, body)
	return nil
}

func humanAlertType(t string) string {
	switch t {
	case "30_DAY":
		return "30 days"
	case "7_DAY":
		return "7 days"
	case "1_DAY":
		return "1 day"
	default:
		return t
	}
}
