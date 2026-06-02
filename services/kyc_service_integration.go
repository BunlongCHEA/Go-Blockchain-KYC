package services

import (
	"fmt"
	"log"
	"time"

	"Go-Blockchain-KYC/config"
	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/storage"
)

// KYCService handles KYC status change business logic and CBS notification.
type KYCService struct {
	storage     storage.Storage
	cbsNotifier *CBSNotifier
}

// NewKYCService wires storage + CBS notifier using app config.
// Call from main.go: services.NewKYCService(store, &cfg.CBSIntegration)
func NewKYCService(store storage.Storage, cfg *config.CBSIntegrationConfig) *KYCService {
	return &KYCService{
		storage:     store,
		cbsNotifier: NewCBSNotifier(cfg),
	}
}

// SuspendKYC sets a KYC record's status to SUSPENDED in both the blockchain
// in-memory state (via storage.UpdateKYCStatus) and notifies CBS via NextJS gateway.
//
// Call this from the handler AFTER blockchain.SuspendKYC() succeeds.
func (s *KYCService) SuspendKYC(customerID, verifiedBy string) error {
	// 1. Persist status change to DB
	if err := s.storage.UpdateKYCStatus(
		customerID,
		models.StatusSuspended,
		verifiedBy,
		time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("SuspendKYC: DB update failed: %w", err)
	}

	// 2. Notify CBS via NextJS integration gateway (best-effort)
	if notifyErr := s.cbsNotifier.NotifyStatusChange(customerID, models.StatusSuspended); notifyErr != nil {
		// Log but do NOT fail — KYC suspend is already committed
		log.Printf("[KYCService] WARNING: failed to notify CBS of SUSPENDED for %s: %v",
			customerID, notifyErr)
	}

	log.Printf("[KYCService] KYC SUSPENDED: customer_id=%s by=%s", customerID, verifiedBy)
	return nil
}

// ExpireKYC sets a KYC record's status to EXPIRED in DB and notifies CBS via NextJS gateway.
//
// Call this from the handler or the renewal scheduler AFTER blockchain.ExpireKYC() succeeds.
func (s *KYCService) ExpireKYC(customerID string) error {
	// 1. Persist status change to DB
	if err := s.storage.UpdateKYCStatus(
		customerID,
		models.StatusExpired,
		"system", // expired by system / scheduler
		time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("ExpireKYC: DB update failed: %w", err)
	}

	// 2. Notify CBS via NextJS integration gateway (best-effort)
	if notifyErr := s.cbsNotifier.NotifyStatusChange(customerID, models.StatusExpired); notifyErr != nil {
		log.Printf("[KYCService] WARNING: failed to notify CBS of EXPIRED for %s: %v",
			customerID, notifyErr)
	}

	log.Printf("[KYCService] KYC EXPIRED: customer_id=%s", customerID)
	return nil
}
