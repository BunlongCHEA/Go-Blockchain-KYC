package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/storage"
)

// KYCService handles KYC status change business logic and CBS notification.
type KYCService struct {
	storage   storage.Storage
	publisher *KYCEventPublisher // nil when MQ not configured (graceful degradation)
}

func NewKYCService(store storage.Storage, publisher *KYCEventPublisher) *KYCService {
	return &KYCService{storage: store, publisher: publisher}
}

func (s *KYCService) SuspendKYC(customerID, verifiedBy string) error {
	if err := s.storage.UpdateKYCStatus(
		customerID, models.StatusSuspended, verifiedBy, time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("SuspendKYC DB: %w", err)
	}
	s.publishAsync(customerID, "SUSPENDED", verifiedBy)
	log.Printf("[KYCService] KYC SUSPENDED: customer_id=%s by=%s", customerID, verifiedBy)
	return nil
}

func (s *KYCService) ExpireKYC(customerID string) error {
	if err := s.storage.UpdateKYCStatus(
		customerID, models.StatusExpired, "system", time.Now().Unix(),
	); err != nil {
		return fmt.Errorf("ExpireKYC DB: %w", err)
	}
	s.publishAsync(customerID, "EXPIRED", "system")
	log.Printf("[KYCService] KYC EXPIRED: customer_id=%s", customerID)
	return nil
}

// publishAsync fires and forgets — a DB-level status update must not fail
// because MQ is temporarily unavailable.
func (s *KYCService) publishAsync(customerID, status, actor string) {
	if s.publisher == nil {
		log.Printf("[KYCService] MQ publisher not configured — skipping event for %s", customerID)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// bankID is fetched from DB to avoid passing it down through every call
		kyc, err := s.storage.GetKYC(customerID)
		bankID := ""
		if err == nil && kyc != nil {
			bankID = kyc.BankID
		}
		if pubErr := s.publisher.PublishStatusChange(ctx, customerID, status, bankID, actor); pubErr != nil {
			log.Printf("[KYCService] WARN MQ publish failed for %s: %v (status already committed to DB)",
				customerID, pubErr)
		}
	}()
}
