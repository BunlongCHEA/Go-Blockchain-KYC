package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/config"
	"Go-Blockchain-KYC/crypto"
	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/monitoring"
	"Go-Blockchain-KYC/storage"
	"Go-Blockchain-KYC/utils"
	"Go-Blockchain-KYC/verification"
)

// Handlers holds all HTTP handlers
type Handlers struct {
	blockchain          *models.Blockchain
	authService         *auth.AuthService
	storage             storage.Storage
	rbac                *auth.RBAC
	verificationService *verification.VerificationService
	monitoringService   *monitoring.MonitoringService
	keyManager          *crypto.KeyManager
	config              *config.Config
	envelope            *crypto.EnvelopeEncryptor
	signingKeyMgr       *crypto.SigningKeyManager
}

// UpdateBankRequest — full or partial bank update
type UpdateBankRequest struct {
	BankID       string          `json:"bank_id"`
	Name         string          `json:"name,omitempty"`
	Code         string          `json:"code,omitempty"`
	Country      string          `json:"country,omitempty"`
	LicenseNo    string          `json:"license_no,omitempty"`
	Address      *models.Address `json:"address,omitempty"`
	ContactEmail string          `json:"contact_email,omitempty"`
	ContactPhone string          `json:"contact_phone,omitempty"`
	IsActive     *bool           `json:"is_active,omitempty"`
}

// IssueVerificationCertificateRequest represents request from external service
type IssueVerificationCertificateRequest struct {
	CustomerID      string `json:"customer_id"`
	RequesterID     string `json:"requester_id"`
	RequesterPubKey string `json:"requester_public_key"`
	ValidityDays    int    `json:"validity_days,omitempty"` // Requested validity
}

// VerifyCertificateRequest represents request to verify a certificate
type VerifyCertificateRequest struct {
	Certificate *models.VerificationCertificate `json:"certificate"`
}

// PeriodicReviewRequest represents a KYC periodic review request
type PeriodicReviewRequest struct {
	CustomerID      string `json:"customer_id"`
	ReviewNotes     string `json:"review_notes"`
	DocumentsValid  bool   `json:"documents_valid"`
	AMLCheckPassed  bool   `json:"aml_check_passed"`
	PEPCheckPassed  bool   `json:"pep_check_passed"`
	RiskLevelUpdate string `json:"risk_level_update,omitempty"` // low, medium, high
}

// ConfigureRenewalAlertRequest represents alert configuration request
type ConfigureRenewalAlertRequest struct {
	CertificateID  string `json:"certificate_id"`
	WebhookURL     string `json:"webhook_url,omitempty"`
	EmailRecipient string `json:"email_recipient,omitempty"`
	IsActive       *bool  `json:"is_active,omitempty"`
	Delivery       string `json:"delivery,omitempty"`      // email|webhook|both|none
	SendInterval   string `json:"send_interval,omitempty"` // immediate|daily|weekly
	// target a single alert row instead of all rows for the cert
	AlertID string `json:"alert_id,omitempty"`
}

// SendRenewalAlertRequest — manual dispatch
type SendRenewalAlertRequest struct {
	CertificateID string `json:"certificate_id"`
	AlertID       string `json:"alert_id"`
}

// GenerateKeyPairRequest represents request to generate key pair
type GenerateKeyPairRequest struct {
	KeyName      string `json:"key_name"`     // e.g., "transaction-service-001"
	KeyType      string `json:"key_type"`     // "RSA" or "ECDSA"
	KeySize      int    `json:"key_size"`     // RSA:  2048, 4096; ECDSA: 256, 384, 521
	Organization string `json:"organization"` // e.g., "Acme Corp"
	Email        string `json:"email"`        // Contact email
	Description  string `json:"description"`  // Purpose of the key
}

// GeneratedKeyPairResponse represents the response after key generation
type GeneratedKeyPairResponse struct {
	KeyID          string `json:"key_id"`
	KeyName        string `json:"key_name"`
	KeyType        string `json:"key_type"`
	KeySize        int    `json:"key_size"`
	PublicKeyPEM   string `json:"public_key_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"` // Only shown once!
	PublicKeyPath  string `json:"public_key_path"`
	PrivateKeyPath string `json:"private_key_path"`
	Fingerprint    string `json:"fingerprint"`
	CreatedAt      string `json:"created_at"`
	ExpiresAt      string `json:"expires_at"` // Key validity (e.g., 2 years)
	Organization   string `json:"organization"`
	Email          string `json:"email"`
	Description    string `json:"description"`
}

// GeneratedKeyPair holds the generated key pair data
type GeneratedKeyPair struct {
	PrivateKey    interface{}
	PublicKey     interface{}
	PrivateKeyPEM string
	PublicKeyPEM  string
}

const (
	GracePeriodDays = 7 // 7-day grace period after certificate expiry
)

// NewHandlers creates a new handlers instance
func NewHandlers(
	blockchain *models.Blockchain,
	authService *auth.AuthService,
	storage storage.Storage,
	rbac *auth.RBAC,
	verificationService *verification.VerificationService,
	monitoringService *monitoring.MonitoringService,
	keyManager *crypto.KeyManager,
	cfg *config.Config,
	envelope *crypto.EnvelopeEncryptor,
	signingKeyMgr *crypto.SigningKeyManager,
) *Handlers {
	return &Handlers{
		blockchain:          blockchain,
		authService:         authService,
		storage:             storage,
		rbac:                rbac,
		verificationService: verificationService,
		monitoringService:   monitoringService,
		keyManager:          keyManager,
		config:              cfg,
		envelope:            envelope,
		signingKeyMgr:       signingKeyMgr,
	}
}

// ==================== Auth Handlers ====================

// Register handles user registration
func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	user, err := h.authService.Register(&req)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Persist user to DB so login survives restart
	// for ALL roles including "customer" so every registered user is durable.
	if h.storage != nil {
		if dbErr := h.storage.SaveUser(user); dbErr != nil {
			// Log but don't fail the registration — user is in memory and
			// can operate this session; next restart may require re-register.
			log.Printf("[Register] Warning: could not persist user to DB: %v", dbErr)
		}

		// Stamp password_changed_at = NOW() on registration
		if pgStore, ok := h.storage.(*storage.PostgresStorage); ok {
			pgStore.UpdatePasswordChangedAt(user.ID)
		}
	}

	// Audit log
	h.audit(r, ActionRegister, ResourceAuth, user.ID, map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})

	SendCreated(w, "user registered successfully", map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
	})
}

// Login handles user login
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	// ── Emergency lock: block all non-admin logins ────────────────────────
	// Admin can still log in to disable the lock.
	if pgStore, ok := h.storage.(*storage.PostgresStorage); ok {
		if locked, _ := pgStore.IsEmergencyLocked(); locked {
			// Need to check role before rejecting — peek at the user record
			if u, _ := pgStore.GetUserByUsername(req.Username); u != nil {
				if u.Role != auth.RoleAdmin {
					h.audit(r, "LOGIN_BLOCKED_EMERGENCY_LOCK", ResourceAuth, req.Username,
						map[string]interface{}{"username": req.Username})
					SendError(w, http.StatusServiceUnavailable,
						"System is in emergency lock. Contact your administrator.")
					return
				}
			}
		}
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		// ALSO audit failed logins — important for brute-force detection
		h.audit(r, "LOGIN_FAILED", ResourceAuth, req.Username, map[string]interface{}{
			"username": req.Username,
			"reason":   err.Error(),
		})

		SendUnauthorized(w, err.Error())
		return
	}

	// ── Password expiry check ─────────────────────────────────────────────
	// Applies to all roles except integration_service (machine account).
	// On expiry: allow login, set password_change_required=true so the UI
	// forces the change-password screen on next action.
	if response.User.Role != auth.RoleIntegrationService {
		if pgStore, ok := h.storage.(*storage.PostgresStorage); ok {
			if pol, err := pgStore.GetPasswordPolicy(); err == nil {
				if changedAt, err := pgStore.GetPasswordChangedAt(response.User.ID); err == nil {
					if storage.IsPasswordExpired(changedAt, pol.IntervalMonths) {
						response.User.PasswordChangeRequired = true
						if err := pgStore.SaveUser(response.User); err != nil {
							log.Printf("[Login] could not persist expiry flag: %v", err)
						}
						h.authService.LoadUser(response.User)
						h.audit(r, "PASSWORD_EXPIRED", ResourceAuth, response.User.ID,
							map[string]interface{}{
								"username":          response.User.Username,
								"days_since_change": int(time.Since(changedAt).Hours() / 24),
							})
					}
				}
			}
		}
	}

	// Audit log: include user.ID from the LoginResponse, not just username
	h.audit(r, ActionLogin, ResourceAuth, response.User.ID, map[string]interface{}{
		"username": req.Username,
		"user_id":  response.User.ID, // Foreign-Key
		"role":     response.User.Role,
	})

	SendSuccess(w, "login successful", response)
}

// RefreshToken handles token refresh
func (h *Handlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	response, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		SendUnauthorized(w, err.Error())
		return
	}

	SendSuccess(w, "token refreshed successfully", response)
}

// GetProfile returns the current user's profile
func (h *Handlers) GetProfile(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	SendSuccess(w, "", map[string]interface{}{
		"id":         user.ID,
		"username":   user.Username,
		"email":      user.Email,
		"role":       user.Role,
		"bank_id":    user.BankID,
		"created_at": user.CreatedAt,
		"last_login": user.LastLogin,
	})
}

// ChangePassword handles password change for authenticated users.
// After a successful change, clears password_change_required flag
// and persists the updated user to the database.
func (h *Handlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.OldPassword == "" {
		SendBadRequest(w, "old_password is required")
		return
	}
	if req.NewPassword == "" {
		SendBadRequest(w, "new_password is required")
		return
	}

	// Enforce password policy:
	// minimum 15 characters, 1 uppercase, 1 number, 1 special character
	if err := validatePasswordPolicy(req.NewPassword); err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Update password in-memory (also clears PasswordChangeRequired flag)
	if err := h.authService.UpdatePassword(user.ID, req.OldPassword, req.NewPassword); err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Persist updated user (new hash + salt + flag cleared) to DB
	if h.storage != nil {
		updatedUser, err := h.authService.GetUserByID(user.ID)
		if err == nil {
			if dbErr := h.storage.SaveUser(updatedUser); dbErr != nil {
				log.Printf("[ChangePassword] Warning: could not persist user to DB: %v", dbErr)
			}
		}

		// Stamp password_changed_at
		if pgStore, ok := h.storage.(*storage.PostgresStorage); ok {
			if err := pgStore.UpdatePasswordChangedAt(user.ID); err != nil {
				log.Printf("[ChangePassword] Warning: could not stamp password_changed_at: %v", err)
			}
		}
	}

	// Audit log
	h.audit(r, ActionPasswordChange, ResourceAuth, user.ID, map[string]interface{}{
		"username": user.Username,
		"role":     user.Role,
	})

	SendSuccess(w, "Password changed successfully", map[string]interface{}{
		"username":                 user.Username,
		"password_change_required": false,
	})
}

// validatePasswordPolicy enforces:
// - minimum 15 characters
// - at least 1 uppercase letter
// - at least 1 number
// - at least 1 special character
func validatePasswordPolicy(password string) error {
	if len(password) < 15 {
		return fmt.Errorf("password must be at least 15 characters")
	}

	var hasUpper, hasNumber, hasSpecial bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasNumber = true
		case !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least 1 uppercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least 1 number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least 1 special character")
	}

	return nil
}

// =========== Auto-Verify KYC Handlers =================

// Auto-verify KYC using external API
func (h *Handlers) AutoVerifyKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		CustomerID string `json:"customer_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	// Get KYC data
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, true)
	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	// Check if already verified
	if kyc.Status == models.StatusVerified {
		SendBadRequest(w, "KYC already verified")
		return
	}

	// Call verification service
	result, err := h.verificationService.VerifyKYC(kyc)
	if err != nil {
		SendInternalError(w, fmt.Sprintf("verification failed: %v", err))
		return
	}

	// Update KYC status based on result
	switch result.Status {
	case models.StatusVerified:
		// Auto-approve:  Create transaction for blockchain
		err = h.blockchain.VerifyKYC(req.CustomerID, user.BankID, user.ID, user.Username)
		if err != nil {
			SendBadRequest(w, err.Error())
			return
		}

		// Persist the pending transaction to DB so it survives restart ──
		if h.storage != nil {
			pendingTxs := h.blockchain.GetPendingTransactions()
			for _, tx := range pendingTxs {
				if tx.CustomerID == req.CustomerID {
					if err := h.storage.SaveTransaction(tx); err != nil {
						log.Printf("[VerifyKYC] Warning: could not persist tx to DB: %v", err)
					}
					break
				}
			}
		}

	case models.StatusRejected:
		err = h.blockchain.RejectKYC(req.CustomerID, user.BankID, user.ID, result.Reason)
		if err != nil {
			SendBadRequest(w, err.Error())
			return
		}

	case models.StatusSuspended:
		err = h.blockchain.SuspendKYC(req.CustomerID, user.BankID, user.ID, result.Reason)
		if err != nil {
			SendBadRequest(w, err.Error())
			return
		}
	}

	// Update in database — preserve scan fields
	kyc.Status = result.Status
	kyc.RiskLevel = result.RiskLevel
	if h.storage != nil {
		if err := h.storage.UpdateKYCStatus(
			req.CustomerID,
			result.Status,
			user.ID,
			time.Now().Unix(),
		); err != nil {
			log.Printf("[AutoVerifyKYC] DB update warning: %v", err)
		}
	}

	// Audit log for auto-verification result
	h.audit(r, ActionKYCAutoVerify, ResourceKYC, req.CustomerID, map[string]interface{}{
		"customer_id": req.CustomerID,
		"status":      result.Status,
		"score":       result.Score,
		"risk_level":  result.RiskLevel,
	})

	SendSuccess(w, "Auto-verification completed", map[string]interface{}{
		"customer_id":      req.CustomerID,
		"status":           result.Status,
		"verified":         result.Verified,
		"score":            result.Score,
		"document_valid":   result.DocumentValid,
		"face_match":       result.FaceMatch,
		"aml_check":        result.AMLCheck,
		"pep_check":        result.PEPCheck,
		"risk_level":       result.RiskLevel,
		"reason":           result.Reason,
		"provider_ref":     result.ProviderRef,
		"on_blockchain":    result.Status == models.StatusVerified,
		"pending_for_mine": result.Status == models.StatusVerified,
	})
}

// ==================== KYC Handlers ====================

// CreateKYCRequest represents a KYC creation request
type CreateKYCRequest struct {
	FirstName    string         `json:"first_name"`
	LastName     string         `json:"last_name"`
	DateOfBirth  string         `json:"date_of_birth"`
	Nationality  string         `json:"nationality"`
	IDType       string         `json:"id_type"`
	IDNumber     string         `json:"id_number"`
	IDExpiryDate string         `json:"id_expiry_date"`
	Address      models.Address `json:"address"`
	Email        string         `json:"email"`
	Phone        string         `json:"phone"`
	BankID       string         `json:"bank_id,omitempty"` // Added to allow override
}

// CreateKYC handles KYC creation
func (h *Handlers) CreateKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req CreateKYCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	// Determine which bank_id to use
	bankID := user.BankID
	if req.BankID != "" {
		// Validate that the requested bank exists and is active
		if !h.blockchain.IsAuthorizedBank(req.BankID) {
			SendBadRequest(w, "invalid or inactive bank_id")
			return
		}
		bankID = req.BankID
	}

	// Ensure bankID is not empty
	if bankID == "" {
		SendBadRequest(w, "bank_id is required")
		return
	}

	customerID := utils.GenerateCustomerID(req.FirstName, req.LastName, req.DateOfBirth)

	kycData := models.NewKYCData(
		customerID,
		req.FirstName,
		req.LastName,
		req.DateOfBirth,
		req.Nationality,
		req.IDType,
		req.IDNumber,
		req.IDExpiryDate,
		req.Address,
		req.Email,
		req.Phone,
		bankID,
	)

	// Save to blockchain memory (NOT to pending transactions)
	err := h.blockchain.CreateKYC(kycData, user.BankID, user.ID)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Save to database
	// log.Printf("SaveKYC result for %s: %v", kycData.CustomerID, h.storage.SaveKYC(kycData))

	if h.storage != nil {
		if err := h.storage.SaveKYC(kycData); err != nil {
			SendInternalError(w, fmt.Sprintf("failed to save KYC to database: %v", err))
			return
		}
		// Link KYC customer_id to user so /kyc/me can resolve the record.
		// customer_id is a hash (GenerateCustomerID) ≠ user.ID, so we store
		// it on the user row. Only customer-role users need this link.
		if user.Role == auth.RoleCustomer {
			user.CustomerID = customerID
			if linkErr := h.storage.SaveUser(user); linkErr != nil {
				log.Printf("[CreateKYC] Warning: could not link customer_id to user: %v", linkErr)
			}
		}
	}

	// Audit log
	h.audit(r, ActionKYCCreate, ResourceKYC, customerID, map[string]interface{}{
		"customer_id": customerID,
		"bank_id":     bankID,
		"first_name":  req.FirstName,
		"last_name":   req.LastName,
		"id_type":     req.IDType,
	})

	// SendCreated(w, "KYC created successfully", map[string]interface{}{
	// 	"customer_id": customerID,
	// 	"status":      kycData.Status,
	// })

	SendCreated(w, "KYC created successfully - pending verification", map[string]interface{}{
		"customer_id":   customerID,
		"bank_id":       bankID,
		"status":        kycData.Status,
		"on_blockchain": false,
		"message":       "KYC saved to database.  Must be VERIFIED before adding to blockchain.",
	})
}

// GetKYC retrieves a KYC record
func (h *Handlers) GetKYC(w http.ResponseWriter, r *http.Request) {
	customerID := r.URL.Query().Get("customer_id")
	if customerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}

	user, _ := GetUserFromContext(r)

	if !h.rbac.CanAccessKYC(user, customerID) {
		SendForbidden(w, "access denied")
		return
	}

	// Audit log for KYC read access (sensitive record access)
	h.audit(r, ActionKYCRead, ResourceKYC, customerID, map[string]interface{}{
		"customer_id": customerID,
	})

	kyc, err := h.blockchain.ReadKYC(customerID, true)
	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	// Add blockchain status info
	response := map[string]interface{}{
		"kyc_data":      kyc,
		"on_blockchain": kyc.IsOnBlockchain(),
		"can_modify":    kyc.CanModify(),
		"can_verify":    kyc.CanVerify(),
	}

	SendSuccess(w, "", response)

	// SendSuccess(w, "", kyc)
}

// UpdateKYC updates a KYC record - Only allowed for non-verified KYC
func (h *Handlers) UpdateKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		CustomerID  string         `json:"customer_id"`
		FirstName   string         `json:"first_name,omitempty"`
		LastName    string         `json:"last_name,omitempty"`
		Address     models.Address `json:"address,omitempty"`
		Email       string         `json:"email,omitempty"`
		Phone       string         `json:"phone,omitempty"`
		Description string         `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	// Get existing KYC
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, true)
	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	// Check if can modify
	if !kyc.CanModify() {
		SendBadRequest(w, "cannot update verified KYC - already on blockchain")
		return
	}

	// Update fields
	if req.FirstName != "" {
		kyc.FirstName = req.FirstName
	}
	if req.LastName != "" {
		kyc.LastName = req.LastName
	}
	if req.Email != "" {
		kyc.Email = req.Email
	}
	if req.Phone != "" {
		kyc.Phone = req.Phone
	}
	if req.Address.Street != "" {
		kyc.Address = req.Address
	}

	err = h.blockchain.UpdateKYC(kyc, user.BankID, user.ID, req.Description)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Update in database
	if h.storage != nil {
		h.storage.SaveKYC(kyc)
	}

	// Audit log for KYC update
	h.audit(r, ActionKYCUpdate, ResourceKYC, req.CustomerID, map[string]interface{}{
		"customer_id": req.CustomerID,
		"description": req.Description,
	})

	SendSuccess(w, "KYC updated successfully", map[string]interface{}{
		"customer_id":   kyc.CustomerID,
		"status":        kyc.Status,
		"on_blockchain": kyc.IsOnBlockchain(),
	})

	// SendSuccess(w, "KYC updated successfully", kyc)
}

// VerifyKYC verifies a KYC record - This creates blockchain transaction
func (h *Handlers) VerifyKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		CustomerID string `json:"customer_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	// Get existing KYC to check status
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, false)
	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	if !kyc.CanVerify() {
		SendBadRequest(w, fmt.Sprintf("cannot verify KYC with status:  %s", kyc.Status))
		return
	}

	// ── Resolve bankID: admin has no BankID, fall back to KYC's bank ──
	bankID := user.BankID
	if bankID == "" {
		bankID = kyc.BankID
	}

	// This will create transaction and add to pending
	err = h.blockchain.VerifyKYC(req.CustomerID, bankID, user.ID, user.Username)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Persist the pending transaction to DB so it survives restart ──
	if h.storage != nil {
		pendingTxs := h.blockchain.GetPendingTransactions()
		for _, tx := range pendingTxs {
			if tx.CustomerID == req.CustomerID {
				if err := h.storage.SaveTransaction(tx); err != nil {
					log.Printf("[VerifyKYC] Warning: could not persist tx to DB: %v", err)
				}
				break
			}
		}
	}

	// Update in database — use targeted UPDATE to preserve scan fields
	if h.storage != nil {
		if err := h.storage.UpdateKYCStatus(
			req.CustomerID,
			models.StatusVerified,
			user.ID,           // verified_by = who clicked Verify => user.Username
			time.Now().Unix(), // verification_date = now
		); err != nil {
			log.Printf("[VerifyKYC] DB update warning: %v", err)
		}
	}

	// Audit log for KYC verification
	h.audit(r, ActionKYCVerify, ResourceKYC, req.CustomerID, map[string]interface{}{
		"customer_id": req.CustomerID,
		"bank_id":     bankID,
		"status":      models.StatusVerified,
	})

	SendSuccess(w, "KYC verified - transaction created for blockchain", map[string]interface{}{
		"customer_id":       req.CustomerID,
		"status":            models.StatusVerified,
		"on_blockchain":     false,
		"pending_for_block": true,
		"message":           "KYC verified.  Transaction added to pending pool.  Mine a block to add to blockchain.",
	})

	// err := h.blockchain.VerifyKYC(req.CustomerID, user.BankID, user.ID)
	// if err != nil {
	// 	SendBadRequest(w, err.Error())
	// 	return
	// }

	// h.blockchain.MineBlock()

	// SendSuccess(w, "KYC verified successfully", nil)
}

// RejectKYC rejects a KYC record - Only updates status, no blockchain
func (h *Handlers) RejectKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		CustomerID string `json:"customer_id"`
		Reason     string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	err := h.blockchain.RejectKYC(req.CustomerID, user.BankID, user.ID, req.Reason)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Update in database — preserve scan fields
	if h.storage != nil {
		if err := h.storage.UpdateKYCStatus(
			req.CustomerID,
			models.StatusRejected,
			user.ID,
			time.Now().Unix(),
		); err != nil {
			log.Printf("[RejectKYC] DB update warning: %v", err)
		}
	}

	// Audit log for KYC rejection
	h.audit(r, ActionKYCReject, ResourceKYC, req.CustomerID, map[string]interface{}{
		"customer_id": req.CustomerID,
		"reason":      req.Reason,
	})

	SendSuccess(w, "KYC rejected - NOT added to blockchain", map[string]interface{}{
		"customer_id":   req.CustomerID,
		"status":        models.StatusRejected,
		"on_blockchain": false,
		"reason":        req.Reason,
	})

	// h.blockchain.MineBlock()

	// SendSuccess(w, "KYC rejected", nil)
}

// DeleteKYC deletes a KYC record
func (h *Handlers) DeleteKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		CustomerID string `json:"customer_id"`
		Reason     string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	err := h.blockchain.DeleteKYC(req.CustomerID, user.BankID, user.ID, req.Reason)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Delete from database
	if h.storage != nil {
		h.storage.DeleteKYC(req.CustomerID)
	}

	// Audit log for KYC deletion
	h.audit(r, ActionKYCDelete, ResourceKYC, req.CustomerID, map[string]interface{}{
		"customer_id": req.CustomerID,
		"reason":      req.Reason,
	})

	SendSuccess(w, "KYC deleted successfully", map[string]interface{}{
		"customer_id": req.CustomerID,
		"message":     "KYC was not on blockchain, deleted from database only",
	})

	// h.blockchain.MineBlock()

	// SendSuccess(w, "KYC deleted successfully", nil)
}

// ListKYC lists all KYC records with optional filters
func (h *Handlers) ListKYC(w http.ResponseWriter, r *http.Request) {
	user, _ := GetUserFromContext(r)

	status := r.URL.Query().Get("status")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 100 {
		perPage = 20
	}

	var records []*models.KYCData

	if status != "" {
		records = h.blockchain.GetKYCByStatus(models.KYCStatus(status))
	} else if user.Role == auth.RoleBankAdmin || user.Role == auth.RoleBankOfficer {
		records = h.blockchain.GetKYCByBank(user.BankID)
	} else {
		allRecords := h.blockchain.GetAllKYCRecords()
		for _, kyc := range allRecords {
			records = append(records, kyc)
		}
	}

	totalItems := len(records)
	start := (page - 1) * perPage
	end := start + perPage

	if start >= totalItems {
		records = []*models.KYCData{}
	} else {
		if end > totalItems {
			end = totalItems
		}
		records = records[start:end]
	}

	// Audit log for KYC list access (sensitive record access)
	h.audit(r, ActionKYCList, ResourceKYC, user.ID, map[string]interface{}{
		"status_filter": status,
		"page":          page,
		"per_page":      perPage,
	})

	SendPaginated(w, records, page, perPage, totalItems)
}

// GetKYCStats returns KYC record counts grouped by status
func (h *Handlers) GetKYCStats(w http.ResponseWriter, r *http.Request) {
	user, _ := GetUserFromContext(r)

	allRecords := h.blockchain.GetAllKYCRecords()

	// Bank-scoped users only see their own bank's records
	counts := map[string]int{
		"total":     0,
		"pending":   0,
		"verified":  0,
		"rejected":  0,
		"suspended": 0,
		"expired":   0,
	}

	for _, kyc := range allRecords {
		// Filter by bank for non-admin roles
		if (user.Role == auth.RoleBankAdmin || user.Role == auth.RoleBankOfficer) && kyc.BankID != user.BankID {
			continue
		}
		counts["total"]++
		switch kyc.Status {
		case models.StatusPending:
			counts["pending"]++
		case models.StatusVerified:
			counts["verified"]++
		case models.StatusRejected:
			counts["rejected"]++
		case models.StatusSuspended:
			counts["suspended"]++
		case models.StatusExpired:
			counts["expired"]++
		}
	}

	SendSuccess(w, "", counts)
}

// GetKYCHistory retrieves transaction history for a customer
func (h *Handlers) GetKYCHistory(w http.ResponseWriter, r *http.Request) {
	customerID := r.URL.Query().Get("customer_id")
	if customerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}

	history := h.blockchain.GetCustomerHistory(customerID)
	SendSuccess(w, "", history)
}

// ==================== Bank Handlers ====================

// RegisterBank handles bank registration
func (h *Handlers) RegisterBank(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string         `json:"name"`
		Code         string         `json:"code"`
		Country      string         `json:"country"`
		LicenseNo    string         `json:"license_no"`
		PublicKey    string         `json:"public_key"`
		Address      models.Address `json:"address"`
		ContactEmail string         `json:"contact_email"`
		ContactPhone string         `json:"contact_phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	bankID := utils.GenerateBankID(req.Name)
	bank := models.NewBank(bankID, req.Name, req.Code, req.Country, req.LicenseNo, req.PublicKey)
	bank.Address = req.Address
	bank.ContactEmail = req.ContactEmail
	bank.ContactPhone = req.ContactPhone

	err := h.blockchain.RegisterBank(bank)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	if h.storage != nil {
		h.storage.SaveBank(bank)
	}

	SendCreated(w, "bank registered successfully", bank)
}

// GetBank retrieves a bank
func (h *Handlers) GetBank(w http.ResponseWriter, r *http.Request) {
	bankID := r.URL.Query().Get("bank_id")
	if bankID == "" {
		SendBadRequest(w, "bank_id is required")
		return
	}

	bank, err := h.blockchain.GetBank(bankID)
	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	SendSuccess(w, "", bank)
}

// ListBanks lists all banks
func (h *Handlers) ListBanks(w http.ResponseWriter, r *http.Request) {
	banks := make([]*models.Bank, 0)
	for _, bank := range h.blockchain.Banks {
		banks = append(banks, bank)
	}
	SendSuccess(w, "", banks)
}

// UpdateBank handles updating an existing bank record.
// PUT /api/v1/banks
func (h *Handlers) UpdateBank(w http.ResponseWriter, r *http.Request) {
	var req UpdateBankRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.BankID == "" {
		SendBadRequest(w, "bank_id is required")
		return
	}

	bank, err := h.blockchain.GetBank(req.BankID)
	if err != nil {
		SendNotFound(w, "bank not found")
		return
	}

	// Apply partial updates
	if req.Name != "" {
		bank.Name = req.Name
	}
	if req.Code != "" {
		bank.Code = req.Code
	}
	if req.Country != "" {
		bank.Country = req.Country
	}
	if req.LicenseNo != "" {
		bank.LicenseNo = req.LicenseNo
	}
	if req.ContactEmail != "" {
		bank.ContactEmail = req.ContactEmail
	}
	if req.ContactPhone != "" {
		bank.ContactPhone = req.ContactPhone
	}
	if req.Address != nil {
		if req.Address.Street != "" {
			bank.Address.Street = req.Address.Street
		}
		if req.Address.City != "" {
			bank.Address.City = req.Address.City
		}
		if req.Address.State != "" {
			bank.Address.State = req.Address.State
		}
		if req.Address.PostalCode != "" {
			bank.Address.PostalCode = req.Address.PostalCode
		}
		if req.Address.Country != "" {
			bank.Address.Country = req.Address.Country
		}
	}
	if req.IsActive != nil {
		bank.IsActive = *req.IsActive
	}
	bank.UpdatedAt = time.Now()

	// Persist
	if h.storage != nil {
		if err := h.storage.SaveBank(bank); err != nil {
			SendInternalError(w, "failed to update bank: "+err.Error())
			return
		}
	}

	// Update in-memory blockchain map
	h.blockchain.Banks[req.BankID] = bank

	h.audit(r, "BANK_UPDATED", "BANK", req.BankID, map[string]interface{}{
		"bank_id": req.BankID,
		"name":    bank.Name,
	})

	SendSuccess(w, "Bank updated successfully", bank)
}

// DeleteBank soft-deletes a bank (sets is_active=false, does not remove row).
// DELETE /api/v1/banks
func (h *Handlers) DeleteBank(w http.ResponseWriter, r *http.Request) {
	bankID := r.URL.Query().Get("bank_id")
	if bankID == "" {
		SendBadRequest(w, "bank_id is required")
		return
	}

	bank, err := h.blockchain.GetBank(bankID)
	if err != nil {
		SendNotFound(w, "bank not found")
		return
	}

	bank.IsActive = false
	bank.UpdatedAt = time.Now()

	if h.storage != nil {
		h.storage.SaveBank(bank)
	}
	h.blockchain.Banks[bankID] = bank

	h.audit(r, "BANK_DEACTIVATED", "BANK", bankID, map[string]interface{}{
		"bank_id": bankID,
		"name":    bank.Name,
	})

	SendSuccess(w, "Bank deactivated", map[string]interface{}{"bank_id": bankID})
}

// ==================== Blockchain Handlers ====================

// GetBlockchainStats returns blockchain statistics
func (h *Handlers) GetBlockchainStats(w http.ResponseWriter, r *http.Request) {
	stats := h.blockchain.GetStats()
	stats["is_valid"] = h.blockchain.IsChainValid()

	// Audit log for blockchain stats access (sensitive operational data)
	h.audit(r, ActionBlockchainStatsRead, ResourceBlockchain, "", map[string]interface{}{
		"total_blocks": stats["total_blocks"],
		"pending_tx":   stats["pending_transactions"],
		"is_valid":     stats["is_valid"],
	})

	SendSuccess(w, "", stats)
}

// GetBlocks returns blockchain blocks
func (h *Handlers) GetBlocks(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 50 {
		perPage = 10
	}

	totalBlocks := h.blockchain.GetChainLength()
	start := (page - 1) * perPage
	end := start + perPage

	if end > totalBlocks {
		end = totalBlocks
	}

	blocks := make([]*models.Block, 0)
	for i := start; i < end; i++ {
		block, err := h.blockchain.GetBlockByIndex(int64(i))
		if err == nil {
			blocks = append(blocks, block)
		}
	}

	// Audit log for block list access (sensitive operational data)
	h.audit(r, ActionBlockListRead, ResourceBlockchain, "", map[string]interface{}{
		"page":         page,
		"per_page":     perPage,
		"total_blocks": totalBlocks,
	})

	SendPaginated(w, blocks, page, perPage, totalBlocks)
}

// GetBlock returns a specific block
func (h *Handlers) GetBlock(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	indexStr := r.URL.Query().Get("index")

	var block *models.Block
	var err error

	if hash != "" {
		block, err = h.blockchain.GetBlockByHash(hash)
	} else if indexStr != "" {
		index, _ := strconv.ParseInt(indexStr, 10, 64)
		block, err = h.blockchain.GetBlockByIndex(index)
	} else {
		SendBadRequest(w, "hash or index is required")
		return
	}

	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	// Audit log for block access (sensitive operational data)
	h.audit(r, ActionBlockRead, ResourceBlockchain, fmt.Sprintf("%d", block.Index), map[string]interface{}{
		"block_index": block.Index,
		"block_hash":  block.Hash,
	})

	SendSuccess(w, "", block)
}

// MineBlock manually triggers block mining
func (h *Handlers) MineBlock(w http.ResponseWriter, r *http.Request) {
	block := h.blockchain.MineBlock()
	if block == nil {
		SendBadRequest(w, "no pending transactions to mine")
		return
	}

	if h.storage != nil {
		h.storage.SaveBlock(block)
	}

	// Audit log for block mining
	h.audit(r, ActionBlockMine, ResourceBlockchain, fmt.Sprintf("%d", block.Index), map[string]interface{}{
		"block_index": block.Index,
		"block_hash":  block.Hash,
		"tx_count":    len(block.Transactions),
	})

	SendCreated(w, "block mined successfully", block)
}

// GetPendingTransactions returns pending transactions
func (h *Handlers) GetPendingTransactions(w http.ResponseWriter, r *http.Request) {
	txs := h.blockchain.GetPendingTransactions()

	// Audit log for pending transaction access (sensitive operational data)
	h.audit(r, ActionPendingTxRead, ResourceBlockchain, "", map[string]interface{}{
		"pending_tx_count": len(txs),
	})
	SendSuccess(w, "", txs)
}

// ValidateChain validates the blockchain
func (h *Handlers) ValidateChain(w http.ResponseWriter, r *http.Request) {
	isValid := h.blockchain.IsChainValid()

	// Audit log for chain validation
	h.audit(r, ActionChainValidate, ResourceBlockchain, "", map[string]interface{}{
		"is_valid": isValid,
	})

	SendSuccess(w, "", map[string]bool{"is_valid": isValid})
}

// ==================== Health Check ====================

// HealthCheck returns service health status
func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	dbStatus := "healthy"
	if h.storage != nil {
		if err := h.storage.Ping(); err != nil {
			dbStatus = "unhealthy"
		}
	}

	status := map[string]interface{}{
		"status":       "healthy",
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"blockchain":   h.blockchain.IsChainValid(),
		"total_blocks": h.blockchain.GetChainLength(),
		"database":     dbStatus,
	}
	SendSuccess(w, "", status)
}

// ================= Audit Log Check ====================

// GetAuditLogs returns audit logs
func (h *Handlers) GetAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	userID := r.URL.Query().Get("user_id")
	action := r.URL.Query().Get("action")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	// Default time range:  last 7 days
	startTime := time.Now().AddDate(0, 0, -7)
	endTime := time.Now()

	// Parse custom date range if provided
	if startStr := r.URL.Query().Get("start_date"); startStr != "" {
		if t, err := time.Parse("2006-01-02", startStr); err == nil {
			startTime = t
		}
	}
	if endStr := r.URL.Query().Get("end_date"); endStr != "" {
		if t, err := time.Parse("2006-01-02", endStr); err == nil {
			endTime = t.Add(24 * time.Hour) // Include entire end day
		}
	}

	// Check if storage is available
	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "audit logs not available - no database configured")
		return
	}

	// Audit log for audit log access (meta-audit)
	h.audit(r, ActionAuditLogRead, ResourceAudit, "", map[string]interface{}{
		"filter_user_id": userID,
		"filter_action":  action,
		"start_date":     startTime.Format("2006-01-02"),
		"end_date":       endTime.Format("2006-01-02"),
		"limit":          limit,
	})

	// Get audit logs from storage
	logs, err := h.storage.GetAuditLogs(userID, action, startTime, endTime, limit)
	if err != nil {
		SendInternalError(w, "failed to retrieve audit logs:  "+err.Error())
		return
	}

	SendSuccess(w, "", map[string]interface{}{
		"logs":       logs,
		"count":      len(logs),
		"start_date": startTime.Format("2006-01-02"),
		"end_date":   endTime.Format("2006-01-02"),
		"filters": map[string]string{
			"user_id": userID,
			"action":  action,
		},
	})
}

// GetSecurityAlerts returns security alerts from monitoring service
func (h *Handlers) GetSecurityAlerts(w http.ResponseWriter, r *http.Request) {
	if h.monitoringService == nil {
		SendError(w, http.StatusServiceUnavailable, "monitoring service not available")
		return
	}

	// Parse query parameters
	userID := r.URL.Query().Get("user_id")
	riskLevelStr := r.URL.Query().Get("risk_level")
	reviewedStr := r.URL.Query().Get("reviewed")

	var riskLevel monitoring.RiskLevel
	if riskLevelStr != "" {
		riskLevel = monitoring.RiskLevel(riskLevelStr)
	}

	var reviewed *bool
	if reviewedStr != "" {
		rev := reviewedStr == "true"
		reviewed = &rev
	}

	// Get alerts from monitoring service
	alerts := h.monitoringService.GetAlerts(userID, riskLevel, reviewed)

	// Get alert counts by risk level
	alertCounts := h.monitoringService.GetAlertCount()

	SendSuccess(w, "", map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
		"summary": map[string]interface{}{
			"total":    len(alerts),
			"low":      alertCounts[monitoring.RiskLow],
			"medium":   alertCounts[monitoring.RiskMedium],
			"high":     alertCounts[monitoring.RiskHigh],
			"critical": alertCounts[monitoring.RiskCritical],
		},
		"filters": map[string]interface{}{
			"user_id":    userID,
			"risk_level": riskLevelStr,
			"reviewed":   reviewedStr,
		},
	})
}

// ReviewSecurityAlert marks an alert as reviewed
func (h *Handlers) ReviewSecurityAlert(w http.ResponseWriter, r *http.Request) {
	if h.monitoringService == nil {
		SendError(w, http.StatusServiceUnavailable, "monitoring service not available")
		return
	}

	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found in context")
		return
	}

	var req struct {
		AlertID string `json:"alert_id"`
		Action  string `json:"action"` // e.g., "acknowledged", "dismissed", "escalated", "resolved"
		Notes   string `json:"notes,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.AlertID == "" {
		SendBadRequest(w, "alert_id is required")
		return
	}

	if req.Action == "" {
		SendBadRequest(w, "action is required")
		return
	}

	// Valid actions
	validActions := map[string]bool{
		"acknowledged": true,
		"dismissed":    true,
		"escalated":    true,
		"resolved":     true,
	}

	if !validActions[req.Action] {
		SendBadRequest(w, "invalid action - must be:  acknowledged, dismissed, escalated, or resolved")
		return
	}

	// Review the alert
	err := h.monitoringService.ReviewAlert(req.AlertID, user.ID, req.Action)
	if err != nil {
		SendNotFound(w, err.Error())
		return
	}

	// Audit log for alert review
	h.audit(r, ActionSecurityAlertReview, ResourceAlert, req.AlertID, map[string]interface{}{
		"alert_id": req.AlertID,
		"action":   req.Action,
		"notes":    req.Notes,
	})

	SendSuccess(w, "Alert reviewed successfully", map[string]interface{}{
		"alert_id":    req.AlertID,
		"reviewed_by": user.ID,
		"action":      req.Action,
		"reviewed_at": time.Now().Format(time.RFC3339),
	})
}

// ==================== Generate Key-Pair For Certificate Handlers ====================

// GenerateRequesterKeyPair generates a key pair for external service
func (h *Handlers) GenerateRequesterKeyPair(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req GenerateKeyPairRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	// Validate request
	if err := validateKeyPairRequest(&req); err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Sanitize key name (remove special characters)
	req.KeyName = sanitizeKeyName(req.KeyName)

	// Check if key name already exists
	if h.storage != nil {
		existing, _ := h.storage.GetRequesterKeyByName(req.KeyName)
		if existing != nil {
			SendBadRequest(w, fmt.Sprintf("key name '%s' already exists", req.KeyName))
			return
		}
	}

	// Generate key pair
	keyPair, err := generateKeyPair(req.KeyType, req.KeySize)
	if err != nil {
		SendInternalError(w, "failed to generate key pair: "+err.Error())
		return
	}

	// Get download directory based on OS
	downloadDir := getDefaultDownloadDir()

	// Create key directory if not exists
	keyDir := filepath.Join(downloadDir, "kyc-blockchain-keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		SendInternalError(w, "failed to create key directory: "+err.Error())
		return
	}

	// Generate file paths
	privateKeyPath := filepath.Join(keyDir, req.KeyName+"_private. pem")
	publicKeyPath := filepath.Join(keyDir, req.KeyName+"_public. pem")

	// Save private key to file
	if err := saveKeyToFile(privateKeyPath, keyPair.PrivateKeyPEM, 0600); err != nil {
		SendInternalError(w, "failed to save private key:  "+err.Error())
		return
	}

	// Save public key to file
	if err := saveKeyToFile(publicKeyPath, keyPair.PublicKeyPEM, 0644); err != nil {
		// Cleanup private key if public key fails
		os.Remove(privateKeyPath)
		SendInternalError(w, "failed to save public key: "+err.Error())
		return
	}

	// Generate key ID and fingerprint
	keyID := generateKeyID(req.KeyName)
	fingerprint := generateFingerprint(keyPair.PublicKeyPEM)

	now := time.Now()
	expiresAt := now.AddDate(2, 0, 0) // 2 years validity

	// Prepare response
	response := &GeneratedKeyPairResponse{
		KeyID:          keyID,
		KeyName:        req.KeyName,
		KeyType:        req.KeyType,
		KeySize:        req.KeySize,
		PublicKeyPEM:   keyPair.PublicKeyPEM,
		PrivateKeyPEM:  keyPair.PrivateKeyPEM, // Only shown once!
		PublicKeyPath:  publicKeyPath,
		PrivateKeyPath: privateKeyPath,
		Fingerprint:    fingerprint,
		CreatedAt:      now.Format(time.RFC3339),
		ExpiresAt:      expiresAt.Format(time.RFC3339),
		Organization:   req.Organization,
		Email:          req.Email,
		Description:    req.Description,
	}

	// Save requester info to database (without private key!)
	if h.storage != nil {
		requesterInfo := &models.RequesterKeyInfo{
			ID:           keyID,
			KeyName:      req.KeyName,
			KeyType:      req.KeyType,
			KeySize:      req.KeySize,
			PublicKeyPEM: keyPair.PublicKeyPEM,
			Fingerprint:  fingerprint,
			Organization: req.Organization,
			Email:        req.Email,
			Description:  req.Description,
			IsActive:     true,
			CreatedAt:    now.Unix(),
			ExpiresAt:    expiresAt.Unix(),
			CreatedBy:    user.ID,
		}

		if err := h.storage.SaveRequesterKey(requesterInfo); err != nil {
			// Cleanup files if database save fails
			os.Remove(privateKeyPath)
			os.Remove(publicKeyPath)
			SendInternalError(w, "failed to save requester info: "+err.Error())
			return
		}

		// Save to audit log
		h.audit(r, ActionKeyGenerate, ResourceKey, keyID, map[string]interface{}{
			"key_id":           keyID,
			"key_name":         req.KeyName,
			"key_type":         req.KeyType,
			"key_size":         req.KeySize,
			"organization":     req.Organization,
			"email":            req.Email,
			"fingerprint":      fingerprint,
			"expires_at":       expiresAt.Unix(),
			"public_key_path":  publicKeyPath,
			"private_key_path": privateKeyPath,
		})
	}

	// Return response with all info
	SendCreated(w, "Key pair generated successfully", map[string]interface{}{
		"key_pair": response,
		"security_notice": map[string]string{
			"warning":     "SAVE YOUR PRIVATE KEY NOW! It will not be shown again.",
			"private_key": "Keep private key secure and never share it",
			"public_key":  "Share public key with KYC service for certificate requests",
			"backup":      "Create a secure backup of your private key",
		},
		"usage_instructions": map[string]string{
			"step_1": "Store the private key securely",
			"step_2": "Use the public_key_pem when calling /api/v1/certificate/issue",
			"step_3": "Sign your requests with the private key for authentication",
			"step_4": "Key expires on " + expiresAt.Format("2006-01-02") + " - renew before expiry",
		},
		"files_saved": map[string]string{
			"private_key": privateKeyPath,
			"public_key":  publicKeyPath,
			"directory":   keyDir,
		},
	})
}

// validateKeyPairRequest validates the key pair request
func validateKeyPairRequest(req *GenerateKeyPairRequest) error {
	if req.KeyName == "" {
		return fmt.Errorf("key_name is required")
	}
	if len(req.KeyName) < 3 || len(req.KeyName) > 50 {
		return fmt.Errorf("key_name must be between 3 and 50 characters")
	}

	// Validate key type
	req.KeyType = strings.ToUpper(req.KeyType)
	if req.KeyType != "RSA" && req.KeyType != "ECDSA" {
		return fmt.Errorf("key_type must be 'RSA' or 'ECDSA'")
	}

	// Validate key size based on type
	if req.KeyType == "RSA" {
		validSizes := map[int]bool{2048: true, 3072: true, 4096: true}
		if !validSizes[req.KeySize] {
			return fmt.Errorf("RSA key_size must be 2048, 3072, or 4096")
		}
	} else if req.KeyType == "ECDSA" {
		validSizes := map[int]bool{256: true, 384: true, 521: true}
		if !validSizes[req.KeySize] {
			return fmt.Errorf("ECDSA key_size must be 256, 384, or 521")
		}
	}

	if req.Organization == "" {
		return fmt.Errorf("organization is required")
	}

	if req.Email == "" {
		return fmt.Errorf("email is required")
	}

	return nil
}

// sanitizeKeyName removes special characters from key name
func sanitizeKeyName(name string) string {
	// Replace spaces with dashes
	name = strings.ReplaceAll(name, " ", "-")

	// Keep only alphanumeric, dash, underscore
	var result strings.Builder
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			result.WriteRune(c)
		}
	}

	return strings.ToLower(result.String())
}

// getDefaultDownloadDir returns the default download directory based on OS
func getDefaultDownloadDir() string {
	var downloadDir string

	switch runtime.GOOS {
	case "windows":
		// Windows: C:\Users\<username>\Downloads
		downloadDir = filepath.Join(os.Getenv("USERPROFILE"), "Downloads")
	case "darwin":
		// macOS: /Users/<username>/Downloads
		downloadDir = filepath.Join(os.Getenv("HOME"), "Downloads")
	case "linux":
		// Linux: /home/<username>/Downloads or XDG_DOWNLOAD_DIR
		xdgDownload := os.Getenv("XDG_DOWNLOAD_DIR")
		if xdgDownload != "" {
			downloadDir = xdgDownload
		} else {
			downloadDir = filepath.Join(os.Getenv("HOME"), "Downloads")
		}
	default:
		// Fallback to home directory
		downloadDir = os.Getenv("HOME")
		if downloadDir == "" {
			downloadDir = "."
		}
	}

	return downloadDir
}

// generateKeyPair generates RSA or ECDSA key pair
func generateKeyPair(keyType string, keySize int) (*GeneratedKeyPair, error) {
	var privateKey interface{}
	var publicKey interface{}
	var privateKeyPEM, publicKeyPEM string

	switch keyType {
	case "RSA":
		rsaKey, err := rsa.GenerateKey(rand.Reader, keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		privateKey = rsaKey
		publicKey = &rsaKey.PublicKey

		// Encode private key to PEM
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		}))

		// Encode public key to PEM
		publicKeyBytes := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
		publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		}))

	case "ECDSA":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			curve = elliptic.P256()
		}

		ecdsaKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}
		privateKey = ecdsaKey
		publicKey = &ecdsaKey.PublicKey

		// Encode private key to PEM
		privateKeyBytes, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
		}
		privateKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyBytes,
		}))

		// Encode public key to PEM
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
		}
		publicKeyPEM = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		}))

	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	return &GeneratedKeyPair{
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		PrivateKeyPEM: privateKeyPEM,
		PublicKeyPEM:  publicKeyPEM,
	}, nil
}

// saveKeyToFile saves key content to a file with specified permissions
func saveKeyToFile(path, content string, perm os.FileMode) error {
	return os.WriteFile(path, []byte(content), perm)
}

// generateKeyID generates a unique key ID
func generateKeyID(keyName string) string {
	return fmt.Sprintf("KEY_%s_%d", strings.ToUpper(keyName[:min(8, len(keyName))]), time.Now().UnixNano()%1000000)
}

// generateFingerprint generates a fingerprint from public key
func generateFingerprint(publicKeyPEM string) string {
	// Simple hash-based fingerprint
	hash := sha256.Sum256([]byte(publicKeyPEM))
	return fmt.Sprintf("SHA256:%x", hash[:8])
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetRequesterKeys returns list of registered requester keys
func (h *Handlers) GetRequesterKeys(w http.ResponseWriter, r *http.Request) {
	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	keys, err := h.storage.GetAllRequesterKeys()
	if err != nil {
		SendInternalError(w, "failed to get requester keys: "+err.Error())
		return
	}

	// Audit log for requester key list access (sensitive info access)
	h.audit(r, ActionKeyRead, ResourceKey, "", map[string]interface{}{
		"count": len(keys),
	})

	SendSuccess(w, "", map[string]interface{}{
		"keys":  keys,
		"count": len(keys),
	})
}

// GetRequesterKeyByID returns a specific requester key
func (h *Handlers) GetRequesterKeyByID(w http.ResponseWriter, r *http.Request) {
	keyID := r.URL.Query().Get("key_id")
	keyName := r.URL.Query().Get("key_name")

	if keyID == "" && keyName == "" {
		SendBadRequest(w, "key_id or key_name is required")
		return
	}

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	var key *models.RequesterKeyInfo
	var err error

	if keyID != "" {
		key, err = h.storage.GetRequesterKeyByID(keyID)
	} else {
		key, err = h.storage.GetRequesterKeyByName(keyName)
	}

	if err != nil {
		SendNotFound(w, "requester key not found")
		return
	}

	// Audit log for requester key access (sensitive info access)
	h.audit(r, ActionKeyRead, ResourceKey, key.ID, map[string]interface{}{
		"key_id":   key.ID,
		"key_name": key.KeyName,
	})

	SendSuccess(w, "", map[string]interface{}{
		"key": key,
	})
}

// RevokeRequesterKey revokes a requester key
func (h *Handlers) RevokeRequesterKey(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req struct {
		KeyID  string `json:"key_id"`
		Reason string `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.KeyID == "" {
		SendBadRequest(w, "key_id is required")
		return
	}

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	// Get key info first
	key, err := h.storage.GetRequesterKeyByID(req.KeyID)
	if err != nil {
		SendNotFound(w, "requester key not found")
		return
	}

	// Revoke the key
	if err := h.storage.RevokeRequesterKey(req.KeyID); err != nil {
		SendInternalError(w, "failed to revoke key: "+err.Error())
		return
	}

	// Save to audit log
	h.audit(r, ActionKeyRevoke, ResourceKey, req.KeyID, map[string]interface{}{
		"key_id":       req.KeyID,
		"key_name":     key.KeyName,
		"organization": key.Organization,
		"reason":       req.Reason,
	})

	SendSuccess(w, "Requester key revoked successfully", map[string]interface{}{
		"key_id":     req.KeyID,
		"key_name":   key.KeyName,
		"revoked_at": time.Now().Format(time.RFC3339),
		"revoked_by": user.ID,
	})
}

// ================= Issue/Re-issue Certificate with Grace Period Check =================

// IssueVerificationCertificate issues a signed KYC verification certificate & with grace period handling
func (h *Handlers) IssueVerificationCertificate(w http.ResponseWriter, r *http.Request) {
	// user, ok := GetUserFromContext(r)
	// if !ok {
	// 	SendUnauthorized(w, "user not found")
	// 	return
	// }

	var req IssueVerificationCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.CustomerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}

	if req.RequesterID == "" {
		SendBadRequest(w, "requester_id is required")
		return
	}

	// Default validity: 365 days
	if req.ValidityDays <= 0 {
		req.ValidityDays = 365
	}

	// Get KYC record
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, false)
	if err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	if kyc.Status != models.StatusVerified {
		SendBadRequest(w, "KYC is not verified - cannot issue certificate")
		return
	}

	// Check if KYC ID document is expired
	idExpired, idExpiryTime := h.isKYCIDExpired(kyc)

	// **GRACE PERIOD:  Allow certificate if ID expired within grace period**
	idInGracePeriod := false
	if idExpired && idExpiryTime != nil {
		gracePeriodEnds := idExpiryTime.AddDate(0, 0, GracePeriodDays)
		idInGracePeriod = time.Now().Before(gracePeriodEnds)
	}

	if idExpired && !idInGracePeriod {
		SendBadRequest(w, "KYC ID document has expired beyond grace period - requires reverification with new ID")
		return
	}

	// Check if periodic review is required
	reviewRequired, _ := h.isPeriodicReviewRequired(kyc)

	// **GRACE PERIOD: Allow certificate if review overdue within grace period**
	reviewInGracePeriod := false
	if reviewRequired {
		lastReview := kyc.LastReviewDate
		if lastReview == 0 {
			lastReview = kyc.VerificationDate
		}
		reviewDueDate := time.Unix(lastReview, 0).AddDate(1, 0, 0)
		gracePeriodEnds := reviewDueDate.AddDate(0, 0, GracePeriodDays)
		reviewInGracePeriod = time.Now().Before(gracePeriodEnds)
	}

	if reviewRequired && !reviewInGracePeriod {
		SendError(w, http.StatusForbidden, "KYC requires periodic review beyond grace period - please complete review first")
		return
	}

	// Warn if in any grace period
	warnings := []string{}
	if idInGracePeriod {
		warnings = append(warnings, "ID document is in grace period - update ID immediately")
	}
	if reviewInGracePeriod {
		warnings = append(warnings, "Periodic review is overdue - complete review immediately")
	}

	// **1: Calculate validity based on ID expiry**
	validityDays := h.calculateCertificateValidity(req.ValidityDays, idExpiryTime, kyc)

	if h.keyManager == nil {
		SendInternalError(w, "key manager not available")
		return
	}

	// Create certificate
	cert := models.NewVerificationCertificate(
		kyc,
		req.RequesterID,
		req.RequesterPubKey,
		"KYC-BLOCKCHAIN-SYSTEM",
		validityDays,
	)

	// Sign using KeyManager (supports both RSA and ECDSA)
	// if err := cert.SignWithKeyManager(h.keyManager); err != nil {
	if err := cert.SignWithSigningManager(h.signingKeyMgr); err != nil {
		SendInternalError(w, "failed to sign certificate:  "+err.Error())
		return
	}

	// Persist certificate to database (allows for audit logging and renewal tracking)
	if h.storage != nil {
		// 1. Persist the new certificate
		if err := h.storage.SaveCertificate(cert); err != nil {
			log.Printf("[IssueVerificationCertificate] Warning: could not persist cert: %v", err)
			// Don't fail the request — certificate was issued, just not persisted
		} else {
			// 2. Deactivate previous certs for same customer+requester
			//    (keeps history, only latest shows in default UI view)
			if deactErr := h.storage.DeactivateOldCertificates(
				cert.CustomerID, cert.RequesterID, cert.CertificateID,
			); deactErr != nil {
				log.Printf("[IssueVerificationCertificate] Warning: could not deactivate old certs: %v", deactErr)
			}

			// 3. Dismiss pending renewal alerts for this customer
			//    (no more "cert expiring" noise after a successful re-issue)
			if alertErr := h.storage.DeactivateRenewalAlerts(cert.CustomerID); alertErr != nil {
				log.Printf("[IssueVerificationCertificate] Warning: could not deactivate renewal alerts: %v", alertErr)
			}
		}
	}

	// Calculate renewal reminder date (30 days before expiry)
	renewalReminderDate := time.Unix(cert.ExpiresAt, 0).AddDate(0, 0, -30)

	// Log the certificate issuance
	if h.storage != nil {
		h.audit(r, ActionCertIssue, ResourceCertificate, cert.CertificateID, map[string]interface{}{
			"customer_id":        req.CustomerID,
			"requester_id":       req.RequesterID,
			"certificate_id":     cert.CertificateID,
			"key_type":           cert.KeyType,
			"requested_validity": req.ValidityDays,
			"actual_validity":    validityDays,
			"expires_at":         cert.ExpiresAt,
			"id_expiry_date":     kyc.IDExpiryDate,
			"renewal_reminder":   renewalReminderDate.Unix(),
		})

		// **2: Schedule renewal alert**
		h.scheduleRenewalAlert(cert, kyc, req.RequesterID)
	}

	// Prepare response with detailed info
	response := map[string]interface{}{
		"certificate": cert,
		"validity_info": map[string]interface{}{
			"requested_days":      req.ValidityDays,
			"actual_days":         validityDays,
			"reason":              h.getValidityReason(req.ValidityDays, validityDays, idExpiryTime),
			"id_expiry_date":      kyc.IDExpiryDate,
			"certificate_expires": time.Unix(cert.ExpiresAt, 0).Format("2006-01-02"),
		},
		"renewal_info": map[string]interface{}{
			"renewal_reminder_date": renewalReminderDate.Format("2006-01-02"),
			"days_until_expiry":     int(time.Until(time.Unix(cert.ExpiresAt, 0)).Hours() / 24),
			"auto_renewal_endpoint": "/api/v1/certificate/issue",
		},
		"kyc_review_info": map[string]interface{}{
			"last_verified":   time.Unix(kyc.VerificationDate, 0).Format("2006-01-02"),
			"next_review_due": time.Unix(kyc.VerificationDate, 0).AddDate(1, 0, 0).Format("2006-01-02"),
		},
	}

	SendSuccess(w, "Verification certificate issued successfully", response)

	// Add warnings to response
	if len(warnings) > 0 {
		response["warnings"] = warnings
		response["grace_period_active"] = true
	}
}

// VerifyCertificate verifies a previously issued certificate, and with grace period support
func (h *Handlers) VerifyCertificate(w http.ResponseWriter, r *http.Request) {
	var req VerifyCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.Certificate == nil {
		SendBadRequest(w, "certificate is required")
		return
	}

	cert := req.Certificate

	// Check expiration with grace period
	isExpired := cert.IsExpired()
	inGracePeriod := false
	gracePeriodEnds := time.Unix(cert.ExpiresAt, 0).AddDate(0, 0, GracePeriodDays)

	if isExpired && time.Now().Before(gracePeriodEnds) {
		inGracePeriod = true
	}

	// Completely expired (past grace period)
	if isExpired && !inGracePeriod {
		SendBadRequest(w, fmt.Sprintf(
			"certificate has expired and grace period (%d days) has ended - please request a new certificate",
			GracePeriodDays,
		))
		return
	}

	if h.keyManager == nil {
		SendInternalError(w, "key manager not available")
		return
	}

	// Verify using KeyManager (handles both RSA and ECDSA)
	err := cert.VerifyWithKeyManager(h.keyManager)
	if err != nil {
		SendBadRequest(w, "certificate signature verification failed: "+err.Error())
		return
	}

	// Optionally verify current KYC status matches certificate
	kyc, err := h.blockchain.ReadKYC(cert.CustomerID, false)
	statusMatch := err == nil && string(kyc.Status) == cert.Status

	response := map[string]interface{}{
		"valid":                true,
		"certificate_id":       cert.CertificateID,
		"customer_id":          cert.CustomerID,
		"status":               cert.Status,
		"key_type":             cert.KeyType,
		"current_status_match": statusMatch,
		"expires_at":           cert.ExpiresAt,
		"expires_at_human":     time.Unix(cert.ExpiresAt, 0).Format("2006-01-02 15:04:05"),
		"is_expired":           isExpired,
	}

	// Add grace period warning
	if inGracePeriod {
		daysRemaining := int(time.Until(gracePeriodEnds).Hours() / 24)
		response["warning"] = "CERTIFICATE_IN_GRACE_PERIOD"
		response["grace_period"] = map[string]interface{}{
			"in_grace_period":   true,
			"grace_period_days": GracePeriodDays,
			"days_remaining":    daysRemaining,
			"grace_period_ends": gracePeriodEnds.Format("2006-01-02 15:04:05"),
			"action_required":   "Please renew certificate immediately",
		}
	}

	message := "Certificate verification successful"
	if inGracePeriod {
		message = "Certificate verified but in grace period - renewal required"
	}

	// Audit log the verification attempt with grace period details
	h.audit(r, ActionCertVerify, ResourceCertificate, cert.CertificateID, map[string]interface{}{
		"certificate_id": cert.CertificateID,
		"customer_id":    cert.CustomerID,
		"requester_id":   cert.RequesterID,
		"in_grace":       inGracePeriod,
		"is_expired":     isExpired,
	})

	SendSuccess(w, message, response)
}

// ListCertificates returns all issued certificates (paginated)
// GET /api/v1/certificates/list?requester_id=X&limit=100
func (h *Handlers) ListCertificates(w http.ResponseWriter, r *http.Request) {
	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	requesterID := r.URL.Query().Get("requester_id")
	limitStr := r.URL.Query().Get("limit")
	includeHistory := r.URL.Query().Get("include_history") == "true"

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	certs, err := h.storage.ListCertificates(requesterID, limit, includeHistory)
	if err != nil {
		SendInternalError(w, "failed to list certificates: "+err.Error())
		return
	}

	// Audit log the certificate listing action
	h.audit(r, ActionCertList, ResourceCertificate, "", map[string]interface{}{
		"requester_id":    requesterID,
		"limit":           limit,
		"include_history": includeHistory,
	})

	// Return the FULL VerificationCertificate shape so the frontend can pass it
	// directly to POST /api/v1/certificate/verify without modification.
	// Using models.VerificationCertificate field names directly.
	type KYCSummaryRow struct {
		FirstName   string `json:"first_name"`
		LastName    string `json:"last_name"`
		Nationality string `json:"nationality"`
		IDType      string `json:"id_type"`
		RiskLevel   string `json:"risk_level"`
		BankID      string `json:"bank_id"`
	}

	type CertRow struct {
		// Frontend display aliases
		ID           string `json:"id"`
		CustomerName string `json:"customer_name"`
		Hash         string `json:"hash"`      // = Signature, for table display
		Issuer       string `json:"issuer"`    // = IssuerID, for table display
		IssuedAt     int64  `json:"issued_at"` // = SignedAt, for table display

		// Full VerificationCertificate fields (matches models.VerificationCertificate JSON tags)
		CertificateID      string        `json:"certificate_id"`
		CustomerID         string        `json:"customer_id"`
		Status             string        `json:"status"`
		VerifiedBy         string        `json:"verified_by"`
		VerificationDate   int64         `json:"verification_date"`
		ExpiresAt          int64         `json:"expires_at"`
		RequesterID        string        `json:"requester_id"`
		RequesterPublicKey string        `json:"requester_public_key,omitempty"`
		KYCSummary         KYCSummaryRow `json:"kyc_summary"`
		IssuerID           string        `json:"issuer_id"`
		IssuerPublicKey    string        `json:"issuer_public_key"`
		KeyType            string        `json:"key_type"`
		Signature          string        `json:"signature"`
		SignedAt           int64         `json:"signed_at"`

		// is_active — lets the UI distinguish latest vs historical
		IsActive bool `json:"is_active"`
	}

	rows := make([]CertRow, 0, len(certs))
	for _, c := range certs {
		customerName := c.KYCSummary.FirstName + " " + c.KYCSummary.LastName
		if customerName == " " {
			customerName = c.CustomerID
		}
		rows = append(rows, CertRow{
			// Display aliases
			ID:           c.CertificateID,
			CustomerName: customerName,
			Hash:         c.Signature,
			Issuer:       c.IssuerID,
			IssuedAt:     c.SignedAt,

			// Full verify fields
			CertificateID:      c.CertificateID,
			CustomerID:         c.CustomerID,
			Status:             c.Status,
			VerifiedBy:         c.VerifiedBy,
			VerificationDate:   c.VerificationDate,
			ExpiresAt:          c.ExpiresAt,
			RequesterID:        c.RequesterID,
			RequesterPublicKey: c.RequesterPubKey,
			KYCSummary: KYCSummaryRow{
				FirstName:   c.KYCSummary.FirstName,
				LastName:    c.KYCSummary.LastName,
				Nationality: c.KYCSummary.Nationality,
				IDType:      c.KYCSummary.IDType,
				RiskLevel:   c.KYCSummary.RiskLevel,
				BankID:      c.KYCSummary.BankID,
			},
			IssuerID:        c.IssuerID,
			IssuerPublicKey: c.IssuerPubKey,
			KeyType:         c.KeyType,
			Signature:       c.Signature,
			SignedAt:        c.SignedAt,
			IsActive:        c.IsActive,
		})
	}

	SendSuccess(w, "", rows)
}

// calculateCertificateValidity calculates the actual certificate validity
// Ensures certificate never exceeds:
// 1. Requested validity
// 2. ID expiry date minus 30 days buffer
// 3. Next KYC review date
func (h *Handlers) calculateCertificateValidity(requestedDays int, idExpiryTime *time.Time, kyc *models.KYCData) int {
	now := time.Now()

	// Start with requested validity
	validityDays := requestedDays

	// **Rule 1: Cannot exceed ID expiry - 30 days buffer**
	if idExpiryTime != nil {
		// Buffer:  certificate expires 30 days before ID expires
		maxExpiryByID := idExpiryTime.AddDate(0, 0, -30)
		daysUntilIDExpiry := int(maxExpiryByID.Sub(now).Hours() / 24)

		if daysUntilIDExpiry > 0 && daysUntilIDExpiry < validityDays {
			validityDays = daysUntilIDExpiry
		}
	}

	// **Rule 2: Cannot exceed next KYC review date (12 months from verification)**
	nextReviewDate := time.Unix(kyc.VerificationDate, 0).AddDate(1, 0, 0)
	daysUntilReview := int(nextReviewDate.Sub(now).Hours() / 24)

	if daysUntilReview > 0 && daysUntilReview < validityDays {
		validityDays = daysUntilReview
	}

	// **Rule 3: Minimum 30 days validity (if possible)**
	if validityDays < 30 && validityDays > 0 {
		// Allow short validity but warn
		validityDays = validityDays
	}

	// **Rule 4: Maximum 365 days**
	if validityDays > 365 {
		validityDays = 365
	}

	// Must be at least 1 day
	if validityDays < 1 {
		validityDays = 1
	}

	return validityDays
}

// getValidityReason explains why validity was adjusted
func (h *Handlers) getValidityReason(requested, actual int, idExpiryTime *time.Time) string {
	if requested == actual {
		return "Requested validity granted"
	}

	if idExpiryTime != nil {
		daysUntilIDExpiry := int(idExpiryTime.Sub(time.Now()).Hours() / 24)
		if actual <= daysUntilIDExpiry-30 {
			return fmt.Sprintf("Limited by ID expiry date (expires in %d days, 30-day buffer applied)", daysUntilIDExpiry)
		}
	}

	return "Limited by periodic KYC review requirement (12 months from verification)"
}

// isKYCIDExpired checks if the KYC ID document is expired
func (h *Handlers) isKYCIDExpired(kyc *models.KYCData) (bool, *time.Time) {
	if kyc.IDExpiryDate == "" {
		return false, nil
	}

	expiryTime, err := time.Parse("2006-01-02", kyc.IDExpiryDate)
	if err != nil {
		return false, nil
	}

	return time.Now().After(expiryTime), &expiryTime
}

// isPeriodicReviewRequired checks if KYC needs periodic review (> 12 months)
func (h *Handlers) isPeriodicReviewRequired(kyc *models.KYCData) (bool, int64) {
	verifiedTime := time.Unix(kyc.VerificationDate, 0)
	reviewThreshold := time.Now().AddDate(-1, 0, 0) // 12 months ago

	return verifiedTime.Before(reviewThreshold), kyc.VerificationDate
}

// scheduleRenewalAlert creates renewal alerts for a certificate
func (h *Handlers) scheduleRenewalAlert(cert *models.VerificationCertificate, kyc *models.KYCData, requesterID string) {
	if h.storage == nil {
		return
	}

	expiresAt := cert.ExpiresAt
	now := time.Now()

	// Alert schedule:  30 days, 7 days, 1 day before expiry
	alertSchedule := []struct {
		alertType  string
		daysBefore int
	}{
		{"30_DAY", 30},
		{"7_DAY", 7},
		{"1_DAY", 1},
	}

	for _, schedule := range alertSchedule {
		alertTime := time.Unix(expiresAt, 0).AddDate(0, 0, -schedule.daysBefore)

		// Only schedule if alert time is in the future
		if alertTime.After(now) {
			alert := models.NewRenewalAlert(
				cert.CertificateID,
				cert.CustomerID,
				requesterID,
				schedule.alertType,
				alertTime.Unix(),
				expiresAt,
			)

			h.storage.SaveRenewalAlert(alert)
		}
	}
}

// ================= Renewal Alert =================

// // GetRenewalAlerts returns renewal alerts for the requester
// func (h *Handlers) GetRenewalAlerts(w http.ResponseWriter, r *http.Request) {
// 	requesterID := r.URL.Query().Get("requester_id")

// 	if h.storage == nil {
// 		SendError(w, http.StatusServiceUnavailable, "storage not available")
// 		return
// 	}

// 	var alerts []*models.RenewalAlert
// 	var err error

// 	if requesterID != "" {
// 		alerts, err = h.storage.GetRenewalAlertsByRequester(requesterID)
// 	} else {
// 		alerts, err = h.storage.GetPendingRenewalAlerts()
// 	}

// 	if err != nil {
// 		SendInternalError(w, "failed to get renewal alerts:  "+err.Error())
// 		return
// 	}

// 	SendSuccess(w, "", map[string]interface{}{
// 		"alerts": alerts,
// 		"count":  len(alerts),
// 	})
// }

// GetRenewalAlerts returns renewal alerts for the requester (supports filtering by requester_id)
// GET /api/v1/alerts/renewal?requester_id=X
func (h *Handlers) GetRenewalAlerts(w http.ResponseWriter, r *http.Request) {
	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	requesterID := r.URL.Query().Get("requester_id")

	alerts, err := h.storage.GetRenewalAlerts(requesterID)
	if err != nil {
		SendInternalError(w, "failed to get renewal alerts: "+err.Error())
		return
	}
	if alerts == nil {
		alerts = []*models.RenewalAlert{}
	}

	// Audit: who is reading renewal alerts
	h.audit(r, "RENEWAL_ALERT_LIST", ResourceAlert, "", map[string]interface{}{
		"requester_id": requesterID,
		"count":        len(alerts),
	})

	SendSuccess(w, "", map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// ConfigureRenewalAlert configures webhook/email for renewal alerts
// POST /api/v1/alerts/renewal/configure
func (h *Handlers) ConfigureRenewalAlert(w http.ResponseWriter, r *http.Request) {
	var req ConfigureRenewalAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.CertificateID == "" && req.AlertID == "" {
		SendBadRequest(w, "certificate_id or alert_id is required")
		return
	}

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	// ── CASE A: single-row toggle (alert_id provided) ─────────────────────
	// The UI uses this when toggling is_active for a specific alert row.
	// Only updates is_active — does NOT touch delivery/webhook/email.
	if req.AlertID != "" && req.IsActive != nil &&
		req.WebhookURL == "" && req.EmailRecipient == "" && req.Delivery == "" {

		if err := h.storage.UpdateRenewalAlertIsActive(req.AlertID, *req.IsActive); err != nil {
			SendInternalError(w, "failed to update alert: "+err.Error())
			return
		}

		h.audit(r, "RENEWAL_ALERT_TOGGLED", ResourceAlert, req.AlertID, map[string]interface{}{
			"alert_id":  req.AlertID,
			"is_active": *req.IsActive,
		})

		SendSuccess(w, "Alert updated", map[string]interface{}{
			"alert_id":  req.AlertID,
			"is_active": *req.IsActive,
		})
		return
	}

	// ── CASE B: full config update (certificate_id, bulk or with AlertID) ──
	// Updates delivery, webhook, email, interval, is_active for all alerts
	// belonging to the certificate — or just the one if alert_id is provided.
	if req.CertificateID == "" {
		SendBadRequest(w, "certificate_id is required for full configuration")
		return
	}

	// Defaults
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	delivery := req.Delivery
	if delivery == "" {
		// Infer from provided URLs
		hasEmail := req.EmailRecipient != ""
		hasWebhook := req.WebhookURL != ""
		switch {
		case hasEmail && hasWebhook:
			delivery = "both"
		case hasEmail:
			delivery = "email"
		case hasWebhook:
			delivery = "webhook"
		default:
			delivery = "none"
		}
	}
	sendInterval := req.SendInterval
	if sendInterval == "" {
		sendInterval = "immediate"
	}

	if err := h.storage.UpdateRenewalAlertFullConfig(
		req.CertificateID,
		req.WebhookURL,
		req.EmailRecipient,
		isActive,
		delivery,
		sendInterval,
	); err != nil {
		SendInternalError(w, "failed to configure alerts: "+err.Error())
		return
	}

	h.audit(r, "RENEWAL_ALERT_CONFIGURED", "RENEWAL_ALERT", req.CertificateID, map[string]interface{}{
		"certificate_id": req.CertificateID,
		"delivery":       delivery,
		"send_interval":  sendInterval,
		"is_active":      isActive,
		"has_webhook":    req.WebhookURL != "",
		"has_email":      req.EmailRecipient != "",
	})

	SendSuccess(w, "Renewal alert configured", map[string]interface{}{
		"certificate_id": req.CertificateID,
		"delivery":       delivery,
		"send_interval":  sendInterval,
		"is_active":      isActive,
	})
}

// SendRenewalAlert — manual dispatch
// POST /api/v1/alerts/renewal/send
// Body: { certificate_id, alert_id }
func (h *Handlers) SendRenewalAlert(w http.ResponseWriter, r *http.Request) {
	var req SendRenewalAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.CertificateID == "" && req.AlertID == "" {
		SendBadRequest(w, "certificate_id or alert_id is required")
		return
	}

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	// Find the alert
	allAlerts, err := h.storage.GetRenewalAlerts("")
	if err != nil {
		SendInternalError(w, "failed to load alerts: "+err.Error())
		return
	}

	// // Fetch the alert to get delivery config
	// alerts, err := h.storage.GetRenewalAlertsByRequester("") // pass empty for all
	// if err != nil {
	// 	SendInternalError(w, "failed to load alerts: "+err.Error())
	// 	return
	// }

	var target *models.RenewalAlert
	for _, a := range allAlerts {
		if (req.AlertID != "" && a.ID == req.AlertID) ||
			(req.CertificateID != "" && a.CertificateID == req.CertificateID) {
			target = a
			break
		}
	}

	if target == nil {
		SendNotFound(w, "renewal alert not found")
		return
	}

	if !target.IsActive {
		SendBadRequest(w, "alert is disabled — enable it first")
		return
	}

	// sent := false
	dispatchStatus := "SENT"
	errs := []string{}

	// ── Dispatch to webhook ──────────────────────────────────────────────────
	if target.WebhookURL != "" &&
		(target.Delivery == "webhook" || target.Delivery == "both") {

		payload := map[string]interface{}{
			"id":             target.ID,
			"certificate_id": target.CertificateID,
			"customer_id":    target.CustomerID,
			"requester_id":   target.RequesterID,
			"alert_type":     target.AlertType,
			"expires_at":     target.CertExpiresAt,
			"manual_send":    true,
			"sent_at":        time.Now().Unix(),
		}
		body, _ := json.Marshal(payload)

		client := &http.Client{Timeout: 10 * time.Second}
		resp, httpErr := client.Post(target.WebhookURL, "application/json", bytes.NewReader(body))
		if httpErr != nil {
			errs = append(errs, "webhook: "+httpErr.Error())
			dispatchStatus = "FAILED"
		} else {
			resp.Body.Close()
			// sent = true
		}
	}

	// ── Email placeholder ────────────────────────────────────────────────────
	// Wire to your SMTP/SES client here.  For now we just log it.
	if target.EmailRecipient != "" &&
		(target.Delivery == "email" || target.Delivery == "both") {

		log.Printf("[SendRenewalAlert] EMAIL to %s: cert %s expires %s",
			target.EmailRecipient,
			target.CertificateID,
			time.Unix(target.CertExpiresAt, 0).Format("2006-01-02"),
		)
		// sent = true
		// TODO: replace log with actual email send:
		// emailService.Send(target.EmailRecipient, subject, body)
	}

	// Mark as sent in DB
	// if sent {
	// 	h.storage.SendRenewalAlertNow(target.ID)
	// }
	if markErr := h.storage.MarkRenewalAlertSent(target.ID, dispatchStatus); markErr != nil {
		log.Printf("[SendRenewalAlert] failed to mark status: %v", markErr)
	}

	h.audit(r, "RENEWAL_ALERT_SENT_MANUAL", ResourceAlert, target.CertificateID, map[string]interface{}{
		"alert_id":       target.ID,
		"certificate_id": target.CertificateID,
		"customer_id":    target.CustomerID,
		"delivery":       target.Delivery,
		"status":         dispatchStatus,
	})

	if len(errs) > 0 {
		SendSuccess(w, "Alert dispatch failed", map[string]interface{}{
			"sent":   dispatchStatus,
			"errors": errs,
		})
		return
	}

	SendSuccess(w, "Renewal alert sent successfully", map[string]interface{}{
		"certificate_id": target.CertificateID,
		"alert_id":       target.ID,
		"sent_to":        target.Delivery,
		"status":         dispatchStatus,
		"sent_at":        time.Now().Unix(),
	})
}

// ==================== Periodic KYC Review Check ====================

// PeriodicReviewKYC performs periodic KYC review
func (h *Handlers) PeriodicReviewKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req PeriodicReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.CustomerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}

	// Get KYC record
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, false)
	if err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	// Must be verified to review
	if kyc.Status != models.StatusVerified {
		SendBadRequest(w, "can only review VERIFIED KYC records")
		return
	}

	// Validate review checks
	if !req.DocumentsValid {
		SendBadRequest(w, "documents must be valid - update documents first if expired")
		return
	}
	if !req.AMLCheckPassed {
		SendBadRequest(w, "AML check must pass for review approval")
		return
	}
	if !req.PEPCheckPassed {
		SendBadRequest(w, "PEP check must pass for review approval")
		return
	}

	// Update risk level if provided
	if req.RiskLevelUpdate != "" {
		validRiskLevels := map[string]bool{"low": true, "medium": true, "high": true}
		if !validRiskLevels[req.RiskLevelUpdate] {
			SendBadRequest(w, "invalid risk_level_update - must be low, medium, or high")
			return
		}
		kyc.RiskLevel = req.RiskLevelUpdate
	}

	// Complete the review
	reviewNotes := fmt.Sprintf(
		"Reviewed by %s on %s.  Notes: %s.  AML:  PASS, PEP: PASS, Docs: VALID",
		user.ID,
		time.Now().Format("2006-01-02 15:04:05"),
		req.ReviewNotes,
	)
	kyc.CompleteReview(reviewNotes)

	// Save to database
	if h.storage != nil {
		h.storage.SaveKYC(kyc)

		// Log the review
		h.audit(r, ActionKYCReview, ResourceKYC, req.CustomerID, map[string]interface{}{
			"customer_id":  req.CustomerID,
			"review_count": kyc.ReviewCount,
			"risk_level":   kyc.RiskLevel,
			"next_review":  kyc.NextReviewDate,
			"aml_check":    "PASS",
			"pep_check":    "PASS",
			"documents":    "VALID",
		})
	}

	SendSuccess(w, "KYC periodic review completed successfully", map[string]interface{}{
		"customer_id":        req.CustomerID,
		"review_date":        time.Unix(kyc.LastReviewDate, 0).Format("2006-01-02"),
		"next_review_date":   time.Unix(kyc.NextReviewDate, 0).Format("2006-01-02"),
		"review_count":       kyc.ReviewCount,
		"risk_level":         kyc.RiskLevel,
		"days_until_review":  kyc.GetDaysUntilReview(),
		"certificate_status": "New certificates can now be issued for 12 months",
	})
}

// GetKYCReviewStatus returns KYC review status
func (h *Handlers) GetKYCReviewStatus(w http.ResponseWriter, r *http.Request) {
	customerID := r.URL.Query().Get("customer_id")
	if customerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}

	kyc, err := h.blockchain.ReadKYC(customerID, false)
	if err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	// Check ID expiry
	idExpired, idExpiryTime := h.isKYCIDExpired(kyc)

	// Check review status
	needsReview := kyc.NeedsPeriodicReview()
	daysUntilReview := kyc.GetDaysUntilReview()

	response := map[string]interface{}{
		"customer_id":       customerID,
		"kyc_status":        kyc.Status,
		"verification_date": time.Unix(kyc.VerificationDate, 0).Format("2006-01-02"),
		"last_review_date":  nil,
		"next_review_date":  nil,
		"review_count":      kyc.ReviewCount,
		"days_until_review": daysUntilReview,
		"needs_review":      needsReview,
		"id_document": map[string]interface{}{
			"id_type":           kyc.IDType,
			"expiry_date":       kyc.IDExpiryDate,
			"is_expired":        idExpired,
			"days_until_expiry": nil,
		},
		"risk_level":            kyc.RiskLevel,
		"can_issue_certificate": !needsReview && !idExpired && kyc.Status == models.StatusVerified,
	}

	if kyc.LastReviewDate > 0 {
		response["last_review_date"] = time.Unix(kyc.LastReviewDate, 0).Format("2006-01-02")
	}
	if kyc.NextReviewDate > 0 {
		response["next_review_date"] = time.Unix(kyc.NextReviewDate, 0).Format("2006-01-02")
	}
	if idExpiryTime != nil {
		daysUntilIDExpiry := int(time.Until(*idExpiryTime).Hours() / 24)
		response["id_document"].(map[string]interface{})["days_until_expiry"] = daysUntilIDExpiry
	}

	// Add action required message
	if idExpired {
		response["action_required"] = "ID document expired - update KYC with new ID"
	} else if needsReview {
		response["action_required"] = "Periodic review required - call POST /api/v1/kyc/review"
	}

	SendSuccess(w, "", response)
}

// ==================== Python ML KYC Handlers ====================

// Config
func pythonKYCServiceURL() string {
	if url := os.Getenv("PYTHON_KYC_SERVICE_URL"); url != "" {
		return url
	}
	return "http://localhost:5001"
}

// Request / Response types
// UploadDocImageRequest accepts base64 image for ID/Passport scan
type UploadDocImageRequest struct {
	CustomerID   string `json:"customer_id"`
	ImageBase64  string `json:"image_base64"`
	DocumentType string `json:"document_type"` // national_id | passport
}

// UploadSelfieRequest accepts base64 selfie + ID image for face comparison
type UploadSelfieRequest struct {
	CustomerID        string `json:"customer_id"`
	SelfieImageBase64 string `json:"selfie_image_base64"`
	IDImageBase64     string `json:"id_image_base64,omitempty"` // optional — if empty, read from KYC record
}

// PythonFaceComparePayload mirrors the Python /api/kyc/face/compare request
type PythonFaceComparePayload struct {
	IDImageBase64     string `json:"id_image_base64"`
	SelfieImageBase64 string `json:"selfie_image_base64"`
}

// PythonFaceCompareResponse mirrors the Python FaceResult response
type PythonFaceCompareResponse struct {
	Verified        bool    `json:"verified"`
	Distance        float64 `json:"distance"`
	Threshold       float64 `json:"threshold"`
	Model           string  `json:"model"`
	SimilarityScore float64 `json:"similarity_score"`
	Preprocessing   string  `json:"preprocessing"`
	Device          string  `json:"device"`
	Error           string  `json:"error,omitempty"`
}

// ScanAndVerifyRequest triggers full OCR + face + DB match pipeline
type ScanAndVerifyRequest struct {
	CustomerID        string `json:"customer_id"`
	IDImageBase64     string `json:"id_image_base64"`
	SelfieImageBase64 string `json:"selfie_image_base64,omitempty"`
	DocumentType      string `json:"document_type"` // national_id | passport
}

// PythonKYCVerifyPayload mirrors the Python API request
type PythonKYCVerifyPayload struct {
	CustomerID        string `json:"customer_id"`
	IDImageBase64     string `json:"id_image_base64,omitempty"`
	SelfieImageBase64 string `json:"selfie_image_base64,omitempty"`
	DocumentType      string `json:"document_type"`
}

// PythonKYCScanPayload mirrors the Python /api/kyc/scan request
type PythonKYCScanPayload struct {
	ImageBase64  string `json:"image_base64"`
	DocumentType string `json:"document_type"`
}

// PythonKYCVerifyResponse mirrors the Python response
type PythonKYCVerifyResponse struct {
	CustomerID       string                 `json:"customer_id"`
	DocumentVerified bool                   `json:"document_verified"`
	FaceMatched      bool                   `json:"face_matched"`
	OCRResult        map[string]interface{} `json:"ocr_result"`
	FaceResult       map[string]interface{} `json:"face_result"`
	FieldMatch       map[string]interface{} `json:"field_match"`
	OverallScore     float64                `json:"overall_score"`
	Status           string                 `json:"status"` // VERIFIED | REJECTED | NEEDS_REVIEW
	Reason           string                 `json:"reason"`
	Timestamp        string                 `json:"timestamp"`
	ScoreBreakdown   map[string]interface{} `json:"score_breakdown"`
	VerifiedBy       string                 `json:"verified_by"`       // "google_vision|ArcFace|gfpgan_restored"
	DocumentHash     string                 `json:"document_hash"`     // SHA-256 hex (64 chars)
	VerificationDate int64                  `json:"verification_date"` // Unix timestamp
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handlers) callPythonKYC(endpoint string, payload interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal error: %w", err)
	}

	// client := &http.Client{Timeout: 6000 * time.Second}
	// url := pythonKYCServiceURL() + endpoint

	timeout := h.config.PythonService.GetTimeoutJSON()
	client := &http.Client{Timeout: timeout}
	url := h.config.PythonService.GetURL() + endpoint

	log.Printf("[Python KYC] POST %s (timeout=%s)", url, timeout)

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("python KYC service unreachable: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("python KYC service error %d: %s", resp.StatusCode, string(raw))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return result, nil
}

// callPythonKYCMultipart sends multipart/form-data with file fields
func (h *Handlers) callPythonKYCMultipart(
	endpoint string,
	fields map[string]string,
	files map[string][]byte,
) (map[string]interface{}, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	for key, val := range fields {
		_ = w.WriteField(key, val)
	}
	for fieldName, data := range files {
		fw, err := w.CreateFormFile(fieldName, fieldName+".jpg")
		if err != nil {
			return nil, err
		}
		_, _ = fw.Write(data)
	}
	w.Close()

	// client := &http.Client{Timeout: 120 * time.Second}
	// url := pythonKYCServiceURL() + endpoint

	timeout := h.config.PythonService.GetTimeoutMultipart()
	client := &http.Client{Timeout: timeout}
	url := h.config.PythonService.GetURL() + endpoint

	log.Printf("[Python KYC] POST %s multipart (timeout=%s)", url, timeout)

	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("python KYC service unreachable: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("python KYC service error %d: %s", resp.StatusCode, string(raw))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("unmarshal error: %w", err)
	}
	return result, nil
}

// mapPythonStatusToKYC maps Python verdict → KYCStatus
func mapPythonStatusToKYC(s string) models.KYCStatus {
	switch s {
	case "VERIFIED":
		return models.StatusVerified
	case "REJECTED":
		return models.StatusRejected
	default:
		return models.StatusPending
	}
}

// Handlers

// UploadDocumentImage accepts a base64 ID card / Passport image,
// calls Python OCR service, and attaches the scan result to the KYC record.
//
// POST /api/v1/kyc/upload-doc
func (h *Handlers) UploadDocumentImage(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	// ── parse body ──
	var req UploadDocImageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.CustomerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}
	if req.ImageBase64 == "" {
		SendBadRequest(w, "image_base64 is required")
		return
	}
	if req.DocumentType == "" {
		req.DocumentType = "national_id"
	}

	// ── verify KYC exists ──
	if _, err := h.blockchain.ReadKYC(req.CustomerID, false); err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	_ = user // used for audit logs if desired

	// ── call Python OCR ──
	payload := PythonKYCScanPayload{
		ImageBase64:  req.ImageBase64,
		DocumentType: req.DocumentType,
	}
	result, err := h.callPythonKYC("/api/kyc/scan", payload)
	if err != nil {
		SendInternalError(w, fmt.Sprintf("OCR service error: %v", err))
		return
	}

	SendSuccess(w, "Document scanned successfully", map[string]interface{}{
		"customer_id":   req.CustomerID,
		"document_type": req.DocumentType,
		"scan_result":   result,
		"scanned_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// UploadDocumentFile accepts multipart file upload for ID card / Passport.
//
// POST /api/v1/kyc/upload-doc/file
func (h *Handlers) UploadDocumentFile(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}
	_ = user

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		SendBadRequest(w, "failed to parse multipart form")
		return
	}

	customerID := r.FormValue("customer_id")
	documentType := r.FormValue("document_type")
	if customerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}
	if documentType == "" {
		documentType = "national_id"
	}

	file, _, err := r.FormFile("id_image")
	if err != nil {
		SendBadRequest(w, "id_image file is required")
		return
	}
	defer file.Close()
	data, _ := io.ReadAll(file)

	result, err := h.callPythonKYCMultipart(
		"/api/kyc/scan/upload",
		map[string]string{"document_type": documentType},
		map[string][]byte{"file": data},
	)
	if err != nil {
		SendInternalError(w, fmt.Sprintf("OCR service error: %v", err))
		return
	}

	SendSuccess(w, "Document scanned successfully", map[string]interface{}{
		"customer_id":   customerID,
		"document_type": documentType,
		"scan_result":   result,
		"scanned_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

// UploadSelfieImage accepts a selfie image, calls the Python face comparison
// API against the ID card photo, and returns the face match result.
//
// The caller can provide id_image_base64 in the request body. If omitted,
// the handler checks whether the KYC record already has an ID image path
// (set by a previous /upload-doc call).
//
// POST /api/v1/kyc/upload-selfie
func (h *Handlers) UploadSelfieImage(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req UploadSelfieRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.CustomerID == "" || req.SelfieImageBase64 == "" {
		SendBadRequest(w, "customer_id and selfie_image_base64 are required")
		return
	}

	// Validate KYC exists
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, false)
	if err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	// Determine the ID image to compare against
	idImageBase64 := req.IDImageBase64
	if idImageBase64 == "" {
		// No ID image in this request — check if KYC already has one from /upload-doc
		if kyc.IDImagePath == "" {
			SendBadRequest(w, "id_image_base64 is required (no previous ID image found for this customer). "+
				"Either include id_image_base64 in the request or call POST /api/v1/kyc/upload-doc first.")
			return
		}
		// ID image was uploaded previously but we don't have the base64 in memory.
		// The caller must provide it explicitly for face comparison.
		SendBadRequest(w, "id_image_base64 is required for face comparison. "+
			"Please include the ID card image along with the selfie.")
		return
	}

	_ = user // available for audit logging

	// ── Call Python face comparison API ──
	payload := PythonFaceComparePayload{
		IDImageBase64:     idImageBase64,
		SelfieImageBase64: req.SelfieImageBase64,
	}
	rawResult, err := h.callPythonKYC("/api/kyc/face/compare", payload)
	if err != nil {
		SendInternalError(w, fmt.Sprintf("Face comparison service error: %v", err))
		return
	}

	// Parse Python response
	var faceResp PythonFaceCompareResponse
	resultBytes, _ := json.Marshal(rawResult)
	_ = json.Unmarshal(resultBytes, &faceResp)

	// ── Update KYC record with selfie path ──
	kyc.SelfieImagePath = fmt.Sprintf("uploads/%s/selfie_image.jpg", req.CustomerID)
	now := time.Now()
	kyc.LastScanAt = &now
	kyc.UpdatedAt = now.Unix()

	// Save updated KYC
	if h.storage != nil {
		h.storage.SaveKYC(kyc)
	}

	// ── Build response ──
	SendSuccess(w, "Selfie uploaded and face comparison completed", map[string]interface{}{
		"customer_id": req.CustomerID,
		"face_result": map[string]interface{}{
			"verified":         faceResp.Verified,
			"distance":         faceResp.Distance,
			"threshold":        faceResp.Threshold,
			"model":            faceResp.Model,
			"similarity_score": faceResp.SimilarityScore,
			"preprocessing":    faceResp.Preprocessing,
			"device":           faceResp.Device,
			"error":            faceResp.Error,
		},
		"uploaded_at":  now.UTC().Format(time.RFC3339),
		"instructions": "Face comparison done. Use POST /api/v1/kyc/scan-verify for full pipeline (OCR + face + DB match + scoring).",
	})
}

// ScanAndVerifyKYC is the main full-pipeline endpoint:
// OCR ID image → Face comparison → DB field match → KYC status update.
//
// POST /api/v1/kyc/scan-verify
func (h *Handlers) ScanAndVerifyKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	var req ScanAndVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.CustomerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}
	if req.IDImageBase64 == "" {
		SendBadRequest(w, "id_image_base64 is required")
		return
	}
	if req.DocumentType == "" {
		req.DocumentType = "national_id"
	}

	// Ensure KYC record exists
	kyc, err := h.blockchain.ReadKYC(req.CustomerID, false)
	if err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	// Call Python full-verify pipeline
	payload := PythonKYCVerifyPayload{
		CustomerID:        req.CustomerID,
		IDImageBase64:     req.IDImageBase64,
		SelfieImageBase64: req.SelfieImageBase64,
		DocumentType:      req.DocumentType,
	}
	rawResult, err := h.callPythonKYC("/api/kyc/verify", payload)
	if err != nil {
		SendInternalError(w, fmt.Sprintf("KYC AI service error: %v", err))
		return
	}

	// Parse Python response
	var pyResp PythonKYCVerifyResponse
	resultBytes, _ := json.Marshal(rawResult)
	_ = json.Unmarshal(resultBytes, &pyResp)

	// ── OCR field completeness check ──
	// If Python reports incomplete extraction, return retryable error
	// Do NOT update KYC status — let the frontend retry with a better image
	if pyResp.Status == "OCR_INCOMPLETE" {
		SendResponse(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"success":         false,
			"retryable":       true,
			"message":         pyResp.Reason,
			"customer_id":     req.CustomerID,
			"ai_status":       pyResp.Status,
			"ocr_result":      pyResp.OCRResult,
			"score_breakdown": pyResp.ScoreBreakdown,
			"instructions":    "Please re-capture the ID card with better lighting/angle and retry.",
		})
		return
	}

	// After parsing pyResp, populate scan fields onto kyc regardless of status
	now := time.Now()
	kyc.LastScanAt = &now
	score := pyResp.OverallScore
	kyc.ScanScore = &score
	kyc.ScanStatus = pyResp.Status // "VERIFIED" | "REJECTED" | "NEEDS_REVIEW"

	// verified_by — from Python response (google_vision|ArcFace|gfpgan_restored)
	if pyResp.VerifiedBy != "" {
		kyc.VerifiedBy = pyResp.VerifiedBy
	}

	// document_hash — from Python response (SHA-256 of id image bytes)
	if pyResp.DocumentHash != "" {
		kyc.DocumentHash = pyResp.DocumentHash
	}

	// verification_date — Unix timestamp now
	kyc.VerificationDate = time.Now().Unix() // always set at scan time

	if pyResp.OCRResult != nil {
		kyc.OCRResult = pyResp.OCRResult
	}

	kyc.IDImagePath = fmt.Sprintf("uploads/%s/id_image.jpg", req.CustomerID)
	kyc.SelfieImagePath = fmt.Sprintf("uploads/%s/selfie_image.jpg", req.CustomerID)

	// ── Resolve bankID (same as ScanAndVerifyKYCFile) ──
	bankID := user.BankID
	if bankID == "" {
		bankID = kyc.BankID
	}

	// Auto-update KYC status based on AI verdict
	aiStatus := mapPythonStatusToKYC(pyResp.Status)
	if kyc.Status == models.StatusPending {
		switch aiStatus {
		case models.StatusVerified:
			if err := h.blockchain.VerifyKYC(req.CustomerID, bankID, user.ID, user.Username); err != nil {
				SendBadRequest(w, err.Error())
				return
			}
			kyc.Status = models.StatusVerified

			// Persist the pending transaction to DB so it survives restart
			if h.storage != nil {
				pendingTxs := h.blockchain.GetPendingTransactions()
				for _, tx := range pendingTxs {
					if tx.CustomerID == req.CustomerID {
						if err := h.storage.SaveTransaction(tx); err != nil {
							log.Printf("[VerifyKYC] Warning: could not persist tx to DB: %v", err)
						}
						break
					}
				}
			}
		case models.StatusRejected:
			if err := h.blockchain.RejectKYC(req.CustomerID, bankID, user.ID, pyResp.Reason); err != nil {
				SendBadRequest(w, err.Error())
				return
			}
			kyc.Status = models.StatusRejected
		}
	}

	// // verified_by — from Python response (google_vision|ArcFace|gfpgan_restored)
	// if v, ok := pyResp.FaceResult["preprocessing"].(string); ok && v != "" {
	// 	ocr := "google_vision"
	// 	model := settings_FACE_MODEL // or read from pyResp.FaceResult["model"]
	// 	if m, ok2 := pyResp.FaceResult["model"].(string); ok2 && m != "" {
	// 		model = m
	// 	}
	// 	kyc.VerifiedBy = ocr + "|" + model + "|" + v
	// } else if vb, ok := pyResp.ScoreBreakdown["verified_by"].(string); ok {
	// 	kyc.VerifiedBy = vb
	// }

	// // verification_date — Unix timestamp now
	// kyc.VerificationDate = time.Now().Unix()

	// // document_hash — from Python response (SHA-256 of id image bytes)
	// if dh, ok := pyResp.ScoreBreakdown["document_hash"].(string); ok && dh != "" {
	// 	kyc.DocumentHash = dh
	// }

	// // Persist
	// if h.storage != nil {
	// 	h.storage.SaveKYC(kyc)
	// }

	// Persist — now includes scan fields + status
	if h.storage != nil {
		if err := h.storage.SaveKYC(kyc); err != nil {
			log.Printf("ERROR SaveKYC %s: %v", req.CustomerID, err)
		}
	}

	// Audit the scan action with detailed info
	h.audit(r, ActionKYCAIScan, ResourceKYC, req.CustomerID, map[string]interface{}{
		"customer_id":       req.CustomerID,
		"document_type":     req.DocumentType,
		"ai_status":         pyResp.Status,
		"kyc_status":        aiStatus,
		"overall_score":     pyResp.OverallScore,
		"document_verified": pyResp.DocumentVerified,
		"face_matched":      pyResp.FaceMatched,
	})

	// Generate document hash for audit trail
	hashInput := req.CustomerID + req.DocumentType + utils.FormatTimestamp(time.Now().Unix())
	_ = hashInput // h.storage could store doc_hash here

	txCreated := kyc.Status == models.StatusVerified

	SendSuccess(w, "KYC AI scan verification completed", map[string]interface{}{
		"customer_id":       req.CustomerID,
		"document_verified": pyResp.DocumentVerified,
		"face_matched":      pyResp.FaceMatched,
		"overall_score":     pyResp.OverallScore,
		"ai_status":         pyResp.Status,
		"kyc_status":        aiStatus,
		"reason":            pyResp.Reason,
		"ocr_result":        pyResp.OCRResult,
		"face_result":       pyResp.FaceResult,
		"field_match":       pyResp.FieldMatch,
		"score_breakdown":   pyResp.ScoreBreakdown,
		"on_blockchain":     false,     // aiStatus == models.StatusVerified,
		"pending_for_mine":  txCreated, // aiStatus == models.StatusVerified,
		"timestamp":         pyResp.Timestamp,
	})
}

// ScanAndVerifyKYCFile is the multipart version of ScanAndVerifyKYC.
//
// POST /api/v1/kyc/scan-verify/file
func (h *Handlers) ScanAndVerifyKYCFile(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		SendBadRequest(w, "failed to parse multipart form")
		return
	}

	customerID := r.FormValue("customer_id")
	documentType := r.FormValue("document_type")
	if customerID == "" {
		SendBadRequest(w, "customer_id is required")
		return
	}
	if documentType == "" {
		documentType = "national_id"
	}

	// Read ID image
	idFile, _, err := r.FormFile("id_image")
	if err != nil {
		SendBadRequest(w, "id_image is required")
		return
	}
	defer idFile.Close()
	idData, _ := io.ReadAll(idFile)

	// Read optional selfie
	files := map[string][]byte{"id_image": idData}
	formFields := map[string]string{
		"customer_id":   customerID,
		"document_type": documentType,
	}
	if selfieFile, _, err2 := r.FormFile("selfie_image"); err2 == nil {
		defer selfieFile.Close()
		selfieData, _ := io.ReadAll(selfieFile)
		files["selfie_image"] = selfieData
	}

	rawResult, err := h.callPythonKYCMultipart("/api/kyc/verify/upload", formFields, files)
	if err != nil {
		SendInternalError(w, fmt.Sprintf("KYC AI service error: %v", err))
		return
	}

	// Parse + auto-update same as JSON version
	var pyResp PythonKYCVerifyResponse
	resultBytes, _ := json.Marshal(rawResult)
	_ = json.Unmarshal(resultBytes, &pyResp)

	// ── OCR field completeness check ──
	// If Python reports incomplete extraction, return retryable error
	// Do NOT update KYC status — let the frontend retry with a better image
	if pyResp.Status == "OCR_INCOMPLETE" {
		SendResponse(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"success":         false,
			"retryable":       true,
			"message":         pyResp.Reason,
			"customer_id":     customerID,
			"ai_status":       pyResp.Status,
			"ocr_result":      pyResp.OCRResult,
			"score_breakdown": pyResp.ScoreBreakdown,
			"instructions":    "Please re-capture the ID card with better lighting/angle and retry.",
		})
		return
	}

	kyc, err := h.blockchain.ReadKYC(customerID, false)
	if err != nil {
		SendNotFound(w, "KYC record not found")
		return
	}

	// After parsing pyResp, populate scan fields onto kyc regardless of status
	now := time.Now()
	kyc.LastScanAt = &now
	score := pyResp.OverallScore
	kyc.ScanScore = &score
	kyc.ScanStatus = pyResp.Status // "VERIFIED" | "REJECTED" | "NEEDS_REVIEW"

	// verified_by — from Python response (google_vision|ArcFace|gfpgan_restored)
	if pyResp.VerifiedBy != "" {
		kyc.VerifiedBy = pyResp.VerifiedBy
	}

	// document_hash — from Python response (SHA-256 of id image bytes)
	if pyResp.DocumentHash != "" {
		kyc.DocumentHash = pyResp.DocumentHash
	}

	// verification_date — Unix timestamp now
	kyc.VerificationDate = time.Now().Unix() // always set at scan time

	if pyResp.OCRResult != nil {
		kyc.OCRResult = pyResp.OCRResult
	}

	// Populate scan image paths on kyc before saving
	// Save a reference path (not the raw bytes) for audit purposes
	kyc.IDImagePath = fmt.Sprintf("uploads/%s/id_image.jpg", customerID)
	kyc.SelfieImagePath = fmt.Sprintf("uploads/%s/selfie_image.jpg", customerID)

	// ── Resolve bankID for VerifyKYC ──
	// Admin users may not have a BankID; fall back to the bank that created the KYC record.
	bankID := user.BankID
	if bankID == "" {
		bankID = kyc.BankID // use the bank that originally created the KYC
	}

	aiStatus := mapPythonStatusToKYC(pyResp.Status)

	if kyc.Status == models.StatusPending {
		switch aiStatus {
		case models.StatusVerified:
			if err := h.blockchain.VerifyKYC(customerID, bankID, user.ID, user.Username); err != nil {
				log.Printf("ERROR VerifyKYC %s: %v", customerID, err)
				SendBadRequest(w, fmt.Sprintf("blockchain VerifyKYC failed: %v", err))
				return
			}
			kyc.Status = models.StatusVerified

			// Persist the pending transaction to DB so it survives restart ──
			if h.storage != nil {
				pendingTxs := h.blockchain.GetPendingTransactions()
				for _, tx := range pendingTxs {
					if tx.CustomerID == customerID {
						if err := h.storage.SaveTransaction(tx); err != nil {
							log.Printf("[VerifyKYC] Warning: could not persist tx to DB: %v", err)
						}
						break
					}
				}
			}
		case models.StatusRejected:
			if err := h.blockchain.RejectKYC(customerID, bankID, user.ID, pyResp.Reason); err != nil {
				log.Printf("ERROR RejectKYC %s: %v", customerID, err)
				SendBadRequest(w, fmt.Sprintf("blockchain RejectKYC failed: %v", err))
				return
			}
			kyc.Status = models.StatusRejected
		}
	}

	// // verified_by — from Python response (google_vision|ArcFace|gfpgan_restored)
	// if v, ok := pyResp.FaceResult["preprocessing"].(string); ok && v != "" {
	// 	ocr := "google_vision"
	// 	model := settings_FACE_MODEL // or read from pyResp.FaceResult["model"]
	// 	if m, ok2 := pyResp.FaceResult["model"].(string); ok2 && m != "" {
	// 		model = m
	// 	}
	// 	kyc.VerifiedBy = ocr + "|" + model + "|" + v
	// } else if vb, ok := pyResp.ScoreBreakdown["verified_by"].(string); ok {
	// 	kyc.VerifiedBy = vb
	// }

	// // verification_date — Unix timestamp now
	// kyc.VerificationDate = time.Now().Unix()

	// // document_hash — from Python response (SHA-256 of id image bytes)
	// if dh, ok := pyResp.ScoreBreakdown["document_hash"].(string); ok && dh != "" {
	// 	kyc.DocumentHash = dh
	// }

	// log.Printf("SaveKYC result for %s: %v", customerID, h.storage.SaveKYC(kyc))
	if h.storage != nil {
		if err := h.storage.SaveKYC(kyc); err != nil {
			log.Printf("ERROR SaveKYC %s: %v", customerID, err)
		}
	}

	// Audit the scan action with detailed info
	h.audit(r, ActionKYCAIScan, ResourceKYC, customerID, map[string]interface{}{
		"customer_id":       customerID,
		"document_type":     documentType,
		"ai_status":         pyResp.Status,
		"kyc_status":        aiStatus,
		"overall_score":     pyResp.OverallScore,
		"document_verified": pyResp.DocumentVerified,
		"face_matched":      pyResp.FaceMatched,
	})

	txCreated := kyc.Status == models.StatusVerified

	SendSuccess(w, "KYC AI scan verification completed", map[string]interface{}{
		"customer_id":       customerID,
		"document_verified": pyResp.DocumentVerified,
		"face_matched":      pyResp.FaceMatched,
		"overall_score":     pyResp.OverallScore,
		"ai_status":         pyResp.Status,
		"kyc_status":        aiStatus,
		"reason":            pyResp.Reason,
		"ocr_result":        pyResp.OCRResult,
		"face_result":       pyResp.FaceResult,
		"field_match":       pyResp.FieldMatch,
		"score_breakdown":   pyResp.ScoreBreakdown,
		"on_blockchain":     false,
		"pending_for_mine":  txCreated,
		"timestamp":         pyResp.Timestamp,
	})
}

// ==================== User Management Handlers ====================

// ListUsers returns all non-deleted users (admin only)
func (h *Handlers) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.storage.GetAllUsers()
	if err != nil {
		SendInternalError(w, "failed to list users: "+err.Error())
		return
	}

	// Strip sensitive fields before sending
	type SafeUser struct {
		ID                     string    `json:"id"`
		Username               string    `json:"username"`
		Email                  string    `json:"email"`
		Role                   string    `json:"role"`
		BankID                 string    `json:"bank_id,omitempty"`
		IsActive               bool      `json:"is_active"`
		IsDeleted              bool      `json:"is_deleted"`
		PasswordChangeRequired bool      `json:"password_change_required"`
		LoginCount             int       `json:"login_count"`
		CreatedAt              time.Time `json:"created_at"`
		UpdatedAt              time.Time `json:"updated_at"`
		LastLogin              time.Time `json:"last_login,omitempty"`
	}

	result := make([]SafeUser, 0, len(users))
	for _, u := range users {
		result = append(result, SafeUser{
			ID:                     u.ID,
			Username:               u.Username,
			Email:                  u.Email,
			Role:                   string(u.Role),
			BankID:                 u.BankID,
			IsActive:               u.IsActive,
			IsDeleted:              u.IsDeleted,
			PasswordChangeRequired: u.PasswordChangeRequired,
			LoginCount:             u.LoginCount,
			CreatedAt:              u.CreatedAt,
			UpdatedAt:              u.UpdatedAt,
			LastLogin:              u.LastLogin,
		})
	}
	SendSuccess(w, "", map[string]interface{}{
		"users": result,
		"count": len(result),
	})
}

// CreateUser creates a new internal user (bank_admin, bank_officer, auditor)
func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
		BankID   string `json:"bank_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.Username == "" || req.Email == "" || req.Password == "" || req.Role == "" {
		SendBadRequest(w, "username, email, password, and role are required")
		return
	}

	// Disallow creating customer or another admin via this endpoint
	allowedRoles := map[string]bool{
		"bank_admin":          true,
		"bank_officer":        true,
		"auditor":             true,
		"integration_service": true, // NextJS gateway machine account
	}
	if !allowedRoles[req.Role] {
		SendBadRequest(w, "role must be one of: bank_admin, bank_officer, auditor, integration_service")
		return
	}

	// Validate bank assignment for bank roles
	// bank_admin and bank_officer require a bank — integration_service does NOT
	if (req.Role == "bank_admin" || req.Role == "bank_officer") && req.BankID == "" {
		SendBadRequest(w, "bank_id is required for bank_admin and bank_officer roles")
		return
	}

	user, err := h.authService.Register(&auth.RegisterRequest{
		Username: req.Username,
		Email:    req.Email,
		Password: req.Password,
		Role:     auth.Role(req.Role),
		BankID:   req.BankID,
	})
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// New internal users must change password on first login
	// user.PasswordChangeRequired = true

	// New internal users must change password on first login
	// Exception: integration_service is a machine account — no interactive login
	if req.Role != string(auth.RoleIntegrationService) {
		user.PasswordChangeRequired = true
	}

	if h.storage != nil {
		if err := h.storage.SaveUser(user); err != nil {
			SendInternalError(w, "failed to persist user: "+err.Error())
			return
		}

		// Audit the user creation action
		h.audit(r, ActionUserCreate, ResourceUser, user.ID, map[string]interface{}{
			"username": user.Username,
			"role":     user.Role,
			"bank_id":  user.BankID,
		})
	}

	SendCreated(w, "user created successfully", map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
		"bank_id":  user.BankID,
	})
}

// UpdateUser updates role, is_active for a user
func (h *Handlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		IsActive *bool  `json:"is_active,omitempty"`
		Role     string `json:"role,omitempty"`
		BankID   string `json:"bank_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.UserID == "" {
		SendBadRequest(w, "user_id is required")
		return
	}

	user, err := h.authService.GetUserByID(req.UserID)
	if err != nil {
		SendNotFound(w, "user not found")
		return
	}

	// Prevent modifying the root admin
	if user.Username == "admin" && req.Role != "" && req.Role != "admin" {
		SendForbidden(w, "cannot change role of root admin")
		return
	}

	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.Role != "" {
		user.Role = auth.Role(req.Role)
	}
	if req.BankID != "" {
		user.BankID = req.BankID
	}
	user.UpdatedAt = time.Now()

	if h.storage != nil {
		h.storage.SaveUser(user)

		// Audit the update action with changed fields
		h.audit(r, ActionUserUpdate, ResourceUser, req.UserID, map[string]interface{}{
			"is_active": req.IsActive,
			"role":      req.Role,
		})
	}

	SendSuccess(w, "user updated successfully", nil)
}

// DeleteUser soft-deletes a user (sets is_deleted=true, is_active=false)
func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.UserID == "" {
		SendBadRequest(w, "user_id is required")
		return
	}

	user, err := h.authService.GetUserByID(req.UserID)
	if err != nil {
		SendNotFound(w, "user not found")
		return
	}
	if user.Username == "admin" {
		SendForbidden(w, "cannot delete root admin")
		return
	}

	user.IsActive = false
	user.IsDeleted = true
	user.UpdatedAt = time.Now()

	if h.storage != nil {
		h.storage.SaveUser(user)

		// Audit the deletion action
		h.audit(r, ActionUserDelete, ResourceUser, req.UserID, map[string]interface{}{
			"username": user.Username,
		})
	}

	SendSuccess(w, "user deleted successfully", nil)
}

// ResetUserPassword resets a user's password to a temp value + forces change
func (h *Handlers) ResetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	if req.UserID == "" {
		SendBadRequest(w, "user_id is required")
		return
	}

	tempPassword, err := h.authService.ResetPassword(req.UserID)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	user, _ := h.authService.GetUserByID(req.UserID)
	if h.storage != nil && user != nil {
		h.storage.SaveUser(user)

		// Stamp password_changed_at — the temp password is a new one
		if pgStore, ok := h.storage.(*storage.PostgresStorage); ok {
			pgStore.UpdatePasswordChangedAt(user.ID)
		}

		// Audit the password reset action
		h.audit(r, ActionPasswordReset, ResourceUser, req.UserID, map[string]interface{}{
			"username": user.Username,
		})
	}

	SendSuccess(w, "password reset successfully", map[string]interface{}{
		"temp_password":            tempPassword,
		"password_change_required": true,
		"message":                  "Share this temporary password securely with the user. They must change it on next login.",
	})
}

// getUserIDFromContext is a helper for audit logs in handlers
func getUserIDFromContext(r *http.Request) string {
	user, ok := GetUserFromContext(r)
	if !ok {
		return "system"
	}
	return user.ID
}

// ── Customer self-service ──────────────────────────────────────────────────

// GetMyKYC returns the authenticated customer's own KYC record.
// The customer_id is stored as the user's ID (set during registration).
// GET /api/v1/kyc/me
func (h *Handlers) GetMyKYC(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	// customer_id is stored on the user record by CreateKYC (CHANGE 4a above).
	// It is a hash (utils.GenerateCustomerID) ≠ user.ID / user.Username.
	// Fall back to user.ID and user.Username only for records created before
	// this fix was deployed (backward compatibility).
	var customerID string
	if user.CustomerID != "" {
		customerID = user.CustomerID
	} else {
		customerID = user.ID // backward compat fallback
	}

	kyc, err := h.blockchain.ReadKYC(customerID, true)
	if err != nil && user.CustomerID == "" {
		// Last resort: try username (old behavior)
		kyc, err = h.blockchain.ReadKYC(user.Username, true)
	}
	if err != nil {
		SendNotFound(w, "no KYC record found for your account")
		return
	}

	SendSuccess(w, "", map[string]interface{}{
		"kyc_data":      kyc,
		"on_blockchain": kyc.IsOnBlockchain(),
		"can_modify":    kyc.CanModify(),
		"can_verify":    kyc.CanVerify(),
	})
}

// GetMyCertificates returns certificates issued to the authenticated customer.
// Looks up by customer_id in the certificates table.
// GET /api/v1/certificates/me
func (h *Handlers) GetMyCertificates(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	// customer_id is stored on user.CustomerID (set by CreateKYC, CHANGE 4a).
	// Fall back to user.ID and user.Username for backward compatibility.
	lookupID := user.CustomerID
	if lookupID == "" {
		lookupID = user.ID
	}
	certs, err := h.storage.GetCertificatesByCustomer(lookupID)
	if (err != nil || len(certs) == 0) && lookupID != user.Username {
		certs, _ = h.storage.GetCertificatesByCustomer(user.Username)
	}
	if err != nil && len(certs) == 0 {
		SendSuccess(w, "", map[string]interface{}{
			"certificates": []interface{}{},
			"count":        0,
		})
		return
	}
	if certs == nil {
		certs = []*models.VerificationCertificate{}
	}

	SendSuccess(w, "", map[string]interface{}{
		"certificates": certs,
		"count":        len(certs),
	})
}

// ── Emergency Security Lock ─────────────────────────────────────────────────

// GetPasswordPolicy returns the current policy. Any authenticated user can read
// (so the frontend can show "password expires in N days").
// GET /api/v1/auth/password-policy
func (h *Handlers) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	pol, err := pgStore.GetPasswordPolicy()
	if err != nil {
		SendInternalError(w, err.Error())
		return
	}

	// Include caller's own password status so frontend can show countdown
	var daysRemaining int
	if user, ok := GetUserFromContext(r); ok {
		if changedAt, err := pgStore.GetPasswordChangedAt(user.ID); err == nil && !changedAt.IsZero() {
			expiresAt := changedAt.AddDate(0, pol.IntervalMonths, 0)
			daysRemaining = int(time.Until(expiresAt).Hours() / 24)
			if daysRemaining < 0 {
				daysRemaining = 0
			}
		}
	}

	h.audit(r, "PASSWORD_POLICY_READ", "SECURITY", "password_policy", nil)

	SendSuccess(w, "", map[string]interface{}{
		"interval_months":     pol.IntervalMonths,
		"updated_by":          pol.UpdatedBy,
		"updated_at":          pol.UpdatedAt,
		"your_days_remaining": daysRemaining,
	})
}

// UpdatePasswordPolicy — admin only.
// PUT /api/v1/auth/password-policy
// Body: { "interval_months": 1|3|6|12 }
func (h *Handlers) UpdatePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}
	var req struct {
		IntervalMonths int `json:"interval_months"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	if err := pgStore.SetPasswordPolicy(req.IntervalMonths, user.ID); err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	h.audit(r, "PASSWORD_POLICY_UPDATED", "SECURITY", "password_policy", map[string]interface{}{
		"interval_months": req.IntervalMonths,
		"actor":           user.Username,
	})

	SendSuccess(w, fmt.Sprintf("Password policy set to %d months", req.IntervalMonths),
		map[string]interface{}{"interval_months": req.IntervalMonths})
}

// ForceAllPasswordReset — admin only.
// POST /api/v1/auth/force-password-reset-all
// Sets password_change_required=TRUE for every non-root, non-machine user.
// Users are NOT logged out — they just get forced to the change-password
// screen on their next login (or their next authenticated page load, if the
// frontend polls it).
func (h *Handlers) ForceAllPasswordReset(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	n, err := pgStore.ForceAllPasswordChange(user.ID)
	if err != nil {
		SendInternalError(w, err.Error())
		return
	}

	h.audit(r, "PASSWORD_FORCE_RESET_ALL", "SECURITY", "users", map[string]interface{}{
		"affected_count": n,
		"actor":          user.Username,
	})

	// Also invalidate the in-memory auth cache so the next token validation
	// picks up the flag immediately.
	if h.authService != nil {
		if users, err := pgStore.GetAllUsers(); err == nil {
			for _, u := range users {
				if u.Username != "admin" && u.Role != auth.RoleIntegrationService {
					u.PasswordChangeRequired = true
					h.authService.LoadUser(u)
				}
			}
		}
	}

	SendSuccess(w, fmt.Sprintf("Forced password reset for %d users", n),
		map[string]interface{}{"affected_count": n})
}

// EmergencyLock — admin only.
// POST /api/v1/security/emergency-lock
// Body: { "locked": true, "reason": "..." }
// When locked=true, all non-admin logins are rejected.
// When locked=false, normal login resumes.
func (h *Handlers) EmergencyLock(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}
	var req struct {
		Locked bool   `json:"locked"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	if err := pgStore.SetEmergencyLock(req.Locked, user.ID); err != nil {
		SendInternalError(w, err.Error())
		return
	}

	action := "EMERGENCY_LOCK_DISABLED"
	msg := "Emergency lock disabled — normal login resumed"
	if req.Locked {
		action = "EMERGENCY_LOCK_ENABLED"
		msg = "Emergency lock enabled — non-admin logins blocked"
	}
	h.audit(r, action, "SECURITY", "emergency_lock", map[string]interface{}{
		"reason": req.Reason,
		"actor":  user.Username,
	})

	SendSuccess(w, msg, map[string]interface{}{"locked": req.Locked})
}

// GetEmergencyLock — any authenticated admin can read status.
// GET /api/v1/security/emergency-lock
func (h *Handlers) GetEmergencyLock(w http.ResponseWriter, r *http.Request) {
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	locked, err := pgStore.IsEmergencyLocked()
	if err != nil {
		SendInternalError(w, err.Error())
		return
	}
	SendSuccess(w, "", map[string]interface{}{"locked": locked})
}

// ── Key rotation — admin only, infrequent (system key: ~1/year; KEK: 1–2/year) ──

// RotateSigningKey generates a new system signing key and activates it.
// Old certs remain verifiable because they carry issuer_public_key + issuer_key_id.
// POST /api/v1/security/keys/signing/rotate
// Body: { "algorithm": "RSA"|"ECDSA", "key_size": 2048|256 }
func (h *Handlers) RotateSigningKey(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}
	var req struct {
		Algorithm string `json:"algorithm"`
		KeySize   int    `json:"key_size"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.Algorithm == "" {
		req.Algorithm = h.config.Crypto.Algorithm
	}
	if req.KeySize == 0 {
		req.KeySize = h.config.Crypto.KeySize
	}

	if h.signingKeyMgr == nil {
		SendError(w, http.StatusServiceUnavailable, "signing key manager not initialized")
		return
	}

	newID, err := h.signingKeyMgr.Rotate(req.Algorithm, req.KeySize, user.ID, true)
	if err != nil {
		SendInternalError(w, "rotation failed: "+err.Error())
		return
	}

	h.audit(r, "SIGNING_KEY_ROTATED", "SECURITY", newID, map[string]interface{}{
		"algorithm": req.Algorithm,
		"key_size":  req.KeySize,
		"actor":     user.Username,
	})

	SendSuccess(w, "Signing key rotated — new certificates will use the new key; old certificates remain verifiable", map[string]interface{}{
		"new_key_id": newID,
		"algorithm":  req.Algorithm,
		"key_size":   req.KeySize,
		"note":       "Retired key is kept for verifying historical certificates",
	})
}

// ListSigningKeys — admin only.
// GET /api/v1/security/keys/signing
func (h *Handlers) ListSigningKeys(w http.ResponseWriter, r *http.Request) {
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	keys, err := pgStore.ListSystemKeys()
	if err != nil {
		SendInternalError(w, err.Error())
		return
	}
	// Strip private key encrypted blobs for safety (ListSystemKeys already does)
	SendSuccess(w, "", map[string]interface{}{"keys": keys, "count": len(keys)})
}

// RotateKEK generates a new KEK, activates it, and kicks off a background
// re-wrap of all DEKs. Returns immediately; caller polls GetKEKRewrapStatus.
// POST /api/v1/security/keys/kek/rotate
func (h *Handlers) RotateKEK(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}
	if h.envelope == nil {
		SendError(w, http.StatusServiceUnavailable, "envelope encryptor not initialized")
		return
	}

	newKEKID, err := h.envelope.GenerateKEK(user.ID, false) // inactive for now
	if err != nil {
		SendInternalError(w, "generate KEK: "+err.Error())
		return
	}
	if err := h.envelope.ActivateKEK(newKEKID, user.ID); err != nil {
		SendInternalError(w, "activate KEK: "+err.Error())
		return
	}

	// Background rewrap — non-blocking.
	go func() {
		pgStore, ok := h.storage.(*storage.PostgresStorage)
		if !ok {
			return
		}
		rows, err := pgStore.ListKYCForRewrap(newKEKID)
		if err != nil {
			log.Printf("[KEK rotate] list rewrap rows: %v", err)
			return
		}
		log.Printf("[KEK rotate] rewrapping %d rows under new KEK %s", len(rows), newKEKID)
		for _, row := range rows {
			newWrapped, newID, err := h.envelope.RewrapDEK(row.WrappedDEK, row.KEKID)
			if err != nil {
				log.Printf("[KEK rotate] rewrap %s failed: %v", row.CustomerID, err)
				continue
			}
			if err := pgStore.RewrapKYCRecord(row.CustomerID, newWrapped, newID); err != nil {
				log.Printf("[KEK rotate] persist rewrap %s failed: %v", row.CustomerID, err)
			}
		}
		log.Printf("[KEK rotate] rewrap complete for KEK %s", newKEKID)
	}()

	h.audit(r, "KEK_ROTATED", "SECURITY", newKEKID, map[string]interface{}{
		"actor": user.Username,
	})

	SendSuccess(w, "KEK rotated. Background re-wrap of DEKs has started.", map[string]interface{}{
		"new_kek_id": newKEKID,
		"note":       "DEK re-wrap runs in background. Old KEK stays available for unwrap until re-wrap completes.",
	})
}

// ListKEKs — admin only.
// GET /api/v1/security/keys/kek
func (h *Handlers) ListKEKs(w http.ResponseWriter, r *http.Request) {
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}
	keks, err := pgStore.ListKEKs()
	if err != nil {
		SendInternalError(w, err.Error())
		return
	}
	SendSuccess(w, "", map[string]interface{}{"keks": keks, "count": len(keks)})
}
