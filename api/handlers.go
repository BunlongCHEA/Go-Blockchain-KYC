package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"Go-Blockchain-KYC/auth"
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
) *Handlers {
	return &Handlers{
		blockchain:          blockchain,
		authService:         authService,
		storage:             storage,
		rbac:                rbac,
		verificationService: verificationService,
		monitoringService:   monitoringService,
		keyManager:          keyManager,
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

	response, err := h.authService.Login(&req)
	if err != nil {
		SendUnauthorized(w, err.Error())
		return
	}

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
		err = h.blockchain.VerifyKYC(req.CustomerID, user.BankID, user.ID)
		if err != nil {
			SendBadRequest(w, err.Error())
			return
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

	// Update in database
	kyc.Status = result.Status
	kyc.RiskLevel = result.RiskLevel
	if h.storage != nil {
		h.storage.SaveKYC(kyc)
	}

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
	if h.storage != nil {
		h.storage.SaveKYC(kycData)
	}

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

	// This will create transaction and add to pending
	err = h.blockchain.VerifyKYC(req.CustomerID, user.BankID, user.ID)
	if err != nil {
		SendBadRequest(w, err.Error())
		return
	}

	// Update in database
	kyc.Status = models.StatusVerified
	if h.storage != nil {
		h.storage.SaveKYC(kyc)
	}

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

	// Update in database
	if h.storage != nil {
		kyc, _ := h.blockchain.ReadKYC(req.CustomerID, false)
		if kyc != nil {
			h.storage.SaveKYC(kyc)
		}
	}

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

	SendPaginated(w, records, page, perPage, totalItems)
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

// ==================== Blockchain Handlers ====================

// GetBlockchainStats returns blockchain statistics
func (h *Handlers) GetBlockchainStats(w http.ResponseWriter, r *http.Request) {
	stats := h.blockchain.GetStats()
	stats["is_valid"] = h.blockchain.IsChainValid()
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

	SendCreated(w, "block mined successfully", block)
}

// GetPendingTransactions returns pending transactions
func (h *Handlers) GetPendingTransactions(w http.ResponseWriter, r *http.Request) {
	txs := h.blockchain.GetPendingTransactions()
	SendSuccess(w, "", txs)
}

// ValidateChain validates the blockchain
func (h *Handlers) ValidateChain(w http.ResponseWriter, r *http.Request) {
	isValid := h.blockchain.IsChainValid()
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

	SendSuccess(w, "Alert reviewed successfully", map[string]interface{}{
		"alert_id":    req.AlertID,
		"reviewed_by": user.ID,
		"action":      req.Action,
		"reviewed_at": time.Now().Format(time.RFC3339),
	})
}

// ================= Issue/Re-issue Certificate with Grace Period Check =================

// IssueVerificationCertificate issues a signed KYC verification certificate & with grace period handling
func (h *Handlers) IssueVerificationCertificate(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r)
	if !ok {
		SendUnauthorized(w, "user not found")
		return
	}

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
	if err := cert.SignWithKeyManager(h.keyManager); err != nil {
		SendInternalError(w, "failed to sign certificate:  "+err.Error())
		return
	}

	// Calculate renewal reminder date (30 days before expiry)
	renewalReminderDate := time.Unix(cert.ExpiresAt, 0).AddDate(0, 0, -30)

	// Log the certificate issuance
	if h.storage != nil {
		h.storage.SaveAuditLog(&models.AuditLog{
			UserID:       user.ID,
			Action:       "CERTIFICATE_ISSUED",
			ResourceType: "KYC_CERTIFICATE",
			ResourceID:   cert.CertificateID,
			Details: map[string]interface{}{
				"customer_id":        req.CustomerID,
				"requester_id":       req.RequesterID,
				"certificate_id":     cert.CertificateID,
				"key_type":           cert.KeyType,
				"requested_validity": req.ValidityDays,
				"actual_validity":    validityDays,
				"expires_at":         cert.ExpiresAt,
				"id_expiry_date":     kyc.IDExpiryDate,
				"renewal_reminder":   renewalReminderDate.Unix(),
			},
			IPAddress: getClientIP(r),
			CreatedAt: time.Now(),
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

	SendSuccess(w, message, response)
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

// GetRenewalAlerts returns renewal alerts for the requester
func (h *Handlers) GetRenewalAlerts(w http.ResponseWriter, r *http.Request) {
	requesterID := r.URL.Query().Get("requester_id")

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	var alerts []*models.RenewalAlert
	var err error

	if requesterID != "" {
		alerts, err = h.storage.GetRenewalAlertsByRequester(requesterID)
	} else {
		alerts, err = h.storage.GetPendingRenewalAlerts()
	}

	if err != nil {
		SendInternalError(w, "failed to get renewal alerts:  "+err.Error())
		return
	}

	SendSuccess(w, "", map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// ConfigureRenewalAlert configures webhook/email for renewal alerts
func (h *Handlers) ConfigureRenewalAlert(w http.ResponseWriter, r *http.Request) {
	var req ConfigureRenewalAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	if req.CertificateID == "" {
		SendBadRequest(w, "certificate_id is required")
		return
	}

	if req.WebhookURL == "" && req.EmailRecipient == "" {
		SendBadRequest(w, "webhook_url or email_recipient is required")
		return
	}

	if h.storage == nil {
		SendError(w, http.StatusServiceUnavailable, "storage not available")
		return
	}

	// Update alerts for this certificate
	err := h.storage.UpdateRenewalAlertConfig(req.CertificateID, req.WebhookURL, req.EmailRecipient)
	if err != nil {
		SendInternalError(w, "failed to configure alerts: "+err.Error())
		return
	}

	SendSuccess(w, "Renewal alerts configured successfully", map[string]interface{}{
		"certificate_id":  req.CertificateID,
		"webhook_url":     req.WebhookURL,
		"email_recipient": req.EmailRecipient,
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
		h.storage.SaveAuditLog(&models.AuditLog{
			UserID:       user.ID,
			Action:       "KYC_PERIODIC_REVIEW",
			ResourceType: "KYC",
			ResourceID:   req.CustomerID,
			Details: map[string]interface{}{
				"customer_id":  req.CustomerID,
				"review_count": kyc.ReviewCount,
				"risk_level":   kyc.RiskLevel,
				"next_review":  kyc.NextReviewDate,
				"aml_check":    "PASS",
				"pep_check":    "PASS",
				"documents":    "VALID",
			},
			IPAddress: getClientIP(r),
			CreatedAt: time.Now(),
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
