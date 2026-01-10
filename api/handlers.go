package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/models"
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
}

// NewHandlers creates a new handlers instance
func NewHandlers(blockchain *models.Blockchain, authService *auth.AuthService, storage storage.Storage, rbac *auth.RBAC, verificationService *verification.VerificationService) *Handlers {
	return &Handlers{
		blockchain:          blockchain,
		authService:         authService,
		storage:             storage,
		rbac:                rbac,
		verificationService: verificationService,
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
		user.BankID,
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
