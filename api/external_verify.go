package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/storage"
)

// ─── Request / Response types ────────────────────────────────────────────────

// ExternalVerifyRequest is the payload CBS sends to look up a KYC record.
type ExternalVerifyRequest struct {
	IDType   string `json:"id_type"`   // e.g. "NATIONAL_ID", "PASSPORT"
	IDNumber string `json:"id_number"` // the plain document number
	BankID   string `json:"bank_id"`   // the requesting bank's ID in Go-KYC
}

// ExternalVerifyResponse is returned to CBS on a successful verification.
// Field names use snake_case JSON tags to match GoKycVerifyResponse.java.
type ExternalVerifyResponse struct {
	CustomerID   string                `json:"customer_id"`
	FirstName    string                `json:"first_name"`
	LastName     string                `json:"last_name"`
	DateOfBirth  string                `json:"date_of_birth"`
	Nationality  string                `json:"nationality"`
	IDType       string                `json:"id_type"`
	IDNumber     string                `json:"id_number"` // decrypted — returned to CBS
	IDExpiryDate string                `json:"id_expiry_date"`
	Address      ExternalVerifyAddress `json:"address"`
	Email        string                `json:"email"` // decrypted
	Phone        string                `json:"phone"` // decrypted
	Status       string                `json:"status"`
	BankID       string                `json:"bank_id"`
	// User fields — required by CBS for eligibility check
	UserRole  string `json:"user_role"` // "customer"
	IsActive  bool   `json:"is_active"`
	IsDeleted bool   `json:"is_deleted"`
}

type ExternalVerifyAddress struct {
	Street     string `json:"street"`
	City       string `json:"city"`
	State      string `json:"state"`
	PostalCode string `json:"postal_code"`
	Country    string `json:"country"`
}

// ─── Handler ─────────────────────────────────────────────────────────────────

// ExternalVerifyKYC handles POST /api/v1/kyc/external-verify.
//
// Called by an external system (e.g. Core Banking System) to verify whether a
// person identified by their document (id_type + id_number) has a VERIFIED KYC
// record linked to the requesting bank, and whether the linked user account
// satisfies role=customer / is_active / !is_deleted.
//
// Auth: Bearer JWT — caller must have role admin | bank_admin | bank_officer |
//
//	integration_service.
//
// Request body:
//
//	{ "id_type": "NATIONAL_ID", "id_number": "AB12345678", "bank_id": "BANK00000001" }
//
// Success 200 — KYC found and all checks pass.
// 400          — missing / invalid fields.
// 403          — caller lacks permission.
// 404          — no matching KYC record found.
// 422          — record found but fails eligibility (status, role, active, deleted).
func (h *Handlers) ExternalVerifyKYC(w http.ResponseWriter, r *http.Request) {
	// ── 1. Decode request ────────────────────────────────────────────────────
	var req ExternalVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		SendBadRequest(w, "invalid request body")
		return
	}

	req.IDType = strings.TrimSpace(strings.ToUpper(req.IDType))
	req.IDNumber = strings.TrimSpace(req.IDNumber)
	req.BankID = strings.TrimSpace(req.BankID)

	if req.IDType == "" || req.IDNumber == "" || req.BankID == "" {
		SendBadRequest(w, "id_type, id_number, and bank_id are required")
		return
	}

	// ── 2. Require PostgresStorage + envelope encryptor ──────────────────────
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok || h.envelope == nil {
		log.Printf("[ExternalVerifyKYC] storage or envelope not available")
		SendInternalError(w, "service not properly initialised")
		return
	}

	// ── 3. Validate bank exists and is active ────────────────────────────────
	bank, err := h.storage.GetBank(req.BankID)
	if err != nil || bank == nil {
		SendNotFound(w, "bank not found: "+req.BankID)
		return
	}
	if !bank.IsActive {
		SendError(w, http.StatusUnprocessableEntity, "bank is not active: "+req.BankID)
		return
	}

	// ── 4. Load encrypted KYC rows for this bank + id_type ──────────────────
	rawRows, err := pgStore.GetKYCRawByBankAndIDType(req.BankID, req.IDType)
	if err != nil {
		log.Printf("[ExternalVerifyKYC] DB error: %v", err)
		SendInternalError(w, "failed to query KYC records")
		return
	}
	if len(rawRows) == 0 {
		SendNotFound(w, "no KYC records found for this bank and document type")
		return
	}

	// ── 5. Decrypt id_number for each row and compare ───────────────────────
	var matchedRow *storage.KYCRawRow
	for i := range rawRows {
		row := &rawRows[i]
		if row.WrappedDEK == "" || row.KEKID == "" {
			continue // skip rows without envelope key material
		}
		plainBytes, decErr := h.envelope.DecryptField(row.IDNumberEnc, row.WrappedDEK, row.KEKID)
		if decErr != nil {
			log.Printf("[ExternalVerifyKYC] decrypt id_number for %s: %v", row.CustomerID, decErr)
			continue
		}
		if strings.EqualFold(strings.TrimSpace(string(plainBytes)), req.IDNumber) {
			matchedRow = row
			break
		}
	}

	if matchedRow == nil {
		SendNotFound(w, "no KYC record matches the provided document number")
		return
	}

	// ── 6. KYC eligibility checks ────────────────────────────────────────────
	if !strings.EqualFold(matchedRow.Status, "VERIFIED") {
		SendError(w, http.StatusUnprocessableEntity,
			"KYC record is not VERIFIED (current status: "+matchedRow.Status+")")
		return
	}

	// ── 7. Look up the linked user (role / active / deleted checks) ──────────
	linkedUser, err := pgStore.GetUserByCustomerID(matchedRow.CustomerID)
	if err != nil {
		// No linked user record — cannot confirm eligibility
		SendError(w, http.StatusUnprocessableEntity,
			"no user account linked to this KYC record")
		return
	}

	if linkedUser.Role != auth.RoleCustomer {
		SendError(w, http.StatusUnprocessableEntity,
			"KYC subject does not have the 'customer' role")
		return
	}
	if !linkedUser.IsActive {
		SendError(w, http.StatusUnprocessableEntity,
			"user account is not active")
		return
	}
	if linkedUser.IsDeleted {
		SendError(w, http.StatusUnprocessableEntity,
			"user account has been deleted")
		return
	}

	// ── 8. Decrypt remaining PII for the response ────────────────────────────
	email := decryptFieldSafe(h, matchedRow.EmailEnc, matchedRow.WrappedDEK, matchedRow.KEKID)
	phone := decryptFieldSafe(h, matchedRow.PhoneEnc, matchedRow.WrappedDEK, matchedRow.KEKID)
	idNumber := req.IDNumber // already confirmed — use the plain input

	// ── 9. Audit ─────────────────────────────────────────────────────────────
	caller, _ := GetUserFromContext(r)
	callerID := "unknown"
	if caller != nil {
		callerID = caller.ID
	}
	h.audit(r, "EXTERNAL_VERIFY_KYC", "KYC", matchedRow.CustomerID, map[string]interface{}{
		"bank_id":      req.BankID,
		"id_type":      req.IDType,
		"requested_by": callerID,
	})

	// ── 10. Build and return response ────────────────────────────────────────
	resp := ExternalVerifyResponse{
		CustomerID:   matchedRow.CustomerID,
		FirstName:    matchedRow.FirstName,
		LastName:     matchedRow.LastName,
		DateOfBirth:  matchedRow.DateOfBirth,
		Nationality:  matchedRow.Nationality,
		IDType:       matchedRow.IDType,
		IDNumber:     idNumber,
		IDExpiryDate: matchedRow.IDExpiryDate,
		Address: ExternalVerifyAddress{
			Street:     matchedRow.AddressStreet,
			City:       matchedRow.AddressCity,
			State:      matchedRow.AddressState,
			PostalCode: matchedRow.AddressPostal,
			Country:    matchedRow.AddressCountry,
		},
		Email:     email,
		Phone:     phone,
		Status:    matchedRow.Status,
		BankID:    matchedRow.BankID,
		UserRole:  string(linkedUser.Role),
		IsActive:  linkedUser.IsActive,
		IsDeleted: linkedUser.IsDeleted,
	}

	log.Printf("[ExternalVerifyKYC] verified customer_id=%s bank=%s by=%s",
		matchedRow.CustomerID, req.BankID, callerID)

	SendSuccess(w, "KYC verified successfully", resp)
}

// decryptFieldSafe decrypts a ciphertext using envelope; returns empty string on error.
func decryptFieldSafe(h *Handlers, ciphertext, wrappedDEK, kekID string) string {
	if ciphertext == "" || wrappedDEK == "" || kekID == "" {
		return ""
	}
	plain, err := h.envelope.DecryptField(ciphertext, wrappedDEK, kekID)
	if err != nil {
		log.Printf("[decryptFieldSafe] warning: %v", err)
		return ""
	}
	return string(plain)
}
