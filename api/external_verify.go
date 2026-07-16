package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"Go-Blockchain-KYC/auth"
	kyccrypto "Go-Blockchain-KYC/crypto"
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

	// Normalise — do NOT uppercase id_type; the DB may store it in any case.
	// We use LOWER() on both sides in SQL, so keep the original casing here
	// to avoid double-transformation confusion.
	req.IDType = strings.TrimSpace(req.IDType)
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
	//
	// Two decryption paths:
	//   A) Envelope-encrypted  — wrapped_dek != "" && kek_id != ""
	//      Uses h.envelope.DecryptField (current path, post-migration records).
	//   B) Legacy-encrypted    — wrapped_dek == ""
	//      Uses the old crypto.Encryptor with config.Crypto.EncryptionKey
	//      (records created before envelope encryption was deployed).
	var matchedRow *storage.KYCRawRow
	for i := range rawRows {
		row := &rawRows[i]

		var plainBytes []byte
		var decErr error

		if row.WrappedDEK != "" && row.KEKID != "" {
			// Path A: envelope encryption
			plainBytes, decErr = h.envelope.DecryptField(row.IDNumberEnc, row.WrappedDEK, row.KEKID)
		} else {
			// Path B: legacy direct-AES encryption (pre-envelope records)
			var plain string
			plain, decErr = decryptLegacyField(h, row.IDNumberEnc)
			if decErr == nil {
				plainBytes = []byte(plain)
			}
		}

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

// ─── Decrypt helpers ──────────────────────────────────────────────────────────

// decryptFieldSafe decrypts a PII field and returns an empty string on any error
// so a partial failure doesn't abort the whole response.
//
// Two paths:
//   - Envelope (new): wrappedDEK and kekID both non-empty → h.envelope.DecryptField
//   - Legacy (old):   wrappedDEK empty                   → decryptLegacyField
func decryptFieldSafe(h *Handlers, ciphertext, wrappedDEK, kekID string) string {
	if ciphertext == "" {
		return ""
	}
	if wrappedDEK != "" && kekID != "" {
		// Envelope-encrypted record (post-migration)
		plain, err := h.envelope.DecryptField(ciphertext, wrappedDEK, kekID)
		if err != nil {
			log.Printf("[decryptFieldSafe] envelope decrypt warning: %v", err)
			return ""
		}
		return string(plain)
	}
	// Legacy record (pre-migration, wrapped_dek = NULL)
	plain, err := decryptLegacyField(h, ciphertext)
	if err != nil {
		log.Printf("[decryptFieldSafe] legacy decrypt warning: %v", err)
		return ""
	}
	return plain
}

// decryptLegacyField decrypts a ciphertext that was encrypted with the old
// crypto.Encryptor (direct AES-256-GCM using config.Crypto.EncryptionKey).
//
// These are KYC records created before envelope encryption was deployed.
// The config key is expected to be a base64-encoded 32-byte value.
func decryptLegacyField(h *Handlers, ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", fmt.Errorf("empty ciphertext")
	}

	// encKey := h.config.Crypto.EncryptionKey
	encKey := h.config.Crypto.GetEncryptionKey()
	if encKey == "" {
		return "", fmt.Errorf("crypto.encryption_key not set — cannot decrypt legacy record")
	}

	// Determine the raw key bytes.
	// Priority:
	//   1. Raw string bytes — the original code did []byte(encryptionKey) directly,
	//      so a 32-char hex string like "b2238066b2001667869629d24a9f5fd4"
	//      gives exactly 32 bytes and is the common case.
	//   2. Base64 — if the string isn't 32 bytes raw, try decoding as base64
	//      (e.g. a newly generated 32-byte key encoded for config storage).
	keyBytes := []byte(encKey)
	if len(keyBytes) != 32 {
		if decoded, err2 := base64.StdEncoding.DecodeString(encKey); err2 == nil && len(decoded) == 32 {
			keyBytes = decoded
		}
	}
	if len(keyBytes) != 32 {
		return "", fmt.Errorf(
			"legacy encryption key must be 32 bytes — got %d (raw) — check crypto.encryption_key in config",
			len([]byte(encKey)),
		)
	}

	enc, err := kyccrypto.NewEncryptor(keyBytes)
	if err != nil {
		return "", fmt.Errorf("build legacy encryptor: %w", err)
	}
	return enc.DecryptString(ciphertext)
}
