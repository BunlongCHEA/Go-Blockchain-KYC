package api

// kyc_auto_user.go
//
// Auto-creates a customer portal account when an admin manually verifies a
// KYC record.  Called exclusively from the VerifyKYC handler.
//
// FLOW
// ────
//  1. Admin calls POST /api/v1/kyc/verify
//  2. Existing verification logic runs (blockchain tx, DB status update)
//  3. ensureCustomerUser() is called:
//       a. If a user already linked to this customer_id exists  → return it (no-op)
//       b. Otherwise, read KYC with decryption to get name/email,
//          generate credentials, call authService.Register, persist to DB
//  4. Response includes portal_access block with username / temp_password
//
// ACCOUNT PROPERTIES (newly created)
//   role:                   customer
//   password_change_required: true   (customer MUST change on first login)
//   bank_id:                from KYC record
//   customer_id:            the Go-KYC customer_id (links user ↔ KYC)
//
// USERNAME FORMAT
//   "firstname.lastname"   e.g. "john.doe"
//   If taken:              "firstname.lastname_<tail6>"
//   If name unavailable:   "customer_<tail8>"

import (
	"crypto/rand"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/storage"
)

// ── Result returned to the caller ────────────────────────────────────────────

// CustomerPortalResult describes the outcome of ensureCustomerUser.
type CustomerPortalResult struct {
	User         *auth.User
	TempPassword string // non-empty only when Created = true
	Created      bool
}

// ── Main entry point ─────────────────────────────────────────────────────────

// ensureCustomerUser looks up or creates a 'customer' role account for a
// verified KYC record.
//
// It is idempotent: calling it multiple times for the same customer_id
// returns the existing user without modification after the first call.
func (h *Handlers) ensureCustomerUser(
	customerID string,
	r *http.Request,
) (*CustomerPortalResult, error) {

	if h.storage == nil {
		return nil, fmt.Errorf("storage not initialised")
	}
	pgStore, ok := h.storage.(*storage.PostgresStorage)
	if !ok {
		return nil, fmt.Errorf("postgres storage required for customer user creation")
	}

	// ── Step 1: Check if user already linked to this customer_id ─────────────
	existing, err := pgStore.GetUserByCustomerID(customerID)
	if err == nil && existing != nil {
		// User exists — ensure they are not locked out (may have been deactivated
		// while their KYC was pending).
		if !existing.IsActive || existing.IsDeleted {
			existing.IsActive = true
			existing.IsDeleted = false
			existing.UpdatedAt = time.Now()
			if saveErr := pgStore.SaveUser(existing); saveErr != nil {
				log.Printf("[ensureCustomerUser] re-activate %s: %v", existing.Username, saveErr)
			}
			h.authService.LoadUser(existing)
		}
		return &CustomerPortalResult{User: existing, Created: false}, nil
	}

	// ── Step 2: Read KYC with decryption to get name / email ─────────────────
	// decrypt=true unwraps the envelope-encrypted PII fields so we can use
	// the customer's real email and name for the new account.
	kyc, err := h.blockchain.ReadKYC(customerID, true)
	if err != nil {
		return nil, fmt.Errorf("read decrypted KYC for customer %s: %w", customerID, err)
	}

	// ── Step 3: Derive username ───────────────────────────────────────────────
	username := deriveCustomerUsername(kyc.FirstName, kyc.LastName, customerID)

	// Ensure uniqueness — if taken, append last-6 chars of customer_id
	if _, taken := pgStore.GetUserByUsername(username); taken == nil {
		tail := customerID
		if len(tail) > 6 {
			tail = tail[len(tail)-6:]
		}
		username = username + "_" + tail
	}

	// ── Step 4: Resolve email ─────────────────────────────────────────────────
	// kyc.Email may be "[ENCRYPTED]" if the envelope is unavailable, or empty
	// for admin-entered records.  Fall back to a portal-local address so
	// Register() does not fail on empty email.
	email := kyc.Email
	if email == "" || email == "[ENCRYPTED]" {
		email = username + "@portal.kyc.local"
		log.Printf("[ensureCustomerUser] KYC email unavailable for %s — using placeholder", customerID)
	}

	// ── Step 5: Generate temporary password ───────────────────────────────────
	tempPwd, err := generateTempPassword()
	if err != nil {
		return nil, fmt.Errorf("generate temp password: %w", err)
	}

	// ── Step 6: Register the account ─────────────────────────────────────────
	newUser, regErr := h.authService.Register(&auth.RegisterRequest{
		Username: username,
		Email:    email,
		Password: tempPwd,
		Role:     auth.RoleCustomer,
		BankID:   kyc.BankID,
	})
	if regErr != nil {
		// Second attempt: email may already be taken by another account
		// (customer registered before the admin created the KYC).
		// In that case link the existing account instead.
		if byEmail, lookupErr := pgStore.GetUserByUsername(username); lookupErr == nil {
			byEmail.CustomerID = customerID
			byEmail.IsActive = true
			byEmail.UpdatedAt = time.Now()
			pgStore.SaveUser(byEmail)
			h.authService.LoadUser(byEmail)
			return &CustomerPortalResult{User: byEmail, Created: false}, nil
		}
		return nil, fmt.Errorf("register customer user %q: %w", username, regErr)
	}

	// ── Step 7: Link customer_id and force password change ────────────────────
	newUser.CustomerID = customerID
	newUser.PasswordChangeRequired = true
	newUser.IsActive = true
	newUser.UpdatedAt = time.Now()

	if saveErr := pgStore.SaveUser(newUser); saveErr != nil {
		log.Printf("[ensureCustomerUser] persist %s: %v", username, saveErr)
	}
	// Stamp password_changed_at = now (so the policy clock starts fresh)
	pgStore.UpdatePasswordChangedAt(newUser.ID)

	// Hot-load into the in-memory auth service map so the user can login
	// without a server restart.
	h.authService.LoadUser(newUser)

	// ── Audit ─────────────────────────────────────────────────────────────────
	h.audit(r, ActionUserCreate, ResourceUser, newUser.ID, map[string]interface{}{
		"username":     username,
		"role":         string(auth.RoleCustomer),
		"bank_id":      kyc.BankID,
		"customer_id":  customerID,
		"auto_created": true,
		"trigger":      "kyc_manual_verify",
	})

	log.Printf("[ensureCustomerUser] created portal account %q for KYC customer %s", username, customerID)

	return &CustomerPortalResult{
		User:         newUser,
		TempPassword: tempPwd,
		Created:      true,
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// deriveCustomerUsername produces a lowercase "firstname.lastname" username
// from KYC name fields.  Non-alphanumeric characters are stripped.
// Falls back to "customer_<tail>" when both name fields are empty.
//
//	"John", "Doe",  "abc123" → "john.doe"
//	"",     "Doe",  "abc123" → "doe"
//	"",     "",     "xyzabc" → "customer_xyzabc"
func deriveCustomerUsername(firstName, lastName, customerID string) string {
	clean := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		var b strings.Builder
		for _, c := range s {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				b.WriteRune(c)
			}
		}
		return b.String()
	}

	first := clean(firstName)
	last := clean(lastName)

	switch {
	case first != "" && last != "":
		return first + "." + last
	case first != "":
		return first
	case last != "":
		return last
	default:
		tail := customerID
		if len(tail) > 8 {
			tail = tail[len(tail)-8:]
		}
		return "customer_" + tail
	}
}

// generateTempPassword creates a cryptographically random 16-character password
// that satisfies the Go-KYC policy enforced by validatePasswordPolicy():
//
//	≥ 15 chars, ≥ 1 uppercase, ≥ 1 digit, ≥ 1 special character.
//
// The password is shuffled so the required characters are not predictably
// placed at fixed positions.
func generateTempPassword() (string, error) {
	const (
		upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		lower   = "abcdefghijklmnopqrstuvwxyz"
		digits  = "0123456789"
		special = "!@#$%^&*"
		all     = upper + lower + digits + special
	)

	// randIdx returns a cryptographically random index in [0, n).
	randIdx := func(n int) (int, error) {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return 0, err
		}
		// Simple modulo — acceptable bias for a temp password generator.
		return int(b[0]) % n, nil
	}

	// Guarantee at least one character from each required class.
	buf := make([]byte, 0, 16)
	for _, charset := range []string{upper, lower, digits, special} {
		i, err := randIdx(len(charset))
		if err != nil {
			return "", err
		}
		buf = append(buf, charset[i])
	}

	// Fill remaining positions from the full alphabet.
	for len(buf) < 16 {
		i, err := randIdx(len(all))
		if err != nil {
			return "", err
		}
		buf = append(buf, all[i])
	}

	// Fisher-Yates shuffle so required chars are not always at positions 0-3.
	for i := len(buf) - 1; i > 0; i-- {
		j, err := randIdx(i + 1)
		if err != nil {
			return "", err
		}
		buf[i], buf[j] = buf[j], buf[i]
	}

	return string(buf), nil
}
