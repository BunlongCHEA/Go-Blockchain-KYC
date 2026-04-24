package api

import (
	"net/http"
	"time"

	"Go-Blockchain-KYC/models"
)

// audit is the single entry-point for all audit log writes.
//
// Parameters:
//
//	r            — the current HTTP request (extracts userID + IP automatically)
//	action       — string constant, e.g. "KYC_VERIFIED" (see ActionXxx consts below)
//	resourceType — e.g. "KYC", "USER", "CERTIFICATE", "BLOCKCHAIN"
//	resourceID   — the primary identifier of the affected resource
//	details      — arbitrary extra fields; pass nil if nothing extra needed
//
// The write is fire-and-forget in a goroutine — zero latency impact on the
// HTTP response.  Failures are silently dropped (audit is best-effort).
func (h *Handlers) audit(
	r *http.Request,
	action string,
	resourceType string,
	resourceID string,
	details map[string]interface{},
) {
	if h.storage == nil {
		return
	}

	userID := getUserIDFromContext(r)
	ip := getClientIP(r)

	if details == nil {
		details = map[string]interface{}{}
	}

	entry := &models.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
		IPAddress:    ip,
		CreatedAt:    time.Now(),
	}

	// Fire-and-forget — never blocks the response path
	go func() {
		_ = h.storage.SaveAuditLog(entry)
	}()
}

// ─── Action constants ─────────────────────────────────────────────────────────
// Centralised so typos are caught at compile time.

const (
	// Auth
	ActionLogin          = "LOGIN"
	ActionLogout         = "LOGOUT"
	ActionRegister       = "REGISTER"
	ActionTokenRefresh   = "TOKEN_REFRESH"
	ActionPasswordChange = "PASSWORD_CHANGED"
	ActionPasswordReset  = "USER_PASSWORD_RESET"

	// KYC lifecycle
	ActionKYCCreate     = "KYC_CREATED"
	ActionKYCRead       = "KYC_READ" // GET (sensitive record access)
	ActionKYCList       = "KYC_LIST" // GET list
	ActionKYCUpdate     = "KYC_UPDATED"
	ActionKYCVerify     = "KYC_VERIFIED"
	ActionKYCAutoVerify = "KYC_AUTO_VERIFIED"
	ActionKYCReject     = "KYC_REJECTED"
	ActionKYCDelete     = "KYC_DELETED"
	ActionKYCReview     = "KYC_PERIODIC_REVIEW"

	// KYC AI scan
	ActionKYCDocUpload    = "KYC_DOC_UPLOADED"
	ActionKYCSelfieUpload = "KYC_SELFIE_UPLOADED"
	ActionKYCAIScan       = "KYC_AI_SCAN"

	// Certificates
	ActionCertIssue  = "CERTIFICATE_ISSUED"
	ActionCertVerify = "CERTIFICATE_VERIFIED"
	ActionCertList   = "CERTIFICATE_LIST" // GET — who is viewing all certs

	// Requester keys
	ActionKeyGenerate = "REQUESTER_KEYPAIR_GENERATED"
	ActionKeyRevoke   = "REQUESTER_KEY_REVOKED"
	ActionKeyRead     = "REQUESTER_KEY_READ"

	// Blockchain
	ActionBlockMine           = "BLOCK_MINED"
	ActionBlockRead           = "BLOCK_READ"
	ActionBlockListRead       = "BLOCK_LIST_READ"
	ActionBlockchainStatsRead = "BLOCKCHAIN_STATS_READ"
	ActionChainValidate       = "CHAIN_VALIDATED"
	ActionPendingTxRead       = "PENDING_TX_READ"

	// User management
	ActionUserCreate = "USER_CREATED"
	ActionUserUpdate = "USER_UPDATED"
	ActionUserDelete = "USER_DELETED"

	// Audit / security (meta — watching the watchers)
	ActionAuditLogRead = "AUDIT_LOG_READ"
	// ActionSecurityAlertRead   = "SECURITY_ALERT_READ"
	ActionSecurityAlertReview = "SECURITY_ALERT_REVIEWED"

	// Password policy / security actions
	ActionPasswordPolicyRead   = "PASSWORD_POLICY_READ"
	ActionPasswordPolicyUpdate = "PASSWORD_POLICY_UPDATED"
	ActionPasswordForceAll     = "PASSWORD_FORCE_RESET_ALL"
	ActionEmergencyLock        = "EMERGENCY_LOCK_ENABLED"
	ActionEmergencyUnlock      = "EMERGENCY_LOCK_DISABLED"

	// Key rotation
	ActionSigningKeyRotate = "SIGNING_KEY_ROTATED"
	ActionKEKRotate        = "KEK_ROTATED"
	ActionKEKRewrap        = "KEK_REWRAP_COMPLETED"
)

// ─── Resource type constants ──────────────────────────────────────────────────

const (
	ResourceAuth        = "AUTH"
	ResourceKYC         = "KYC"
	ResourceCertificate = "KYC_CERTIFICATE"
	ResourceKey         = "REQUESTER_KEY"
	ResourceBlockchain  = "BLOCKCHAIN"
	ResourceUser        = "USER"
	ResourceAudit       = "AUDIT"
	ResourceAlert       = "SECURITY_ALERT"
	ResourceSecurity    = "SECURITY"
)
