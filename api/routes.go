package api

import (
	"net/http"

	"Go-Blockchain-KYC/auth"
)

// SetupRoutes configures all API routes
func SetupRoutes(handlers *Handlers, middleware *Middleware) http.Handler {
	mux := http.NewServeMux()

	// ==================== Public Routes ====================

	// Root endpoint
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		SendSuccess(w, "", map[string]interface{}{
			"message": "KYC Blockchain API",
			"version": "1.0.0",
			"status":  "running",
		})
	})

	// Health check
	mux.HandleFunc("GET /health", handlers.HealthCheck)

	// Auth routes
	mux.HandleFunc("POST /api/v1/auth/register", handlers.Register)
	mux.HandleFunc("POST /api/v1/auth/login", handlers.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", handlers.RefreshToken)
	// mux.Handle("POST /api/v1/auth/refresh",
	// 	middleware.Authenticate(http.HandlerFunc(handlers.RefreshToken)))

	// Public — needed by customer registration form to populate bank dropdown
	mux.HandleFunc("GET /api/v1/banks/list",
		http.HandlerFunc(handlers.ListBanks))

	// Public - no auth needed
	mux.Handle("POST /api/v1/certificate/verify",
		http.HandlerFunc(handlers.VerifyCertificate))

	// ==================== Protected Routes ====================

	// ==================== Profile & Auth Routes
	mux.Handle("GET /api/v1/auth/profile",
		middleware.Authenticate(http.HandlerFunc(handlers.GetProfile)))

	// Password change
	mux.Handle("POST /api/v1/auth/change-password",
		middleware.Authenticate(http.HandlerFunc(handlers.ChangePassword)))

	// ==================== Bank & Blockchain Routes

	// Bank Routes
	mux.Handle("POST /api/v1/banks",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankCreate)(
				http.HandlerFunc(handlers.RegisterBank))))

	mux.Handle("GET /api/v1/banks",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankRead)(
				http.HandlerFunc(handlers.GetBank))))

	// mux.Handle("GET /api/v1/banks/list",
	// 	middleware.Authenticate(
	// 		middleware.RequirePermission(auth.PermBankRead)(
	// 			http.HandlerFunc(handlers.ListBanks))))

	// Bank CRUD additions
	mux.Handle("PUT /api/v1/banks",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankCreate)( // reuse create perm
				http.HandlerFunc(handlers.UpdateBank))))

	mux.Handle("DELETE /api/v1/banks",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.DeleteBank))))

	// ==================== Blockchain Routes

	// Blockchain Routes
	mux.Handle("GET /api/v1/blockchain/stats",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetBlockchainStats))))

	mux.Handle("GET /api/v1/blockchain/blocks",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetBlocks))))

	mux.Handle("GET /api/v1/blockchain/block",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetBlock))))

	mux.Handle("POST /api/v1/blockchain/mine",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainMine)(
				http.HandlerFunc(handlers.MineBlock))))

	mux.Handle("GET /api/v1/blockchain/pending",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetPendingTransactions))))

	mux.Handle("GET /api/v1/blockchain/validate",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.ValidateChain))))

	// ==================== Audit Routes

	// Monitoring Routes
	mux.Handle("GET /api/v1/audit/logs",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermAuditRead)(
				http.HandlerFunc(handlers.GetAuditLogs))))

	mux.Handle("GET /api/v1/security/alerts",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.GetSecurityAlerts))))

	mux.Handle("POST /api/v1/security/alerts/review",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.ReviewSecurityAlert))))

	// Renewal Alerts Routes
	mux.Handle("GET /api/v1/alerts/renewal",
		middleware.Authenticate(
			http.HandlerFunc(handlers.GetRenewalAlerts)))

	mux.Handle("POST /api/v1/alerts/renewal/configure",
		middleware.Authenticate(
			http.HandlerFunc(handlers.ConfigureRenewalAlert)))

	// Manual alert dispatch
	mux.Handle("POST /api/v1/alerts/renewal/send",
		middleware.Authenticate(
			http.HandlerFunc(handlers.SendRenewalAlert)))

	// ==================== Requester Key & Certificate Routes

	mux.Handle("POST /api/v1/keys/generate",
		middleware.Authenticate(
			http.HandlerFunc(handlers.GenerateRequesterKeyPair)))

	mux.Handle("GET /api/v1/keys",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.GetRequesterKeys))))

	mux.Handle("GET /api/v1/keys/info",
		middleware.Authenticate(
			http.HandlerFunc(handlers.GetRequesterKeyByID)))

	mux.Handle("POST /api/v1/keys/revoke",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.RevokeRequesterKey))))

	// Certificate Routes
	mux.Handle("POST /api/v1/certificate/issue",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.IssueVerificationCertificate))))

	// List all issued certificates (admin / bank_admin)
	mux.Handle("GET /api/v1/certificates/list",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.ListCertificates))))

	// mux.Handle("GET /api/v1/certificate",
	// 	middleware.Authenticate(
	// 		http.HandlerFunc(handlers.GetCertificate)))

	// ==================== KYC Lists Routes
	mux.Handle("POST /api/v1/kyc",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCCreate)(
				http.HandlerFunc(handlers.CreateKYC))))

	mux.Handle("GET /api/v1/kyc",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYC))))

	mux.Handle("PUT /api/v1/kyc",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCUpdate)(
				http.HandlerFunc(handlers.UpdateKYC))))

	mux.Handle("DELETE /api/v1/kyc",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCDelete)(
				http.HandlerFunc(handlers.DeleteKYC))))

	mux.Handle("GET /api/v1/kyc/list",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.ListKYC))))

	mux.Handle("GET /api/v1/kyc/history",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYCHistory))))

	mux.Handle("POST /api/v1/kyc/verify",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCVerify)(
				http.HandlerFunc(handlers.VerifyKYC))))

	mux.Handle("POST /api/v1/kyc/reject",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCReject)(
				http.HandlerFunc(handlers.RejectKYC))))

	mux.Handle("POST /api/v1/kyc/auto-verify",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCVerify)(
				http.HandlerFunc(handlers.AutoVerifyKYC))))

	// KYC Review Routes
	mux.Handle("POST /api/v1/kyc/review",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin, auth.RoleBankOfficer)(
				http.HandlerFunc(handlers.PeriodicReviewKYC))))

	mux.Handle("GET /api/v1/kyc/review/status",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYCReviewStatus))))

	mux.Handle("GET /api/v1/kyc/stats",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYCStats))))

	// ==================== KYC AI Scan Routes

	// POST /api/v1/kyc/upload-doc          – base64 ID/Passport scan
	mux.Handle("POST /api/v1/kyc/upload-doc",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCCreate)(
				http.HandlerFunc(handlers.UploadDocumentImage))))

	// POST /api/v1/kyc/upload-doc/file     – multipart file ID/Passport scan
	mux.Handle("POST /api/v1/kyc/upload-doc/file",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCCreate)(
				http.HandlerFunc(handlers.UploadDocumentFile))))

	// POST /api/v1/kyc/upload-selfie       – base64 selfie upload
	mux.Handle("POST /api/v1/kyc/upload-selfie",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCCreate)(
				http.HandlerFunc(handlers.UploadSelfieImage))))

	// POST /api/v1/kyc/scan-verify         – full OCR + face + DB + KYC update (base64)
	mux.Handle("POST /api/v1/kyc/scan-verify",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCVerify)(
				http.HandlerFunc(handlers.ScanAndVerifyKYC))))

	// POST /api/v1/kyc/scan-verify/file    – full pipeline (multipart)
	mux.Handle("POST /api/v1/kyc/scan-verify/file",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCVerify)(
				http.HandlerFunc(handlers.ScanAndVerifyKYCFile))))

	// ==================== User Management Routes

	// List all users (admin only)
	mux.Handle("GET /api/v1/users/list",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.ListUsers))))

	// Create internal user (admin only)
	mux.Handle("POST /api/v1/users",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.CreateUser))))

	// Update user (toggle active, role, etc.)
	mux.Handle("PATCH /api/v1/users",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.UpdateUser))))

	// Soft-delete user (is_deleted = true, not removed from DB)
	mux.Handle("DELETE /api/v1/users",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.DeleteUser))))

	// Reset password for a user (sets temp password + password_change_required)
	mux.Handle("POST /api/v1/users/reset-password",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.ResetUserPassword))))

	// ==================== Customer Self-Service Routes

	// Customer self-service
	mux.Handle("GET /api/v1/kyc/me",
		middleware.Authenticate(
			http.HandlerFunc(handlers.GetMyKYC)))

	mux.Handle("GET /api/v1/certificates/me",
		middleware.Authenticate(
			http.HandlerFunc(handlers.GetMyCertificates)))

	// Apply global middleware
	handler := middleware.CORS(middleware.Logging(middleware.RateLimit(100)(mux)))

	// ==================== Emergency Security

	mux.Handle("GET /api/v1/auth/password-policy",
		middleware.Authenticate(http.HandlerFunc(handlers.GetPasswordPolicy)))

	mux.Handle("PUT /api/v1/auth/password-policy",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.UpdatePasswordPolicy))))

	mux.Handle("POST /api/v1/auth/force-password-reset-all",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.ForceAllPasswordReset))))

	// Emergency lock — admin only
	mux.Handle("GET /api/v1/security/emergency-lock",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.GetEmergencyLock))))

	mux.Handle("POST /api/v1/security/emergency-lock",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.EmergencyLock))))

	// ==================== Key Management Routes

	// Key rotation — admin only
	mux.Handle("POST /api/v1/security/keys/signing/rotate",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.RotateSigningKey))))

	mux.Handle("GET /api/v1/security/keys/signing",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.ListSigningKeys))))

	mux.Handle("POST /api/v1/security/keys/kek/rotate",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.RotateKEK))))

	mux.Handle("GET /api/v1/security/keys/kek",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.ListKEKs))))

	// ==================== Integration API Key Routes ====================
	// All routes require admin or integration_service role.
	// integration_service can only call stats (so the gateway can self-report).

	// GET  /api/v1/integration/keys             → list all keys
	// GET  /api/v1/integration/keys?hash=<sha>  → lookup by hash (gateway)
	mux.Handle("GET /api/v1/integration/keys",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.ListIntegrationKeys))))

	// POST /api/v1/integration/keys → upsert single key (admin UI)
	mux.Handle("POST /api/v1/integration/keys",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.UpsertIntegrationKey))))

	// POST /api/v1/integration/keys/sync → bulk upsert (admin sync)
	mux.Handle("POST /api/v1/integration/keys/sync",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.SyncIntegrationKeys))))

	// POST /api/v1/integration/keys/stats → increment stats (gateway hot path)
	// integration_service role can call this (gateway uses that role's JWT)
	mux.Handle("POST /api/v1/integration/keys/stats",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.IncrementIntegrationKeyStats))))

	// DELETE /api/v1/integration/keys?id=<id> → soft delete (admin only)
	mux.Handle("DELETE /api/v1/integration/keys",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleIntegrationService)(
				http.HandlerFunc(handlers.DeleteIntegrationKey))))

	return handler
}
