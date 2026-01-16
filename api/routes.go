package api

import (
	"net/http"

	"Go-Blockchain-KYC/auth"
)

// SetupRoutes configures all API routes
func SetupRoutes(handlers *Handlers, middleware *Middleware) http.Handler {
	mux := http.NewServeMux()

	// ==================== Public Routes ====================

	// Health check
	mux.HandleFunc("GET /health", handlers.HealthCheck)

	// Auth routes
	mux.HandleFunc("POST /api/v1/auth/register", handlers.Register)
	mux.HandleFunc("POST /api/v1/auth/login", handlers.Login)
	mux.HandleFunc("POST /api/v1/auth/refresh", handlers.RefreshToken)
	// mux.Handle("POST /api/v1/auth/refresh",
	// 	middleware.Authenticate(http.HandlerFunc(handlers.RefreshToken)))

	// ==================== Protected Routes ====================

	// Profile
	mux.Handle("GET /api/v1/auth/profile",
		middleware.Authenticate(http.HandlerFunc(handlers.GetProfile)))

	// KYC Routes
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

	// Bank Routes
	mux.Handle("POST /api/v1/banks",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankCreate)(
				http.HandlerFunc(handlers.RegisterBank))))

	mux.Handle("GET /api/v1/banks",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankRead)(
				http.HandlerFunc(handlers.GetBank))))

	mux.Handle("GET /api/v1/banks/list",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankRead)(
				http.HandlerFunc(handlers.ListBanks))))

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

	// Monitoring Routes
	mux.Handle("GET /api/v1/audit/logs",
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermAuditRead)(
				http.HandlerFunc(handlers.GetAuditLogs))))

	mux.Handle("GET /api/v1/security/alerts",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.GetSecurityAlerts))))

	mux.Handle("POST /api/v1/security/alerts/review",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.ReviewSecurityAlert))))

	// Certificate Routes
	mux.Handle("POST /api/v1/certificate/issue",
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin)(
				http.HandlerFunc(handlers.IssueVerificationCertificate))))

	mux.Handle("POST /api/v1/certificate/verify",
		http.HandlerFunc(handlers.VerifyCertificate)) // Public - no auth needed

	// Renewal Alerts Routes
	mux.Handle("GET /api/v1/alerts/renewal",
		middleware.Authenticate(
			http.HandlerFunc(handlers.GetRenewalAlerts)))

	mux.Handle("POST /api/v1/alerts/renewal/configure",
		middleware.Authenticate(
			http.HandlerFunc(handlers.ConfigureRenewalAlert)))

	// Apply global middleware
	handler := middleware.CORS(middleware.Logging(middleware.RateLimit(100)(mux)))

	return handler
}
