package api

import (
	"net/http"

	"Go-Blockchain-KYC/auth"
)

// // SetupRoutes configures all API routes
// func SetupRoutes(handlers *Handlers, middleware *Middleware) http.Handler {
// 	mux := http.NewServeMux()

// 	// Debug endpoint - shows all registered routes
// 	mux.HandleFunc("/debug/routes", func(w http.ResponseWriter, r *http.Request) {
// 		routes := []string{
// 			"GET /",
// 			"GET /health",
// 			"POST /api/v1/auth/register",
// 			"POST /api/v1/auth/login",
// 			"POST /api/v1/auth/refresh",
// 			"GET /api/v1/auth/profile",
// 			"POST /api/v1/kyc",
// 			"GET /api/v1/kyc",
// 			"PUT /api/v1/kyc",
// 			"DELETE /api/v1/kyc",
// 			"GET /api/v1/kyc/list",
// 			"POST /api/v1/kyc/verify",
// 			"POST /api/v1/kyc/reject",
// 			"POST /api/v1/kyc/auto-verify",
// 			"GET /api/v1/banks",
// 			"GET /api/v1/banks/list",
// 			"POST /api/v1/banks",
// 			"GET /api/v1/blockchain/stats",
// 			"POST /api/v1/blockchain/mine",
// 		}

// 		w.Header().Set("Content-Type", "text/plain")
// 		fmt.Fprintf(w, "Registered Routes:\n\n")
// 		for _, route := range routes {
// 			fmt.Fprintf(w, "%s\n", route)
// 		}
// 	})

// 	// Root endpoint - MUST handle trailing slash
// 	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
// 		// Only match exact "/"
// 		if r.URL.Path != "/" {
// 			http.NotFound(w, r)
// 			return
// 		}
// 		SendSuccess(w, "", map[string]interface{}{
// 			"message": "KYC Blockchain API",
// 			"version": "1.0.0",
// 			"status":  "running",
// 		})
// 	})

// 	// Health check
// 	mux.HandleFunc("/health", handlers.HealthCheck)

// 	// Auth routes
// 	mux.HandleFunc("/api/v1/auth/register", handlers.Register)
// 	mux.HandleFunc("/api/v1/auth/login", handlers.Login)
// 	mux.HandleFunc("/api/v1/auth/refresh", handlers.RefreshToken)

// 	// Profile (protected)
// 	mux.Handle("/api/v1/auth/profile",
// 		middleware.Authenticate(http.HandlerFunc(handlers.GetProfile)))

// 	// Certificate verification (public)
// 	mux.HandleFunc("/api/v1/certificate/verify", handlers.VerifyCertificate)

// 	// ==================== KYC Routes ====================

// 	// KYC CRUD
// 	mux.HandleFunc("/api/v1/kyc", func(w http.ResponseWriter, r *http.Request) {
// 		switch r.Method {
// 		case http.MethodPost:
// 			middleware.Authenticate(
// 				middleware.RequirePermission(auth.PermKYCCreate)(
// 					http.HandlerFunc(handlers.CreateKYC))).ServeHTTP(w, r)
// 		case http.MethodGet:
// 			middleware.Authenticate(
// 				middleware.RequirePermission(auth.PermKYCRead)(
// 					http.HandlerFunc(handlers.GetKYC))).ServeHTTP(w, r)
// 		case http.MethodPut:
// 			middleware.Authenticate(
// 				middleware.RequirePermission(auth.PermKYCUpdate)(
// 					http.HandlerFunc(handlers.UpdateKYC))).ServeHTTP(w, r)
// 		case http.MethodDelete:
// 			middleware.Authenticate(
// 				middleware.RequirePermission(auth.PermKYCDelete)(
// 					http.HandlerFunc(handlers.DeleteKYC))).ServeHTTP(w, r)
// 		default:
// 			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		}
// 	})

// 	mux.Handle("/api/v1/kyc/list",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.ListKYC))))

// 	mux.Handle("/api/v1/kyc/history",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.GetKYCHistory))))

// 	mux.Handle("/api/v1/kyc/verify",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCVerify)(
// 				http.HandlerFunc(handlers.VerifyKYC))))

// 	mux.Handle("/api/v1/kyc/reject",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCReject)(
// 				http.HandlerFunc(handlers.RejectKYC))))

// 	mux.Handle("/api/v1/kyc/auto-verify",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCVerify)(
// 				http.HandlerFunc(handlers.AutoVerifyKYC))))

// 	mux.Handle("/api/v1/kyc/review",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin, auth.RoleBankOfficer)(
// 				http.HandlerFunc(handlers.PeriodicReviewKYC))))

// 	mux.Handle("/api/v1/kyc/review/status",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.GetKYCReviewStatus))))

// 	// ==================== Bank Routes ====================

// 	mux.HandleFunc("/api/v1/banks", func(w http.ResponseWriter, r *http.Request) {
// 		switch r.Method {
// 		case http.MethodPost:
// 			middleware.Authenticate(
// 				middleware.RequirePermission(auth.PermBankCreate)(
// 					http.HandlerFunc(handlers.RegisterBank))).ServeHTTP(w, r)
// 		case http.MethodGet:
// 			middleware.Authenticate(
// 				middleware.RequirePermission(auth.PermBankRead)(
// 					http.HandlerFunc(handlers.GetBank))).ServeHTTP(w, r)
// 		default:
// 			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		}
// 	})

// 	mux.Handle("/api/v1/banks/list",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBankRead)(
// 				http.HandlerFunc(handlers.ListBanks))))

// 	// ==================== Blockchain Routes ====================

// 	mux.Handle("/api/v1/blockchain/stats",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetBlockchainStats))))

// 	mux.Handle("/api/v1/blockchain/blocks",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetBlocks))))

// 	mux.Handle("/api/v1/blockchain/block",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetBlock))))

// 	mux.Handle("/api/v1/blockchain/mine",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainMine)(
// 				http.HandlerFunc(handlers.MineBlock))))

// 	mux.Handle("/api/v1/blockchain/pending",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetPendingTransactions))))

// 	mux.Handle("/api/v1/blockchain/validate",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.ValidateChain))))

// 	// ==================== Monitoring Routes ====================

// 	mux.Handle("/api/v1/audit/logs",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermAuditRead)(
// 				http.HandlerFunc(handlers.GetAuditLogs))))

// 	mux.Handle("/api/v1/security/alerts",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.GetSecurityAlerts))))

// 	mux.Handle("/api/v1/security/alerts/review",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.ReviewSecurityAlert))))

// 	// ==================== Key Management Routes ====================

// 	mux.Handle("/api/v1/keys/generate",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.GenerateRequesterKeyPair)))

// 	mux.Handle("/api/v1/keys",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.GetRequesterKeys))))

// 	mux.Handle("/api/v1/keys/info",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.GetRequesterKeyByID)))

// 	mux.Handle("/api/v1/keys/revoke",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.RevokeRequesterKey))))

// 	// ==================== Certificate Routes ====================

// 	mux.Handle("/api/v1/certificate/issue",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin)(
// 				http.HandlerFunc(handlers.IssueVerificationCertificate))))

// 	// ==================== Renewal Alerts ====================

// 	mux.Handle("/api/v1/alerts/renewal",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.GetRenewalAlerts)))

// 	mux.Handle("/api/v1/alerts/renewal/configure",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.ConfigureRenewalAlert)))

// 	// Apply global middleware
// 	handler := middleware.CORS(middleware.Logging(middleware.RateLimit(100)(mux)))

// 	return handler
// }

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

	// Requester Key Routes
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
