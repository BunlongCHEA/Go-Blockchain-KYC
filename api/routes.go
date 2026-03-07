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
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		SendSuccess(w, "", map[string]interface{}{
			"message": "KYC Blockchain API",
			"version": "1.0.0",
			"status":  "running",
		})
	})

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handlers.HealthCheck(w, r)
	})

	// Auth routes
	mux.HandleFunc("/api/v1/auth/register", methodHandler(http.MethodPost, handlers.Register))
	mux.HandleFunc("/api/v1/auth/login", methodHandler(http.MethodPost, handlers.Login))
	mux.HandleFunc("/api/v1/auth/refresh", methodHandler(http.MethodPost, handlers.RefreshToken))

	// Profile
	mux.Handle("/api/v1/auth/profile", methodHandler(http.MethodGet,
		middleware.Authenticate(http.HandlerFunc(handlers.GetProfile)).ServeHTTP))

	// Certificate verification (public)
	mux.HandleFunc("/api/v1/certificate/verify", methodHandler(http.MethodPost, handlers.VerifyCertificate))

	// ==================== Protected Routes ====================

	// KYC Routes
	mux.Handle("/api/v1/kyc", routeByMethod(map[string]http.Handler{
		http.MethodPost: middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCCreate)(
				http.HandlerFunc(handlers.CreateKYC))),
		http.MethodGet: middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYC))),
		http.MethodPut: middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCUpdate)(
				http.HandlerFunc(handlers.UpdateKYC))),
		http.MethodDelete: middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCDelete)(
				http.HandlerFunc(handlers.DeleteKYC))),
	}))

	mux.Handle("/api/v1/kyc/list", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.ListKYC))).ServeHTTP))

	mux.Handle("/api/v1/kyc/history", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYCHistory))).ServeHTTP))

	mux.Handle("/api/v1/kyc/verify", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCVerify)(
				http.HandlerFunc(handlers.VerifyKYC))).ServeHTTP))

	mux.Handle("/api/v1/kyc/reject", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCReject)(
				http.HandlerFunc(handlers.RejectKYC))).ServeHTTP))

	mux.Handle("/api/v1/kyc/auto-verify", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCVerify)(
				http.HandlerFunc(handlers.AutoVerifyKYC))).ServeHTTP))

	mux.Handle("/api/v1/kyc/review", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin, auth.RoleBankOfficer)(
				http.HandlerFunc(handlers.PeriodicReviewKYC))).ServeHTTP))

	mux.Handle("/api/v1/kyc/review/status", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermKYCRead)(
				http.HandlerFunc(handlers.GetKYCReviewStatus))).ServeHTTP))

	// Bank Routes
	mux.Handle("/api/v1/banks", routeByMethod(map[string]http.Handler{
		http.MethodPost: middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankCreate)(
				http.HandlerFunc(handlers.RegisterBank))),
		http.MethodGet: middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankRead)(
				http.HandlerFunc(handlers.GetBank))),
	}))

	mux.Handle("/api/v1/banks/list", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBankRead)(
				http.HandlerFunc(handlers.ListBanks))).ServeHTTP))

	// Blockchain Routes
	mux.Handle("/api/v1/blockchain/stats", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetBlockchainStats))).ServeHTTP))

	mux.Handle("/api/v1/blockchain/blocks", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetBlocks))).ServeHTTP))

	mux.Handle("/api/v1/blockchain/block", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetBlock))).ServeHTTP))

	mux.Handle("/api/v1/blockchain/mine", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainMine)(
				http.HandlerFunc(handlers.MineBlock))).ServeHTTP))

	mux.Handle("/api/v1/blockchain/pending", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.GetPendingTransactions))).ServeHTTP))

	mux.Handle("/api/v1/blockchain/validate", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermBlockchainRead)(
				http.HandlerFunc(handlers.ValidateChain))).ServeHTTP))

	// Monitoring Routes
	mux.Handle("/api/v1/audit/logs", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequirePermission(auth.PermAuditRead)(
				http.HandlerFunc(handlers.GetAuditLogs))).ServeHTTP))

	mux.Handle("/api/v1/security/alerts", routeByMethod(map[string]http.Handler{
		http.MethodGet: middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.GetSecurityAlerts))),
		http.MethodPost: middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.ReviewSecurityAlert))),
	}))

	// Key Management Routes
	mux.Handle("/api/v1/keys/generate", methodHandler(http.MethodPost,
		middleware.Authenticate(http.HandlerFunc(handlers.GenerateRequesterKeyPair)).ServeHTTP))

	mux.Handle("/api/v1/keys", methodHandler(http.MethodGet,
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.GetRequesterKeys))).ServeHTTP))

	mux.Handle("/api/v1/keys/info", methodHandler(http.MethodGet,
		middleware.Authenticate(http.HandlerFunc(handlers.GetRequesterKeyByID)).ServeHTTP))

	mux.Handle("/api/v1/keys/revoke", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin)(
				http.HandlerFunc(handlers.RevokeRequesterKey))).ServeHTTP))

	// Certificate Routes
	mux.Handle("/api/v1/certificate/issue", methodHandler(http.MethodPost,
		middleware.Authenticate(
			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin)(
				http.HandlerFunc(handlers.IssueVerificationCertificate))).ServeHTTP))

	// Renewal Alerts
	mux.Handle("/api/v1/alerts/renewal", routeByMethod(map[string]http.Handler{
		http.MethodGet:  middleware.Authenticate(http.HandlerFunc(handlers.GetRenewalAlerts)),
		http.MethodPost: middleware.Authenticate(http.HandlerFunc(handlers.ConfigureRenewalAlert)),
	}))

	// Apply global middleware
	handler := middleware.CORS(middleware.Logging(middleware.RateLimit(100)(mux)))

	return handler
}

// methodHandler wraps a handler to only accept a specific HTTP method
func methodHandler(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler(w, r)
	}
}

// routeByMethod routes requests to different handlers based on HTTP method
func routeByMethod(methods map[string]http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler, ok := methods[r.Method]
		if !ok {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// // SetupRoutes configures all API routes
// func SetupRoutes(handlers *Handlers, middleware *Middleware) http.Handler {
// 	mux := http.NewServeMux()

// 	// ==================== Public Routes ====================

// 	// Root endpoint
// 	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
// 		SendSuccess(w, "", map[string]interface{}{
// 			"message": "KYC Blockchain API",
// 			"version": "1.0.0",
// 			"status":  "running",
// 		})
// 	})

// 	// Health check
// 	mux.HandleFunc("GET /health", handlers.HealthCheck)

// 	// Auth routes
// 	mux.HandleFunc("POST /api/v1/auth/register", handlers.Register)
// 	mux.HandleFunc("POST /api/v1/auth/login", handlers.Login)
// 	mux.HandleFunc("POST /api/v1/auth/refresh", handlers.RefreshToken)
// 	// mux.Handle("POST /api/v1/auth/refresh",
// 	// 	middleware.Authenticate(http.HandlerFunc(handlers.RefreshToken)))

// 	// ==================== Protected Routes ====================

// 	// Profile
// 	mux.Handle("GET /api/v1/auth/profile",
// 		middleware.Authenticate(http.HandlerFunc(handlers.GetProfile)))

// 	// KYC Routes
// 	mux.Handle("POST /api/v1/kyc",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCCreate)(
// 				http.HandlerFunc(handlers.CreateKYC))))

// 	mux.Handle("GET /api/v1/kyc",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.GetKYC))))

// 	mux.Handle("PUT /api/v1/kyc",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCUpdate)(
// 				http.HandlerFunc(handlers.UpdateKYC))))

// 	mux.Handle("DELETE /api/v1/kyc",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCDelete)(
// 				http.HandlerFunc(handlers.DeleteKYC))))

// 	mux.Handle("GET /api/v1/kyc/list",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.ListKYC))))

// 	mux.Handle("GET /api/v1/kyc/history",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.GetKYCHistory))))

// 	mux.Handle("POST /api/v1/kyc/verify",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCVerify)(
// 				http.HandlerFunc(handlers.VerifyKYC))))

// 	mux.Handle("POST /api/v1/kyc/reject",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCReject)(
// 				http.HandlerFunc(handlers.RejectKYC))))

// 	mux.Handle("POST /api/v1/kyc/auto-verify",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCVerify)(
// 				http.HandlerFunc(handlers.AutoVerifyKYC))))

// 	// KYC Review Routes
// 	mux.Handle("POST /api/v1/kyc/review",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin, auth.RoleBankOfficer)(
// 				http.HandlerFunc(handlers.PeriodicReviewKYC))))

// 	mux.Handle("GET /api/v1/kyc/review/status",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermKYCRead)(
// 				http.HandlerFunc(handlers.GetKYCReviewStatus))))

// 	// Bank Routes
// 	mux.Handle("POST /api/v1/banks",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBankCreate)(
// 				http.HandlerFunc(handlers.RegisterBank))))

// 	mux.Handle("GET /api/v1/banks",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBankRead)(
// 				http.HandlerFunc(handlers.GetBank))))

// 	mux.Handle("GET /api/v1/banks/list",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBankRead)(
// 				http.HandlerFunc(handlers.ListBanks))))

// 	// Blockchain Routes
// 	mux.Handle("GET /api/v1/blockchain/stats",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetBlockchainStats))))

// 	mux.Handle("GET /api/v1/blockchain/blocks",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetBlocks))))

// 	mux.Handle("GET /api/v1/blockchain/block",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetBlock))))

// 	mux.Handle("POST /api/v1/blockchain/mine",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainMine)(
// 				http.HandlerFunc(handlers.MineBlock))))

// 	mux.Handle("GET /api/v1/blockchain/pending",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.GetPendingTransactions))))

// 	mux.Handle("GET /api/v1/blockchain/validate",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermBlockchainRead)(
// 				http.HandlerFunc(handlers.ValidateChain))))

// 	// Monitoring Routes
// 	mux.Handle("GET /api/v1/audit/logs",
// 		middleware.Authenticate(
// 			middleware.RequirePermission(auth.PermAuditRead)(
// 				http.HandlerFunc(handlers.GetAuditLogs))))

// 	mux.Handle("GET /api/v1/security/alerts",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.GetSecurityAlerts))))

// 	mux.Handle("POST /api/v1/security/alerts/review",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.ReviewSecurityAlert))))

// 	// Requester Key Routes
// 	mux.Handle("POST /api/v1/keys/generate",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.GenerateRequesterKeyPair)))

// 	mux.Handle("GET /api/v1/keys",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.GetRequesterKeys))))

// 	mux.Handle("GET /api/v1/keys/info",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.GetRequesterKeyByID)))

// 	mux.Handle("POST /api/v1/keys/revoke",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin)(
// 				http.HandlerFunc(handlers.RevokeRequesterKey))))

// 	// Certificate Routes
// 	mux.Handle("POST /api/v1/certificate/issue",
// 		middleware.Authenticate(
// 			middleware.RequireRole(auth.RoleAdmin, auth.RoleBankAdmin)(
// 				http.HandlerFunc(handlers.IssueVerificationCertificate))))

// 	mux.Handle("POST /api/v1/certificate/verify",
// 		http.HandlerFunc(handlers.VerifyCertificate)) // Public - no auth needed

// 	// Renewal Alerts Routes
// 	mux.Handle("GET /api/v1/alerts/renewal",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.GetRenewalAlerts)))

// 	mux.Handle("POST /api/v1/alerts/renewal/configure",
// 		middleware.Authenticate(
// 			http.HandlerFunc(handlers.ConfigureRenewalAlert)))

// 	// Apply global middleware
// 	handler := middleware.CORS(middleware.Logging(middleware.RateLimit(100)(mux)))

// 	return handler
// }
