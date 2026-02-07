package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/config"
	"Go-Blockchain-KYC/crypto"
	"Go-Blockchain-KYC/models"
	"Go-Blockchain-KYC/monitoring"
	"Go-Blockchain-KYC/storage"
	"Go-Blockchain-KYC/verification"
)

// Server represents the HTTP server
type Server struct {
	config              *config.Config
	httpServer          *http.Server
	blockchain          *models.Blockchain
	authService         *auth.AuthService
	storage             storage.Storage
	rbac                *auth.RBAC
	verificationService *verification.VerificationService
	monitoringService   *monitoring.MonitoringService
	keyManager          *crypto.KeyManager
}

// NewServer creates a new server instance
func NewServer(
	cfg *config.Config,
	blockchain *models.Blockchain,
	authService *auth.AuthService,
	store storage.Storage,
	verificationService *verification.VerificationService,
	monitoringService *monitoring.MonitoringService,
	keyManager *crypto.KeyManager,
) *Server {
	return &Server{
		config:              cfg,
		blockchain:          blockchain,
		authService:         authService,
		storage:             store,
		rbac:                auth.NewRBAC(),
		verificationService: verificationService,
		monitoringService:   monitoringService,
		keyManager:          keyManager,
	}
}

// Start starts the HTTP server
func (s *Server) Start() error {
	// Create handlers
	handlers := NewHandlers(s.blockchain, s.authService, s.storage, s.rbac, s.verificationService, s.monitoringService, s.keyManager)

	// Create middleware
	middleware := NewMiddleware(s.authService, s.rbac, s.monitoringService)

	// Setup routes
	router := SetupRoutes(handlers, middleware)

	// Configure server
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
		IdleTimeout:  s.config.Server.IdleTimeout,
	}

	// Configure TLS if certificates are provided
	if s.config.Server.TLSCertFile != "" && s.config.Server.TLSKeyFile != "" {
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
	}

	// Channel to listen for errors
	serverErrors := make(chan error, 1)

	// Start server in goroutine
	go func() {
		log.Printf("Starting server on %s", addr)
		if s.config.Server.TLSCertFile != "" {
			serverErrors <- s.httpServer.ListenAndServeTLS(
				s.config.Server.TLSCertFile,
				s.config.Server.TLSKeyFile,
			)
		} else {
			serverErrors <- s.httpServer.ListenAndServe()
		}
	}()

	// Channel to listen for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	// Block until we receive a signal or error
	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		log.Printf("Received signal %v, starting graceful shutdown", sig)
		return s.Shutdown()
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.httpServer.Close()
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}

	// Close database connection
	if s.storage != nil {
		if err := s.storage.Close(); err != nil {
			log.Printf("Error closing storage: %v", err)
		}
	}

	log.Println("Server shutdown complete")
	return nil
}
