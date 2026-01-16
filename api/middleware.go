package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/monitoring"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	UserContextKey   ContextKey = "user"
	ClaimsContextKey ContextKey = "claims"
)

// Middleware holds dependencies for middleware functions
type Middleware struct {
	authService *auth.AuthService
	rbac        *auth.RBAC
	monitoring  *monitoring.MonitoringService
}

// NewMiddleware creates a new middleware instance
func NewMiddleware(authService *auth.AuthService, rbac *auth.RBAC, monitoringService *monitoring.MonitoringService) *Middleware {
	return &Middleware{
		authService: authService,
		rbac:        rbac,
		monitoring:  monitoringService,
	}
}

// Logging logs HTTP requests
func (m *Middleware) Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)

		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapper.statusCode, duration)

		// Record activity for monitoring
		if m.monitoring != nil {
			userID := "anonymous"
			if user, ok := GetUserFromContext(r); ok {
				userID = user.ID
			}

			activity := monitoring.UserActivity{
				UserID:     userID,
				Action:     r.Method + " " + r.URL.Path,
				Resource:   getResourceType(r.URL.Path),
				ResourceID: r.URL.Query().Get("customer_id"),
				IPAddress:  getClientIP(r),
				UserAgent:  r.UserAgent(),
				Timestamp:  time.Now(),
				Success:    wrapper.statusCode < 400,
				Details: map[string]interface{}{
					"method":      r.Method,
					"path":        r.URL.Path,
					"status_code": wrapper.statusCode,
					"duration_ms": duration.Milliseconds(),
				},
			}

			m.monitoring.RecordActivity(activity)
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// CORS handles Cross-Origin Resource Sharing
func (m *Middleware) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Authenticate validates JWT token and sets user in context
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			SendUnauthorized(w, "missing authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			SendUnauthorized(w, "invalid authorization header format")
			return
		}

		token := parts[1]
		user, claims, err := m.authService.ValidateToken(token)
		if err != nil {
			SendUnauthorized(w, "invalid or expired token")
			return
		}

		// Add user and claims to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole checks if user has required role
func (m *Middleware) RequireRole(roles ...auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(UserContextKey).(*auth.User)
			if !ok {
				SendUnauthorized(w, "user not found in context")
				return
			}

			hasRole := false
			for _, role := range roles {
				if user.Role == role {
					hasRole = true
					break
				}
			}

			if !hasRole {
				SendForbidden(w, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermission checks if user has required permission
func (m *Middleware) RequirePermission(permission auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := r.Context().Value(UserContextKey).(*auth.User)
			if !ok {
				SendUnauthorized(w, "user not found in context")
				return
			}

			if !m.rbac.HasPermission(user.Role, permission) {
				SendForbidden(w, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit implements basic rate limiting
func (m *Middleware) RateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
	// Simple in-memory rate limiter
	type client struct {
		count    int
		lastSeen time.Time
	}

	clients := make(map[string]*client)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr

			c, exists := clients[ip]
			if !exists {
				clients[ip] = &client{count: 1, lastSeen: time.Now()}
			} else {
				if time.Since(c.lastSeen) > time.Minute {
					c.count = 1
					c.lastSeen = time.Now()
				} else {
					c.count++
				}

				if c.count > requestsPerMinute {
					SendError(w, http.StatusTooManyRequests, "rate limit exceeded")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext retrieves user from request context
func GetUserFromContext(r *http.Request) (*auth.User, bool) {
	user, ok := r.Context().Value(UserContextKey).(*auth.User)
	return user, ok
}

// GetClaimsFromContext retrieves claims from request context
func GetClaimsFromContext(r *http.Request) (*auth.Claims, bool) {
	claims, ok := r.Context().Value(ClaimsContextKey).(*auth.Claims)
	return claims, ok
}

// getResourceType extracts resource type from path
func getResourceType(path string) string {
	if strings.Contains(path, "/kyc") {
		return "KYC"
	}
	if strings.Contains(path, "/bank") {
		return "BANK"
	}
	if strings.Contains(path, "/blockchain") {
		return "BLOCKCHAIN"
	}
	if strings.Contains(path, "/auth") {
		return "AUTH"
	}
	return "OTHER"
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}
	return ip
}
