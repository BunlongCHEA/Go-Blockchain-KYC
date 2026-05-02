package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"Go-Blockchain-KYC/auth"
	"Go-Blockchain-KYC/monitoring"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	UserContextKey   ContextKey = "user"
	ClaimsContextKey ContextKey = "claims"
	TrackedUserIDKey ContextKey = "tracked_user_id" // for monitoring: tracks which user is being acted on, even if the caller is an admin
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

		// ── Inject a mutable *string pointer into context
		// Authenticate (deeper in the chain) will write the real user.ID into
		// this pointer. When next.ServeHTTP returns, we read it here.
		// This is necessary because r.WithContext() inside Authenticate creates
		// a NEW request — the original `r` here never sees those changes.
		userIDPtr := new(string)
		*userIDPtr = "anonymous" // default — overwritten by Authenticate if token valid
		r = r.WithContext(context.WithValue(r.Context(), TrackedUserIDKey, userIDPtr))

		next.ServeHTTP(wrapper, r)

		duration := time.Since(start)
		log.Printf("%s %s %d %v", r.Method, r.URL.Path, wrapper.statusCode, duration)

		if r.URL.Path == "/health" || r.URL.Path == "/" {
			return
		}
		if m.monitoring == nil {
			return
		}

		// ── Record activity for monitoring
		// Read the real userID — Authenticate has written it by now
		userID := *userIDPtr
		if userID == "anonymous" {
			switch {
			case strings.Contains(r.URL.Path, "/auth/login"):
				userID = "auth:login"
			case strings.Contains(r.URL.Path, "/auth/register"):
				userID = "auth:register"
			case strings.Contains(r.URL.Path, "/certificate/verify"):
				userID = "public:verify"
			case strings.Contains(r.URL.Path, "/banks/list"):
				userID = "public:banks_list"
			case strings.Contains(r.URL.Path, "/health"):
				userID = "public:health_check"
			}
		}

		m.monitoring.RecordActivity(monitoring.UserActivity{
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
		})
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
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
			m.recordFailedAuth(r, "missing authorization header")
			SendUnauthorized(w, "missing authorization header")
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.recordFailedAuth(r, "invalid authorization header format")
			SendUnauthorized(w, "invalid authorization header format")
			return
		}

		user, claims, err := m.authService.ValidateToken(parts[1])
		if err != nil {
			m.recordFailedAuth(r, "invalid or expired token")
			SendUnauthorized(w, "invalid or expired token")
			return
		}

		// ── Write real userID back to the shared pointer
		// Logging middleware injected this pointer before the chain ran.
		// Writing here makes it visible to Logging after next.ServeHTTP returns
		// even though r.WithContext() below creates a new request copy.
		if ptr, ok := r.Context().Value(TrackedUserIDKey).(*string); ok {
			*ptr = user.ID
		}

		// Add user and claims to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// recordFailedAuth sends a failed-login event to monitoring so
// AnomalyMultipleFailedAuth can trigger after N failures from the same IP.
func (m *Middleware) recordFailedAuth(r *http.Request, reason string) {
	if m.monitoring == nil {
		return
	}
	// Key by IP so attempts from unauthenticated callers still accumulate.
	// Use "anon:<ip>" so isSystemUser() doesn't suppress it AND it's
	// still distinguishable from real user IDs.
	ip := getClientIP(r)
	m.monitoring.RecordActivity(monitoring.UserActivity{
		UserID:    "anon:" + ip,
		Action:    "LOGIN_FAILED", // triggers FailedAuthCount++ in monitoring
		Resource:  "AUTH",
		IPAddress: ip,
		UserAgent: r.UserAgent(),
		Timestamp: time.Now(),
		Success:   false,
		Details:   map[string]interface{}{"reason": reason, "path": r.URL.Path},
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

	var mu sync.Mutex // sync.Mutex (currently has a data race)
	clients := make(map[string]*client)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// ip := r.RemoteAddr
			ip := getClientIP(r) // was r.RemoteAddr (includes port, wrong key)

			mu.Lock()
			c, exists := clients[ip]
			if !exists {
				clients[ip] = &client{count: 1, lastSeen: time.Now()}
				mu.Unlock()
			} else {
				if time.Since(c.lastSeen) > time.Minute {
					c.count = 1
					c.lastSeen = time.Now()
				} else {
					c.count++
				}

				over := c.count > requestsPerMinute
				mu.Unlock()
				if over {
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
	switch {
	case strings.Contains(path, "/kyc"):
		return "KYC"
	case strings.Contains(path, "/certificate"):
		return "CERTIFICATE"
	case strings.Contains(path, "/bank"):
		return "BANK"
	case strings.Contains(path, "/blockchain"):
		return "BLOCKCHAIN"
	case strings.Contains(path, "/auth"):
		return "AUTH"
	case strings.Contains(path, "/users"):
		return "USER"
	case strings.Contains(path, "/security"):
		return "SECURITY"
	case strings.Contains(path, "/audit"):
		return "AUDIT"
	default:
		return "OTHER"
	}
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
