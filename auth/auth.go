package auth

import (
	"errors"
	"sync"
	"time"

	"Go-Blockchain-KYC/crypto"
)

// User represents an authenticated user
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	PasswordSalt string    `json:"-"`
	Role         Role      `json:"role"`
	BankID       string    `json:"bank_id,omitempty"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
}

// AuthService handles authentication operations
type AuthService struct {
	users      map[string]*User // username -> User
	usersByID  map[string]*User // id -> User
	sessions   map[string]*Session
	jwtService *JWTService
	mutex      sync.RWMutex
}

// Session represents a user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	User         *User     `json:"user"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     Role   `json:"role"`
	BankID   string `json:"bank_id,omitempty"`
}

// NewAuthService creates a new authentication service
func NewAuthService(jwtSecret string, tokenExpiry, refreshExpiry time.Duration) *AuthService {
	return &AuthService{
		users:      make(map[string]*User),
		usersByID:  make(map[string]*User),
		sessions:   make(map[string]*Session),
		jwtService: NewJWTService(jwtSecret, tokenExpiry, refreshExpiry),
	}
}

// Register registers a new user
func (a *AuthService) Register(req *RegisterRequest) (*User, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Check if username exists
	if _, exists := a.users[req.Username]; exists {
		return nil, errors.New("username already exists")
	}

	// Generate salt and hash password
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		return nil, err
	}

	passwordHash := crypto.HashPassword(req.Password, salt)

	// Create user
	user := &User{
		ID:           generateUserID(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		PasswordSalt: salt,
		Role:         req.Role,
		BankID:       req.BankID,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	a.users[user.Username] = user
	a.usersByID[user.ID] = user

	return user, nil
}

// Login authenticates a user and returns tokens
func (a *AuthService) Login(req *LoginRequest) (*LoginResponse, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	user, exists := a.users[req.Username]
	if !exists {
		return nil, errors.New("invalid credentials")
	}

	if !user.IsActive {
		return nil, errors.New("user account is disabled")
	}

	// Verify password
	if !crypto.VerifyPassword(req.Password, user.PasswordSalt, user.PasswordHash) {
		return nil, errors.New("invalid credentials")
	}

	// Generate tokens
	accessToken, expiresAt, err := a.jwtService.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := a.jwtService.GenerateRefreshToken(user)
	if err != nil {
		return nil, err
	}

	// Update last login
	user.LastLogin = time.Now()

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
		User:         user,
	}, nil
}

// ValidateToken validates a JWT token and returns the user
func (a *AuthService) ValidateToken(tokenString string) (*User, *Claims, error) {
	claims, err := a.jwtService.ValidateToken(tokenString)
	if err != nil {
		return nil, nil, err
	}

	a.mutex.RLock()
	user, exists := a.usersByID[claims.UserID]
	a.mutex.RUnlock()

	if !exists {
		return nil, nil, errors.New("user not found")
	}

	if !user.IsActive {
		return nil, nil, errors.New("user account is disabled")
	}

	return user, claims, nil
}

// RefreshToken refreshes an access token
func (a *AuthService) RefreshToken(refreshToken string) (*LoginResponse, error) {
	claims, err := a.jwtService.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != "refresh" {
		return nil, errors.New("invalid refresh token")
	}

	a.mutex.RLock()
	user, exists := a.usersByID[claims.UserID]
	a.mutex.RUnlock()

	if !exists {
		return nil, errors.New("user not found")
	}

	// Generate new tokens
	accessToken, expiresAt, err := a.jwtService.GenerateAccessToken(user)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := a.jwtService.GenerateRefreshToken(user)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresAt:    expiresAt,
		User:         user,
	}, nil
}

// GetUserByID retrieves a user by ID
func (a *AuthService) GetUserByID(id string) (*User, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	user, exists := a.usersByID[id]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

// UpdatePassword updates a user's password
func (a *AuthService) UpdatePassword(userID, oldPassword, newPassword string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	user, exists := a.usersByID[userID]
	if !exists {
		return errors.New("user not found")
	}

	// Verify old password
	if !crypto.VerifyPassword(oldPassword, user.PasswordSalt, user.PasswordHash) {
		return errors.New("invalid old password")
	}

	// Generate new salt and hash
	salt, err := crypto.GenerateSalt(16)
	if err != nil {
		return err
	}

	user.PasswordHash = crypto.HashPassword(newPassword, salt)
	user.PasswordSalt = salt
	user.UpdatedAt = time.Now()

	return nil
}

// DeactivateUser deactivates a user account
func (a *AuthService) DeactivateUser(userID string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	user, exists := a.usersByID[userID]
	if !exists {
		return errors.New("user not found")
	}

	user.IsActive = false
	user.UpdatedAt = time.Now()

	return nil
}

// Helper function to generate user ID
func generateUserID() string {
	return "USR" + generateRandomString(12)
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1 * time.Nanosecond)
	}
	return string(b)
}
