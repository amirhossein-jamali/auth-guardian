package jwt

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainJWT "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/jwt"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"

	"github.com/golang-jwt/jwt/v5"
)

// Common error messages for consistency
const (
	errUnexpectedSigningMethod = "unexpected signing method"
	errInvalidToken            = "invalid token"
	errInvalidClaims           = "invalid claims"
	errInvalidTokenType        = "invalid token type"
)

// JWTTokenService implements the TokenService interface for phase 1
type JWTTokenService struct {
	config            *Config
	logger            logger.Logger
	blacklistedTokens map[string]time.Time
	mutex             sync.RWMutex
}

// NOTE: This in-memory blacklist implementation has limitations:
// 1. It doesn't persist across service restarts
// 2. In a multi-instance environment (horizontal scaling), each instance has its own blacklist
//
// For production use, consider implementing a shared storage solution like Redis:
// - Redis provides atomic operations and persistence
// - It can be shared across multiple service instances
// - It has built-in TTL support for automatic expiration
// - Example implementation would replace the map with Redis SET or HASH commands
// - SETEX command can be used to automatically expire blacklisted tokens

// NewJWTTokenService creates a new JWT token service
func NewJWTTokenService(config *Config, logger logger.Logger) *JWTTokenService {
	service := &JWTTokenService{
		config:            config,
		logger:            logger,
		blacklistedTokens: make(map[string]time.Time),
		mutex:             sync.RWMutex{},
	}

	// Start a background goroutine to clean up expired blacklisted tokens
	go service.cleanupBlacklistedTokens()

	return service
}

// cleanupBlacklistedTokens periodically removes expired tokens from the blacklist
func (s *JWTTokenService) cleanupBlacklistedTokens() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		s.mutex.Lock()
		now := time.Now()
		for token, expiry := range s.blacklistedTokens {
			if now.After(expiry) {
				delete(s.blacklistedTokens, token)
			}
		}
		s.mutex.Unlock()

		s.logger.Info("Cleaned up expired blacklisted tokens")
	}
}

// GenerateTokenPair creates a simple token pair for phase 1
func (s *JWTTokenService) GenerateTokenPair(user *entity.User) (*domainJWT.TokenPair, error) {
	now := time.Now()
	accessTokenExp := now.Add(s.config.AccessTokenExpiration)
	refreshTokenExp := now.Add(s.config.RefreshTokenExpiration)

	// Generate access token
	accessTokenClaims := jwt.MapClaims{
		"sub":   user.ID.String(),
		"email": user.Email.Value(),
		"exp":   accessTokenExp.Unix(),
		"iat":   now.Unix(),
		"iss":   s.config.Issuer,
		"typ":   "access",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte(s.config.AccessTokenSecret))
	if err != nil {
		s.logger.Error("Failed to sign access token",
			model.NewField("error", err.Error()),
			model.NewField("userId", user.ID.String()))
		return nil, err
	}

	// Generate refresh token
	refreshTokenClaims := jwt.MapClaims{
		"sub": user.ID.String(),
		"exp": refreshTokenExp.Unix(),
		"iat": now.Unix(),
		"iss": s.config.Issuer,
		"typ": "refresh",
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.RefreshTokenSecret))
	if err != nil {
		s.logger.Error("Failed to sign refresh token",
			model.NewField("error", err.Error()),
			model.NewField("userId", user.ID.String()))
		return nil, err
	}

	// Create token pair
	return &domainJWT.TokenPair{
		AccessToken:           accessTokenString,
		RefreshToken:          refreshTokenString,
		AccessTokenExpiresAt:  accessTokenExp,
		RefreshTokenExpiresAt: refreshTokenExp,
	}, nil
}

// ValidateAccessToken validates token and returns claims
func (s *JWTTokenService) ValidateAccessToken(tokenString string) (*domainJWT.Claims, error) {
	// Sanitize token (remove Bearer prefix if present)
	tokenString = sanitizeToken(tokenString)

	// Validate token
	claims, err := s.validateToken(tokenString, s.config.AccessTokenSecret, "access")
	if err != nil {
		s.logger.Warn("Access token validation failed", model.NewField("error", err.Error()))
		return nil, err
	}

	// Extract basic claims
	userID, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	// Create domain claims
	domainClaims := &domainJWT.Claims{
		UserID: userID,
		Email:  email,
		Type:   "access",
	}

	// Extract expiration time if present
	if exp, ok := claims["exp"].(float64); ok {
		domainClaims.ExpiresAt = time.Unix(int64(exp), 0)
	}

	return domainClaims, nil
}

// ValidateRefreshToken validates a refresh token and returns the associated claims
func (s *JWTTokenService) ValidateRefreshToken(tokenString string) (*domainJWT.Claims, error) {
	// Sanitize token
	tokenString = sanitizeToken(tokenString)

	// Validate token
	claims, err := s.validateToken(tokenString, s.config.RefreshTokenSecret, "refresh")
	if err != nil {
		s.logger.Warn("Refresh token validation failed", model.NewField("error", err.Error()))
		return nil, err
	}

	// Extract claims
	userID, _ := claims["sub"].(string)

	// Create domain claims
	domainClaims := &domainJWT.Claims{
		UserID: userID,
		Type:   "refresh",
	}

	// Extract expiration time if present
	if exp, ok := claims["exp"].(float64); ok {
		domainClaims.ExpiresAt = time.Unix(int64(exp), 0)
	}

	return domainClaims, nil
}

// validateToken performs common token validation logic
func (s *JWTTokenService) validateToken(tokenString string, secret string, tokenType string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(errUnexpectedSigningMethod)
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New(errInvalidToken)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New(errInvalidClaims)
	}

	// Verify token type
	if typ, ok := claims["typ"].(string); !ok || typ != tokenType {
		return nil, errors.New(errInvalidTokenType)
	}

	return claims, nil
}

// RevokeToken invalidates a token before its expiration time
func (s *JWTTokenService) RevokeToken(tokenString string) error {
	// Sanitize token
	tokenString = sanitizeToken(tokenString)

	// Try to parse as access token first
	claims, err := s.validateToken(tokenString, s.config.AccessTokenSecret, "access")
	if err != nil {
		// If not an access token, try as refresh token
		claims, err = s.validateToken(tokenString, s.config.RefreshTokenSecret, "refresh")
		if err != nil {
			s.logger.Warn("Failed to revoke token: invalid token", model.NewField("error", err.Error()))
			return err
		}
	}

	// Get expiration time
	var expiry time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiry = time.Unix(int64(exp), 0)
	} else {
		// If no expiration found, set a default (24 hours)
		expiry = time.Now().Add(24 * time.Hour)
	}

	// Add to blacklist
	s.mutex.Lock()
	s.blacklistedTokens[tokenString] = expiry
	s.mutex.Unlock()

	s.logger.Info("Token blacklisted successfully")
	return nil
}

// BlacklistCheck checks if a token has been revoked
func (s *JWTTokenService) BlacklistCheck(tokenString string) (bool, error) {
	// Sanitize token
	tokenString = sanitizeToken(tokenString)

	// Check if token is in blacklist
	s.mutex.RLock()
	_, blacklisted := s.blacklistedTokens[tokenString]
	s.mutex.RUnlock()

	return blacklisted, nil
}

// sanitizeToken removes potential 'Bearer ' prefix from token
func sanitizeToken(tokenString string) string {
	return strings.TrimPrefix(strings.TrimSpace(tokenString), "Bearer ")
}
