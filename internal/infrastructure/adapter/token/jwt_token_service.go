package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the claims in a JWT token
type Claims struct {
	UserID string `json:"user_id"`
	Type   string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// JWTConfig holds configuration for JWTTokenService
type JWTConfig struct {
	AccessSecret     string
	RefreshSecret    string
	AccessExpiresIn  time.Duration
	RefreshExpiresIn time.Duration
}

// JWTTokenService implements TokenService using JWT
type JWTTokenService struct {
	logger        logger.Logger
	timeProvider  tport.Provider
	accessSecret  string
	refreshSecret string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
	tokenStore    token.TokenStore
}

// NewJWTTokenService creates a new JWTTokenService
func NewJWTTokenService(
	config JWTConfig,
	timeProvider tport.Provider,
	tokenStore token.TokenStore,
	logger logger.Logger,
) token.TokenService {
	return &JWTTokenService{
		logger:        logger,
		timeProvider:  timeProvider,
		accessSecret:  config.AccessSecret,
		refreshSecret: config.RefreshSecret,
		accessExpiry:  config.AccessExpiresIn,
		refreshExpiry: config.RefreshExpiresIn,
		tokenStore:    tokenStore,
	}
}

// GenerateTokens generates an access token and refresh token for a user
func (s *JWTTokenService) GenerateTokens(userID string) (string, string, int64, error) {
	// Generate access token
	now := s.timeProvider.Now()
	accessExpires := s.timeProvider.Add(now, s.accessExpiry)

	accessTokenID := uuid.New().String()
	accessClaims := Claims{
		UserID: userID,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(accessExpires.Unix(), 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(now.Unix(), 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(now.Unix(), 0)),
			ID:        accessTokenID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(s.accessSecret))
	if err != nil {
		s.logger.Error("Failed to sign access token", map[string]any{
			"userId": userID,
			"error":  err.Error(),
		})
		return "", "", 0, err
	}

	// Generate refresh token
	refreshExpires := s.timeProvider.Add(now, s.refreshExpiry)
	refreshTokenID := uuid.New().String()
	refreshClaims := Claims{
		UserID: userID,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(refreshExpires.Unix(), 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(now.Unix(), 0)),
			NotBefore: jwt.NewNumericDate(time.Unix(now.Unix(), 0)),
			ID:        refreshTokenID,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.refreshSecret))
	if err != nil {
		s.logger.Error("Failed to sign refresh token", map[string]any{
			"userId": userID,
			"error":  err.Error(),
		})
		return "", "", 0, err
	}

	// Store refresh token for future validation
	if err := s.tokenStore.StoreToken(refreshTokenID, userID, refreshExpires.Unix()); err != nil {
		s.logger.Error("Failed to store refresh token", map[string]any{
			"userId": userID,
			"error":  err.Error(),
		})
		return "", "", 0, err
	}

	return accessTokenString, refreshTokenString, accessExpires.Unix(), nil
}

// ValidateAccessToken validates an access token and returns the user ID
func (s *JWTTokenService) ValidateAccessToken(tokenString string) (string, error) {
	// Parse t
	t, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.accessSecret), nil
	})

	// Handle parsing errors
	if err != nil {
		s.logger.Debug("Failed to parse access t", map[string]any{
			"error": err.Error(),
		})
		return "", err
	}

	// Extract and validate claims
	if claims, ok := t.Claims.(*Claims); ok && t.Valid {
		// Check t type
		if claims.Type != "access" {
			return "", errors.New("invalid t type")
		}

		return claims.UserID, nil
	}

	return "", errors.New("invalid t")
}

// ValidateRefreshToken validates a refresh token and returns the user ID
func (s *JWTTokenService) ValidateRefreshToken(tokenString string) (string, error) {
	// Parse t
	t, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.refreshSecret), nil
	})

	// Handle parsing errors
	if err != nil {
		s.logger.Debug("Failed to parse refresh t", map[string]any{
			"error": err.Error(),
		})
		return "", err
	}

	// Extract and validate claims
	if claims, ok := t.Claims.(*Claims); ok && t.Valid {
		// Check t type
		if claims.Type != "refresh" {
			return "", errors.New("invalid t type")
		}

		// Check if t is revoked
		isRevoked, err := s.tokenStore.IsTokenRevoked(claims.ID)
		if err != nil {
			s.logger.Error("Failed to check if t is revoked", map[string]any{
				"tokenId": claims.ID,
				"error":   err.Error(),
			})
			return "", err
		}

		if isRevoked {
			return "", errors.New("t is revoked")
		}

		// Check if t exists in store
		userID, err := s.tokenStore.GetUserIDByToken(claims.ID)
		if err != nil {
			s.logger.Error("Failed to get user ID from t store", map[string]any{
				"tokenId": claims.ID,
				"error":   err.Error(),
			})
			return "", err
		}

		// Verify that the t belongs to the claimed user
		if userID != claims.UserID {
			return "", errors.New("t user ID mismatch")
		}

		return claims.UserID, nil
	}

	return "", errors.New("invalid t")
}

// RevokeToken revokes a token
func (s *JWTTokenService) RevokeToken(tokenString string) error {
	// Parse t without validation to extract ID
	t, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		s.logger.Error("Failed to parse t for revocation", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	// Extract claims
	if claims, ok := t.Claims.(*Claims); ok {
		// Only refresh tokens can be revoked
		if claims.Type != "refresh" {
			return errors.New("only refresh tokens can be revoked")
		}

		// Revoke the t
		if err := s.tokenStore.RevokeToken(claims.ID); err != nil {
			s.logger.Error("Failed to revoke t", map[string]any{
				"tokenId": claims.ID,
				"error":   err.Error(),
			})
			return err
		}

		s.logger.Debug("Token revoked successfully", map[string]any{
			"tokenId": claims.ID,
		})
		return nil
	}

	return errors.New("invalid t")
}

// IsTokenRevoked checks if a token is revoked
func (s *JWTTokenService) IsTokenRevoked(tokenString string) (bool, error) {
	// Parse t without validation to extract ID
	t, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		s.logger.Error("Failed to parse t for revocation check", map[string]any{
			"error": err.Error(),
		})
		return false, err
	}

	// Extract claims
	if claims, ok := t.Claims.(*Claims); ok {
		// Only refresh tokens can be revoked
		if claims.Type != "refresh" {
			return false, errors.New("only refresh tokens can be revoked")
		}

		// Check if t is revoked
		isRevoked, err := s.tokenStore.IsTokenRevoked(claims.ID)
		if err != nil {
			s.logger.Error("Failed to check if t is revoked", map[string]any{
				"tokenId": claims.ID,
				"error":   err.Error(),
			})
			return false, err
		}

		return isRevoked, nil
	}

	return false, errors.New("invalid t")
}
