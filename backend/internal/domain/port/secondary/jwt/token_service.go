package jwt

import "github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"

// TokenService defines the interface for token operations
type TokenService interface {
	// GenerateTokenPair creates a new pair of access and refresh tokens for a user
	GenerateTokenPair(user *entity.User) (*TokenPair, error)

	// ValidateAccessToken validates an access token and returns the associated claims
	ValidateAccessToken(token string) (*Claims, error)

	// ValidateRefreshToken validates a refresh token and returns the associated claims
	ValidateRefreshToken(token string) (*Claims, error)

	// RevokeToken invalidates a token before its expiration time
	RevokeToken(token string) error

	// BlacklistCheck checks if a token has been revoked
	BlacklistCheck(token string) (bool, error)
}
