package token

// TokenService handles JWT token operations
type TokenService interface {
	// GenerateTokens generates an access token and refresh token for a user
	GenerateTokens(userID string) (accessToken string, refreshToken string, expiresAt int64, err error)
	// ValidateAccessToken validates an access token and returns the user ID
	ValidateAccessToken(token string) (userID string, err error)
	// ValidateRefreshToken validates a refresh token and returns the user ID
	ValidateRefreshToken(token string) (userID string, err error)
	// RevokeToken revokes a token
	RevokeToken(token string) error
	// IsTokenRevoked checks if a token is revoked
	IsTokenRevoked(token string) (bool, error)
}
