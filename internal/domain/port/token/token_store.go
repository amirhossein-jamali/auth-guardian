package token

// TokenStore defines the interface for storing and retrieving token information
type TokenStore interface {
	// StoreToken stores a token with its associated user ID and expiration time
	StoreToken(tokenID string, userID string, expiresAt int64) error
	// GetUserIDByToken retrieves the user ID associated with a token
	GetUserIDByToken(tokenID string) (string, error)
	// RevokeToken marks a token as revoked
	RevokeToken(tokenID string) error
	// IsTokenRevoked checks if a token is revoked
	IsTokenRevoked(tokenID string) (bool, error)
}
