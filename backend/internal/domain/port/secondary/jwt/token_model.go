package jwt

import "time"

// TokenPair represents a pair of access and refresh tokens
type TokenPair struct {
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	TokenID               string    `json:"token_id,omitempty"`
}

// Claims represents the data stored in a JWT token
type Claims struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email,omitempty"`
	Name      string    `json:"name,omitempty"`
	TokenID   string    `json:"token_id,omitempty"`
	Type      string    `json:"type,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}
