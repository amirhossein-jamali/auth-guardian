package entity

import (
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
)

type AuthSession struct {
	ID           valueobject.ID
	UserID       valueobject.ID
	RefreshToken string
	UserAgent    string
	IP           string
	ExpiresAt    time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

func NewAuthSession(
	idGenerator func() valueobject.ID,
	userID valueobject.ID,
	refreshToken string,
	userAgent string,
	ip string,
	expiresAt time.Time,
) *AuthSession {
	now := time.Now()
	return &AuthSession{
		ID:           idGenerator(),
		UserID:       userID,
		RefreshToken: refreshToken,
		UserAgent:    userAgent,
		IP:           ip,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// IsExpired checks if the session has expired
func (s *AuthSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// UpdateToken updates the refresh token and expiry time
func (s *AuthSession) UpdateToken(refreshToken string, expiresAt time.Time) {
	s.RefreshToken = refreshToken
	s.ExpiresAt = expiresAt
	s.UpdatedAt = time.Now()
}
