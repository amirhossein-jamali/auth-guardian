package entity

import (
	"time"

	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
)

type AuthSession struct {
	ID             ID
	UserID         ID
	RefreshToken   string
	UserAgent      string
	IP             string
	ExpiresAt      time.Time
	LastActivityAt time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func NewAuthSession(
	id ID,
	userID ID,
	refreshToken string,
	userAgent string,
	ip string,
	expiresAt time.Time,
	now time.Time,
) *AuthSession {
	return &AuthSession{
		ID:             id,
		UserID:         userID,
		RefreshToken:   refreshToken,
		UserAgent:      userAgent,
		IP:             ip,
		ExpiresAt:      expiresAt,
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// IsExpired checks if the session has expired using injected time provider
func (s *AuthSession) IsExpired(tp tport.Provider) bool {
	return tp.Now().After(s.ExpiresAt)
}

func (s *AuthSession) UpdateToken(refreshToken string, expiresAt time.Time, now time.Time) {
	s.RefreshToken = refreshToken
	s.ExpiresAt = expiresAt
	s.UpdatedAt = now
}

func (s *AuthSession) ToInfo(current bool) *AuthSessionInfo {
	return NewAuthSessionInfo(
		s.ID.String(),
		s.UserAgent,
		s.IP,
		s.LastActivityAt,
		s.CreatedAt,
		current,
	)
}
