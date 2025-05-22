package entity

import "time"

// AuthSessionInfo represents a simplified view of an auth session
type AuthSessionInfo struct {
	SessionID    string
	UserAgent    string
	IP           string
	LastActivity time.Time
	CreatedAt    time.Time
	Current      bool
}

func NewAuthSessionInfo(
	sessionID string,
	userAgent string,
	ip string,
	lastActivity time.Time,
	createdAt time.Time,
	current bool,
) *AuthSessionInfo {
	return &AuthSessionInfo{
		SessionID:    sessionID,
		UserAgent:    userAgent,
		IP:           ip,
		LastActivity: lastActivity,
		CreatedAt:    createdAt,
		Current:      current,
	}
}
