package entity

import (
	"time"
)

// AuthSessionInfo represents a simplified view of an auth session
// for presenting to users in the UI
type AuthSessionInfo struct {
	SessionID    string    `json:"session_id"`
	UserAgent    string    `json:"user_agent"`
	IP           string    `json:"ip"`
	LastActivity time.Time `json:"last_activity"`
	CreatedAt    time.Time `json:"created_at"`
	Current      bool      `json:"current"`
}
