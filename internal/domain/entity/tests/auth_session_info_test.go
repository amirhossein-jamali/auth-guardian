package tests

import (
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthSessionInfo(t *testing.T) {
	// Arrange
	sessionID := "session-abc-123"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
	ip := "192.168.1.100"
	lastActivity := time.Date(2023, 1, 15, 12, 30, 0, 0, time.UTC)
	createdAt := time.Date(2023, 1, 1, 10, 0, 0, 0, time.UTC)

	// Act
	sessionInfo := entity.NewAuthSessionInfo(
		sessionID,
		userAgent,
		ip,
		lastActivity,
		createdAt,
		true,
	)

	// Assert
	assert.NotNil(t, sessionInfo, "SessionInfo should not be nil")
	assert.Equal(t, sessionID, sessionInfo.SessionID, "SessionID should match the provided value")
	assert.Equal(t, userAgent, sessionInfo.UserAgent, "UserAgent should match the provided value")
	assert.Equal(t, ip, sessionInfo.IP, "IP should match the provided value")
	assert.Equal(t, lastActivity, sessionInfo.LastActivity, "LastActivity should match the provided value")
	assert.Equal(t, createdAt, sessionInfo.CreatedAt, "CreatedAt should match the provided value")
	assert.Equal(t, true, sessionInfo.Current, "Current should match the provided value")

	// Test with different values
	t.Run("With different values", func(t *testing.T) {
		// Arrange
		sessionID := "different-session-456"
		userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
		ip := "10.0.0.1"
		lastActivity := time.Date(2023, 2, 20, 18, 45, 30, 0, time.UTC)
		createdAt := time.Date(2023, 2, 1, 9, 15, 0, 0, time.UTC)

		// Act
		sessionInfo := entity.NewAuthSessionInfo(
			sessionID,
			userAgent,
			ip,
			lastActivity,
			createdAt,
			false,
		)

		// Assert
		assert.NotNil(t, sessionInfo, "SessionInfo should not be nil")
		assert.Equal(t, sessionID, sessionInfo.SessionID, "SessionID should match the provided value")
		assert.Equal(t, userAgent, sessionInfo.UserAgent, "UserAgent should match the provided value")
		assert.Equal(t, ip, sessionInfo.IP, "IP should match the provided value")
		assert.Equal(t, lastActivity, sessionInfo.LastActivity, "LastActivity should match the provided value")
		assert.Equal(t, createdAt, sessionInfo.CreatedAt, "CreatedAt should match the provided value")
		assert.Equal(t, false, sessionInfo.Current, "Current should match the provided value")
	})
}
