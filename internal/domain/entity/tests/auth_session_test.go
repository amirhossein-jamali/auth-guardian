package tests

import (
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	mocks "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthSession(t *testing.T) {
	// Arrange
	id := entity.NewID("session-123")
	userID := entity.NewID("user-456")
	refreshToken := "refresh-token-xyz"
	userAgent := "Mozilla/5.0"
	ip := "192.168.1.1"
	expiresAt := time.Date(2023, 2, 1, 12, 0, 0, 0, time.UTC)
	now := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	// Act
	session := entity.NewAuthSession(id, userID, refreshToken, userAgent, ip, expiresAt, now)

	// Assert
	assert.Equal(t, id, session.ID, "ID should match the provided ID")
	assert.Equal(t, userID, session.UserID, "UserID should match the provided UserID")
	assert.Equal(t, refreshToken, session.RefreshToken, "RefreshToken should match the provided token")
	assert.Equal(t, userAgent, session.UserAgent, "UserAgent should match the provided agent")
	assert.Equal(t, ip, session.IP, "IP should match the provided IP")
	assert.Equal(t, expiresAt, session.ExpiresAt, "ExpiresAt should match the provided time")
	assert.Equal(t, now, session.LastActivityAt, "LastActivityAt should be set to now")
	assert.Equal(t, now, session.CreatedAt, "CreatedAt should be set to now")
	assert.Equal(t, now, session.UpdatedAt, "UpdatedAt should be set to now")
}

func TestAuthSession_IsExpired(t *testing.T) {
	// Arrange
	expiresAt := time.Date(2023, 2, 1, 12, 0, 0, 0, time.UTC)
	session := &entity.AuthSession{
		ID:        entity.NewID("session-123"),
		ExpiresAt: expiresAt,
	}

	// Create mock time provider
	t.Run("Session is not expired", func(t *testing.T) {
		mockTimeProvider := mocks.NewMockTimeProvider(t)
		beforeExpiry := time.Date(2023, 1, 31, 12, 0, 0, 0, time.UTC) // Before expiry date
		mockTimeProvider.EXPECT().Now().Return(beforeExpiry)

		// Act
		isExpired := session.IsExpired(mockTimeProvider)

		// Assert
		assert.False(t, isExpired, "Session should not be expired when current time is before expiry")
	})

	t.Run("Session is expired", func(t *testing.T) {
		mockTimeProvider := mocks.NewMockTimeProvider(t)
		afterExpiry := time.Date(2023, 2, 2, 12, 0, 0, 0, time.UTC) // After expiry date
		mockTimeProvider.EXPECT().Now().Return(afterExpiry)

		// Act
		isExpired := session.IsExpired(mockTimeProvider)

		// Assert
		assert.True(t, isExpired, "Session should be expired when current time is after expiry")
	})

	t.Run("Session expires exactly at expiry time", func(t *testing.T) {
		mockTimeProvider := mocks.NewMockTimeProvider(t)
		atExpiry := expiresAt // Exactly at expiry date
		mockTimeProvider.EXPECT().Now().Return(atExpiry)

		// Act
		isExpired := session.IsExpired(mockTimeProvider)

		// Assert
		assert.False(t, isExpired, "Session should not be expired exactly at expiry time")
	})
}

func TestAuthSession_UpdateToken(t *testing.T) {
	// Arrange
	initialExpiresAt := time.Date(2023, 2, 1, 12, 0, 0, 0, time.UTC)
	initialCreatedAt := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	initialUpdatedAt := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	initialToken := "old-refresh-token"

	session := &entity.AuthSession{
		ID:           entity.NewID("session-123"),
		RefreshToken: initialToken,
		ExpiresAt:    initialExpiresAt,
		CreatedAt:    initialCreatedAt,
		UpdatedAt:    initialUpdatedAt,
	}

	newToken := "new-refresh-token"
	newExpiresAt := time.Date(2023, 3, 1, 12, 0, 0, 0, time.UTC)
	now := time.Date(2023, 1, 15, 12, 0, 0, 0, time.UTC)

	// Act
	session.UpdateToken(newToken, newExpiresAt, now)

	// Assert
	assert.Equal(t, newToken, session.RefreshToken, "RefreshToken should be updated to the new token")
	assert.Equal(t, newExpiresAt, session.ExpiresAt, "ExpiresAt should be updated to the new expiry time")
	assert.Equal(t, now, session.UpdatedAt, "UpdatedAt should be updated to the current time")
	assert.Equal(t, initialCreatedAt, session.CreatedAt, "CreatedAt should remain unchanged")
}

func TestAuthSession_ToInfo(t *testing.T) {
	// Arrange
	sessionID := entity.NewID("session-123")
	userAgent := "Mozilla/5.0"
	ip := "192.168.1.1"
	lastActivityAt := time.Date(2023, 1, 15, 12, 0, 0, 0, time.UTC)
	createdAt := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)

	session := &entity.AuthSession{
		ID:             sessionID,
		UserAgent:      userAgent,
		IP:             ip,
		LastActivityAt: lastActivityAt,
		CreatedAt:      createdAt,
	}

	// Test with current=true
	t.Run("Current session", func(t *testing.T) {
		// Act
		info := session.ToInfo(true)

		// Assert
		assert.Equal(t, sessionID.String(), info.SessionID, "SessionID should match the session ID as string")
		assert.Equal(t, userAgent, info.UserAgent, "UserAgent should match")
		assert.Equal(t, ip, info.IP, "IP should match")
		assert.Equal(t, lastActivityAt, info.LastActivity, "LastActivity should match")
		assert.Equal(t, createdAt, info.CreatedAt, "CreatedAt should match")
		assert.True(t, info.Current, "Current should be true")
	})

	// Test with current=false
	t.Run("Non-current session", func(t *testing.T) {
		// Act
		info := session.ToInfo(false)

		// Assert
		assert.Equal(t, sessionID.String(), info.SessionID, "SessionID should match the session ID as string")
		assert.Equal(t, userAgent, info.UserAgent, "UserAgent should match")
		assert.Equal(t, ip, info.IP, "IP should match")
		assert.Equal(t, lastActivityAt, info.LastActivity, "LastActivity should match")
		assert.Equal(t, createdAt, info.CreatedAt, "CreatedAt should match")
		assert.False(t, info.Current, "Current should be false")
	})
}
