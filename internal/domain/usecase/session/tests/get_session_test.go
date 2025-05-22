package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/session"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupGetSessionsMocks(t *testing.T) (
	*mockRepo.MockAuthSessionRepository,
	*mockLogger.MockLogger,
) {
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	logger := mockLogger.NewMockLogger(t)

	return authSessionRepo, logger
}

func TestGetSessionsUseCase_Execute_Success_WithCurrentSession(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Test data with valid UUID format
	userID := "123e4567-e89b-12d3-a456-426614174000"
	refreshToken := "valid_refresh_token"
	now := time.Now()

	// Create test sessions with the correct fields
	session1 := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174001"),
		UserID:         entity.NewID(userID),
		RefreshToken:   "token1",
		UserAgent:      "Chrome on Windows",
		IP:             "192.168.1.1",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	session2 := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174002"),
		UserID:         entity.NewID(userID),
		RefreshToken:   "token2",
		UserAgent:      "Firefox on Mac",
		IP:             "192.168.1.2",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	sessions := []*entity.AuthSession{session1, session2}

	// Setup expectations
	authSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(sessions, nil)
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, refreshToken).Return(session1, nil)

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       userID,
		CurrentToken: refreshToken,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Sessions, 2)

	// Verify current session is marked correctly
	foundCurrent := false
	for _, s := range result.Sessions {
		if s.SessionID == "123e4567-e89b-12d3-a456-426614174001" {
			assert.True(t, s.Current, "Session 1 should be marked as current")
			foundCurrent = true
		} else {
			assert.False(t, s.Current, "Other sessions should not be marked as current")
		}
	}
	assert.True(t, foundCurrent, "Should have found the current session")
}

func TestGetSessionsUseCase_Execute_Success_WithoutCurrentSession(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Test data with valid UUID
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()

	// Create test sessions with the correct fields
	session1 := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174001"),
		UserID:         entity.NewID(userID),
		RefreshToken:   "token1",
		UserAgent:      "Chrome on Windows",
		IP:             "192.168.1.1",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	session2 := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174002"),
		UserID:         entity.NewID(userID),
		RefreshToken:   "token2",
		UserAgent:      "Firefox on Mac",
		IP:             "192.168.1.2",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	sessions := []*entity.AuthSession{session1, session2}

	// Setup expectations
	authSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(sessions, nil)

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       userID,
		CurrentToken: "", // No current token
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Sessions, 2)

	// Verify no session is marked as current
	for _, s := range result.Sessions {
		assert.False(t, s.Current, "No session should be marked as current")
	}
}

func TestGetSessionsUseCase_Execute_InvalidUserID(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       "invalid-id", // Invalid user ID - not a UUID
		CurrentToken: "token",
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "userID")
}

func TestGetSessionsUseCase_Execute_RepositoryError(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Test data with valid UUID
	userID := "123e4567-e89b-12d3-a456-426614174000"
	repoError := errors.New("database error")

	// Setup expectations
	authSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(nil, repoError)
	logger.EXPECT().Error("Failed to get sessions for user", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["userId"] == userID && data["error"] == repoError.Error()
	})).Return()

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       userID,
		CurrentToken: "token",
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, repoError, err)
	assert.Nil(t, result)
}

func TestGetSessionsUseCase_Execute_CurrentSessionNotFound(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Test data with valid UUID
	userID := "123e4567-e89b-12d3-a456-426614174000"
	invalidToken := "invalid_token"
	now := time.Now()

	// Create test sessions with the correct fields
	session1 := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174001"),
		UserID:         entity.NewID(userID),
		RefreshToken:   "token1",
		UserAgent:      "Chrome on Windows",
		IP:             "192.168.1.1",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	sessions := []*entity.AuthSession{session1}

	// Setup expectations
	authSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(sessions, nil)
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, invalidToken).Return(nil, errors.New("token not found"))

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       userID,
		CurrentToken: invalidToken,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Sessions, 1)

	// Verify no session is marked as current
	for _, s := range result.Sessions {
		assert.False(t, s.Current, "No session should be marked as current when token is invalid")
	}
}

func TestGetSessionsUseCase_Execute_CurrentSessionFromDifferentUser(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Test data with valid UUIDs
	userID := "123e4567-e89b-12d3-a456-426614174000"
	otherUserID := "123e4567-e89b-12d3-a456-426614174999"
	refreshToken := "valid_refresh_token"
	now := time.Now()

	// Create test sessions with the correct fields
	session1 := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174001"),
		UserID:         entity.NewID(userID),
		RefreshToken:   "token1",
		UserAgent:      "Chrome on Windows",
		IP:             "192.168.1.1",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	otherUserSession := &entity.AuthSession{
		ID:             entity.NewID("123e4567-e89b-12d3-a456-426614174888"),
		UserID:         entity.NewID(otherUserID), // Different user
		RefreshToken:   "token_other",
		UserAgent:      "Safari on iPhone",
		IP:             "192.168.1.3",
		ExpiresAt:      now.Add(24 * time.Hour),
		LastActivityAt: now,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	sessions := []*entity.AuthSession{session1}

	// Setup expectations
	authSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return(sessions, nil)
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, refreshToken).Return(otherUserSession, nil)

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       userID,
		CurrentToken: refreshToken,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Sessions, 1)

	// Verify no session is marked as current since the session belongs to a different user
	for _, s := range result.Sessions {
		assert.False(t, s.Current, "No session should be marked as current for different user")
	}
}

func TestGetSessionsUseCase_Execute_NoSessions(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Test data with valid UUID
	userID := "123e4567-e89b-12d3-a456-426614174000"

	// Setup expectations - user has no sessions
	authSessionRepo.EXPECT().GetByUserID(mock.Anything, entity.NewID(userID)).Return([]*entity.AuthSession{}, nil)

	// Create use case
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	input := session.GetSessionsInput{
		UserID:       userID,
		CurrentToken: "",
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Empty(t, result.Sessions, "Result should have no sessions")
}

func TestNewGetSessionsUseCase(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupGetSessionsMocks(t)

	// Act
	useCase := session.NewGetSessionsUseCase(
		authSessionRepo,
		logger,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &session.GetSessionsUseCase{}, useCase)
}
