package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupRefreshTokenMocks(t *testing.T) (
	*mockRepo.MockAuthSessionRepository,
	*mockToken.MockTokenService,
	*mockTime.MockTimeProvider,
	*mockLogger.MockLogger,
) {
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	tokenService := mockToken.NewMockTokenService(t)
	timeProvider := mockTime.NewMockTimeProvider(t)
	logger := mockLogger.NewMockLogger(t)

	return authSessionRepo, tokenService, timeProvider, logger
}

func createTestSession() *entity.AuthSession {
	userID := entity.NewID("test-user-id")
	sessionID := entity.NewID("test-session-id")
	refreshToken := "test-refresh-token-123.xyz"
	userAgent := "Mozilla/5.0"
	ip := "192.168.1.1"
	expiresAt := time.Now().Add(24 * time.Hour)
	createdAt := time.Now().Add(-1 * time.Hour)

	return entity.NewAuthSession(
		sessionID,
		userID,
		refreshToken,
		userAgent,
		ip,
		expiresAt,
		createdAt,
	)
}

func TestRefreshTokenUseCase_Execute_Success(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data
	session := createTestSession()
	input := auth.RefreshTokenInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0 (Updated)",
		IP:           "192.168.1.100",
	}
	newAccessToken := "new-access-token-xyz"
	newRefreshToken := "new-refresh-token-abc"
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	// Setup expectations
	now := time.Now()
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	timeProvider.EXPECT().Now().Return(now).Times(2) // Once for expiration check, once for update
	tokenService.EXPECT().GenerateTokens(session.UserID.String()).Return(newAccessToken, newRefreshToken, expiresAt, nil)

	// Expect session update with new token
	authSessionRepo.EXPECT().Update(
		mock.Anything,
		mock.MatchedBy(func(updatedSession *entity.AuthSession) bool {
			return updatedSession.ID.String() == session.ID.String() &&
				updatedSession.RefreshToken == newRefreshToken &&
				updatedSession.UpdatedAt.Equal(now)
		}),
	).Return(nil)

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, newAccessToken, result.AccessToken)
	assert.Equal(t, newRefreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)
}

func TestRefreshTokenUseCase_Execute_EmptyToken(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data with empty refresh token
	input := auth.RefreshTokenInput{
		RefreshToken: "",
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	var validationErr domainErr.ValidationError
	ok := errors.As(err, &validationErr)
	assert.True(t, ok, "Error should be of type ValidationError")
	assert.Equal(t, "refreshToken", validationErr.Field)
}

func TestRefreshTokenUseCase_Execute_SessionNotFound(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data
	input := auth.RefreshTokenInput{
		RefreshToken: "non-existent-token",
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations - session not found
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, "non-existent-token").Return(nil, nil)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Maybe()

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, domainErr.ErrSessionNotFound, err)
}

func TestRefreshTokenUseCase_Execute_ExpiredSession(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data - create an expired session
	expiredSession := createTestSession()
	expiredSession.ExpiresAt = time.Now().Add(-1 * time.Hour) // Expired 1 hour ago

	input := auth.RefreshTokenInput{
		RefreshToken: expiredSession.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations
	now := time.Now()
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, expiredSession.RefreshToken).Return(expiredSession, nil)
	timeProvider.EXPECT().Now().Return(now)
	// Expect DeleteByID to be called for expired session
	authSessionRepo.EXPECT().DeleteByID(mock.Anything, expiredSession.ID).Return(nil)

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, domainErr.ErrExpiredToken, err)
}

func TestRefreshTokenUseCase_Execute_DatabaseError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data
	input := auth.RefreshTokenInput{
		RefreshToken: "existing-token",
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations - database error
	dbError := errors.New("database error")
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, "existing-token").Return(nil, dbError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, dbError, err)
}

func TestRefreshTokenUseCase_Execute_TokenGenerationError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data
	session := createTestSession()
	input := auth.RefreshTokenInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}

	// Setup expectations
	now := time.Now()
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	timeProvider.EXPECT().Now().Return(now)

	// Token generation error
	tokenGenError := errors.New("token generation failed")
	tokenService.EXPECT().GenerateTokens(session.UserID.String()).Return("", "", int64(0), tokenGenError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, domainErr.ErrTokenGenerationFailed, err)
}

func TestRefreshTokenUseCase_Execute_SessionUpdateError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data
	session := createTestSession()
	input := auth.RefreshTokenInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    "Mozilla/5.0",
		IP:           "192.168.1.1",
	}
	newAccessToken := "new-access-token-xyz"
	newRefreshToken := "new-refresh-token-abc"
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	// Setup expectations
	now := time.Now()
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	timeProvider.EXPECT().Now().Return(now).Times(2) // Once for expiration check, once for update
	tokenService.EXPECT().GenerateTokens(session.UserID.String()).Return(newAccessToken, newRefreshToken, expiresAt, nil)

	// Session update error
	updateError := errors.New("session update failed")
	authSessionRepo.EXPECT().Update(mock.Anything, mock.Anything).Return(updateError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, updateError, err)
}

func TestRefreshTokenUseCase_Execute_WithDifferentIpAndUserAgent(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Test data
	session := createTestSession()
	originalUserAgent := session.UserAgent
	originalIP := session.IP

	// New request with different IP and user agent
	input := auth.RefreshTokenInput{
		RefreshToken: session.RefreshToken,
		UserAgent:    originalUserAgent + " (Updated)",
		IP:           "10.0.0.1", // Different IP
	}
	newAccessToken := "new-access-token-xyz"
	newRefreshToken := "new-refresh-token-abc"
	expiresAt := time.Now().Add(24 * time.Hour).Unix()

	// Setup expectations
	now := time.Now()
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	timeProvider.EXPECT().Now().Return(now).Times(2)
	tokenService.EXPECT().GenerateTokens(session.UserID.String()).Return(newAccessToken, newRefreshToken, expiresAt, nil)

	// Expect session update
	authSessionRepo.EXPECT().Update(
		mock.Anything,
		mock.MatchedBy(func(updatedSession *entity.AuthSession) bool {
			// Verify that original IP and user agent are preserved
			return updatedSession.ID.String() == session.ID.String() &&
				updatedSession.RefreshToken == newRefreshToken &&
				updatedSession.UserAgent == originalUserAgent && // Should not change
				updatedSession.IP == originalIP && // Should not change
				updatedSession.UpdatedAt.Equal(now)
		}),
	).Return(nil)

	// Create use case
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Act
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, newAccessToken, result.AccessToken)
	assert.Equal(t, newRefreshToken, result.RefreshToken)
	assert.Equal(t, expiresAt, result.ExpiresAt)
}

func TestNewRefreshTokenUseCase(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, timeProvider, logger := setupRefreshTokenMocks(t)

	// Act
	useCase := auth.NewRefreshTokenUseCase(
		authSessionRepo,
		tokenService,
		timeProvider,
		logger,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &auth.RefreshTokenUseCase{}, useCase)
}
