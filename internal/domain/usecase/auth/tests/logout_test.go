package tests

import (
	"context"
	"errors"
	"testing"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockToken "github.com/amirhossein-jamali/auth-guardian/mocks/port/token"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupLogoutMocks(t *testing.T) (
	*mockRepo.MockAuthSessionRepository,
	*mockToken.MockTokenService,
	*mockLogger.MockLogger,
) {
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	tokenService := mockToken.NewMockTokenService(t)
	logger := mockLogger.NewMockLogger(t)

	return authSessionRepo, tokenService, logger
}

func TestLogoutUseCase_Execute_Success(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger := setupLogoutMocks(t)

	// Test data
	session := createTestSession() // Reusing the helper from refresh_token_test.go
	input := auth.LogoutInput{
		RefreshToken: session.RefreshToken,
	}

	// Setup expectations
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)
	authSessionRepo.EXPECT().DeleteByID(mock.Anything, session.ID).Return(nil)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestLogoutUseCase_Execute_EmptyToken(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger := setupLogoutMocks(t)

	// Test data with empty refresh token
	input := auth.LogoutInput{
		RefreshToken: "",
	}

	// Create use case
	useCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	var validationErr domainErr.ValidationError
	ok := errors.As(err, &validationErr)
	assert.True(t, ok, "Error should be of type ValidationError")
	assert.Equal(t, "refreshToken", validationErr.Field)
}

func TestLogoutUseCase_Execute_SessionNotFound(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger := setupLogoutMocks(t)

	// Test data
	input := auth.LogoutInput{
		RefreshToken: "non-existent-token",
	}

	// Setup expectations - session not found
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, "non-existent-token").Return(nil, nil)

	// Create use case
	useCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err, "Should return success when session is not found (already logged out)")
}

func TestLogoutUseCase_Execute_GetSessionDatabaseError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger := setupLogoutMocks(t)

	// Test data
	input := auth.LogoutInput{
		RefreshToken: "existing-token",
	}

	// Setup expectations - database error
	dbError := errors.New("database error")
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, "existing-token").Return(nil, dbError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, dbError, err)
}

func TestLogoutUseCase_Execute_DeleteSessionError(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger := setupLogoutMocks(t)

	// Test data
	session := createTestSession()
	input := auth.LogoutInput{
		RefreshToken: session.RefreshToken,
	}

	// Setup expectations
	authSessionRepo.EXPECT().GetByRefreshToken(mock.Anything, session.RefreshToken).Return(session, nil)

	// Delete session error
	deleteError := errors.New("delete session failed")
	authSessionRepo.EXPECT().DeleteByID(mock.Anything, session.ID).Return(deleteError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, deleteError, err)
}

func TestNewLogoutUseCase(t *testing.T) {
	// Arrange
	authSessionRepo, tokenService, logger := setupLogoutMocks(t)

	// Act
	useCase := auth.NewLogoutUseCase(
		authSessionRepo,
		tokenService,
		logger,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &auth.LogoutUseCase{}, useCase)
}
