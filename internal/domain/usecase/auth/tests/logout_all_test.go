package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/auth"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupLogoutAllMocks(t *testing.T) (
	*mockRepo.MockAuthSessionRepository,
	*mockLogger.MockLogger,
) {
	authSessionRepo := mockRepo.NewMockAuthSessionRepository(t)
	logger := mockLogger.NewMockLogger(t)

	return authSessionRepo, logger
}

func TestLogoutAllUseCase_Execute_Success(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupLogoutAllMocks(t)

	// Test data
	userId := "test-user-id"
	input := auth.LogoutAllInput{
		UserID: userId,
	}

	// Setup expectations
	authSessionRepo.EXPECT().DeleteAllByUserID(
		mock.Anything,
		mock.MatchedBy(func(id entity.ID) bool {
			return id.String() == userId
		}),
	).Return(nil)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
}

func TestLogoutAllUseCase_Execute_EmptyUserID(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupLogoutAllMocks(t)

	// Test data with empty user ID
	input := auth.LogoutAllInput{
		UserID: "",
	}

	// Create use case
	useCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	var validationErr domainErr.ValidationError
	ok := errors.As(err, &validationErr)
	assert.True(t, ok, "Error should be of type ValidationError")
	assert.Equal(t, "userID", validationErr.Field)
}

func TestLogoutAllUseCase_Execute_DatabaseError(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupLogoutAllMocks(t)

	// Test data
	userId := "test-user-id"
	input := auth.LogoutAllInput{
		UserID: userId,
	}

	// Setup expectations - database error
	dbError := errors.New("database error")
	authSessionRepo.EXPECT().DeleteAllByUserID(mock.Anything, mock.Anything).Return(dbError)
	logger.EXPECT().Error(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, dbError, err)
}

func TestLogoutAllUseCase_Execute_With_NonExistentUser(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupLogoutAllMocks(t)

	// Test data for a user ID that doesn't exist
	nonExistentUserId := "non-existent-user-id"
	input := auth.LogoutAllInput{
		UserID: nonExistentUserId,
	}

	// Setup expectations - no error even if user doesn't exist (idempotent behavior)
	authSessionRepo.EXPECT().DeleteAllByUserID(
		mock.Anything,
		mock.MatchedBy(func(id entity.ID) bool {
			return id.String() == nonExistentUserId
		}),
	).Return(nil)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err, "Should succeed even if user doesn't exist")
}

func TestLogoutAllUseCase_Execute_With_InvalidUserID(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupLogoutAllMocks(t)

	// Test data with potentially problematic user ID (e.g., with SQL injection)
	suspiciousUserId := "user-id-with-special-chars';DROP TABLE users;--"
	input := auth.LogoutAllInput{
		UserID: suspiciousUserId,
	}

	// Setup expectations - the repository should handle sanitization
	authSessionRepo.EXPECT().DeleteAllByUserID(
		mock.Anything,
		mock.MatchedBy(func(id entity.ID) bool {
			return id.String() == suspiciousUserId
		}),
	).Return(nil)
	logger.EXPECT().Info(mock.Anything, mock.Anything).Return()

	// Create use case
	useCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	// Act
	err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err, "Should handle special characters in user ID properly")
}

func TestNewLogoutAllUseCase(t *testing.T) {
	// Arrange
	authSessionRepo, logger := setupLogoutAllMocks(t)

	// Act
	useCase := auth.NewLogoutAllUseCase(
		authSessionRepo,
		logger,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &auth.LogoutAllUseCase{}, useCase)
}
