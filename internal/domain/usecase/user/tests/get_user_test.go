package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/user"

	// Mocks
	mockLogger "github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	mockRepo "github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mockTime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupGetUserMocks(t *testing.T) (
	*mockRepo.MockUserRepository,
	*mockLogger.MockLogger,
	*mockTime.MockTimeProvider,
) {
	userRepo := mockRepo.NewMockUserRepository(t)
	logger := mockLogger.NewMockLogger(t)
	timeProvider := mockTime.NewMockTimeProvider(t)

	return userRepo, logger, timeProvider
}

func TestGetUserUseCase_Execute_Success(t *testing.T) {
	// Arrange
	userRepo, logger, timeProvider := setupGetUserMocks(t)

	// Test data with valid UUID format
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()
	elapsed := 100 * time.Millisecond

	// Create mock user
	mockUser := &entity.User{
		ID:        entity.NewID(userID),
		Email:     "test@example.com",
		FirstName: "Test",
		LastName:  "User",
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Setup expectations
	timeProvider.EXPECT().Now().Return(now)
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(mockUser, nil)
	timeProvider.EXPECT().Since(now).Return(elapsed)
	logger.EXPECT().Info("User retrieved successfully", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["userId"] == userID && data["elapsed"] == elapsed.String()
	}))

	// Create use case
	useCase := user.NewGetUserUseCase(
		userRepo,
		logger,
		timeProvider,
	)

	// Act
	input := user.GetUserInput{
		UserID: userID,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, mockUser, result.User)
}

func TestGetUserUseCase_Execute_UserNotFound(t *testing.T) {
	// Arrange
	userRepo, logger, timeProvider := setupGetUserMocks(t)

	// Test data with valid UUID format
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()

	// Setup expectations
	timeProvider.EXPECT().Now().Return(now)
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(nil, nil) // User not found but no error

	// Create use case
	useCase := user.NewGetUserUseCase(
		userRepo,
		logger,
		timeProvider,
	)

	// Act
	input := user.GetUserInput{
		UserID: userID,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domainErr.ErrUserNotFound, err)
	assert.Nil(t, result)
}

func TestGetUserUseCase_Execute_InvalidUserID(t *testing.T) {
	// Arrange
	userRepo, logger, timeProvider := setupGetUserMocks(t)

	// Test data with invalid UUID format
	userID := "invalid-user-id"
	now := time.Now()

	// Setup expectations
	timeProvider.EXPECT().Now().Return(now)

	// Create use case
	useCase := user.NewGetUserUseCase(
		userRepo,
		logger,
		timeProvider,
	)

	// Act
	input := user.GetUserInput{
		UserID: userID,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "userID")
}

func TestGetUserUseCase_Execute_RepositoryError(t *testing.T) {
	// Arrange
	userRepo, logger, timeProvider := setupGetUserMocks(t)

	// Test data with valid UUID format
	userID := "123e4567-e89b-12d3-a456-426614174000"
	now := time.Now()
	repoError := errors.New("database connection error")

	// Setup expectations
	timeProvider.EXPECT().Now().Return(now)
	userRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(nil, repoError)
	logger.EXPECT().Error("Failed to get user by ID", mock.MatchedBy(func(data map[string]interface{}) bool {
		return data["userId"] == userID && data["error"] == repoError.Error()
	}))

	// Create use case
	useCase := user.NewGetUserUseCase(
		userRepo,
		logger,
		timeProvider,
	)

	// Act
	input := user.GetUserInput{
		UserID: userID,
	}
	result, err := useCase.Execute(context.Background(), input)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, repoError, err)
	assert.Nil(t, result)
}

func TestNewGetUserUseCase(t *testing.T) {
	// Arrange
	userRepo, logger, timeProvider := setupGetUserMocks(t)

	// Act
	useCase := user.NewGetUserUseCase(
		userRepo,
		logger,
		timeProvider,
	)

	// Assert
	assert.NotNil(t, useCase)
	assert.IsType(t, &user.GetUserUseCase{}, useCase)
}
