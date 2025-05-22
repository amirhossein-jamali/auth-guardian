package tests

import (
	"context"
	"errors"
	"testing"
	stdtime "time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/usecase/user"
	"github.com/amirhossein-jamali/auth-guardian/mocks/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/mocks/port/repository"
	mocktime "github.com/amirhossein-jamali/auth-guardian/mocks/port/time"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUpdateProfileUseCase_Execute(t *testing.T) {
	// Define fixed test time
	testTime := stdtime.Date(2023, 1, 1, 12, 0, 0, 0, stdtime.UTC)
	testElapsed := 100 * stdtime.Millisecond

	t.Run("successful profile update with all fields", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		// Create test user
		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
			UpdatedAt: testTime.Add(-24 * stdtime.Hour),
		}

		// Setup expectations
		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)
		mockUserRepo.EXPECT().EmailExists(mock.Anything, "new@example.com").Return(false, nil)
		mockUserRepo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(u *entity.User) bool {
			return u.Email == "new@example.com" &&
				u.FirstName == "NewFirst" &&
				u.LastName == "NewLast" &&
				u.UpdatedAt == testTime
		})).Return(nil)

		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockTimeProvider.EXPECT().Since(testTime).Return(testElapsed)

		mockLogger.EXPECT().Info(mock.Anything, mock.Anything)

		mockAuditLogger.EXPECT().LogSecurityEvent(mock.Anything, "profile_updated", mock.MatchedBy(func(metadata map[string]any) bool {
			changes, ok := metadata["changes"].(map[string]interface{})
			if !ok {
				return false
			}
			return metadata["userId"] == userID &&
				metadata["ip"] == "192.168.1.1" &&
				changes != nil
		})).Return(nil)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			Email:     "new@example.com",
			FirstName: "NewFirst",
			LastName:  "NewLast",
			IP:        "192.168.1.1",
		})

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "new@example.com", result.User.Email)
		assert.Equal(t, "NewFirst", result.User.FirstName)
		assert.Equal(t, "NewLast", result.User.LastName)
		assert.Equal(t, testTime, result.User.UpdatedAt)
	})

	t.Run("successful profile update with partial fields", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "existing@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
		}

		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)
		mockUserRepo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(u *entity.User) bool {
			return u.Email == "existing@example.com" &&
				u.FirstName == "NewFirst" &&
				u.LastName == "OldLast"
		})).Return(nil)

		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockTimeProvider.EXPECT().Since(testTime).Return(testElapsed)

		mockLogger.EXPECT().Info(mock.Anything, mock.Anything)

		mockAuditLogger.EXPECT().LogSecurityEvent(mock.Anything, "profile_updated", mock.Anything).Return(nil)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			FirstName: "NewFirst",
			IP:        "192.168.1.1",
		})

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "existing@example.com", result.User.Email)
		assert.Equal(t, "NewFirst", result.User.FirstName)
		assert.Equal(t, "OldLast", result.User.LastName)
	})

	t.Run("invalid user ID", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		// Need to add Now() expectation even for validation errors
		mockTimeProvider.EXPECT().Now().Return(testTime)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    "invalid-id",
			FirstName: "NewFirst",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("user not found", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"

		// Add Now() expectation
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(nil, nil)
		mockLogger.EXPECT().Error(mock.Anything, mock.Anything).Maybe()

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			FirstName: "NewFirst",
		})

		// Assert
		assert.Equal(t, domainErr.ErrUserNotFound, err)
		assert.Nil(t, result)
	})

	t.Run("repository error", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		repoErr := errors.New("database error")

		// Add Now() expectation
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(nil, repoErr)
		mockLogger.EXPECT().Error(mock.Anything, mock.Anything)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			FirstName: "NewFirst",
		})

		// Assert
		assert.Equal(t, repoErr, err)
		assert.Nil(t, result)
	})

	t.Run("invalid email", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
		}

		// Add Now() expectation
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			Email:     "invalid-email",
			FirstName: "NewFirst",
		})

		// Assert
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("email already exists", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
		}

		// Add Now() expectation
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)
		mockUserRepo.EXPECT().EmailExists(mock.Anything, "new@example.com").Return(true, nil)
		mockLogger.EXPECT().Error(mock.Anything, mock.Anything).Maybe()

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			Email:     "new@example.com",
			FirstName: "NewFirst",
		})

		// Assert
		assert.Equal(t, domainErr.ErrEmailAlreadyExists, err)
		assert.Nil(t, result)
	})

	t.Run("failed to update user", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
		}
		updateErr := errors.New("failed to update user")

		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)
		mockUserRepo.EXPECT().Update(mock.Anything, mock.Anything).Return(updateErr)
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockLogger.EXPECT().Error(mock.Anything, mock.Anything)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			FirstName: "NewFirst",
		})

		// Assert
		assert.Equal(t, updateErr, err)
		assert.Nil(t, result)
	})

	t.Run("audit logging failure should not affect success", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "old@example.com",
			FirstName: "OldFirst",
			LastName:  "OldLast",
		}
		auditErr := errors.New("audit logging failed")

		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)
		mockUserRepo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil)
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockTimeProvider.EXPECT().Since(testTime).Return(testElapsed)
		mockLogger.EXPECT().Info(mock.Anything, mock.Anything)
		mockLogger.EXPECT().Warn(mock.Anything, mock.Anything)
		mockAuditLogger.EXPECT().LogSecurityEvent(mock.Anything, mock.Anything, mock.Anything).Return(auditErr)

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			FirstName: "NewFirst",
			IP:        "192.168.1.1",
		})

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("no changes made", func(t *testing.T) {
		// Arrange
		mockUserRepo := repository.NewMockUserRepository(t)
		mockTimeProvider := mocktime.NewMockTimeProvider(t)
		mockLogger := logger.NewMockLogger(t)
		mockAuditLogger := logger.NewMockAuditLogger(t)

		userID := "123e4567-e89b-12d3-a456-426614174000"
		existingUser := &entity.User{
			ID:        entity.ID(userID),
			Email:     "existing@example.com",
			FirstName: "ExistingFirst",
			LastName:  "ExistingLast",
		}

		// Add Now() expectation
		mockTimeProvider.EXPECT().Now().Return(testTime)
		mockUserRepo.EXPECT().GetByID(mock.Anything, entity.ID(userID)).Return(existingUser, nil)
		// No update should be called since no changes were made

		// Create the use case
		uc := user.NewUpdateProfileUseCase(mockUserRepo, mockTimeProvider, mockLogger, mockAuditLogger)

		// Act
		result, err := uc.Execute(context.Background(), user.UpdateProfileInput{
			UserID:    userID,
			Email:     "existing@example.com",
			FirstName: "ExistingFirst",
			LastName:  "ExistingLast",
		})

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, existingUser, result.User)
	})
}
