package auth

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
)

// LogoutAllInput represents data needed for logging out from all devices
type LogoutAllInput struct {
	UserID string
}

// LogoutAllUseCase handles logging out from all devices
type LogoutAllUseCase struct {
	authSessionRepo repository.AuthSessionRepository
	logger          logger.Logger
}

// NewLogoutAllUseCase creates a new instance of LogoutAllUseCase
func NewLogoutAllUseCase(
	authSessionRepo repository.AuthSessionRepository,
	logger logger.Logger,
) *LogoutAllUseCase {
	return &LogoutAllUseCase{
		authSessionRepo: authSessionRepo,
		logger:          logger,
	}
}

// Execute logs out a user from all devices by deleting all their sessions
func (uc *LogoutAllUseCase) Execute(ctx context.Context, input LogoutAllInput) error {
	// Validate input
	if input.UserID == "" {
		return domainErr.NewValidationError("userID", "user ID is required")
	}

	// Delete all sessions for the user
	err := uc.authSessionRepo.DeleteAllByUserID(ctx, entity.NewID(input.UserID))
	if err != nil {
		uc.logger.Error("Failed to delete all sessions for user", map[string]interface{}{
			"userId": input.UserID,
			"error":  err.Error(),
		})
		return err
	}

	uc.logger.Info("User logged out from all devices successfully", map[string]interface{}{
		"userId": input.UserID,
	})

	return nil
}
