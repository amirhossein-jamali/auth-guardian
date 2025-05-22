package auth

import (
	"context"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
)

// LogoutInput represents data needed for logout
type LogoutInput struct {
	RefreshToken string
}

// LogoutUseCase handles user logout
type LogoutUseCase struct {
	authSessionRepo repository.AuthSessionRepository
	tokenService    token.TokenService
	logger          logger.Logger
}

// NewLogoutUseCase creates a new instance of LogoutUseCase
func NewLogoutUseCase(
	authSessionRepo repository.AuthSessionRepository,
	tokenService token.TokenService,
	logger logger.Logger,
) *LogoutUseCase {
	return &LogoutUseCase{
		authSessionRepo: authSessionRepo,
		tokenService:    tokenService,
		logger:          logger,
	}
}

// Execute logs out a user by invalidating their refresh token
func (uc *LogoutUseCase) Execute(ctx context.Context, input LogoutInput) error {
	// Validate input
	if input.RefreshToken == "" {
		return domainErr.NewValidationError("refreshToken", "refresh token is required")
	}

	// Get session by refresh token
	session, err := uc.authSessionRepo.GetByRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		uc.logger.Error("Failed to get session by refresh token", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	if session == nil {
		// Session not found, consider it already logged out
		return nil
	}

	// Delete the session
	err = uc.authSessionRepo.DeleteByID(ctx, session.ID)
	if err != nil {
		uc.logger.Error("Failed to delete session", map[string]interface{}{
			"sessionId": session.ID.String(),
			"error":     err.Error(),
		})
		return err
	}

	uc.logger.Info("User logged out successfully", map[string]interface{}{
		"userId":    session.UserID.String(),
		"sessionId": session.ID.String(),
	})

	return nil
}
