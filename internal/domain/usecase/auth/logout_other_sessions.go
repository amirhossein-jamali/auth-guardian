package auth

import (
	"context"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

// LogoutOtherSessionsInput represents data needed for logging out all other sessions
type LogoutOtherSessionsInput struct {
	RefreshToken string
	UserAgent    string
	IP           string
}

// LogoutOtherSessionsUseCase handles logging out all sessions except the current one
type LogoutOtherSessionsUseCase struct {
	authSessionRepo repository.AuthSessionRepository
	tokenService    token.TokenService
	logger          logger.Logger
	timeProvider    time.Provider
	auditLogger     logger.AuditLogger
}

// NewLogoutOtherSessionsUseCase creates a new instance of LogoutOtherSessionsUseCase
func NewLogoutOtherSessionsUseCase(
	authSessionRepo repository.AuthSessionRepository,
	tokenService token.TokenService,
	logger logger.Logger,
	timeProvider time.Provider,
	auditLogger logger.AuditLogger,
) *LogoutOtherSessionsUseCase {
	return &LogoutOtherSessionsUseCase{
		authSessionRepo: authSessionRepo,
		tokenService:    tokenService,
		logger:          logger,
		timeProvider:    timeProvider,
		auditLogger:     auditLogger,
	}
}

// Execute logs out all sessions except the current one
func (uc *LogoutOtherSessionsUseCase) Execute(ctx context.Context, input LogoutOtherSessionsInput) error {
	// Measure execution time
	startTime := uc.timeProvider.Now()

	// Validate refresh token
	if err := validator.ValidateRefreshToken(input.RefreshToken); err != nil {
		return err
	}

	// Find current session by refresh token
	currentSession, err := uc.authSessionRepo.GetByRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		uc.logger.Error("Failed to get session by refresh token", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	if currentSession == nil {
		return domainErr.ErrInvalidSession
	}

	// Delete all other sessions for this user
	count, err := uc.authSessionRepo.DeleteAllExcept(ctx, currentSession.UserID, currentSession.ID)
	if err != nil {
		uc.logger.Error("Failed to delete other sessions", map[string]any{
			"userId":    currentSession.UserID.String(),
			"sessionId": currentSession.ID.String(),
			"error":     err.Error(),
		})
		return err
	}

	// Log security event if audit logger is available
	if uc.auditLogger != nil {
		_ = uc.auditLogger.LogSecurityEvent(ctx, "logout_other_sessions", map[string]any{
			"userId":          currentSession.UserID.String(),
			"sessionId":       currentSession.ID.String(),
			"sessionsRemoved": count,
			"ip":              input.IP,
			"userAgent":       input.UserAgent,
		})
	}

	// Log with execution time
	elapsed := uc.timeProvider.Now().Sub(startTime)
	uc.logger.Info("Other sessions logged out successfully", map[string]any{
		"userId":          currentSession.UserID.String(),
		"sessionsRemoved": count,
		"elapsed":         elapsed.String(),
	})

	return nil
}
