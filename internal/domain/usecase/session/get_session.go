package session

import (
	"context"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

// GetSessionsInput represents data needed to get user sessions
type GetSessionsInput struct {
	UserID       string
	CurrentToken string
}

// GetSessionsOutput represents the result of getting user sessions
type GetSessionsOutput struct {
	Sessions []*entity.AuthSessionInfo
}

// GetSessionsUseCase handles getting user sessions
type GetSessionsUseCase struct {
	authSessionRepo repository.AuthSessionRepository
	logger          logger.Logger
}

// NewGetSessionsUseCase creates a new instance of GetSessionsUseCase
func NewGetSessionsUseCase(
	authSessionRepo repository.AuthSessionRepository,
	logger logger.Logger,
) *GetSessionsUseCase {
	return &GetSessionsUseCase{
		authSessionRepo: authSessionRepo,
		logger:          logger,
	}
}

// Execute gets all active sessions for a user
func (uc *GetSessionsUseCase) Execute(ctx context.Context, input GetSessionsInput) (*GetSessionsOutput, error) {
	// Validate user ID
	if err := validator.ValidateID("userID", input.UserID); err != nil {
		return nil, err
	}

	// Get all sessions for the user
	sessions, err := uc.authSessionRepo.GetByUserID(ctx, entity.NewID(input.UserID))
	if err != nil {
		uc.logger.Error("Failed to get sessions for user", map[string]interface{}{
			"userId": input.UserID,
			"error":  err.Error(),
		})
		return nil, err
	}

	// Get current session if token is provided
	var currentSessionID string
	if input.CurrentToken != "" {
		currentSession, err := uc.authSessionRepo.GetByRefreshToken(ctx, input.CurrentToken)
		if err == nil && currentSession != nil {
			currentSessionID = currentSession.ID.String()
		}
	}

	// Convert to session info objects
	sessionInfos := make([]*entity.AuthSessionInfo, len(sessions))
	for i, session := range sessions {
		isCurrent := session.ID.String() == currentSessionID
		sessionInfos[i] = session.ToInfo(isCurrent)
	}

	return &GetSessionsOutput{
		Sessions: sessionInfos,
	}, nil
}
