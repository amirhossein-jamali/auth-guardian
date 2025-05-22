package auth

import (
	"context"
	"time"

	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/token"
)

// RefreshTokenInput represents data needed for token refresh
type RefreshTokenInput struct {
	RefreshToken string
	UserAgent    string
	IP           string
}

// RefreshTokenOutput represents the result of a successful token refresh
type RefreshTokenOutput struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64
}

// RefreshTokenUseCase handles token refresh operations
type RefreshTokenUseCase struct {
	authSessionRepo repository.AuthSessionRepository
	tokenService    token.TokenService
	timeProvider    tport.Provider
	logger          logger.Logger
}

// NewRefreshTokenUseCase creates a new instance of RefreshTokenUseCase
func NewRefreshTokenUseCase(
	authSessionRepo repository.AuthSessionRepository,
	tokenService token.TokenService,
	timeProvider tport.Provider,
	logger logger.Logger,
) *RefreshTokenUseCase {
	return &RefreshTokenUseCase{
		authSessionRepo: authSessionRepo,
		tokenService:    tokenService,
		timeProvider:    timeProvider,
		logger:          logger,
	}
}

// Execute refreshes an access token using a refresh token
func (uc *RefreshTokenUseCase) Execute(ctx context.Context, input RefreshTokenInput) (*RefreshTokenOutput, error) {
	// Only checking for empty string is sufficient as the main validation happens in the repository
	if input.RefreshToken == "" {
		return nil, domainErr.NewValidationError("refreshToken", "refresh token is required")
	}

	// Get session by refresh token
	session, err := uc.authSessionRepo.GetByRefreshToken(ctx, input.RefreshToken)
	if err != nil {
		uc.logger.Error("Failed to get session by refresh token", map[string]any{
			"error": err.Error(),
		})
		return nil, err
	}

	if session == nil {
		return nil, domainErr.ErrSessionNotFound
	}

	// Check if session has expired
	if session.IsExpired(uc.timeProvider) {
		// Delete expired session - but don't log error since it's not critical
		_ = uc.authSessionRepo.DeleteByID(ctx, session.ID)
		return nil, domainErr.ErrExpiredToken
	}

	// Validate refresh token with token service - we already have the session
	// so we only need basic validation from token service
	userID := session.UserID.String()

	// Generate new tokens
	accessToken, refreshToken, expiresAt, err := uc.tokenService.GenerateTokens(userID)
	if err != nil {
		uc.logger.Error("Failed to generate tokens", map[string]any{
			"userId": userID,
			"error":  err.Error(),
		})
		return nil, domainErr.ErrTokenGenerationFailed
	}

	// Update session with new refresh token
	now := uc.timeProvider.Now()
	expiresAtTime := time.Unix(expiresAt, 0)
	session.UpdateToken(refreshToken, expiresAtTime, now)

	err = uc.authSessionRepo.Update(ctx, session)
	if err != nil {
		uc.logger.Error("Failed to update session", map[string]any{
			"sessionId": session.ID.String(),
			"error":     err.Error(),
		})
		return nil, err
	}

	return &RefreshTokenOutput{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}
