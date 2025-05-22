package auth

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainErr "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/idgenerator"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/validator"
)

// DefaultSessionCreator implements SessionCreator interface
type DefaultSessionCreator struct {
	authSessionRepo repository.AuthSessionRepository
	idGenerator     idgenerator.IDGenerator
	timeProvider    tport.Provider
	logger          logger.Logger
}

// NewSessionCreator creates a new DefaultSessionCreator
func NewSessionCreator(
	authSessionRepo repository.AuthSessionRepository,
	idGenerator idgenerator.IDGenerator,
	timeProvider tport.Provider,
	logger logger.Logger,
) *DefaultSessionCreator {
	return &DefaultSessionCreator{
		authSessionRepo: authSessionRepo,
		idGenerator:     idGenerator,
		timeProvider:    timeProvider,
		logger:          logger,
	}
}

// CreateSession creates a new authentication session
func (sc *DefaultSessionCreator) CreateSession(
	ctx context.Context,
	userID entity.ID,
	refreshToken string,
	userAgent string,
	ip string,
	expiresAt int64,
) error {
	// Validate userID
	if userID.String() == "" {
		return domainErr.NewValidationError("userID", "user ID is required")
	}

	// Validate refresh token
	if err := validator.ValidateRefreshToken(refreshToken); err != nil {
		return err
	}

	// Validate expires at
	if err := validator.ValidateExpiresAt(expiresAt); err != nil {
		return err
	}

	// Get current time
	now := sc.timeProvider.Now()
	expireTime := time.Unix(expiresAt, 0)

	// Create a new auth session with a generated ID
	session := entity.NewAuthSession(
		entity.NewID(sc.idGenerator.GenerateID()),
		userID,
		refreshToken,
		userAgent,
		ip,
		expireTime,
		now,
	)

	// Store the session in the repository
	err := sc.authSessionRepo.Create(ctx, session)
	if err != nil {
		sc.logger.Error("Failed to create auth session", map[string]interface{}{
			"userID": userID.String(),
			"error":  err.Error(),
		})
		return err
	}

	sc.logger.Info("Auth session created successfully", map[string]interface{}{
		"sessionID": session.ID.String(),
		"userID":    userID.String(),
	})

	return nil
}
