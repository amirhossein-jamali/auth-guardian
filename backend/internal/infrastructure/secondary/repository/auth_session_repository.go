package repository

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database"
	dbModel "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database/model"
	"gorm.io/gorm"
)

// GormAuthSessionRepository implements the AuthSessionRepository interface using GORM
type GormAuthSessionRepository struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewGormAuthSessionRepository creates a new instance of GormAuthSessionRepository
func NewGormAuthSessionRepository(db *gorm.DB, logger logger.Logger) *GormAuthSessionRepository {
	return &GormAuthSessionRepository{
		db:     db,
		logger: logger,
	}
}

// checkContext verifies if the context is still valid
func (r *GormAuthSessionRepository) checkContext(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// toModel converts a domain entity to a database model
func (r *GormAuthSessionRepository) toModel(session *entity.AuthSession) *dbModel.AuthSession {
	return &dbModel.AuthSession{
		ID:           session.ID.String(),
		UserID:       session.UserID.String(),
		RefreshToken: session.RefreshToken,
		UserAgent:    session.UserAgent,
		IP:           session.IP,
		ExpiresAt:    session.ExpiresAt,
		CreatedAt:    session.CreatedAt,
		UpdatedAt:    session.UpdatedAt,
	}
}

// toEntity converts a database model to a domain entity
func (r *GormAuthSessionRepository) toEntity(dbSession dbModel.AuthSession) (*entity.AuthSession, error) {
	sessionID, err := valueobject.ParseID(dbSession.ID)
	if err != nil {
		return nil, err
	}

	userID, err := valueobject.ParseID(dbSession.UserID)
	if err != nil {
		return nil, err
	}

	return &entity.AuthSession{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: dbSession.RefreshToken,
		UserAgent:    dbSession.UserAgent,
		IP:           dbSession.IP,
		ExpiresAt:    dbSession.ExpiresAt,
		CreatedAt:    dbSession.CreatedAt,
		UpdatedAt:    dbSession.UpdatedAt,
	}, nil
}

// Create stores a new auth session in the database
func (r *GormAuthSessionRepository) Create(ctx context.Context, session *entity.AuthSession) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}

	dbSession := r.toModel(session)
	result := r.db.WithContext(ctx).Create(dbSession)

	if result.Error != nil {
		r.logger.Error("Failed to create auth session",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", session.UserID.String()))
		return database.MapError(result.Error)
	}

	return nil
}

// GetByRefreshToken retrieves an auth session by its refresh token
func (r *GormAuthSessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*entity.AuthSession, error) {
	if err := r.checkContext(ctx); err != nil {
		return nil, err
	}

	var dbSession dbModel.AuthSession
	result := r.db.WithContext(ctx).
		Where("refresh_token = ? AND expires_at > ?", refreshToken, time.Now()).
		First(&dbSession)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, domainError.ErrInvalidToken
		}
		r.logger.Error("Failed to get auth session by refresh token",
			model.NewField("error", result.Error.Error()))
		return nil, database.MapError(result.Error)
	}

	return r.toEntity(dbSession)
}

// GetByUserIDAndUserAgent retrieves the most recent auth session for a user with a specific user agent
func (r *GormAuthSessionRepository) GetByUserIDAndUserAgent(ctx context.Context, userID valueobject.ID, userAgent string) (*entity.AuthSession, error) {
	if err := r.checkContext(ctx); err != nil {
		return nil, err
	}

	var dbSession dbModel.AuthSession
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND user_agent = ? AND expires_at > ?", userID.String(), userAgent, time.Now()).
		Order("created_at DESC").
		First(&dbSession)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, domainError.ErrSessionNotFound
		}
		r.logger.Error("Failed to get auth session by user ID and user agent",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", userID.String()))
		return nil, database.MapError(result.Error)
	}

	return r.toEntity(dbSession)
}

// DeleteByUserID removes all auth sessions for a specific user
func (r *GormAuthSessionRepository) DeleteByUserID(ctx context.Context, userID valueobject.ID) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID.String()).
		Delete(&dbModel.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete auth sessions by user ID",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", userID.String()))
		return database.MapError(result.Error)
	}

	return nil
}

// DeleteByID removes a specific auth session by its ID
func (r *GormAuthSessionRepository) DeleteByID(ctx context.Context, id valueobject.ID) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("id = ?", id.String()).
		Delete(&dbModel.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete auth session",
			model.NewField("error", result.Error.Error()),
			model.NewField("sessionId", id.String()))
		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		return domainError.ErrSessionNotFound
	}

	return nil
}

// DeleteExpired removes all expired auth sessions
func (r *GormAuthSessionRepository) DeleteExpired(ctx context.Context) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&dbModel.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete expired auth sessions",
			model.NewField("error", result.Error.Error()))
		return database.MapError(result.Error)
	}

	return nil
}

// Update updates an existing auth session
func (r *GormAuthSessionRepository) Update(ctx context.Context, session *entity.AuthSession) error {
	if err := r.checkContext(ctx); err != nil {
		return err
	}

	updates := map[string]interface{}{
		"refresh_token": session.RefreshToken,
		"expires_at":    session.ExpiresAt,
		"updated_at":    session.UpdatedAt,
	}

	result := r.db.WithContext(ctx).
		Model(&dbModel.AuthSession{}).
		Where("id = ?", session.ID.String()).
		Updates(updates)

	if result.Error != nil {
		r.logger.Error("Failed to update auth session",
			model.NewField("error", result.Error.Error()),
			model.NewField("sessionId", session.ID.String()))
		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		return domainError.ErrSessionNotFound
	}

	return nil
}

// CountByUserID counts the number of active sessions for a user
func (r *GormAuthSessionRepository) CountByUserID(ctx context.Context, userID valueobject.ID) (int64, error) {
	if err := r.checkContext(ctx); err != nil {
		return 0, err
	}

	var count int64
	result := r.db.WithContext(ctx).
		Model(&dbModel.AuthSession{}).
		Where("user_id = ? AND expires_at > ?", userID.String(), time.Now()).
		Count(&count)

	if result.Error != nil {
		r.logger.Error("Failed to count auth sessions by user ID",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", userID.String()))
		return 0, database.MapError(result.Error)
	}

	return count, nil
}
