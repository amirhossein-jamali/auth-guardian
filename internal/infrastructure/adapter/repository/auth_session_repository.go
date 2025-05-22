package repository

import (
	"context"
	"errors"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/logger"
	repo "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/repository"
	tport "github.com/amirhossein-jamali/auth-guardian/internal/domain/port/time"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/database"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/adapter/model"

	"gorm.io/gorm"
)

// GormAuthSessionRepository implements the AuthSessionRepository interface using GORM
type GormAuthSessionRepository struct {
	db           *gorm.DB
	logger       logger.Logger
	contextUtil  ContextChecker
	timeProvider tport.Provider
}

// NewGormAuthSessionRepository creates a new GormAuthSessionRepository
func NewGormAuthSessionRepository(db *gorm.DB, logger logger.Logger, timeProvider tport.Provider) repo.AuthSessionRepository {
	return &GormAuthSessionRepository{
		db:           db,
		logger:       logger,
		contextUtil:  &DefaultContextChecker{},
		timeProvider: timeProvider,
	}
}

// toModel converts a domain entity to a database model
func (r *GormAuthSessionRepository) toModel(session *entity.AuthSession) *model.AuthSession {
	return &model.AuthSession{
		ID:             session.ID.String(),
		UserID:         session.UserID.String(),
		RefreshToken:   session.RefreshToken,
		UserAgent:      session.UserAgent,
		IP:             session.IP,
		ExpiresAt:      session.ExpiresAt,
		LastActivityAt: session.LastActivityAt,
		CreatedAt:      session.CreatedAt,
		UpdatedAt:      session.UpdatedAt,
	}
}

// toEntity converts a database model to a domain entity
func (r *GormAuthSessionRepository) toEntity(dbSession model.AuthSession) (*entity.AuthSession, error) {
	session := &entity.AuthSession{
		ID:             entity.ID(dbSession.ID),
		UserID:         entity.ID(dbSession.UserID),
		RefreshToken:   dbSession.RefreshToken,
		UserAgent:      dbSession.UserAgent,
		IP:             dbSession.IP,
		ExpiresAt:      dbSession.ExpiresAt,
		LastActivityAt: dbSession.LastActivityAt,
		CreatedAt:      dbSession.CreatedAt,
		UpdatedAt:      dbSession.UpdatedAt,
	}
	return session, nil
}

// ExecuteInTransaction executes operations within a transaction
// This allows multiple operations to be executed atomically
func (r *GormAuthSessionRepository) ExecuteInTransaction(ctx context.Context, fn func(txRepo repo.AuthSessionRepository) error) error {
	// Check if context is valid
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	// Begin a new transaction
	tx := r.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		r.logger.Error("Failed to begin transaction", map[string]any{"error": tx.Error.Error()})
		return database.MapError(tx.Error)
	}

	// Create a repository that uses the transaction
	txRepo := &GormAuthSessionRepository{
		db:           tx,
		logger:       r.logger,
		contextUtil:  r.contextUtil,
		timeProvider: r.timeProvider,
	}

	// Execute the provided function with the transaction-bound repository
	err := fn(txRepo)
	if err != nil {
		// If an error occurs, rollback the transaction
		r.logger.Debug("Rolling back transaction due to error", map[string]any{"error": err.Error()})
		tx.Rollback()
		return err
	}

	// If everything succeeds, commit the transaction
	if err := tx.Commit().Error; err != nil {
		r.logger.Error("Failed to commit transaction", map[string]any{"error": err.Error()})
		return database.MapError(err)
	}

	return nil
}

// Create creates a new session
func (r *GormAuthSessionRepository) Create(ctx context.Context, session *entity.AuthSession) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	dbSession := r.toModel(session)
	result := r.db.WithContext(ctx).Create(dbSession)

	if result.Error != nil {
		r.logger.Error("Failed to create session", map[string]any{
			"sessionId": session.ID.String(),
			"userId":    session.UserID.String(),
			"error":     result.Error.Error(),
		})
	}

	return database.MapError(result.Error)
}

// GetByUserID gets all sessions for a user
func (r *GormAuthSessionRepository) GetByUserID(ctx context.Context, userID entity.ID) ([]*entity.AuthSession, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return nil, err
	}

	var dbSessions []model.AuthSession
	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID.String()).
		Order("created_at DESC").
		Find(&dbSessions)

	if result.Error != nil {
		r.logger.Error("Failed to get sessions by user ID", map[string]any{
			"userId": userID.String(),
			"error":  result.Error.Error(),
		})
		return nil, database.MapError(result.Error)
	}

	sessions := make([]*entity.AuthSession, 0, len(dbSessions))
	for _, dbSession := range dbSessions {
		session, err := r.toEntity(dbSession)
		if err != nil {
			r.logger.Error("Failed to convert session model to entity", map[string]any{
				"sessionId": dbSession.ID,
				"error":     err.Error(),
			})
			return nil, err
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// GetByRefreshToken gets a session by refresh token
func (r *GormAuthSessionRepository) GetByRefreshToken(ctx context.Context, refreshToken string) (*entity.AuthSession, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return nil, err
	}

	var dbSession model.AuthSession
	result := r.db.WithContext(ctx).
		Where("refresh_token = ?", refreshToken).
		First(&dbSession)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r.logger.Debug("Session not found by refresh token", map[string]any{"tokenHash": refreshToken[:8]})
			return nil, domainError.ErrInvalidToken
		}
		r.logger.Error("Failed to get session by refresh token", map[string]any{
			"tokenHash": refreshToken[:8],
			"error":     result.Error.Error(),
		})
		return nil, database.MapError(result.Error)
	}

	return r.toEntity(dbSession)
}

// GetByUserIDAndUserAgent gets a session by userID and userAgent
func (r *GormAuthSessionRepository) GetByUserIDAndUserAgent(ctx context.Context, userID entity.ID, userAgent string) (*entity.AuthSession, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return nil, err
	}

	var dbSession model.AuthSession
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND user_agent = ?", userID.String(), userAgent).
		Order("created_at DESC").
		First(&dbSession)

	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			r.logger.Debug("Session not found by user ID and user agent", map[string]any{
				"userId":    userID.String(),
				"userAgent": userAgent,
			})
			return nil, domainError.ErrSessionNotFound
		}
		r.logger.Error("Failed to get session by user ID and user agent", map[string]any{
			"userId":    userID.String(),
			"userAgent": userAgent,
			"error":     result.Error.Error(),
		})
		return nil, database.MapError(result.Error)
	}

	return r.toEntity(dbSession)
}

// DeleteAllByUserID deletes all sessions for a user
func (r *GormAuthSessionRepository) DeleteAllByUserID(ctx context.Context, userID entity.ID) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID.String()).
		Delete(&model.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete all sessions for user", map[string]any{
			"userId": userID.String(),
			"error":  result.Error.Error(),
		})
	} else {
		r.logger.Info("Deleted all sessions for user", map[string]any{
			"userId":       userID.String(),
			"deletedCount": result.RowsAffected,
		})
	}

	return database.MapError(result.Error)
}

// DeleteByID deletes a session by ID
func (r *GormAuthSessionRepository) DeleteByID(ctx context.Context, id entity.ID) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("id = ?", id.String()).
		Delete(&model.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete session", map[string]any{
			"sessionId": id.String(),
			"error":     result.Error.Error(),
		})
		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("Session not found for deletion", map[string]any{"sessionId": id.String()})
		return domainError.ErrSessionNotFound
	}

	return nil
}

// DeleteExpired deletes expired sessions
func (r *GormAuthSessionRepository) DeleteExpired(ctx context.Context, before time.Time) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	result := r.db.WithContext(ctx).
		Where("expires_at < ?", before).
		Delete(&model.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete expired sessions", map[string]any{
			"beforeTime": before.Unix(),
			"error":      result.Error.Error(),
		})
	} else {
		r.logger.Info("Deleted expired sessions", map[string]any{
			"beforeTime":   before.Unix(),
			"deletedCount": result.RowsAffected,
		})
	}

	return database.MapError(result.Error)
}

// Update updates a session
func (r *GormAuthSessionRepository) Update(ctx context.Context, session *entity.AuthSession) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	updates := map[string]interface{}{
		"refresh_token":    session.RefreshToken,
		"expires_at":       session.ExpiresAt,
		"last_activity_at": session.LastActivityAt,
		"updated_at":       session.UpdatedAt,
	}

	result := r.db.WithContext(ctx).
		Model(&model.AuthSession{}).
		Where("id = ?", session.ID.String()).
		Updates(updates)

	if result.Error != nil {
		r.logger.Error("Failed to update session", map[string]any{
			"sessionId": session.ID.String(),
			"error":     result.Error.Error(),
		})
		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		r.logger.Debug("Session not found for update", map[string]any{"sessionId": session.ID.String()})
		return domainError.ErrSessionNotFound
	}

	return nil
}

// CountByUserID counts the number of sessions for a user
func (r *GormAuthSessionRepository) CountByUserID(ctx context.Context, userID entity.ID) (int64, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return 0, err
	}

	var count int64
	result := r.db.WithContext(ctx).
		Model(&model.AuthSession{}).
		Where("user_id = ?", userID.String()).
		Count(&count)

	if result.Error != nil {
		r.logger.Error("Failed to count sessions for user", map[string]any{
			"userId": userID.String(),
			"error":  result.Error.Error(),
		})
		return 0, database.MapError(result.Error)
	}

	return count, nil
}

// DeleteOldestByUserID deletes the oldest session for a user
// Uses a transaction to ensure finding and deleting happen atomically
func (r *GormAuthSessionRepository) DeleteOldestByUserID(ctx context.Context, userID entity.ID) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	return r.ExecuteInTransaction(ctx, func(txRepo repo.AuthSessionRepository) error {
		// Convert to GormAuthSessionRepository to access the DB
		txGormRepo, ok := txRepo.(*GormAuthSessionRepository)
		if !ok {
			r.logger.Error("Invalid repository type in transaction", map[string]any{
				"expected": "GormAuthSessionRepository",
				"actual":   "unknown",
			})
			return errors.New("invalid repository type")
		}

		// Find the oldest session
		var oldestSession model.AuthSession
		findResult := txGormRepo.db.WithContext(ctx).
			Where("user_id = ?", userID.String()).
			Order("created_at ASC").
			First(&oldestSession)

		if findResult.Error != nil {
			if errors.Is(findResult.Error, gorm.ErrRecordNotFound) {
				r.logger.Debug("No sessions found to delete", map[string]any{"userId": userID.String()})
				return nil // No sessions to delete
			}
			r.logger.Error("Failed to find oldest session", map[string]any{
				"userId": userID.String(),
				"error":  findResult.Error.Error(),
			})
			return database.MapError(findResult.Error)
		}

		// Delete the session
		deleteResult := txGormRepo.db.WithContext(ctx).
			Where("id = ?", oldestSession.ID).
			Delete(&model.AuthSession{})

		if deleteResult.Error != nil {
			r.logger.Error("Failed to delete oldest session", map[string]any{
				"userId":    userID.String(),
				"sessionId": oldestSession.ID,
				"error":     deleteResult.Error.Error(),
			})
		} else {
			r.logger.Info("Deleted oldest session", map[string]any{
				"userId":    userID.String(),
				"sessionId": oldestSession.ID,
			})
		}

		return database.MapError(deleteResult.Error)
	})
}

// EnsureSessionLimit ensures the number of sessions for a user doesn't exceed the limit
// Uses a transaction to ensure counting and deleting happen atomically
func (r *GormAuthSessionRepository) EnsureSessionLimit(ctx context.Context, userID entity.ID, limit int64) error {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return err
	}

	return r.ExecuteInTransaction(ctx, func(txRepo repo.AuthSessionRepository) error {
		// Convert to GormAuthSessionRepository to access the DB
		txGormRepo, ok := txRepo.(*GormAuthSessionRepository)
		if !ok {
			r.logger.Error("Invalid repository type in transaction", map[string]any{
				"expected": "GormAuthSessionRepository",
				"actual":   "unknown",
			})
			return errors.New("invalid repository type")
		}

		// Count the number of sessions
		var count int64
		countResult := txGormRepo.db.WithContext(ctx).
			Model(&model.AuthSession{}).
			Where("user_id = ?", userID.String()).
			Count(&count)

		if countResult.Error != nil {
			r.logger.Error("Failed to count sessions", map[string]any{
				"userId": userID.String(),
				"error":  countResult.Error.Error(),
			})
			return database.MapError(countResult.Error)
		}

		if count < limit {
			return nil
		}

		// Calculate how many sessions to delete to stay under the limit
		toDelete := count - limit + 1 // +1 to make room for new session

		// Find the oldest sessions
		var oldestSessions []model.AuthSession
		findResult := txGormRepo.db.WithContext(ctx).
			Where("user_id = ?", userID.String()).
			Order("created_at ASC").
			Limit(int(toDelete)).
			Find(&oldestSessions)

		if findResult.Error != nil {
			r.logger.Error("Failed to find oldest sessions", map[string]any{
				"userId": userID.String(),
				"limit":  toDelete,
				"error":  findResult.Error.Error(),
			})
			return database.MapError(findResult.Error)
		}

		if len(oldestSessions) == 0 {
			return nil
		}

		// Extract IDs for deletion
		var ids []string
		for _, session := range oldestSessions {
			ids = append(ids, session.ID)
		}

		// Delete the sessions
		deleteResult := txGormRepo.db.WithContext(ctx).
			Where("id IN ?", ids).
			Delete(&model.AuthSession{})

		if deleteResult.Error != nil {
			r.logger.Error("Failed to delete oldest sessions", map[string]any{
				"userId":       userID.String(),
				"sessionCount": len(ids),
				"error":        deleteResult.Error.Error(),
			})
		} else {
			r.logger.Info("Deleted oldest sessions to enforce limit", map[string]any{
				"userId":       userID.String(),
				"limit":        limit,
				"deletedCount": deleteResult.RowsAffected,
			})
		}

		return database.MapError(deleteResult.Error)
	})
}

// BatchDeleteExpired deletes expired sessions in batches
// No transaction needed as each batch is processed independently and safely
func (r *GormAuthSessionRepository) BatchDeleteExpired(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return 0, err
	}

	var totalDeleted int64
	beforeTimeUnix := before.Unix()

	for {
		// Check context at each iteration to allow cancellation between batches
		if err := r.contextUtil.CheckContext(ctx); err != nil {
			return totalDeleted, err
		}

		// Find a batch of expired sessions
		var expiredSessions []model.AuthSession
		findResult := r.db.WithContext(ctx).
			Where("expires_at < ?", before).
			Limit(batchSize).
			Find(&expiredSessions)

		if findResult.Error != nil {
			r.logger.Error("Failed to find expired sessions", map[string]any{
				"beforeTime": beforeTimeUnix,
				"batchSize":  batchSize,
				"error":      findResult.Error.Error(),
			})
			return totalDeleted, database.MapError(findResult.Error)
		}

		// No more expired sessions to delete
		if len(expiredSessions) == 0 {
			break
		}

		// Extract IDs for deletion
		var ids []string
		for _, session := range expiredSessions {
			ids = append(ids, session.ID)
		}

		// Delete the batch
		deleteResult := r.db.WithContext(ctx).
			Where("id IN ?", ids).
			Delete(&model.AuthSession{})

		if deleteResult.Error != nil {
			r.logger.Error("Failed to delete batch of expired sessions", map[string]any{
				"batchSize": len(ids),
				"error":     deleteResult.Error.Error(),
			})
			return totalDeleted, database.MapError(deleteResult.Error)
		}

		totalDeleted += deleteResult.RowsAffected
		r.logger.Debug("Deleted batch of expired sessions", map[string]any{
			"batchSize":    len(ids),
			"deletedCount": deleteResult.RowsAffected,
			"totalDeleted": totalDeleted,
		})

		// If we got fewer results than the batch size, we're done
		if len(expiredSessions) < batchSize {
			break
		}
	}

	r.logger.Info("Completed batch deletion of expired sessions", map[string]any{
		"beforeTime":   beforeTimeUnix,
		"totalDeleted": totalDeleted,
	})

	return totalDeleted, nil
}

// DeleteAllExcept deletes all sessions for a user except the specified session
func (r *GormAuthSessionRepository) DeleteAllExcept(ctx context.Context, userID entity.ID, sessionID entity.ID) (int64, error) {
	if err := r.contextUtil.CheckContext(ctx); err != nil {
		return 0, err
	}

	result := r.db.WithContext(ctx).
		Where("user_id = ? AND id != ?", userID.String(), sessionID.String()).
		Delete(&model.AuthSession{})

	if result.Error != nil {
		r.logger.Error("Failed to delete all sessions except current", map[string]any{
			"userId":    userID.String(),
			"sessionId": sessionID.String(),
			"error":     result.Error.Error(),
		})
		return 0, database.MapError(result.Error)
	}

	r.logger.Info("Deleted all sessions except current", map[string]any{
		"userId":       userID.String(),
		"sessionId":    sessionID.String(),
		"deletedCount": result.RowsAffected,
	})

	return result.RowsAffected, nil
}
