package repository

import (
	"context"
	"time"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
)

// AuthSessionRepository defines the interface for authentication session data access
type AuthSessionRepository interface {
	// Create creates a new session
	Create(ctx context.Context, session *entity.AuthSession) error
	// GetByUserID gets all sessions for a user
	GetByUserID(ctx context.Context, userID entity.ID) ([]*entity.AuthSession, error)
	// GetByRefreshToken gets a session by refresh token
	GetByRefreshToken(ctx context.Context, refreshToken string) (*entity.AuthSession, error)
	// GetByUserIDAndUserAgent gets a session by userID and userAgent
	GetByUserIDAndUserAgent(ctx context.Context, userID entity.ID, userAgent string) (*entity.AuthSession, error)
	// DeleteAllByUserID deletes all sessions for a user
	DeleteAllByUserID(ctx context.Context, userID entity.ID) error
	// DeleteByID deletes a session by ID
	DeleteByID(ctx context.Context, id entity.ID) error
	// DeleteExpired deletes expired sessions
	DeleteExpired(ctx context.Context, before time.Time) error
	// Update updates a session
	Update(ctx context.Context, session *entity.AuthSession) error
	// CountByUserID counts the number of sessions for a user
	CountByUserID(ctx context.Context, userID entity.ID) (int64, error)
	// DeleteOldestByUserID deletes the oldest session for a user
	DeleteOldestByUserID(ctx context.Context, userID entity.ID) error
	// EnsureSessionLimit ensures the number of sessions for a user doesn't exceed the limit
	// by automatically deleting the oldest sessions if necessary
	EnsureSessionLimit(ctx context.Context, userID entity.ID, limit int64) error
	// BatchDeleteExpired deletes expired sessions in batches to prevent database overload
	// It will process at most 'batchSize' sessions at once
	BatchDeleteExpired(ctx context.Context, before time.Time, batchSize int) (int64, error)
	// DeleteAllExcept deletes all sessions for a user except the specified session
	DeleteAllExcept(ctx context.Context, userID entity.ID, sessionID entity.ID) (int64, error)
	// ExecuteInTransaction executes operations within a transaction
	ExecuteInTransaction(ctx context.Context, fn func(txRepo AuthSessionRepository) error) error
}
