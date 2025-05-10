package repository

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
)

type AuthSessionRepository interface {
	Create(ctx context.Context, session *entity.AuthSession) error
	GetByRefreshToken(ctx context.Context, refreshToken string) (*entity.AuthSession, error)
	GetByUserIDAndUserAgent(ctx context.Context, userID valueobject.ID, userAgent string) (*entity.AuthSession, error)
	DeleteByUserID(ctx context.Context, userID valueobject.ID) error
	DeleteByID(ctx context.Context, id valueobject.ID) error
	DeleteExpired(ctx context.Context) error
	Update(ctx context.Context, session *entity.AuthSession) error
	CountByUserID(ctx context.Context, userID valueobject.ID) (int64, error)
}
