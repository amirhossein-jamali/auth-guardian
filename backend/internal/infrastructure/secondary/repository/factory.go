package repository

import (
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/mapper"
	"gorm.io/gorm"
)

// RepositoryFactory creates repository instances
type RepositoryFactory struct {
	db     *gorm.DB
	logger logger.Logger
}

// NewRepositoryFactory creates a new RepositoryFactory
func NewRepositoryFactory(db *gorm.DB, logger logger.Logger) *RepositoryFactory {
	return &RepositoryFactory{
		db:     db,
		logger: logger,
	}
}

// WithTransaction returns a new factory that uses the given transaction
func (f *RepositoryFactory) WithTransaction(tx *gorm.DB) *RepositoryFactory {
	return &RepositoryFactory{
		db:     tx,
		logger: f.logger,
	}
}

// CreateUserRepository creates a new user repository
func (f *RepositoryFactory) CreateUserRepository() repository.UserRepository {
	userMapper := mapper.NewUserMapper(f.logger)
	return NewGormUserRepository(f.db, f.logger, userMapper)
}

// CreateAuthSessionRepository creates a new auth session repository
func (f *RepositoryFactory) CreateAuthSessionRepository() repository.AuthSessionRepository {
	return NewGormAuthSessionRepository(f.db, f.logger)
}
