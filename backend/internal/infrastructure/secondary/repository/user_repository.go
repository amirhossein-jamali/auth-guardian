// backend/internal/infrastructure/secondary/repository/user_repository.go
package repository

import (
	"context"

	"github.com/amirhossein-jamali/auth-guardian/internal/domain/entity"
	domainError "github.com/amirhossein-jamali/auth-guardian/internal/domain/error"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/logger/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/port/secondary/repository"
	"github.com/amirhossein-jamali/auth-guardian/internal/domain/valueobject"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database"
	dbModel "github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/database/model"
	"github.com/amirhossein-jamali/auth-guardian/internal/infrastructure/secondary/mapper"

	"gorm.io/gorm"
)

// GormUserRepository implements the UserRepository interface using GORM
type GormUserRepository struct {
	db     *gorm.DB
	logger logger.Logger
	mapper mapper.UserMapperInterface
}

// Ensure GormUserRepository implements UserRepository
var _ repository.UserRepository = (*GormUserRepository)(nil)

// NewGormUserRepository creates a new GORM-based user repository
func NewGormUserRepository(db *gorm.DB, logger logger.Logger, mapper mapper.UserMapperInterface) repository.UserRepository {
	return &GormUserRepository{
		db:     db,
		logger: logger,
		mapper: mapper,
	}
}

// WithTx returns a new repository instance with the given transaction
func (r *GormUserRepository) WithTx(tx *gorm.DB) repository.UserRepository {
	return NewGormUserRepository(tx, r.logger, r.mapper)
}

// Create stores a new user in the database
func (r *GormUserRepository) Create(ctx context.Context, user *entity.User) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Convert domain entity to database model
	userDTO := r.mapper.FromEntity(user)
	dbUser := r.mapper.ToModel(userDTO)

	// Use transaction with context
	result := r.db.WithContext(ctx).Create(&dbUser)
	if result.Error != nil {
		r.logger.Error("Failed to create user in database",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", user.ID.String()))

		return database.MapError(result.Error)
	}

	return nil
}

// GetByID retrieves a user by ID from the database
func (r *GormUserRepository) GetByID(ctx context.Context, id valueobject.ID) (*entity.User, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var dbUser dbModel.User
	result := r.db.WithContext(ctx).Where("id = ?", id.String()).First(&dbUser)
	if result.Error != nil {
		r.logger.Error("Failed to get user by ID",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", id.String()))

		return nil, database.MapError(result.Error)
	}

	// Convert database model to domain entity using mapper
	userDTO := r.mapper.FromModel(dbUser)
	user, err := r.mapper.ToEntity(userDTO)
	if err != nil {
		r.logger.Error("Failed to map user model to entity",
			model.NewField("error", err.Error()),
			model.NewField("userId", id.String()))
		return nil, err
	}

	return user, nil
}

// GetByEmail retrieves a user by email from the database
func (r *GormUserRepository) GetByEmail(ctx context.Context, email valueobject.Email) (*entity.User, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var dbUser dbModel.User
	result := r.db.WithContext(ctx).Where("email = ?", email.Value()).First(&dbUser)
	if result.Error != nil {
		r.logger.Error("Failed to get user by email",
			model.NewField("error", result.Error.Error()),
			model.NewField("email", email.Value()))

		return nil, database.MapError(result.Error)
	}

	// Convert database model to domain entity using mapper
	userDTO := r.mapper.FromModel(dbUser)
	user, err := r.mapper.ToEntity(userDTO)
	if err != nil {
		r.logger.Error("Failed to map user model to entity",
			model.NewField("error", err.Error()),
			model.NewField("userId", dbUser.ID))
		return nil, err
	}

	return user, nil
}

// Update updates an existing user in the database
func (r *GormUserRepository) Update(ctx context.Context, user *entity.User) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Convert domain entity to database model
	userDTO := r.mapper.FromEntity(user)
	dbUser := r.mapper.ToModel(userDTO)

	result := r.db.WithContext(ctx).Model(&dbModel.User{}).Where("id = ?", user.ID.String()).Updates(dbUser)
	if result.Error != nil {
		r.logger.Error("Failed to update user",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", user.ID.String()))

		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		return domainError.ErrUserNotFound
	}

	return nil
}

// Delete removes a user from the database
func (r *GormUserRepository) Delete(ctx context.Context, id valueobject.ID) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	result := r.db.WithContext(ctx).Where("id = ?", id.String()).Delete(&dbModel.User{})
	if result.Error != nil {
		r.logger.Error("Failed to delete user",
			model.NewField("error", result.Error.Error()),
			model.NewField("userId", id.String()))

		return database.MapError(result.Error)
	}

	if result.RowsAffected == 0 {
		return domainError.ErrUserNotFound
	}

	return nil
}

// EmailExists checks if a user with the given email exists
func (r *GormUserRepository) EmailExists(ctx context.Context, email valueobject.Email) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	var count int64
	result := r.db.WithContext(ctx).Model(&dbModel.User{}).Where("email = ?", email.Value()).Count(&count)
	if result.Error != nil {
		r.logger.Error("Failed to check email existence",
			model.NewField("error", result.Error.Error()),
			model.NewField("email", email.Value()))

		return false, database.MapError(result.Error)
	}

	return count > 0, nil
}
